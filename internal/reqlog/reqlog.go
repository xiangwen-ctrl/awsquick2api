// Package reqlog records request metrics, rolling JSONL archives, and
// a credential-scrubbed in-memory log ring buffer mirrored to the Web panel.
package reqlog

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultMaxEntries   = 500
	defaultMaxLogs      = 1000
	archiveQueueCap     = 512
	archiveRetainDays   = 14
	maxArchiveLineBytes = 1 << 20
	maxPartialBytes     = 8 * 1024
	maxErrorMsgBytes    = 300
)

var (
	// scheme://user:pass@host (proxy URLs, *url.Error messages, DB URIs ...).
	credURLRe = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s"'<>]+@`)
	// "Bearer <token>" anywhere (headers, error strings, URL-encoded %20).
	bearerRe = regexp.MustCompile(`(?i)\b(Bearer)(?:\s+|%20)[A-Za-z0-9._~+/=-]{8,}`)
	// Authorization header / field values of any scheme (Basic, Token, Digest ...).
	authHeaderRe = regexp.MustCompile(`(?i)(\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?)(?:(?:basic|bearer|token|digest|negotiate|aws4-hmac-sha256)\s+)?[^"'\s,;}]+`)
	// Gateway keys: qk_ (inference api_key) and qka_ (panel admin_key), including custom hyphen/underscore keys.
	apiKeyRe = regexp.MustCompile(`(?i)\bqka?_[A-Za-z0-9_-]{8,}`)
	jwtRe    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	// Query-string bearer/auth tokens (e.g. WebSocket ?token=... or &token=...).
	queryTokenRe = regexp.MustCompile(`(?i)([?&]token=)([^"'\s&,;}\]]{4,})`)
	// JSON / header / query / form style secrets: "refresh_token":"...", access_token=..., x-api-key: ...
	secretFieldRe = regexp.MustCompile(`(?i)(["']?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|client[_-]?secret|api[_-]?key|admin[_-]?key|x-api-key|password|passwd|secret|encryption[_-]?key|code[_-]?verifier)\b["']?\s*[:=]\s*["']?)([^"'\s&,;}\]]{4,})`)
)

const (
	redactedURLCred = "***@"
	redactedAuth    = "[REDACTED]"
	redactedKey     = "[REDACTED_KEY]"
	redactedJWT     = "[REDACTED_JWT]"
	redactedField   = "[REDACTED]"
)

// Entry captures sanitized operational metadata only (never dialogue text or credentials).
type Entry struct {
	ID               string `json:"id"`
	Timestamp        int64  `json:"ts"`
	Path             string `json:"path"`
	RequestedModel   string `json:"requested_model"`
	ModelSlot        string `json:"model_slot"`
	ActualModel      string `json:"actual_model,omitempty"`
	AccountUID       string `json:"account_uid,omitempty"`
	AccountLabel     string `json:"account_label,omitempty"`
	KeyID            string `json:"key_id,omitempty"`
	KeyName          string `json:"key_name,omitempty"`
	Status           int    `json:"status"`
	ErrorCode        string `json:"error_code,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
	ThreadReused     bool   `json:"thread_reused,omitempty"`
	EmptyRetried     bool   `json:"empty_retried,omitempty"`
	Stream           bool   `json:"stream"`
	TTFBMs           int64  `json:"ttfb_ms"`
	TotalMs          int64  `json:"total_ms"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	CacheReadTokens  int    `json:"cache_read_tokens,omitempty"`
}

// Metrics summarizes recent request performance for the Web dashboard.
type Metrics struct {
	TotalRequests   int64   `json:"total_requests"`
	SuccessRequests int64   `json:"success_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	SuccessRate     float64 `json:"success_rate"`
	AvgTTFBMs       int64   `json:"avg_ttfb_ms"`
	TotalPromptTok  int64   `json:"total_prompt_tokens"`
	TotalCompTok    int64   `json:"total_completion_tokens"`
	TotalTokens     int64   `json:"total_tokens"`
	ThreadReused    int64   `json:"thread_reused"`
}

// LogLine is one sanitized runtime log line mirrored to the panel.
type LogLine struct {
	Timestamp int64  `json:"ts"`
	Text      string `json:"text"`
}

type archiveCmd struct {
	entry     Entry
	clearDone chan error
}

// Recorder manages metadata-only request history, optional JSONL archive, and runtime log ring.
type Recorder struct {
	dir string

	mu           sync.Mutex
	sendMu       sync.RWMutex // guards blocking sends on archiveCh against close
	archive      bool
	closed       bool
	archiveCh    chan archiveCmd
	loopDone     chan struct{}
	wg           sync.WaitGroup
	closeOnce    sync.Once
	entries      []Entry
	maxEntries   int
	entryHead    int
	entryCount   int
	totalReqs    int64
	succReqs     int64
	errReqs      int64
	ttfbSumMs    int64
	ttfbCount    int64
	promptSum    int64
	compSum      int64
	threadReused int64

	logMu    sync.Mutex
	logs     []LogLine
	maxLogs  int
	logHead  int
	logCount int
	partial  string
}

func New(dir string, archive bool) *Recorder {
	r := &Recorder{
		dir:        dir,
		archive:    archive,
		entries:    make([]Entry, defaultMaxEntries),
		maxEntries: defaultMaxEntries,
		logs:       make([]LogLine, defaultMaxLogs),
		maxLogs:    defaultMaxLogs,
	}
	if archive && dir != "" {
		r.mu.Lock()
		r.ensureWriterLocked()
		r.mu.Unlock()
	}
	return r
}

func (r *Recorder) ensureWriterLocked() {
	if r.closed || r.dir == "" || r.archiveCh != nil {
		return
	}
	_ = os.MkdirAll(r.dir, 0o700)
	r.archiveCh = make(chan archiveCmd, archiveQueueCap)
	r.loopDone = make(chan struct{})
	r.wg.Add(1)
	go r.archiveLoop(r.archiveCh, r.loopDone, r.dir)
}

func (r *Recorder) SetArchive(enabled bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.archive = enabled
	if enabled && r.dir != "" {
		r.ensureWriterLocked()
	}
}

func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		ch := r.archiveCh
		r.mu.Unlock()
		if ch != nil {
			// Wait for any Clear that observed closed == false to finish its send
			// before closing, so nobody can send on a closed channel.
			r.sendMu.Lock()
			close(ch)
			r.sendMu.Unlock()
			r.wg.Wait()
		}
	})
}

func NewRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "req_" + hex.EncodeToString(b[:])
}

func (r *Recorder) Record(e Entry) {
	if r == nil {
		return
	}
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixMilli()
	}
	e.ErrorMessage = sanitizeText(e.ErrorMessage, maxErrorMsgBytes)

	r.mu.Lock()
	r.totalReqs++
	if e.Status >= 200 && e.Status < 300 {
		r.succReqs++
	} else {
		r.errReqs++
	}
	if e.TTFBMs > 0 {
		r.ttfbSumMs += e.TTFBMs
		r.ttfbCount++
	}
	r.promptSum += int64(e.PromptTokens)
	r.compSum += int64(e.CompletionTokens)
	if e.ThreadReused {
		r.threadReused++
	}

	r.entries[r.entryHead] = e
	r.entryHead = (r.entryHead + 1) % r.maxEntries
	if r.entryCount < r.maxEntries {
		r.entryCount++
	}

	if r.archive && !r.closed && r.archiveCh != nil {
		select {
		case r.archiveCh <- archiveCmd{entry: e}:
		default:
		}
	}
	r.mu.Unlock()
}

func (r *Recorder) Clear(includeArchive bool) error {
	if r == nil {
		return nil
	}
	// sendMu (read side) is held from observing closed == false until the send
	// completes; Close takes the write side before close(ch).
	r.sendMu.RLock()
	r.mu.Lock()
	r.entries = make([]Entry, r.maxEntries)
	r.entryHead = 0
	r.entryCount = 0
	ch := r.archiveCh
	loopDone := r.loopDone
	closed := r.closed
	dir := r.dir
	r.mu.Unlock()

	if !includeArchive || dir == "" {
		r.sendMu.RUnlock()
		return nil
	}
	if ch != nil && !closed {
		done := make(chan error, 1)
		select {
		case ch <- archiveCmd{clearDone: done}:
			r.sendMu.RUnlock()
		case <-loopDone:
			r.sendMu.RUnlock()
			return removeArchiveFiles(dir)
		}
		select {
		case err := <-done:
			return err
		case <-loopDone:
			return removeArchiveFiles(dir)
		}
	}
	r.sendMu.RUnlock()
	return removeArchiveFiles(dir)
}

func (r *Recorder) archiveLoop(ch <-chan archiveCmd, loopDone chan struct{}, dir string) {
	defer r.wg.Done()
	defer close(loopDone)

	var (
		f            *os.File
		openDay      string
		lastCleanDay string
	)
	closeFile := func() {
		if f != nil {
			_ = f.Close()
			f = nil
			openDay = ""
		}
	}
	defer closeFile()

	for cmd := range ch {
		if cmd.clearDone != nil {
			closeFile()
			cmd.clearDone <- removeArchiveFiles(dir)
			continue
		}
		e := cmd.entry
		ts := time.UnixMilli(e.Timestamp)
		day := ts.Format("2006-01-02")

		if day != lastCleanDay {
			lastCleanDay = day
			pruneOldArchives(dir, ts, archiveRetainDays)
		}
		if day != openDay || f == nil {
			closeFile()
			_ = os.MkdirAll(dir, 0o700)
			path := filepath.Join(dir, "requests-"+day+".jsonl")
			nf, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				continue
			}
			f = nf
			openDay = day
		}

		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		raw = append(raw, '\n')
		if _, err := f.Write(raw); err != nil {
			closeFile()
		}
	}
}

func removeArchiveFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var firstErr error
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, "requests-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if rerr := os.Remove(filepath.Join(dir, name)); rerr != nil && !os.IsNotExist(rerr) && firstErr == nil {
			firstErr = rerr
		}
	}
	return firstErr
}

func pruneOldArchives(dir string, now time.Time, retainDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	cutoff := today.AddDate(0, 0, -retainDays)
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, "requests-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		dateStr := strings.TrimSuffix(strings.TrimPrefix(name, "requests-"), ".jsonl")
		d, err := time.ParseInLocation("2006-01-02", dateStr, now.Location())
		if err != nil {
			continue
		}
		if d.Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

func (r *Recorder) Recent(limit int) []Entry {
	if r == nil {
		return []Entry{}
	}
	if limit <= 0 {
		limit = 100
	} else if limit > r.maxEntries {
		limit = r.maxEntries
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entryCount == 0 {
		return []Entry{}
	}
	if limit > r.entryCount {
		limit = r.entryCount
	}
	out := make([]Entry, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (r.entryHead - 1 - i + r.maxEntries) % r.maxEntries
		out = append(out, r.entries[idx])
	}
	return out
}

func (r *Recorder) LoadFromArchive() int {
	if r == nil || r.dir == "" {
		return 0
	}
	dirEntries, err := os.ReadDir(r.dir)
	if err != nil {
		return 0
	}
	var files []string
	for _, ent := range dirEntries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasPrefix(name, "requests-") && strings.HasSuffix(name, ".jsonl") {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		return 0
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	newestFirst := make([]Entry, 0, min(r.maxEntries, 128))
	for _, name := range files {
		if len(newestFirst) >= r.maxEntries {
			break
		}
		loaded := readArchiveFileEntries(filepath.Join(r.dir, name))
		for i := len(loaded) - 1; i >= 0 && len(newestFirst) < r.maxEntries; i-- {
			newestFirst = append(newestFirst, loaded[i])
		}
	}
	if len(newestFirst) == 0 {
		return 0
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(newestFirst) - 1; i >= 0; i-- {
		r.entries[r.entryHead] = newestFirst[i]
		r.entryHead = (r.entryHead + 1) % r.maxEntries
		if r.entryCount < r.maxEntries {
			r.entryCount++
		}
	}
	return len(newestFirst)
}

func readArchiveFileEntries(path string) []Entry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []Entry
	br := bufio.NewReaderSize(f, 64*1024)
	for {
		line, rerr := readBoundedArchiveLine(br, maxArchiveLineBytes)
		if len(line) > 0 {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				var e Entry
				if err := json.Unmarshal([]byte(trimmed), &e); err == nil && (e.ID != "" || e.Timestamp != 0) {
					out = append(out, e)
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	return out
}

func readBoundedArchiveLine(br *bufio.Reader, maxBytes int) (string, error) {
	var buf []byte
	oversized := false
	for {
		frag, err := br.ReadSlice('\n')
		if !oversized {
			if len(buf)+len(frag) > maxBytes {
				oversized = true
				buf = nil
			} else {
				buf = append(buf, frag...)
			}
		}
		if err == nil {
			if oversized {
				return "", nil
			}
			return string(buf), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if oversized {
			return "", err
		}
		if errors.Is(err, io.EOF) {
			return string(buf), io.EOF
		}
		return "", err
	}
}

func (r *Recorder) Metrics() Metrics {
	if r == nil {
		return Metrics{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var rate float64
	if r.totalReqs > 0 {
		rate = float64(r.succReqs) / float64(r.totalReqs) * 100.0
	}
	var avgTTFB int64
	if r.ttfbCount > 0 {
		avgTTFB = r.ttfbSumMs / r.ttfbCount
	}
	return Metrics{
		TotalRequests:   r.totalReqs,
		SuccessRequests: r.succReqs,
		ErrorRequests:   r.errReqs,
		SuccessRate:     rate,
		AvgTTFBMs:       avgTTFB,
		TotalPromptTok:  r.promptSum,
		TotalCompTok:    r.compSum,
		TotalTokens:     r.promptSum + r.compSum,
		ThreadReused:    r.threadReused,
	}
}

func (r *Recorder) Write(p []byte) (int, error) {
	if r == nil {
		return len(p), nil
	}
	r.logMu.Lock()
	defer r.logMu.Unlock()

	chunk := r.partial + string(p)
	lines := strings.Split(chunk, "\n")
	rem := lines[len(lines)-1]
	if len(rem) > maxPartialBytes {
		rem = truncateUTF8(rem, maxPartialBytes)
	}
	r.partial = rem

	now := time.Now().UnixMilli()
	for _, ln := range lines[:len(lines)-1] {
		s := strings.TrimRight(ln, "\r")
		if s == "" {
			continue
		}
		s = scrubCredentials(s)
		r.logs[r.logHead] = LogLine{Timestamp: now, Text: s}
		r.logHead = (r.logHead + 1) % r.maxLogs
		if r.logCount < r.maxLogs {
			r.logCount++
		}
	}
	return len(p), nil
}

func (r *Recorder) RecentLogs(limit int) []LogLine {
	if r == nil {
		return []LogLine{}
	}
	if limit <= 0 {
		limit = 200
	} else if limit > r.maxLogs {
		limit = r.maxLogs
	}
	r.logMu.Lock()
	defer r.logMu.Unlock()
	if r.logCount == 0 {
		return []LogLine{}
	}
	if limit > r.logCount {
		limit = r.logCount
	}
	out := make([]LogLine, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (r.logHead - 1 - i + r.maxLogs) % r.maxLogs
		out = append(out, r.logs[idx])
	}
	return out
}

// ScrubCredentials redacts credentials from free-form text before it is logged or
// persisted: URL userinfo (e.g. proxy user:pass@ inside *url.Error messages),
// Authorization Bearer/Basic/Token values, qk_/qka_ gateway keys, JWTs, and
// access/refresh/id tokens, client secrets, passwords and API keys written as
// JSON fields, headers, query parameters or form values.
func ScrubCredentials(s string) string {
	return scrubCredentials(s)
}

func scrubCredentials(s string) string {
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") && strings.Contains(s, "@") {
		s = credURLRe.ReplaceAllString(s, "${1}"+redactedURLCred)
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "authorization") {
		s = authHeaderRe.ReplaceAllString(s, "${1}"+redactedAuth)
	}
	if strings.Contains(lower, "bearer") {
		s = bearerRe.ReplaceAllString(s, "${1} "+redactedAuth)
	}
	if strings.Contains(lower, "qk_") || strings.Contains(lower, "qka_") {
		s = apiKeyRe.ReplaceAllString(s, redactedKey)
	}
	if strings.Contains(s, "eyJ") {
		s = jwtRe.ReplaceAllString(s, redactedJWT)
	}
	if strings.Contains(lower, "token=") {
		s = queryTokenRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := queryTokenRe.FindStringSubmatch(m)
			if len(sub) < 3 || isRedactionMarker(sub[2]) {
				return m
			}
			return sub[1] + redactedField
		})
	}
	if strings.ContainsAny(s, ":=") {
		s = secretFieldRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := secretFieldRe.FindStringSubmatch(m)
			if len(sub) < 3 || isRedactionMarker(sub[2]) {
				return m
			}
			return sub[1] + redactedField
		})
	}
	return s
}

func isRedactionMarker(v string) bool {
	return strings.HasPrefix(v, "[REDACTED") || strings.HasPrefix(v, "***")
}

func sanitizeText(s string, maxBytes int) string {
	s = scrubCredentials(s)
	if maxBytes > 0 && len(s) > maxBytes {
		return truncateUTF8(s, maxBytes)
	}
	return s
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
