// Package apikeys provides lightweight scoped inference API keys stored locally
// with SHA-256 hashes (no plaintext sub-keys on disk) and metadata-only usage counters.
package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/safefile"
)

const (
	maxKeys          = 256
	maxKeyNameRunes  = 64
	usageFlushWindow = 5 * time.Second
)

var (
	ErrKeyNotFound = errors.New("api key not found")
	ErrKeyLimit    = errors.New("maximum number of scoped api keys reached")
)

// KeyRecord is the on-disk representation of one scoped inference key.
// Plaintext secrets are never stored; only Hash (SHA-256 hex) and Mask are persisted.
type KeyRecord struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Mask             string   `json:"mask"`
	Hash             string   `json:"hash"`
	Enabled          bool     `json:"enabled"`
	AllowedModels    []string `json:"allowed_models,omitempty"`
	ExpiresAt        int64    `json:"expires_at,omitempty"`
	MaxDailyRequests int64    `json:"max_daily_requests,omitempty"`
	MaxTotalTokens   int64    `json:"max_total_tokens,omitempty"`
	TotalRequests    int64    `json:"total_requests"`
	TotalTokens      int64    `json:"total_tokens"`
	DailyDate        string   `json:"daily_date,omitempty"`
	DailyRequests    int64    `json:"daily_requests,omitempty"`
	CreatedAt        int64    `json:"created_at"`
	LastUsedAt       int64    `json:"last_used_at,omitempty"`
}

// KeyView is the panel-safe view of a scoped inference key (omits Hash).
type KeyView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Mask             string   `json:"mask"`
	Enabled          bool     `json:"enabled"`
	AllowedModels    []string `json:"allowed_models"`
	ExpiresAt        int64    `json:"expires_at,omitempty"`
	MaxDailyRequests int64    `json:"max_daily_requests,omitempty"`
	MaxTotalTokens   int64    `json:"max_total_tokens,omitempty"`
	TotalRequests    int64    `json:"total_requests"`
	TotalTokens      int64    `json:"total_tokens"`
	DailyDate        string   `json:"daily_date,omitempty"`
	DailyRequests    int64    `json:"daily_requests"`
	CreatedAt        int64    `json:"created_at"`
	LastUsedAt       int64    `json:"last_used_at,omitempty"`
	Expired          bool     `json:"expired,omitempty"`
}

// CreateInput configures a newly created scoped API key.
type CreateInput struct {
	Name             string   `json:"name"`
	AllowedModels    []string `json:"allowed_models,omitempty"`
	ExpiresAt        int64    `json:"expires_at,omitempty"`
	MaxDailyRequests int64    `json:"max_daily_requests,omitempty"`
	MaxTotalTokens   int64    `json:"max_total_tokens,omitempty"`
}

// UpdatePatch applies partial updates to an existing scoped API key.
type UpdatePatch struct {
	Name             *string   `json:"name,omitempty"`
	Enabled          *bool     `json:"enabled,omitempty"`
	AllowedModels    *[]string `json:"allowed_models,omitempty"`
	ExpiresAt        *int64    `json:"expires_at,omitempty"`
	MaxDailyRequests *int64    `json:"max_daily_requests,omitempty"`
	MaxTotalTokens   *int64    `json:"max_total_tokens,omitempty"`
}

// AuthResult reports the outcome of authenticating a bearer/x-api-key against scoped keys.
type AuthResult struct {
	Matched       bool
	Key           *KeyView
	DeniedStatus  int
	DeniedCode    string
	DeniedMessage string
}

type storeFile struct {
	Version int         `json:"version"`
	Keys    []KeyRecord `json:"keys"`
}

// Store manages scoped inference API keys with atomic 0600 persistence.
type Store struct {
	path string
	now  func() time.Time

	mu        sync.Mutex
	flushMu   sync.Mutex
	byID      map[string]*KeyRecord
	dirty     bool
	lastFlush time.Time
}

// NewStore loads scoped keys from path (missing file starts empty).
func NewStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		now:  time.Now,
		byID: map[string]*KeyRecord{},
	}
	if strings.TrimSpace(path) == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("read api keys: %w", err)
	}
	var sf storeFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		return nil, fmt.Errorf("parse api keys: %w", err)
	}
	for i := range sf.Keys {
		rec := sf.Keys[i]
		if rec.ID == "" || rec.Hash == "" {
			continue
		}
		rec.AllowedModels = cleanModelList(rec.AllowedModels)
		cp := rec
		s.byID[rec.ID] = &cp
	}
	return s, nil
}

func (s *Store) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func hashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func maskKey(raw string) string {
	if len(raw) <= 10 {
		return "qk_****"
	}
	return raw[:7] + "..." + raw[len(raw)-4:]
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("apikeys: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

func cleanName(raw string) (string, error) {
	name := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw))
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if len([]rune(name)) > maxKeyNameRunes {
		return "", fmt.Errorf("name must be at most %d characters", maxKeyNameRunes)
	}
	return name, nil
}

func cleanModelList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		low := strings.ToLower(m)
		if seen[low] {
			continue
		}
		seen[low] = true
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Store) viewLocked(rec *KeyRecord, now time.Time) KeyView {
	today := now.UTC().Format("2006-01-02")
	daily := rec.DailyRequests
	dailyDate := rec.DailyDate
	if dailyDate != today {
		daily = 0
		dailyDate = today
	}
	allowed := []string{}
	if len(rec.AllowedModels) > 0 {
		allowed = append([]string(nil), rec.AllowedModels...)
	}
	expired := rec.ExpiresAt > 0 && now.UnixMilli() >= rec.ExpiresAt
	return KeyView{
		ID:               rec.ID,
		Name:             rec.Name,
		Mask:             rec.Mask,
		Enabled:          rec.Enabled,
		AllowedModels:    allowed,
		ExpiresAt:        rec.ExpiresAt,
		MaxDailyRequests: rec.MaxDailyRequests,
		MaxTotalTokens:   rec.MaxTotalTokens,
		TotalRequests:    rec.TotalRequests,
		TotalTokens:      rec.TotalTokens,
		DailyDate:        dailyDate,
		DailyRequests:    daily,
		CreatedAt:        rec.CreatedAt,
		LastUsedAt:       rec.LastUsedAt,
		Expired:          expired,
	}
}

func (s *Store) snapshotRecordsLocked() []KeyRecord {
	out := make([]KeyRecord, 0, len(s.byID))
	for _, rec := range s.byID {
		cp := *rec
		if len(rec.AllowedModels) > 0 {
			cp.AllowedModels = append([]string(nil), rec.AllowedModels...)
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Store) writeDisk(records []KeyRecord) error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	raw, err := json.MarshalIndent(storeFile{Version: 1, Keys: records}, "", "  ")
	if err != nil {
		return err
	}
	return safefile.WriteAtomic(s.path, append(raw, '\n'), 0o600)
}

// List returns panel-safe views of all scoped keys ordered by creation time.
func (s *Store) List() []KeyView {
	if s == nil {
		return []KeyView{}
	}
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	recs := s.snapshotRecordsLocked()
	views := make([]KeyView, 0, len(recs))
	for i := range recs {
		views = append(views, s.viewLocked(&recs[i], now))
	}
	return views
}

// Create generates a new scoped inference API key, persists only its SHA-256 hash,
// and returns the plaintext secret once.
func (s *Store) Create(in CreateInput) (KeyView, string, error) {
	if s == nil {
		return KeyView{}, "", errors.New("api key store unavailable")
	}
	name, err := cleanName(in.Name)
	if err != nil {
		return KeyView{}, "", err
	}
	if in.MaxDailyRequests < 0 || in.MaxTotalTokens < 0 || in.ExpiresAt < 0 {
		return KeyView{}, "", fmt.Errorf("limits and expires_at must be non-negative")
	}
	now := s.clock()
	plain := "qk_" + randomHex(20)
	rec := &KeyRecord{
		ID:               "key_" + randomHex(6),
		Name:             name,
		Mask:             maskKey(plain),
		Hash:             hashKey(plain),
		Enabled:          true,
		AllowedModels:    cleanModelList(in.AllowedModels),
		ExpiresAt:        in.ExpiresAt,
		MaxDailyRequests: in.MaxDailyRequests,
		MaxTotalTokens:   in.MaxTotalTokens,
		CreatedAt:        now.UnixMilli(),
	}

	s.mu.Lock()
	if len(s.byID) >= maxKeys {
		s.mu.Unlock()
		return KeyView{}, "", ErrKeyLimit
	}
	s.byID[rec.ID] = rec
	records := s.snapshotRecordsLocked()
	view := s.viewLocked(rec, now)
	s.dirty = false
	s.lastFlush = now
	s.mu.Unlock()

	if err := s.writeDisk(records); err != nil {
		s.mu.Lock()
		delete(s.byID, rec.ID)
		s.mu.Unlock()
		return KeyView{}, "", err
	}
	return view, plain, nil
}

// Update modifies metadata/limits of an existing scoped key and persists atomically.
func (s *Store) Update(id string, patch UpdatePatch) (KeyView, error) {
	if s == nil {
		return KeyView{}, errors.New("api key store unavailable")
	}
	now := s.clock()
	s.mu.Lock()
	rec, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return KeyView{}, ErrKeyNotFound
	}
	prev := *rec
	if len(rec.AllowedModels) > 0 {
		prev.AllowedModels = append([]string(nil), rec.AllowedModels...)
	}
	if patch.Name != nil {
		name, err := cleanName(*patch.Name)
		if err != nil {
			s.mu.Unlock()
			return KeyView{}, err
		}
		rec.Name = name
	}
	if patch.Enabled != nil {
		rec.Enabled = *patch.Enabled
	}
	if patch.AllowedModels != nil {
		rec.AllowedModels = cleanModelList(*patch.AllowedModels)
	}
	if patch.ExpiresAt != nil {
		if *patch.ExpiresAt < 0 {
			*rec = prev
			s.mu.Unlock()
			return KeyView{}, fmt.Errorf("expires_at must be non-negative")
		}
		rec.ExpiresAt = *patch.ExpiresAt
	}
	if patch.MaxDailyRequests != nil {
		if *patch.MaxDailyRequests < 0 {
			*rec = prev
			s.mu.Unlock()
			return KeyView{}, fmt.Errorf("max_daily_requests must be non-negative")
		}
		rec.MaxDailyRequests = *patch.MaxDailyRequests
	}
	if patch.MaxTotalTokens != nil {
		if *patch.MaxTotalTokens < 0 {
			*rec = prev
			s.mu.Unlock()
			return KeyView{}, fmt.Errorf("max_total_tokens must be non-negative")
		}
		rec.MaxTotalTokens = *patch.MaxTotalTokens
	}
	records := s.snapshotRecordsLocked()
	view := s.viewLocked(rec, now)
	s.dirty = false
	s.lastFlush = now
	s.mu.Unlock()

	if err := s.writeDisk(records); err != nil {
		s.mu.Lock()
		if cur, exists := s.byID[id]; exists {
			*cur = prev
		}
		s.mu.Unlock()
		return KeyView{}, err
	}
	return view, nil
}

// Delete removes a scoped key by ID and persists atomically.
func (s *Store) Delete(id string) error {
	if s == nil {
		return errors.New("api key store unavailable")
	}
	now := s.clock()
	s.mu.Lock()
	prev, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return ErrKeyNotFound
	}
	delete(s.byID, id)
	records := s.snapshotRecordsLocked()
	s.dirty = false
	s.lastFlush = now
	s.mu.Unlock()

	if err := s.writeDisk(records); err != nil {
		s.mu.Lock()
		s.byID[id] = prev
		s.mu.Unlock()
		return err
	}
	return nil
}

// Authenticate validates a presented API key against stored scoped keys.
// Matched is false when the token does not match any scoped key.
func (s *Store) Authenticate(presented string) AuthResult {
	presented = strings.TrimSpace(presented)
	if s == nil || presented == "" {
		return AuthResult{}
	}
	wantHash := []byte(hashKey(presented))
	now := s.clock()
	today := now.UTC().Format("2006-01-02")

	s.mu.Lock()
	defer s.mu.Unlock()
	var matched *KeyRecord
	for _, rec := range s.byID {
		if len(rec.Hash) == len(wantHash) && subtle.ConstantTimeCompare([]byte(rec.Hash), wantHash) == 1 {
			matched = rec
		}
	}
	if matched == nil {
		return AuthResult{}
	}
	view := s.viewLocked(matched, now)
	if !matched.Enabled {
		return AuthResult{
			Matched:       true,
			Key:           &view,
			DeniedStatus:  401,
			DeniedCode:    "authentication_error",
			DeniedMessage: "API key is disabled",
		}
	}
	if matched.ExpiresAt > 0 && now.UnixMilli() >= matched.ExpiresAt {
		return AuthResult{
			Matched:       true,
			Key:           &view,
			DeniedStatus:  401,
			DeniedCode:    "authentication_error",
			DeniedMessage: "API key has expired",
		}
	}
	daily := matched.DailyRequests
	if matched.DailyDate != today {
		daily = 0
	}
	if matched.MaxDailyRequests > 0 && daily >= matched.MaxDailyRequests {
		return AuthResult{
			Matched:       true,
			Key:           &view,
			DeniedStatus:  429,
			DeniedCode:    "rate_limit_error",
			DeniedMessage: "API key daily request limit exceeded",
		}
	}
	if matched.MaxTotalTokens > 0 && matched.TotalTokens >= matched.MaxTotalTokens {
		return AuthResult{
			Matched:       true,
			Key:           &view,
			DeniedStatus:  429,
			DeniedCode:    "rate_limit_error",
			DeniedMessage: "API key total token limit exceeded",
		}
	}
	return AuthResult{Matched: true, Key: &view}
}

// RecordUsage updates metadata-only request/token counters for a scoped key.
func (s *Store) RecordUsage(id string, tokens int) {
	if s == nil || id == "" {
		return
	}
	if tokens < 0 {
		tokens = 0
	}
	now := s.clock()
	today := now.UTC().Format("2006-01-02")

	var records []KeyRecord
	s.mu.Lock()
	rec, ok := s.byID[id]
	if ok {
		if rec.DailyDate != today {
			rec.DailyDate = today
			rec.DailyRequests = 0
		}
		rec.TotalRequests++
		rec.DailyRequests++
		rec.TotalTokens += int64(tokens)
		rec.LastUsedAt = now.UnixMilli()
		s.dirty = true
		if s.path != "" && (s.lastFlush.IsZero() || now.Sub(s.lastFlush) >= usageFlushWindow) {
			records = s.snapshotRecordsLocked()
			s.dirty = false
			s.lastFlush = now
		}
	}
	s.mu.Unlock()

	if records != nil {
		if err := s.writeDisk(records); err != nil {
			s.mu.Lock()
			s.dirty = true
			s.mu.Unlock()
		}
	}
}

// Flush persists any buffered usage counter updates to disk.
func (s *Store) Flush() error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return nil
	}
	now := s.clock()
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	records := s.snapshotRecordsLocked()
	s.dirty = false
	s.lastFlush = now
	s.mu.Unlock()

	if err := s.writeDisk(records); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// ModelAllowed checks whether any normalized candidate matches the scoped key's
// optional allowed_models list. Empty allowed_models allows all globally visible models.
func ModelAllowed(key *KeyView, cands []string) bool {
	if key == nil || len(key.AllowedModels) == 0 {
		return true
	}
	allow := make(map[string]bool, len(key.AllowedModels))
	for _, m := range key.AllowedModels {
		if low := strings.ToLower(strings.TrimSpace(m)); low != "" {
			allow[low] = true
		}
	}
	for _, c := range cands {
		if low := strings.ToLower(strings.TrimSpace(c)); low != "" && allow[low] {
			return true
		}
	}
	return false
}
