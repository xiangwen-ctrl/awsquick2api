package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxThreads = 300
	threadTTL  = 6 * time.Hour
)

var conversationHeaders = []string{
	"X-Aws-Quick-Conversation",
	"Session_id",
	"Session-Id",
	"X-Session-Id",
	"X-Session-Affinity",
	"X-Thread-Id",
	"X-Conversation-Id",
	"Conversation_id",
}

// ConversationIDFromHeaders extracts an explicit client conversation/session header if present.
func ConversationIDFromHeaders(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, name := range conversationHeaders {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			if len(v) > 256 {
				return v[:256]
			}
			return v
		}
	}
	return ""
}

// Digest returns a compact 24-hex SHA-256 prefix for text comparison.
func Digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:12])
}

// MessageKey produces a stable matching key for conversation prefix comparison.
// Assistant messages match by role alone because clients often re-format prior assistant replies.
func MessageKey(m map[string]any) string {
	role := msgRole(m)
	if role == "assistant" {
		return "assistant"
	}
	tcID, _ := m["tool_call_id"].(string)
	name, _ := m["name"].(string)
	body := ContentText(m["content"], nil, nil)
	// ContentText drops image parts, so two turns that differ only by their
	// attached image would collide. Fold the raw structured content in too.
	if content, ok := m["content"]; ok && content != nil {
		if _, isStr := content.(string); !isStr {
			if raw, err := json.Marshal(content); err == nil {
				body += "\n" + string(raw)
			}
		}
	}
	flags := ""
	if isErr, _ := m["is_error"].(bool); isErr {
		flags = "\nis_error"
	}
	return role + ":" + Digest(tcID+"\n"+name+flags+"\n"+body)
}

// ThreadEntry tracks one active Amazon Quick server-side thread and its committed history keys.
type ThreadEntry struct {
	ID      string
	Account string
	Session string
	Custom  string // digest of last sent custom_prompt
	Keys    []string
	Busy    bool
	At      time.Time
}

// ThreadStore matches multi-turn requests onto existing Amazon Quick threads so only newly
// appended messages travel over the 64 KB WebSocket frame.
type ThreadStore struct {
	mu      sync.Mutex
	threads map[string]*ThreadEntry
	order   []string
}

func NewThreadStore() *ThreadStore {
	return &ThreadStore{
		threads: map[string]*ThreadEntry{},
	}
}

// Match finds and claims (marks Busy=true) the longest matching thread for (account, session, keys).
func (s *ThreadStore) Match(account, session string, keys []string) *ThreadEntry {
	if s == nil || len(keys) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var best *ThreadEntry
	for id, t := range s.threads {
		if now.Sub(t.At) > threadTTL {
			delete(s.threads, id)
			s.removeOrderLocked(id)
			continue
		}
		if t.Busy || t.Account != account || t.Session != session {
			continue
		}
		if len(t.Keys) >= len(keys) || (best != nil && len(t.Keys) <= len(best.Keys)) {
			continue
		}
		matched := true
		for i, k := range t.Keys {
			if keys[i] != k {
				matched = false
				break
			}
		}
		if matched {
			best = t
		}
	}
	if best == nil {
		return nil
	}
	// Newly added messages must not already include an assistant turn written elsewhere.
	for _, k := range keys[len(best.Keys):] {
		if k == "assistant" {
			return nil
		}
	}
	best.Busy = true
	cp := *best
	cp.Keys = append([]string(nil), best.Keys...)
	return &cp
}

// Commit records a completed turn (including the assistant reply) onto threadID.
func (s *ThreadStore) Commit(threadID, account, session, customDigest string, keys []string) {
	if s == nil || threadID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.threads, threadID)
	s.removeOrderLocked(threadID)

	for len(s.threads) >= maxThreads && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.threads, oldest)
	}

	nextKeys := make([]string, len(keys)+1)
	copy(nextKeys, keys)
	nextKeys[len(keys)] = "assistant"

	s.threads[threadID] = &ThreadEntry{
		ID:      threadID,
		Account: account,
		Session: session,
		Custom:  customDigest,
		Keys:    nextKeys,
		Busy:    false,
		At:      time.Now(),
	}
	s.order = append(s.order, threadID)
}

// Drop deletes a thread entry (e.g., on failure or invalidation).
func (s *ThreadStore) Drop(threadID string) {
	if s == nil || threadID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.threads, threadID)
	s.removeOrderLocked(threadID)
}

func (s *ThreadStore) removeOrderLocked(id string) {
	for i, x := range s.order {
		if x == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}
