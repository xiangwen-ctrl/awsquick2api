package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
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

// MessageKey hashes the complete normalized message, including assistant replies.
func MessageKey(m map[string]any) string {
	role := msgRole(m)
	normalized := maps.Clone(m)
	normalized["role"] = role
	switch content := m["content"].(type) {
	case nil:
		normalized["content"] = ""
	case []any:
		var text strings.Builder
		allText := true
		for _, part := range content {
			p, _ := part.(map[string]any)
			kind, _ := p["type"].(string)
			value, ok := p["text"].(string)
			if !ok || len(p) != 2 || (kind != "text" && kind != "input_text" && kind != "output_text") {
				allText = false
				break
			}
			text.WriteString(value)
		}
		if allText {
			normalized["content"] = text.String()
		}
	}
	raw, _ := json.Marshal(normalized)
	return role + ":" + Digest(string(raw))
}

func assistantReplyKey(res ChatResult) string {
	msg := map[string]any{"role": "assistant", "content": res.Text}
	if res.Reasoning != "" {
		msg["reasoning_content"] = res.Reasoning
	}
	if len(res.ToolCalls) > 0 {
		calls := make([]any, 0, len(res.ToolCalls))
		for _, call := range res.ToolCalls {
			calls = append(calls, map[string]any{
				"id": call.ID, "type": "function",
				"function": map[string]any{"name": call.Name, "arguments": call.Arguments},
			})
		}
		msg["tool_calls"] = calls
	}
	return MessageKey(msg)
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
	if s == nil || session == "" || len(keys) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var best *ThreadEntry
	ambiguous := false
	for id, t := range s.threads {
		if now.Sub(t.At) > threadTTL {
			delete(s.threads, id)
			s.removeOrderLocked(id)
			continue
		}
		if t.Busy || t.Account != account || t.Session != session {
			continue
		}
		if len(t.Keys) >= len(keys) || (best != nil && len(t.Keys) < len(best.Keys)) {
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
			ambiguous = best != nil && len(t.Keys) == len(best.Keys)
			best = t
		}
	}
	if best == nil || ambiguous {
		return nil
	}
	// Newly added messages must not already include an assistant turn written elsewhere.
	for _, k := range keys[len(best.Keys):] {
		if strings.HasPrefix(k, "assistant:") {
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
	if s == nil || threadID == "" || session == "" || len(keys) == 0 {
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

	s.threads[threadID] = &ThreadEntry{
		ID:      threadID,
		Account: account,
		Session: session,
		Custom:  customDigest,
		Keys:    append([]string(nil), keys...),
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
