// Package session provides sticky conversation-to-account routing with rolling TTL.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"strings"
	"sync"
	"time"
)

const (
	defaultTTL         = 30 * time.Minute
	maxBindings        = 10000
	maxExplicitIDBytes = 128
)

type binding struct {
	UID      string
	ConvID   string
	LastSeen time.Time
}

// Router maps conversation keys to (account UID, conversation ID) so multi-turn chats
// stay on the same account for server-side thread reuse.
type Router struct {
	mu        sync.Mutex
	enabled   bool
	ttl       time.Duration
	bindings  map[string]binding
	stopCh    chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func New(ttl time.Duration) *Router {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Router{
		enabled:  true,
		ttl:      ttl,
		bindings: map[string]binding{},
		stopCh:   make(chan struct{}),
	}
}

func (r *Router) UpdateConfig(enabled bool, ttl time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
	if ttl > 0 {
		r.ttl = ttl
	}
	if !enabled {
		clear(r.bindings)
	}
}

func (r *Router) StartGC() {
	if r == nil {
		return
	}
	r.startOnce.Do(func() {
		go func() {
			tk := time.NewTicker(5 * time.Minute)
			defer tk.Stop()
			for {
				select {
				case <-r.stopCh:
					return
				case <-tk.C:
					r.gc()
				}
			}
		}()
	})
}

func (r *Router) StopGC() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

func (r *Router) gc() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, b := range r.bindings {
		if now.Sub(b.LastSeen) > r.ttl {
			delete(r.bindings, k)
		}
	}
}

func (r *Router) Lookup(key string) (uid, convID string, ok bool) {
	if r == nil || key == "" {
		return "", "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return "", "", false
	}
	b, exists := r.bindings[key]
	if !exists || time.Since(b.LastSeen) > r.ttl {
		if exists {
			delete(r.bindings, key)
		}
		return "", "", false
	}
	b.LastSeen = time.Now()
	r.bindings[key] = b
	return b.UID, b.ConvID, true
}

func (r *Router) Bind(key, uid, convID string) string {
	if r == nil || key == "" || uid == "" {
		return convID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return convID
	}
	if convID == "" {
		var b [16]byte
		_, _ = rand.Read(b[:])
		convID = "conv_" + hex.EncodeToString(b[:])
	}
	now := time.Now()
	if _, exists := r.bindings[key]; !exists && len(r.bindings) >= maxBindings {
		r.evictLocked(now)
	}
	r.bindings[key] = binding{UID: uid, ConvID: convID, LastSeen: now}
	return convID
}

func (r *Router) evictLocked(now time.Time) {
	for k, b := range r.bindings {
		if now.Sub(b.LastSeen) > r.ttl {
			delete(r.bindings, k)
		}
	}
	if len(r.bindings) < maxBindings {
		return
	}
	var (
		oldestKey  string
		oldestTime time.Time
		first      = true
	)
	for k, b := range r.bindings {
		if first || b.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.LastSeen
			first = false
		}
	}
	if !first {
		delete(r.bindings, oldestKey)
	}
}

func (r *Router) Unbind(key string) {
	if r == nil || key == "" {
		return
	}
	r.mu.Lock()
	delete(r.bindings, key)
	r.mu.Unlock()
}

func (r *Router) UnbindAccount(uid string) {
	if r == nil || uid == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.bindings {
		if b.UID == uid {
			delete(r.bindings, k)
		}
	}
}

func (r *Router) Count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bindings)
}

// DeriveKey builds a deterministic sticky session key from explicit header/body
// conversation_id, or falls back to streaming SHA-256 over (system + first user message).
func DeriveKey(explicitID string, messages []any) string {
	if s := strings.TrimSpace(explicitID); s != "" {
		if len(s) > maxExplicitIDBytes {
			sum := sha256.Sum256([]byte(s))
			return "id:" + hex.EncodeToString(sum[:16])
		}
		return "id:" + s
	}

	var (
		sysVal       any
		firstUserVal any
		hasSys       bool
		hasUser      bool
	)
	for _, raw := range messages {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "system", "developer":
			if !hasSys && hasNonEmptyContent(m["content"]) {
				sysVal = m["content"]
				hasSys = true
			}
		case "user":
			if !hasUser && hasNonEmptyContent(m["content"]) {
				firstUserVal = m["content"]
				hasUser = true
			}
		}
		if hasSys && hasUser {
			break
		}
	}
	if !hasSys && !hasUser {
		return ""
	}

	h := sha256.New()
	if hasSys {
		writeNormalizedContent(h, sysVal)
	}
	_, _ = h.Write([]byte{0x1f})
	if hasUser {
		writeNormalizedContent(h, firstUserVal)
	}
	sum := h.Sum(nil)
	return "d:" + hex.EncodeToString(sum[:12])
}

func hasNonEmptyContent(v any) bool {
	if v == nil {
		return false
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) != ""
	case []any:
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					if strings.TrimSpace(t) != "" {
						return true
					}
					continue
				}
			}
			if item != nil {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func writeNormalizedContent(h hash.Hash, v any) {
	switch x := v.(type) {
	case string:
		_, _ = h.Write([]byte(x))
	case []any:
		enc := json.NewEncoder(h)
		enc.SetEscapeHTML(false)
		wrote := false
		for _, item := range x {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					if strings.TrimSpace(t) == "" {
						continue
					}
					if wrote {
						_, _ = h.Write([]byte{'\n'})
					}
					_, _ = h.Write([]byte(t))
					wrote = true
					continue
				}
			}
			_ = enc.Encode(item)
			wrote = true
		}
	default:
		enc := json.NewEncoder(h)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
	}
}
