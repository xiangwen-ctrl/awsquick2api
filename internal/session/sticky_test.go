package session

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRouterBindLookupUnbindAndTTL(t *testing.T) {
	// Nil router safety.
	var nilR *Router
	if _, _, ok := nilR.Lookup("k"); ok {
		t.Fatal("nil router lookup must return false")
	}
	if got := nilR.Bind("k", "u1", "c1"); got != "c1" {
		t.Fatalf("nil router bind = %q", got)
	}
	nilR.Unbind("k")
	nilR.UnbindAccount("u1")
	nilR.UpdateConfig(false, time.Second)
	nilR.StartGC()
	nilR.StopGC()
	if nilR.Count() != 0 {
		t.Fatal("nil router count must be 0")
	}

	r := New(60 * time.Millisecond)
	r.StartGC()
	defer r.StopGC()

	// Generated conversation ID when empty.
	convID := r.Bind("k1", "u1", "")
	if !strings.HasPrefix(convID, "conv_") {
		t.Fatalf("expected generated conv_ id, got %q", convID)
	}
	if r.Count() != 1 {
		t.Fatalf("count = %d, want 1", r.Count())
	}
	uid, gotConv, ok := r.Lookup("k1")
	if !ok || uid != "u1" || gotConv != convID {
		t.Fatalf("Lookup(k1) = (%q, %q, %v)", uid, gotConv, ok)
	}

	// Bind another key on u1 and one on u2, then test UnbindAccount.
	r.Bind("k2", "u1", "c2")
	r.Bind("k3", "u2", "c3")
	r.UnbindAccount("u1")
	if _, _, ok := r.Lookup("k1"); ok {
		t.Fatal("k1 should be unbound after UnbindAccount(u1)")
	}
	if _, _, ok := r.Lookup("k2"); ok {
		t.Fatal("k2 should be unbound after UnbindAccount(u1)")
	}
	if uid, c, ok := r.Lookup("k3"); !ok || uid != "u2" || c != "c3" {
		t.Fatalf("k3 should remain bound, got (%q, %q, %v)", uid, c, ok)
	}

	// Unbind single key.
	r.Unbind("k3")
	if r.Count() != 0 {
		t.Fatalf("count after Unbind = %d, want 0", r.Count())
	}

	// TTL expiry.
	r.Bind("exp", "u1", "cexp")
	time.Sleep(80 * time.Millisecond)
	if _, _, ok := r.Lookup("exp"); ok {
		t.Fatal("expired binding should not be returned")
	}
	if r.Count() != 0 {
		t.Fatalf("expired binding should be deleted on lookup, count=%d", r.Count())
	}

	// Disabling clears existing bindings and ignores new binds.
	r.Bind("k4", "u1", "c4")
	r.UpdateConfig(false, time.Minute)
	if r.Count() != 0 {
		t.Fatalf("disabling router must clear bindings, count=%d", r.Count())
	}
	r.Bind("k5", "u1", "c5")
	if _, _, ok := r.Lookup("k5"); ok || r.Count() != 0 {
		t.Fatal("disabled router must not store bindings")
	}
}

func TestRouterEvictLocked(t *testing.T) {
	r := New(10 * time.Minute)
	now := time.Now()
	// Fill up to maxBindings with one expired entry and one oldest active entry.
	for i := 0; i < maxBindings; i++ {
		ts := now.Add(-time.Duration(i) * time.Millisecond)
		r.bindings[fmt.Sprintf("k_%05d", i)] = binding{
			UID:      "u1",
			ConvID:   "c",
			LastSeen: ts,
		}
	}
	// Make k_00001 expired.
	r.bindings["k_00001"] = binding{UID: "u1", ConvID: "c", LastSeen: now.Add(-20 * time.Minute)}
	r.evictLocked(now)
	if _, exists := r.bindings["k_00001"]; exists {
		t.Fatal("expired binding was not evicted")
	}
	if len(r.bindings) != maxBindings-1 {
		t.Fatalf("unexpected size after expired eviction: %d", len(r.bindings))
	}

	// Re-fill to maxBindings with all non-expired entries: evictLocked must drop the oldest.
	r.bindings["k_fresh"] = binding{UID: "u1", ConvID: "c", LastSeen: now}
	oldestKey := fmt.Sprintf("k_%05d", maxBindings-1)
	r.evictLocked(now)
	if _, exists := r.bindings[oldestKey]; exists {
		t.Fatalf("oldest binding %s was not evicted", oldestKey)
	}
	if len(r.bindings) != maxBindings-1 {
		t.Fatalf("unexpected size after oldest eviction: %d", len(r.bindings))
	}
}

func TestDeriveKey(t *testing.T) {
	// Explicit short ID.
	if got := DeriveKey(" conv-123 ", nil); got != "id:conv-123" {
		t.Fatalf("explicit id = %q", got)
	}
	// Explicit oversized ID is hashed.
	longID := strings.Repeat("x", maxExplicitIDBytes+10)
	gotLong := DeriveKey(longID, nil)
	if !strings.HasPrefix(gotLong, "id:") || len(gotLong) != 3+32 {
		t.Fatalf("oversized id = %q", gotLong)
	}
	if DeriveKey(longID, nil) != gotLong {
		t.Fatal("oversized id hash must be deterministic")
	}

	// Empty messages yield empty key.
	if got := DeriveKey("", []any{map[string]any{"role": "assistant", "content": "hi"}}); got != "" {
		t.Fatalf("expected empty key without system/user, got %q", got)
	}

	// Deterministic hash over system + first user message, ignoring subsequent turns.
	m1 := []any{
		map[string]any{"role": "system", "content": "You are helpful"},
		map[string]any{"role": "user", "content": "hello"},
		map[string]any{"role": "assistant", "content": "hi"},
		map[string]any{"role": "user", "content": "second question"},
	}
	m2 := []any{
		map[string]any{"role": "developer", "content": "You are helpful"},
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "hello"},
		}},
	}
	k1 := DeriveKey("", m1)
	k2 := DeriveKey("", m2)
	if !strings.HasPrefix(k1, "d:") || k1 != k2 {
		t.Fatalf("expected matching deterministic keys, got k1=%q k2=%q", k1, k2)
	}

	// Different first user message produces a different key.
	m3 := []any{
		map[string]any{"role": "system", "content": "You are helpful"},
		map[string]any{"role": "user", "content": "different"},
	}
	if k3 := DeriveKey("", m3); k3 == k1 {
		t.Fatalf("different user prompts collided on %q", k3)
	}
}
