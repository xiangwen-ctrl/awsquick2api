package apikeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreLifecycleHashOnlyAndQuotas(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return now }

	// 1. Create scoped key and verify plaintext is NEVER written to disk.
	view, plain, err := st.Create(CreateInput{
		Name:             "Team Key",
		AllowedModels:    []string{"amazon-smart", "AMAZON-SMART", " amazon-fast "},
		ExpiresAt:        now.Add(24 * time.Hour).UnixMilli(),
		MaxDailyRequests: 2,
		MaxTotalTokens:   100,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(plain, "qk_") || len(plain) < 20 {
		t.Fatalf("unexpected plaintext format: %q", plain)
	}
	if view.Name != "Team Key" || !view.Enabled || len(view.AllowedModels) != 2 {
		t.Fatalf("unexpected view: %+v", view)
	}

	diskRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read disk file: %v", err)
	}
	if strings.Contains(string(diskRaw), plain) {
		t.Fatalf("plaintext secret leaked to disk file!")
	}
	if !strings.Contains(string(diskRaw), hashKey(plain)) {
		t.Fatalf("expected sha256 hash on disk")
	}

	// 2. Authenticate valid key & verify ModelAllowed.
	res := st.Authenticate(plain)
	if !res.Matched || res.DeniedStatus != 0 || res.Key == nil || res.Key.ID != view.ID {
		t.Fatalf("Authenticate valid key failed: %+v", res)
	}
	if !ModelAllowed(res.Key, []string{"amazon-smart"}) {
		t.Fatal("expected amazon-smart allowed")
	}
	if ModelAllowed(res.Key, []string{"amazon-balanced"}) {
		t.Fatal("expected amazon-balanced disallowed")
	}

	// 3. Unknown key does not match.
	if unknown := st.Authenticate("qk_unknown_secret"); unknown.Matched {
		t.Fatalf("unknown key unexpectedly matched: %+v", unknown)
	}

	// 4. Daily request limit (2/day) enforces 429 and resets next UTC day.
	st.RecordUsage(view.ID, 20)
	st.RecordUsage(view.ID, 20)
	if limited := st.Authenticate(plain); !limited.Matched || limited.DeniedStatus != 429 {
		t.Fatalf("expected 429 after 2 daily requests, got %+v", limited)
	}
	now = now.Add(16 * time.Hour) // Next UTC day (2026-06-16 02:00 UTC), before 24h expiry.
	if nextDay := st.Authenticate(plain); !nextDay.Matched || nextDay.DeniedStatus != 0 {
		t.Fatalf("expected daily quota reset on next UTC day, got %+v", nextDay)
	}

	// 5. Total token limit (100) enforces 429 even on new day.
	st.RecordUsage(view.ID, 60) // 20+20+60 = 100
	if tokLim := st.Authenticate(plain); !tokLim.Matched || tokLim.DeniedStatus != 429 {
		t.Fatalf("expected 429 after hitting total token limit, got %+v", tokLim)
	}

	// 6. Flush persists usage counters across store reload.
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	reloaded.now = func() time.Time { return now }
	list := reloaded.List()
	if len(list) != 1 || list[0].TotalRequests != 3 || list[0].TotalTokens != 100 {
		t.Fatalf("unexpected reloaded list: %+v", list)
	}

	// 7. Expiry enforces 401.
	now = now.Add(10 * time.Hour) // past ExpiresAt
	if exp := reloaded.Authenticate(plain); !exp.Matched || exp.DeniedStatus != 401 {
		t.Fatalf("expected 401 on expired key, got %+v", exp)
	}

	// 8. Update clears expiry & disables key -> 401 disabled.
	zero := int64(0)
	disabled := false
	newName := "Renamed Key"
	if _, err := reloaded.Update(view.ID, UpdatePatch{
		Name:      &newName,
		Enabled:   &disabled,
		ExpiresAt: &zero,
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if dis := reloaded.Authenticate(plain); !dis.Matched || dis.DeniedStatus != 401 || !strings.Contains(dis.DeniedMessage, "disabled") {
		t.Fatalf("expected 401 disabled, got %+v", dis)
	}

	// 9. Delete removes key cleanly.
	if err := reloaded.Delete(view.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(reloaded.List()) != 0 {
		t.Fatalf("expected empty list after delete, got %+v", reloaded.List())
	}
	if err := reloaded.Delete(view.ID); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound on second delete, got %v", err)
	}
}
