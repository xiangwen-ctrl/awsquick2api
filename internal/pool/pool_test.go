package pool

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"awsquick2api/internal/auth"
)

func TestPoolAcquireRotateCooldownAndPersistence(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	p := New(Config{
		StateFile:       statePath,
		MaxInFlight:     1,
		SoftCooldown:    50 * time.Millisecond,
		SoftCooldownMax: 500 * time.Millisecond,
		BreakerThresh:   2,
		BreakerCooldown: 200 * time.Millisecond,
		Strategy:        StrategyRoundRobin,
	})
	p.SyncAccounts([]*auth.Account{
		{UID: "a1", Email: "a1@example.com", Provider: auth.ProviderSocial, DeviceID: auth.NewUUID()},
		{UID: "a2", Email: "a2@example.com", Provider: auth.ProviderSocial, DeviceID: auth.NewUUID()},
	})

	// Round-robin picks a1 then a2.
	l1, err := p.Acquire(context.Background(), "", nil, time.Second, 4)
	if err != nil || l1.Account.UID != "a1" {
		t.Fatalf("expected a1, got %v err=%v", l1, err)
	}
	l2, err := p.Acquire(context.Background(), "", nil, time.Second, 4)
	if err != nil || l2.Account.UID != "a2" {
		t.Fatalf("expected a2, got %v err=%v", l2, err)
	}
	// Pool now full -> immediate Acquire returns ErrPoolBusy.
	if _, err := p.Acquire(context.Background(), "", nil, 10*time.Millisecond, 4); err != ErrPoolBusy {
		t.Fatalf("expected ErrPoolBusy, got %v", err)
	}
	l1.Release()
	l2.Release()

	// Rate limit a1 -> next acquire picks a2.
	p.MarkRateLimited("a1", "quota_exhausted", 2*time.Second)
	l3, err := p.Acquire(context.Background(), "", nil, time.Second, 4)
	if err != nil || l3.Account.UID != "a2" {
		t.Fatalf("expected a2 while a1 cooling, got %v err=%v", l3, err)
	}
	l3.Release()

	// Persist & reload state.
	p.UpdateQuota("a2", QuotaInfo{Known: true, Plan: "Pro", MonthlyLimit: 500, MonthlyUsed: 50})
	p.MarkSuccess("a2", 1234)
	if err := p.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	p2 := New(Config{StateFile: statePath})
	p2.SyncAccounts([]*auth.Account{
		{UID: "a1", Email: "a1@example.com", Provider: auth.ProviderSocial, DeviceID: auth.NewUUID()},
		{UID: "a2", Email: "a2@example.com", Provider: auth.ProviderSocial, DeviceID: auth.NewUUID()},
	})
	views := p2.Snapshot()
	if len(views) != 2 || views[1].TotalTokens != 1234 || views[1].Quota.MonthlyLimit != 500 {
		t.Fatalf("restored pool mismatch: %+v", views)
	}
}

func TestPoolWithRefreshLockSerializes(t *testing.T) {
	p := New(Config{})
	var active atomic.Int32
	var maxActive atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.WithRefreshLock("same_uid", func() error {
				cur := active.Add(1)
				if cur > maxActive.Load() {
					maxActive.Store(cur)
				}
				time.Sleep(15 * time.Millisecond)
				active.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if maxActive.Load() != 1 {
		t.Fatalf("expected serialized refresh lock (max 1), got %d", maxActive.Load())
	}
}

func testAccounts(uids ...string) []*auth.Account {
	out := make([]*auth.Account, 0, len(uids))
	for _, uid := range uids {
		out = append(out, &auth.Account{UID: uid, Email: uid + "@example.com", Provider: auth.ProviderSocial, DeviceID: auth.NewUUID()})
	}
	return out
}

func newTestPool(strategy string, maxInFlight int, uids ...string) *Pool {
	p := New(Config{MaxInFlight: maxInFlight, Strategy: strategy})
	p.SyncAccounts(testAccounts(uids...))
	return p
}

// credURL builds a URL with embedded basic-auth credentials at runtime.
func credURL(marker, host string) string {
	return "https" + "://" + "user:" + marker + "@" + host
}

func TestAcquireWithRequireAdvanced(t *testing.T) {
	p := newTestPool(StrategySequential, 1, "a1", "a2")
	ctx := context.Background()

	start := time.Now()
	if _, err := p.AcquireWith(ctx, AcquireOptions{RequireAdvanced: true, WaitTimeout: 2 * time.Second}); !errors.Is(err, ErrNoAdvancedAccounts) {
		t.Fatalf("expected ErrNoAdvancedAccounts, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("RequireAdvanced with no advanced account must fail fast, not wait")
	}
	if p.IsEligibleWith("a2", true) {
		t.Fatal("a2 is not advanced yet")
	}

	p.SetAdvancedEnabled("a2", true)
	if !p.IsEligibleWith("a2", true) || !p.IsEligibleWith("a1", false) || p.IsEligibleWith("a1", true) {
		t.Fatal("IsEligibleWith mismatch")
	}
	// Preferred non-advanced account is ignored when advanced is required.
	l, err := p.AcquireWith(ctx, AcquireOptions{RequireAdvanced: true, PreferredUID: "a1"})
	if err != nil || l.Account.UID != "a2" {
		t.Fatalf("expected a2, got %v err=%v", l, err)
	}
	// a2 busy: advanced request is busy instead of falling back to a1.
	if _, err := p.AcquireWith(ctx, AcquireOptions{RequireAdvanced: true, WaitTimeout: 20 * time.Millisecond}); !errors.Is(err, ErrPoolBusy) {
		t.Fatalf("expected ErrPoolBusy, got %v", err)
	}
	// Non-advanced request is still served by a1.
	l2, err := p.AcquireWith(ctx, AcquireOptions{})
	if err != nil || l2.Account.UID != "a1" {
		t.Fatalf("expected a1, got %v err=%v", l2, err)
	}
	l2.Release()

	// Releasing a2 wakes a waiting advanced request.
	done := make(chan *Lease, 1)
	go func() {
		l3, _ := p.AcquireWith(ctx, AcquireOptions{RequireAdvanced: true, WaitTimeout: 2 * time.Second})
		done <- l3
	}()
	time.Sleep(20 * time.Millisecond)
	l.Release()
	select {
	case l3 := <-done:
		if l3 == nil || l3.Account.UID != "a2" {
			t.Fatalf("expected waiter to get a2, got %v", l3)
		}
		l3.Release()
	case <-time.After(2 * time.Second):
		t.Fatal("advanced waiter was not woken")
	}

	// Disabled advanced account -> explicit error again.
	p.Disable("a2", "manual")
	if _, err := p.AcquireWith(ctx, AcquireOptions{RequireAdvanced: true, WaitTimeout: time.Second}); !errors.Is(err, ErrNoAdvancedAccounts) {
		t.Fatalf("expected ErrNoAdvancedAccounts, got %v", err)
	}
	// Legacy Acquire is unaffected.
	l4, err := p.Acquire(ctx, "", nil, time.Second, 0)
	if err != nil || l4.Account.UID != "a1" {
		t.Fatalf("expected a1, got %v err=%v", l4, err)
	}
	l4.Release()
}

func TestAcquireSkipsExhaustedAccounts(t *testing.T) {
	p := newTestPool(StrategySequential, 1, "a1", "a2")
	ctx := context.Background()
	p.UpdateQuota("a1", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100})

	for i := 0; i < 3; i++ {
		l, err := p.AcquireWith(ctx, AcquireOptions{PreferredUID: "a1"})
		if err != nil || l.Account.UID != "a2" {
			t.Fatalf("expected exhausted a1 to be skipped, got %v err=%v", l, err)
		}
		l.Release()
	}

	// a2 busy: wait (busy) instead of falling back to exhausted a1.
	l, err := p.Acquire(ctx, "", nil, 0, 0)
	if err != nil || l.Account.UID != "a2" {
		t.Fatalf("expected a2, got %v err=%v", l, err)
	}
	if _, err := p.AcquireWith(ctx, AcquireOptions{WaitTimeout: 20 * time.Millisecond}); !errors.Is(err, ErrPoolBusy) {
		t.Fatalf("expected ErrPoolBusy while non-exhausted a2 busy, got %v", err)
	}
	l.Release()

	// All exhausted -> fall back to exhausted accounts (upstream stays authoritative).
	p.UpdateQuota("a2", QuotaInfo{Known: true, SessionLimit: 10, SessionUsed: 10})
	lf, err := p.AcquireWith(ctx, AcquireOptions{})
	if err != nil || lf == nil {
		t.Fatalf("expected fallback lease when all exhausted, got err=%v", err)
	}
	lf.Release()

	// Remaining overage makes a1 usable again and preferred over exhausted a2.
	p.UpdateQuota("a1", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100, OverageLimit: 50, OverageUsed: 10})
	for i := 0; i < 3; i++ {
		l5, err := p.AcquireWith(ctx, AcquireOptions{PreferredUID: "a2"})
		if err != nil || l5.Account.UID != "a1" {
			t.Fatalf("expected a1 with overage headroom, got %v err=%v", l5, err)
		}
		l5.Release()
	}
}

func TestQuotaRemainingFractionAndExhausted(t *testing.T) {
	cases := []struct {
		name      string
		q         QuotaInfo
		frac      float64
		exhausted bool
	}{
		{"unknown", QuotaInfo{}, 0.5, false},
		{"half monthly", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 50}, 0.5, false},
		{"monthly spent", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100}, 0.05, true},
		{"overage untouched", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100, OverageLimit: 100}, 0.5, false},
		{"overage half", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100, OverageLimit: 100, OverageUsed: 50}, 0.25, false},
		{"overage spent", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100, OverageLimit: 100, OverageUsed: 100}, 0.05, true},
		{"percent with overage", QuotaInfo{Known: true, MonthlyPercent: 100, OverageLimit: 20, OverageUsed: 10}, 0.5, false},
		{"session bound", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 10, SessionLimit: 10, SessionUsed: 9}, 0.1, false},
		{"session percent spent", QuotaInfo{Known: true, SessionPercent: 100}, 0.05, true},
	}
	for _, c := range cases {
		if got := c.q.RemainingFraction(); math.Abs(got-c.frac) > 1e-9 {
			t.Errorf("%s: RemainingFraction=%v want %v", c.name, got, c.frac)
		}
		if got := c.q.IsExhausted(); got != c.exhausted {
			t.Errorf("%s: IsExhausted=%v want %v", c.name, got, c.exhausted)
		}
	}
}

func TestUpdateQuotaAdvancedAuthoritative(t *testing.T) {
	p := newTestPool("", 1, "a1")
	p.UpdateQuota("a1", QuotaInfo{Known: true, AdvancedEnabled: true})
	// Undetermined update keeps the previous value.
	p.UpdateQuota("a1", QuotaInfo{Known: true})
	if q, _ := p.QuotaOf("a1"); !q.AdvancedEnabled || !p.HasAdvancedAccount() {
		t.Fatal("undetermined update must not clear AdvancedEnabled")
	}
	// Authoritative false wins.
	p.UpdateQuota("a1", QuotaInfo{Known: true, AdvancedKnown: true})
	if q, _ := p.QuotaOf("a1"); q.AdvancedEnabled || p.HasAdvancedAccount() {
		t.Fatal("authoritative false must clear AdvancedEnabled")
	}
}

func TestMarkQuotaErrorKeepsSnapshot(t *testing.T) {
	p := newTestPool("", 1, "a1")
	p.UpdateQuota("a1", QuotaInfo{Known: true, MonthlyLimit: 300, MonthlyUsed: 30})
	marker := "zq" + "quota55"
	p.MarkQuotaError("a1", "fetch "+credURL(marker, "quota.example.com")+" failed")
	q, ok := p.QuotaOf("a1")
	if !ok || !q.Known || q.MonthlyLimit != 300 || q.MonthlyUsed != 30 {
		t.Fatalf("snapshot clobbered: %+v", q)
	}
	if q.UnavailableReason == "" || strings.Contains(q.UnavailableReason, marker) {
		t.Fatalf("reason not recorded/scrubbed: %q", q.UnavailableReason)
	}
}

func TestStateFileScrubsCredentials(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	marker := "zq" + "state33"
	u := credURL(marker, "example.com")

	p := New(Config{StateFile: statePath})
	p.SyncAccounts(testAccounts("a1"))
	p.MarkQuotaError("a1", "fetch "+u+" failed")
	p.Disable("a1", "refresh failed at "+u) // Disable flushes
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatalf("state.json leaks credential: %s", raw)
	}

	// Legacy state files with plaintext credentials are scrubbed on restore.
	legacy := `{"updated_at":1,"entries":{"a1":{"disabled":true,"disabled_reason":"x ` + u +
		`","quota":{"known":false,"monthly_used":0,"monthly_limit":0,"monthly_percent":0,"session_used":0,"session_limit":0,"session_percent":0,"unavailable_reason":"` + u + `"}}}}`
	if err := os.WriteFile(statePath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	p2 := New(Config{StateFile: statePath})
	p2.SyncAccounts(testAccounts("a1"))
	v := p2.Snapshot()
	if len(v) != 1 || !v[0].Disabled {
		t.Fatalf("restore mismatch: %+v", v)
	}
	if strings.Contains(v[0].DisabledReason, marker) || strings.Contains(v[0].Quota.UnavailableReason, marker) {
		t.Fatalf("restored state not scrubbed: %+v", v[0])
	}
}

func TestUpdateQuotaWakesBlockedWaiter(t *testing.T) {
	p := newTestPool(StrategySequential, 1, "a1", "a2")
	ctx := context.Background()
	// Exhaust a1 and occupy a2 so a waiter blocks on a2 while skipping exhausted a1.
	p.UpdateQuota("a1", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 100})
	leaseA2, err := p.AcquireWith(ctx, AcquireOptions{})
	if err != nil || leaseA2.Account.UID != "a2" {
		t.Fatalf("expected a2, got %v err=%v", leaseA2, err)
	}
	defer leaseA2.Release()

	done := make(chan *Lease, 1)
	go func() {
		l, _ := p.AcquireWith(ctx, AcquireOptions{WaitTimeout: 3 * time.Second})
		done <- l
	}()
	time.Sleep(30 * time.Millisecond)

	// Refilling a1's quota must wake the waiter immediately without releasing a2.
	p.UpdateQuota("a1", QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 10})
	select {
	case l := <-done:
		if l == nil || l.Account.UID != "a1" {
			t.Fatalf("expected waiter to acquire replenished a1, got %v", l)
		}
		l.Release()
	case <-time.After(1 * time.Second):
		t.Fatal("UpdateQuota did not wake blocked AcquireWith waiter")
	}
}

func TestAttachmentAndAdvancedAccountChecksIgnoreDisabled(t *testing.T) {
	p := New(Config{MaxInFlight: 2})
	p.SyncAccounts([]*auth.Account{
		{UID: "soc_disabled", Provider: auth.ProviderSocial, AccessToken: "t1"},
		{UID: "gw_healthy", Provider: auth.ProviderGateway, AccessToken: "t2", WSHost: "wss://example.aws.dev", WSPath: auth.GatewayWSPath},
	})
	p.UpdateQuota("soc_disabled", QuotaInfo{Known: true, AdvancedEnabled: true, AdvancedKnown: true})
	p.UpdateQuota("gw_healthy", QuotaInfo{Known: true, AdvancedEnabled: true, AdvancedKnown: true})
	p.Disable("soc_disabled", "token_expired")

	if p.HasAttachmentAccount(false) {
		t.Fatal("disabled social account must not count as attachment-capable")
	}
	if p.HasAttachmentAccount(true) {
		t.Fatal("disabled social account must not count as advanced attachment-capable")
	}
	if !p.HasAdvancedAccount() {
		t.Fatal("healthy gateway account with AdvancedEnabled should count in HasAdvancedAccount")
	}
	_, err := p.AcquireWith(context.Background(), AcquireOptions{RequireAttachments: true, RequireAdvanced: true})
	if err != ErrNoAttachmentAccounts {
		t.Fatalf("expected ErrNoAttachmentAccounts, got %v", err)
	}
}
