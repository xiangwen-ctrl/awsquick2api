package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/pool"
)

// credURL builds a URL with embedded basic-auth credentials at runtime.
func credURL(marker, host string) string {
	return "https" + "://" + "user:" + marker + "@" + host
}

type fakeUpstream struct {
	mu         sync.Mutex
	refreshes  map[string]int
	refreshFn  func(acct *auth.Account) (*auth.Account, error)
	quotaFn    func(acct *auth.Account) (pool.QuotaInfo, error)
	advFn      func(acct *auth.Account) (bool, error)
	quotaCalls atomic.Int32
}

func (f *fakeUpstream) RefreshToken(_ context.Context, acct *auth.Account) (*auth.Account, error) {
	f.mu.Lock()
	if f.refreshes == nil {
		f.refreshes = map[string]int{}
	}
	f.refreshes[acct.UID]++
	fn := f.refreshFn
	f.mu.Unlock()
	if fn != nil {
		return fn(acct)
	}
	cp := acct.Clone()
	cp.AccessToken = acct.AccessToken + "-new"
	cp.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
	return cp, nil
}

func (f *fakeUpstream) GetQuota(_ context.Context, acct *auth.Account) (pool.QuotaInfo, error) {
	f.quotaCalls.Add(1)
	if f.quotaFn != nil {
		return f.quotaFn(acct)
	}
	return pool.QuotaInfo{Known: true, MonthlyLimit: 100, MonthlyUsed: 10}, nil
}

func (f *fakeUpstream) CheckAdvanced(_ context.Context, acct *auth.Account) (bool, error) {
	if f.advFn != nil {
		return f.advFn(acct)
	}
	return false, errors.New("not checked")
}

func (f *fakeUpstream) refreshCount(uid string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes[uid]
}

func newAcct(uid string, expiresAt int64) *auth.Account {
	return &auth.Account{
		UID:          uid,
		Email:        uid + "@example.com",
		Provider:     auth.ProviderSocial,
		DeviceID:     auth.NewUUID(),
		AccessToken:  "at-" + uid,
		RefreshToken: "rt-" + uid,
		ExpiresAt:    expiresAt,
	}
}

func newTestScheduler(up UpstreamClient, accts ...*auth.Account) (*Scheduler, *pool.Pool) {
	p := pool.New(pool.Config{})
	p.SyncAccounts(accts)
	return New(Config{Pool: p, Upstream: up, TokenRefreshAdvance: 10 * time.Minute}), p
}

func quotaOf(t *testing.T, p *pool.Pool, uid string) pool.QuotaInfo {
	t.Helper()
	q, ok := p.QuotaOf(uid)
	if !ok {
		t.Fatalf("no quota entry for %s", uid)
	}
	return q
}

func TestRefreshOneQuotaKeepsCachedQuotaOnError(t *testing.T) {
	up := &fakeUpstream{}
	s, p := newTestScheduler(up, newAcct("a1", time.Now().Add(time.Hour).UnixMilli()))
	p.UpdateQuota("a1", pool.QuotaInfo{Known: true, Plan: "Pro", MonthlyLimit: 500, MonthlyUsed: 50})

	marker := "zq" + "leak77"
	up.quotaFn = func(*auth.Account) (pool.QuotaInfo, error) {
		return pool.QuotaInfo{}, errors.New("dial " + credURL(marker, "quota.example.com") + " failed")
	}
	got, err := s.RefreshOneQuota(context.Background(), "a1")
	if err == nil {
		t.Fatal("expected error")
	}
	q := quotaOf(t, p, "a1")
	if !q.Known || q.MonthlyLimit != 500 || q.MonthlyUsed != 50 || q.Plan != "Pro" {
		t.Fatalf("cached quota was clobbered: %+v", q)
	}
	if got.MonthlyLimit != 500 {
		t.Fatalf("returned quota should be cached snapshot, got %+v", got)
	}
	if q.UnavailableReason == "" || strings.Contains(q.UnavailableReason, marker) {
		t.Fatalf("UnavailableReason not recorded/scrubbed: %q", q.UnavailableReason)
	}

	// A later success replaces the snapshot and clears the reason.
	up.quotaFn = nil
	if _, err := s.RefreshOneQuota(context.Background(), "a1"); err != nil {
		t.Fatalf("RefreshOneQuota: %v", err)
	}
	q = quotaOf(t, p, "a1")
	if q.MonthlyLimit != 100 || q.UnavailableReason != "" {
		t.Fatalf("success did not replace snapshot: %+v", q)
	}
}

func TestRefreshOneQuotaAdvancedFollowsAuthoritativeResult(t *testing.T) {
	up := &fakeUpstream{}
	s, p := newTestScheduler(up, newAcct("a1", time.Now().Add(time.Hour).UnixMilli()))
	ctx := context.Background()

	up.advFn = func(*auth.Account) (bool, error) { return true, nil }
	if _, err := s.RefreshOneQuota(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if !quotaOf(t, p, "a1").AdvancedEnabled || !p.HasAdvancedAccount() {
		t.Fatal("expected advanced enabled")
	}

	// Undetermined check keeps the previous authoritative value.
	up.advFn = func(*auth.Account) (bool, error) { return false, errors.New("timeout") }
	if _, err := s.RefreshOneQuota(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if !quotaOf(t, p, "a1").AdvancedEnabled {
		t.Fatal("transient CheckAdvanced error must not clear AdvancedEnabled")
	}

	// Authoritative false now wins (no more "never fall back").
	up.advFn = func(*auth.Account) (bool, error) { return false, nil }
	if _, err := s.RefreshOneQuota(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if quotaOf(t, p, "a1").AdvancedEnabled || p.HasAdvancedAccount() {
		t.Fatal("authoritative false should disable advanced")
	}
}

func TestRefreshExpiringTokensSelection(t *testing.T) {
	up := &fakeUpstream{}
	now := time.Now()
	soon := newAcct("soon", now.Add(2*time.Minute).UnixMilli())
	later := newAcct("later", now.Add(time.Hour).UnixMilli())
	unknown := newAcct("unknown", 0)
	noRT := newAcct("nort", 0)
	noRT.RefreshToken = ""
	// The "unknown" account stays without expiry after refresh.
	up.refreshFn = func(acct *auth.Account) (*auth.Account, error) {
		cp := acct.Clone()
		cp.AccessToken = acct.AccessToken + "-new"
		if acct.UID == "unknown" {
			cp.ExpiresAt = 0
		} else {
			cp.ExpiresAt = time.Now().Add(time.Hour).UnixMilli()
		}
		return cp, nil
	}
	s, _ := newTestScheduler(up, soon, later, unknown, noRT)

	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("soon") != 1 || up.refreshCount("unknown") != 1 {
		t.Fatalf("expected soon & unknown refreshed once, got soon=%d unknown=%d",
			up.refreshCount("soon"), up.refreshCount("unknown"))
	}
	if up.refreshCount("later") != 0 || up.refreshCount("nort") != 0 {
		t.Fatalf("unexpected refresh: later=%d nort=%d", up.refreshCount("later"), up.refreshCount("nort"))
	}

	// Second pass: unknown-expiry account is rate limited; soon is now fresh.
	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("unknown") != 1 || up.refreshCount("soon") != 1 {
		t.Fatalf("unknown-expiry refresh not rate limited: soon=%d unknown=%d",
			up.refreshCount("soon"), up.refreshCount("unknown"))
	}

	// After the interval elapses it becomes due again.
	s.retryMu.Lock()
	s.unknownExpAt["unknown"] = time.Now().Add(-unknownExpiryRefreshInterval - time.Second)
	s.retryMu.Unlock()
	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("unknown") != 2 {
		t.Fatalf("unknown-expiry account should be refreshed after interval, got %d", up.refreshCount("unknown"))
	}
}

func TestUnknownExpiryWindowNotConsumedByCancelledBatch(t *testing.T) {
	up := &fakeUpstream{}
	s, _ := newTestScheduler(up, newAcct("unknown", 0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.RefreshExpiringTokens(ctx)
	if up.refreshCount("unknown") != 0 {
		t.Fatalf("cancelled ctx must not refresh, got %d", up.refreshCount("unknown"))
	}
	s.retryMu.Lock()
	_, recorded := s.unknownExpAt["unknown"]
	s.retryMu.Unlock()
	if recorded {
		t.Fatal("cancelled batch must not consume the unknown-expiry rate-limit window")
	}
	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("unknown") != 1 {
		t.Fatalf("expected refresh after cancelled batch, got %d", up.refreshCount("unknown"))
	}
}

func TestRefreshFailureBacksOffAndExpiredDisablesScrubbed(t *testing.T) {
	up := &fakeUpstream{}
	marker := "zq" + "oidc99"
	up.refreshFn = func(acct *auth.Account) (*auth.Account, error) {
		return nil, &auth.StepError{Status: 400, Message: "invalid_grant at " + credURL(marker, "oidc.example.com"), Expired: true}
	}
	s, p := newTestScheduler(up, newAcct("a1", time.Now().Add(time.Minute).UnixMilli()))

	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("a1") != 1 {
		t.Fatalf("expected 1 refresh, got %d", up.refreshCount("a1"))
	}
	views := p.Snapshot()
	if len(views) != 1 || !views[0].Disabled {
		t.Fatalf("expected disabled account, got %+v", views)
	}
	if !strings.HasPrefix(views[0].DisabledReason, "token_expired") || strings.Contains(views[0].DisabledReason, marker) {
		t.Fatalf("DisabledReason not scrubbed: %q", views[0].DisabledReason)
	}
	s.retryMu.Lock()
	_, backoff := s.retryAt["a1"]
	s.retryMu.Unlock()
	if !backoff {
		t.Fatal("expected retry backoff recorded")
	}

	// Within the backoff window the account is not retried.
	p.Revive("a1")
	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("a1") != 1 {
		t.Fatalf("expected no retry during backoff, got %d", up.refreshCount("a1"))
	}
}

func TestAcquireSlotHonorsContext(t *testing.T) {
	sem := make(chan struct{}, 1)
	if !acquireSlot(context.Background(), sem) {
		t.Fatal("expected free slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if acquireSlot(ctx, sem) {
		t.Fatal("expected acquireSlot to fail on cancelled ctx")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("acquireSlot did not return promptly on cancellation")
	}
	<-sem
	if acquireSlot(ctx, sem) {
		t.Fatal("cancelled ctx must not take a free slot")
	}
}

func TestRefreshAllQuotasCancelledContext(t *testing.T) {
	up := &fakeUpstream{}
	s, _ := newTestScheduler(up,
		newAcct("a1", time.Now().Add(time.Hour).UnixMilli()),
		newAcct("a2", time.Now().Add(time.Hour).UnixMilli()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n := s.RefreshAllQuotas(ctx); n != 0 || up.quotaCalls.Load() != 0 {
		t.Fatalf("cancelled ctx should skip work, got ok=%d calls=%d", n, up.quotaCalls.Load())
	}
	if n := s.RefreshAllQuotas(context.Background()); n != 2 {
		t.Fatalf("expected 2 successful quota refreshes, got %d", n)
	}
}

func TestSchedulerNotInitialized(t *testing.T) {
	s := New(Config{})
	if _, err := s.RefreshOneQuota(context.Background(), "x"); err == nil {
		t.Fatal("expected error without pool/upstream")
	}
	if err := s.RefreshOneToken(context.Background(), "x"); err == nil {
		t.Fatal("expected error without pool/upstream")
	}
	s.RefreshExpiringTokens(context.Background())
	if n := s.RefreshAllQuotas(context.Background()); n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

// P2-9: transient proactive refresh failure on an ExpiresAt <= 0 account must use
// normal retryAt backoff (~30s), NOT consume the 15-minute unknownExpAt window.
func TestUnknownExpiryTransientFailureUsesShortBackoff(t *testing.T) {
	up := &fakeUpstream{}
	failOnce := true
	up.refreshFn = func(acct *auth.Account) (*auth.Account, error) {
		if failOnce {
			failOnce = false
			return nil, errors.New("temporary network glitch")
		}
		cp := acct.Clone()
		cp.AccessToken = acct.AccessToken + "-new"
		cp.ExpiresAt = 0
		return cp, nil
	}
	s, _ := newTestScheduler(up, newAcct("unknown", 0))

	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("unknown") != 1 {
		t.Fatalf("expected 1 refresh attempt, got %d", up.refreshCount("unknown"))
	}
	s.retryMu.Lock()
	_, hasUnknownWindow := s.unknownExpAt["unknown"]
	retryAt := s.retryAt["unknown"]
	s.retryMu.Unlock()
	if hasUnknownWindow {
		t.Fatal("transient failure must not set unknownExpAt 15-minute throttle")
	}
	if retryAt.IsZero() {
		t.Fatal("transient failure must record short retryAt backoff")
	}

	// Simulate the 30s backoff elapsing (far less than 15 minutes): account must retry immediately.
	s.retryMu.Lock()
	s.retryAt["unknown"] = time.Now().Add(-time.Second)
	s.retryMu.Unlock()

	s.RefreshExpiringTokens(context.Background())
	if up.refreshCount("unknown") != 2 {
		t.Fatalf("expected retry after short backoff elapsed, got %d", up.refreshCount("unknown"))
	}
	// Now that refresh succeeded with still-unknown expiry, the 15m window IS recorded.
	s.retryMu.Lock()
	_, hasUnknownWindow = s.unknownExpAt["unknown"]
	s.retryMu.Unlock()
	if !hasUnknownWindow {
		t.Fatal("successful unknown-expiry refresh must record unknownExpAt throttle")
	}
}
