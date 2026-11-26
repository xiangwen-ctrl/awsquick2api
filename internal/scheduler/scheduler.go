// Package scheduler runs periodic background maintenance for Amazon Quick accounts:
//   - Proactive token refresh (AWS Quick access tokens expire in ~1 hour)
//   - Periodic quota & account settings polling (profile/usage, user-info, get_settings)
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/pool"
	"awsquick2api/internal/reqlog"
)

const (
	batchConcurrency  = 4
	perAccountTimeout = 25 * time.Second
	// unknownExpiryRefreshInterval rate-limits proactive refreshes of accounts whose
	// access-token expiry is unknown (ExpiresAt <= 0). Such accounts are refreshed on
	// the first check, then at most once per interval, so a refresh that still yields
	// no expiry cannot hammer the token endpoint.
	unknownExpiryRefreshInterval = 15 * time.Minute
)

// UpstreamClient is the minimal interface Scheduler requires from internal/upstream.
type UpstreamClient interface {
	RefreshToken(ctx context.Context, acct *auth.Account) (*auth.Account, error)
	GetQuota(ctx context.Context, acct *auth.Account) (pool.QuotaInfo, error)
	CheckAdvanced(ctx context.Context, acct *auth.Account) (bool, error)
}

type Config struct {
	Pool                *pool.Pool
	Upstream            UpstreamClient
	Vault               *auth.Vault
	AuthDir             string
	QuotaEnabled        bool
	QuotaInterval       time.Duration
	TokenRefreshEnabled bool
	TokenCheckInterval  time.Duration
	TokenRefreshAdvance time.Duration
}

type Scheduler struct {
	mu       sync.RWMutex
	cfg      Config
	retryMu  sync.Mutex
	retryAt  map[string]time.Time
	failures map[string]int
	// unknownExpAt records the last successful proactive refresh for accounts that still have ExpiresAt <= 0.
	unknownExpAt map[string]time.Time
}

func New(cfg Config) *Scheduler {
	if cfg.QuotaInterval <= 0 {
		cfg.QuotaInterval = 10 * time.Minute
	}
	if cfg.TokenCheckInterval <= 0 {
		cfg.TokenCheckInterval = 1 * time.Minute
	}
	if cfg.TokenRefreshAdvance <= 0 {
		cfg.TokenRefreshAdvance = 10 * time.Minute
	}
	return &Scheduler{
		cfg:          cfg,
		retryAt:      map[string]time.Time{},
		failures:     map[string]int{},
		unknownExpAt: map[string]time.Time{},
	}
}

func (s *Scheduler) UpdateConfig(quotaOn bool, quotaMin int, refreshOn bool, checkMin, advMin int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.QuotaEnabled = quotaOn
	if quotaMin > 0 {
		s.cfg.QuotaInterval = time.Duration(quotaMin) * time.Minute
	}
	s.cfg.TokenRefreshEnabled = refreshOn
	if checkMin > 0 {
		s.cfg.TokenCheckInterval = time.Duration(checkMin) * time.Minute
	}
	if advMin > 0 {
		s.cfg.TokenRefreshAdvance = time.Duration(advMin) * time.Minute
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.mu.RLock()
			quotaOn := s.cfg.QuotaEnabled
			refreshOn := s.cfg.TokenRefreshEnabled
			s.mu.RUnlock()
			if refreshOn {
				s.RefreshExpiringTokens(ctx)
			}
			if quotaOn {
				s.RefreshAllQuotas(ctx)
			}
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	lastQuota := time.Now()
	lastRefresh := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.RLock()
			cfg := s.cfg
			s.mu.RUnlock()

			if cfg.TokenRefreshEnabled && now.Sub(lastRefresh) >= cfg.TokenCheckInterval {
				lastRefresh = now
				s.RefreshExpiringTokens(ctx)
			}
			if cfg.QuotaEnabled && now.Sub(lastQuota) >= cfg.QuotaInterval {
				lastQuota = now
				s.RefreshAllQuotas(ctx)
			}
			if cfg.Pool != nil {
				s.flushPendingCredentials(ctx, pool.CredentialStore{Pool: cfg.Pool, Dir: cfg.AuthDir, Vault: cfg.Vault})
				_ = cfg.Pool.Flush()
			}
		}
	}
}

func (s *Scheduler) RefreshOneToken(ctx context.Context, uid string) error {
	return s.RefreshOneTokenIfStale(ctx, uid, "")
}

func (s *Scheduler) RefreshOneTokenIfStale(ctx context.Context, uid, staleAccessToken string) error {
	s.mu.RLock()
	p := s.cfg.Pool
	up := s.cfg.Upstream
	vault := s.cfg.Vault
	authDir := s.cfg.AuthDir
	s.mu.RUnlock()

	if p == nil || up == nil {
		return fmt.Errorf("scheduler not initialized")
	}

	store := pool.CredentialStore{Pool: p, Dir: authDir, Vault: vault}
	return p.WithRefreshLock(uid, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := store.FlushPending(uid); err != nil {
			return err
		}
		acct, version := p.CredentialSnapshot(uid)
		if acct == nil {
			return fmt.Errorf("account %q not found", uid)
		}
		if staleAccessToken != "" && acct.AccessToken != staleAccessToken {
			return nil
		}
		if !hasRefreshToken(acct) {
			return fmt.Errorf("account %q has no refresh_token", uid)
		}

		updated, err := up.RefreshToken(ctx, acct)
		if err != nil {
			var se *auth.StepError
			if errors.As(err, &se) && se.Expired {
				store.DisableExpired(uid, version, "token_expired: "+reqlog.ScrubCredentials(se.Message))
			}
			if _, currentVersion := p.CredentialSnapshot(uid); currentVersion != version {
				return nil
			}
			return err
		}
		saved, persistErr := store.CommitRefresh(uid, version, updated)
		if saved == nil {
			return persistErr
		}

		s.retryMu.Lock()
		delete(s.retryAt, uid)
		delete(s.failures, uid)
		if saved.ExpiresAt > 0 {
			delete(s.unknownExpAt, uid)
		} else {
			s.unknownExpAt[uid] = time.Now()
		}
		s.retryMu.Unlock()

		log.Printf("[scheduler] refreshed token acct=%s provider=%s next_exp=%s",
			uid, saved.Provider, time.UnixMilli(saved.ExpiresAt).Format(time.RFC3339))
		if persistErr != nil {
			log.Printf("WARN: [scheduler] account %s will retry credential write: %s", uid, reqlog.ScrubCredentials(persistErr.Error()))
		}
		return persistErr
	})
}

func (s *Scheduler) flushPendingCredentials(ctx context.Context, store pool.CredentialStore) {
	for _, uid := range store.PendingUIDs() {
		if ctx.Err() != nil {
			return
		}
		if _, err := store.FlushPending(uid); err != nil {
			log.Printf("WARN: [scheduler] retry credential write for %s: %s", uid, reqlog.ScrubCredentials(err.Error()))
		}
	}
}

func (s *Scheduler) RefreshExpiringTokens(ctx context.Context) {
	s.mu.RLock()
	p := s.cfg.Pool
	adv := s.cfg.TokenRefreshAdvance
	s.mu.RUnlock()
	if p == nil {
		return
	}

	due := s.dueForRefresh(p.AllAccounts(false), time.Now(), adv)
	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for _, a := range due {
		if !acquireSlot(ctx, sem) {
			break
		}
		wg.Add(1)
		go func(acct *auth.Account) {
			defer wg.Done()
			defer func() { <-sem }()
			actx, cancel := context.WithTimeout(ctx, perAccountTimeout)
			defer cancel()
			if err := s.RefreshOneTokenIfStale(actx, acct.UID, acct.AccessToken); err != nil {
				s.retryMu.Lock()
				s.failures[acct.UID]++
				fails := s.failures[acct.UID]
				delay := time.Duration(min(300, 30*(1<<min(fails-1, 4)))) * time.Second
				s.retryAt[acct.UID] = time.Now().Add(delay)
				delete(s.unknownExpAt, acct.UID)
				s.retryMu.Unlock()
				log.Printf("WARN: [scheduler] proactive refresh %s failed (retry in %s): %s",
					acct.UID, delay, reqlog.ScrubCredentials(err.Error()))
			}
		}(a)
	}
	wg.Wait()
}

// dueForRefresh selects accounts needing a proactive refresh: tokens expiring within
// adv, plus refreshable accounts with unknown expiry (ExpiresAt <= 0), the latter
// rate-limited by unknownExpiryRefreshInterval. Accounts in failure backoff are skipped.
func (s *Scheduler) dueForRefresh(accts []*auth.Account, now time.Time, adv time.Duration) []*auth.Account {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	present := make(map[string]bool, len(accts))
	var due []*auth.Account
	for _, a := range accts {
		if a == nil {
			continue
		}
		present[a.UID] = true
		if next := s.retryAt[a.UID]; !next.IsZero() && now.Before(next) {
			continue
		}
		switch {
		case a.NeedsRefresh(now, adv):
		case a.ExpiresAt <= 0 && hasRefreshToken(a):
			if last := s.unknownExpAt[a.UID]; !last.IsZero() && now.Sub(last) < unknownExpiryRefreshInterval {
				continue
			}
			// The window is recorded only after a successful refresh still leaves
			// ExpiresAt <= 0 (see RefreshOneTokenIfStale), so cancelled batches or
			// transient failures fall back to normal backoff instead of waiting 15m.
		default:
			continue
		}
		due = append(due, a)
	}
	for uid := range s.unknownExpAt {
		if !present[uid] {
			delete(s.unknownExpAt, uid)
		}
	}
	return due
}

func (s *Scheduler) RefreshOneQuota(ctx context.Context, uid string) (pool.QuotaInfo, error) {
	s.mu.RLock()
	p := s.cfg.Pool
	up := s.cfg.Upstream
	s.mu.RUnlock()
	if p == nil || up == nil {
		return pool.QuotaInfo{}, fmt.Errorf("scheduler not initialized")
	}

	acct := p.AuthByUID(uid)
	if acct == nil {
		return pool.QuotaInfo{}, fmt.Errorf("account %q not found", uid)
	}
	if acct.NeedsRefresh(time.Now(), 2*time.Minute) {
		_ = s.RefreshOneTokenIfStale(ctx, uid, acct.AccessToken)
		if refreshed := p.AuthByUID(uid); refreshed != nil {
			acct = refreshed
		}
	}
	q, err := up.GetQuota(ctx, acct)
	if err != nil {
		// Transient failure: keep the cached quota instead of zeroing it and only
		// record the (credential-scrubbed) reason.
		p.MarkQuotaError(uid, err.Error())
		cached, _ := p.QuotaOf(uid)
		return cached, err
	}
	q.UnavailableReason = reqlog.ScrubCredentials(q.UnavailableReason)
	if adv, aerr := up.CheckAdvanced(ctx, acct); aerr == nil {
		q.AdvancedEnabled = adv
		q.AdvancedKnown = true
	}
	// On CheckAdvanced failure q.AdvancedKnown stays as GetQuota reported it, so the
	// pool keeps its last authoritative AdvancedEnabled value.
	p.UpdateQuota(uid, q)
	_ = p.Flush()
	stored, ok := p.QuotaOf(uid)
	if !ok {
		stored = q
	}
	return stored, nil
}

func (s *Scheduler) RefreshAllQuotas(ctx context.Context) int {
	s.mu.RLock()
	p := s.cfg.Pool
	s.mu.RUnlock()
	if p == nil {
		return 0
	}

	accts := p.AllAccounts(false)
	if len(accts) == 0 {
		return 0
	}
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for _, a := range accts {
		if !acquireSlot(ctx, sem) {
			break
		}
		wg.Add(1)
		go func(uid string) {
			defer wg.Done()
			defer func() { <-sem }()
			actx, cancel := context.WithTimeout(ctx, perAccountTimeout)
			defer cancel()
			if _, err := s.RefreshOneQuota(actx, uid); err != nil {
				log.Printf("WARN: [scheduler] quota refresh %s: %s", uid, reqlog.ScrubCredentials(err.Error()))
			} else {
				okCount.Add(1)
			}
		}(a.UID)
	}
	wg.Wait()
	_ = p.Flush()
	return int(okCount.Load())
}

// acquireSlot takes a semaphore slot, returning false as soon as ctx is done
// (including when ctx is already cancelled while slots are still free).
func acquireSlot(ctx context.Context, sem chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func hasRefreshToken(a *auth.Account) bool {
	return a != nil && strings.TrimSpace(a.RefreshToken) != "" && a.RefreshToken != "none"
}
