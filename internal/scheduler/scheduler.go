// Package scheduler runs periodic background maintenance for Amazon Quick accounts:
//   - Proactive token refresh (AWS Quick access tokens expire in ~1 hour)
//   - Periodic quota & account settings polling (profile/usage, user-info, get_settings)
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/pool"
)

const (
	batchConcurrency  = 4
	perAccountTimeout = 25 * time.Second
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
		cfg:      cfg,
		retryAt:  map[string]time.Time{},
		failures: map[string]int{},
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
			_ = cfg.Pool.Flush()
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

	return p.WithRefreshLock(uid, func() error {
		acct := p.AuthByUID(uid)
		if acct == nil {
			return fmt.Errorf("account %q not found", uid)
		}
		if staleAccessToken != "" && acct.AccessToken != staleAccessToken {
			return nil
		}
		if acct.RefreshToken == "" || acct.RefreshToken == "none" {
			return fmt.Errorf("account %q has no refresh_token", uid)
		}

		updated, err := up.RefreshToken(ctx, acct)
		if err != nil {
			var se *auth.StepError
			if errors.As(err, &se) && se.Expired {
				p.Disable(uid, "token_expired: "+se.Message)
			}
			return err
		}

		saved := p.UpdateAccount(updated)
		if saved == nil {
			saved = updated
		}
		if authDir != "" && vault != nil {
			if serr := auth.SaveAccount(authDir, vault, saved); serr != nil {
				log.Printf("WARN: [scheduler] save refreshed account %s: %v", uid, serr)
			}
		}

		s.retryMu.Lock()
		delete(s.retryAt, uid)
		delete(s.failures, uid)
		s.retryMu.Unlock()

		log.Printf("[scheduler] refreshed token acct=%s provider=%s next_exp=%s",
			uid, saved.Provider, time.UnixMilli(saved.ExpiresAt).Format(time.RFC3339))
		return nil
	})
}

func (s *Scheduler) RefreshExpiringTokens(ctx context.Context) {
	s.mu.RLock()
	p := s.cfg.Pool
	adv := s.cfg.TokenRefreshAdvance
	s.mu.RUnlock()

	now := time.Now()
	accts := p.AllAccounts(false)
	var due []*auth.Account
	for _, a := range accts {
		if !a.NeedsRefresh(now, adv) {
			continue
		}
		s.retryMu.Lock()
		nextTry := s.retryAt[a.UID]
		s.retryMu.Unlock()
		if !nextTry.IsZero() && now.Before(nextTry) {
			continue
		}
		due = append(due, a)
	}
	if len(due) == 0 {
		return
	}

	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	for _, a := range due {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
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
				s.retryMu.Unlock()
				log.Printf("WARN: [scheduler] proactive refresh %s failed (retry in %s): %v", acct.UID, delay, err)
			}
		}(a)
	}
	wg.Wait()
}

func (s *Scheduler) RefreshOneQuota(ctx context.Context, uid string) (pool.QuotaInfo, error) {
	s.mu.RLock()
	p := s.cfg.Pool
	up := s.cfg.Upstream
	s.mu.RUnlock()

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
		q.Known = false
		q.UpdatedAt = time.Now().UnixMilli()
		q.UnavailableReason = err.Error()
		p.UpdateQuota(uid, q)
		return q, err
	}
	if adv, aerr := up.CheckAdvanced(ctx, acct); aerr == nil {
		q.AdvancedEnabled = adv
	}
	p.UpdateQuota(uid, q)
	_ = p.Flush()
	return q, nil
}

func (s *Scheduler) RefreshAllQuotas(ctx context.Context) int {
	s.mu.RLock()
	p := s.cfg.Pool
	s.mu.RUnlock()

	accts := p.AllAccounts(false)
	if len(accts) == 0 {
		return 0
	}
	sem := make(chan struct{}, batchConcurrency)
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for _, a := range accts {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(uid string) {
			defer wg.Done()
			defer func() { <-sem }()
			actx, cancel := context.WithTimeout(ctx, perAccountTimeout)
			defer cancel()
			if _, err := s.RefreshOneQuota(actx, uid); err != nil {
				log.Printf("WARN: [scheduler] quota refresh %s: %v", uid, err)
			} else {
				okCount.Add(1)
			}
		}(a.UID)
	}
	wg.Wait()
	_ = p.Flush()
	return int(okCount.Load())
}
