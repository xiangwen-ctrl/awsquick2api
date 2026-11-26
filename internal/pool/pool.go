// Package pool manages multi-account scheduling, in-flight concurrency leases,
// Amazon Quick quota-weighted balancing, exponential backoff cooldowns, circuit
// breaking, per-account refresh locking, and atomic state persistence.
package pool

import (
	"context"
	"log"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"awsquick2api/internal/auth"
	"awsquick2api/internal/reqlog"
)

const (
	StrategyWeighted   = "weighted"
	StrategyRoundRobin = "round_robin"
	StrategySequential = "sequential"
)

// Config configures runtime pool scheduling & protection limits.
type Config struct {
	StateFile       string
	MaxInFlight     int
	SoftCooldown    time.Duration
	SoftCooldownMax time.Duration
	BreakerThresh   int
	BreakerCooldown time.Duration
	Strategy        string
}

// QuotaInfo holds normalized Amazon Quick subscription & usage quota data for one account.
type QuotaInfo struct {
	Known            bool    `json:"known"`
	Plan             string  `json:"plan,omitempty"`
	TrialUntil       int64   `json:"trial_until,omitempty"` // Unix ms
	Unit             string  `json:"unit,omitempty"`        // "credits" | "agent_minutes"
	MonthlyUsed      float64 `json:"monthly_used"`
	MonthlyLimit     float64 `json:"monthly_limit"`
	MonthlyPercent   float64 `json:"monthly_percent"`
	MonthlyResetsAt  int64   `json:"monthly_resets_at,omitempty"`
	OverageUsed      float64 `json:"overage_used,omitempty"`
	OverageLimit     float64 `json:"overage_limit,omitempty"`
	SessionUsed      float64 `json:"session_used"`
	SessionLimit     float64 `json:"session_limit"`
	SessionPercent   float64 `json:"session_percent"`
	SessionResetsAt  int64   `json:"session_resets_at,omitempty"`
	SessionResumeMin float64 `json:"session_resume_min,omitempty"`
	AdvancedEnabled  bool    `json:"advanced_enabled,omitempty"`
	// AdvancedKnown marks AdvancedEnabled as an authoritative result of this update
	// (e.g. CheckAdvanced succeeded). When false, UpdateQuota keeps the previous value.
	AdvancedKnown     bool   `json:"advanced_known,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// RemainingFraction estimates remaining headroom in [0.05, 1.0] for weighted account selection.
func (q QuotaInfo) RemainingFraction() float64 {
	if !q.Known {
		return 0.5
	}
	rem := 1.0
	if mRem, ok := q.monthlyRemaining(); ok && mRem < rem {
		rem = mRem
	}
	if q.SessionLimit > 0 {
		sRem := math.Max(0, (q.SessionLimit-q.SessionUsed)/q.SessionLimit)
		if sRem < rem {
			rem = sRem
		}
	} else if q.SessionPercent > 0 {
		sRem := math.Max(0, (100-q.SessionPercent)/100)
		if sRem < rem {
			rem = sRem
		}
	}
	if rem < 0.05 {
		return 0.05
	}
	return rem
}

// monthlyRemaining returns the remaining monthly headroom fraction, counting any
// remaining overage allowance as additional capacity (monthly limit + overage limit).
// ok is false when no monthly figures are known.
func (q QuotaInfo) monthlyRemaining() (float64, bool) {
	overageRoom := 0.0
	if q.OverageLimit > 0 {
		overageRoom = math.Max(0, q.OverageLimit-q.OverageUsed)
	}
	switch {
	case q.MonthlyLimit > 0:
		capacity := q.MonthlyLimit + math.Max(0, q.OverageLimit)
		room := math.Max(0, q.MonthlyLimit-q.MonthlyUsed) + overageRoom
		return math.Min(1, room/capacity), true
	case q.MonthlyPercent > 0:
		mRem := math.Max(0, (100-q.MonthlyPercent)/100)
		if mRem == 0 && q.OverageLimit > 0 {
			return overageRoom / q.OverageLimit, true
		}
		return mRem, true
	}
	return 0, false
}

// IsExhausted reports whether monthly (without remaining overage) or session quota is 100% spent.
func (q QuotaInfo) IsExhausted() bool {
	if !q.Known {
		return false
	}
	if q.SessionLimit > 0 && q.SessionUsed >= q.SessionLimit {
		return true
	}
	if q.SessionLimit == 0 && q.SessionPercent >= 100 {
		return true
	}
	monthlySpent := (q.MonthlyLimit > 0 && q.MonthlyUsed >= q.MonthlyLimit) || (q.MonthlyLimit == 0 && q.MonthlyPercent >= 100)
	if monthlySpent {
		if q.OverageLimit > 0 && q.OverageUsed < q.OverageLimit {
			return false
		}
		return true
	}
	return false
}

type entry struct {
	acct              *auth.Account
	credentialVersion uint64
	credentialPending bool

	disabled       bool
	disabledReason string

	cooldownUntil  time.Time
	cooldownReason string
	softHits       int
	consecFails    int

	inFlight int
	usedSeq  uint64
	lastUsed time.Time

	quota QuotaInfo

	totalReqs   int64
	totalTokens int64
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

// AccountView is the sanitized runtime snapshot exposed to the Web panel and /healthz.
type AccountView struct {
	UID            string    `json:"uid"`
	DisplayName    string    `json:"display_name"`
	CustomName     string    `json:"custom_name,omitempty"`
	Email          string    `json:"email,omitempty"`
	AccountName    string    `json:"account_name,omitempty"`
	AWSAccountID   string    `json:"aws_account_id,omitempty"`
	Provider       string    `json:"provider"`
	ProviderLabel  string    `json:"provider_label"`
	Region         string    `json:"region"`
	DeviceID       string    `json:"device_id"`
	ExpiresAt      int64     `json:"expires_at"`
	HasRefresh     bool      `json:"has_refresh_token"`
	Disabled       bool      `json:"disabled"`
	DisabledReason string    `json:"disabled_reason,omitempty"`
	Healthy        bool      `json:"healthy"`
	CooldownUntil  int64     `json:"cooldown_until,omitempty"`
	CooldownReason string    `json:"cooldown_reason,omitempty"`
	InFlight       int       `json:"in_flight"`
	Quota          QuotaInfo `json:"quota"`
	TotalReqs      int64     `json:"total_reqs"`
	TotalTokens    int64     `json:"total_tokens"`
}

// Summary aggregates top-level pool health metrics.
type Summary struct {
	Total             int     `json:"total"`
	Healthy           int     `json:"healthy"`
	Cooling           int     `json:"cooling"`
	Disabled          int     `json:"disabled"`
	InFlight          int     `json:"in_flight"`
	QuotaKnownCount   int     `json:"quota_known_count"`
	TotalMonthlyLimit float64 `json:"total_monthly_limit"`
	TotalMonthlyUsed  float64 `json:"total_monthly_used"`
	TotalMonthlyAvail float64 `json:"total_monthly_avail"`
	TotalReqs         int64   `json:"total_reqs"`
	TotalTokens       int64   `json:"total_tokens"`
}

// Pool coordinates concurrent access to all loaded Amazon Quick accounts.
type Pool struct {
	mu    sync.Mutex
	cfg   Config
	byUID map[string]*entry
	order []string

	pickSeq uint64
	rrIdx   int

	notifyCh chan struct{}
	waiters  int

	refreshMu       sync.Mutex
	refreshLocks    map[string]*refLock
	credentialLocks map[string]*refLock
	credentialSeq   uint64

	flushMu    sync.Mutex
	dirtyGen   uint64
	flushedGen uint64
}

func New(cfg Config) *Pool {
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = 2
	}
	if cfg.SoftCooldown <= 0 {
		cfg.SoftCooldown = 60 * time.Second
	}
	if cfg.SoftCooldownMax < cfg.SoftCooldown {
		cfg.SoftCooldownMax = max(cfg.SoftCooldown*4, 3600*time.Second)
	}
	if cfg.BreakerThresh <= 0 {
		cfg.BreakerThresh = 3
	}
	if cfg.BreakerCooldown <= 0 {
		cfg.BreakerCooldown = 900 * time.Second
	}
	if cfg.Strategy == "" {
		cfg.Strategy = StrategyWeighted
	}
	p := &Pool{
		cfg:             cfg,
		byUID:           map[string]*entry{},
		notifyCh:        make(chan struct{}),
		refreshLocks:    map[string]*refLock{},
		credentialLocks: map[string]*refLock{},
	}
	p.restoreState()
	return p
}

func (p *Pool) UpdateConfig(cfg Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cfg.MaxInFlight > 0 {
		p.cfg.MaxInFlight = cfg.MaxInFlight
	}
	if cfg.SoftCooldown > 0 {
		p.cfg.SoftCooldown = cfg.SoftCooldown
	}
	if cfg.SoftCooldownMax >= p.cfg.SoftCooldown {
		p.cfg.SoftCooldownMax = cfg.SoftCooldownMax
	} else if p.cfg.SoftCooldownMax < p.cfg.SoftCooldown {
		p.cfg.SoftCooldownMax = p.cfg.SoftCooldown
	}
	if cfg.BreakerThresh > 0 {
		p.cfg.BreakerThresh = cfg.BreakerThresh
	}
	if cfg.BreakerCooldown > 0 {
		p.cfg.BreakerCooldown = cfg.BreakerCooldown
	}
	if cfg.Strategy != "" {
		p.cfg.Strategy = cfg.Strategy
	}
	p.signalWaitersLocked()
}

func (p *Pool) SyncAccounts(accts []*auth.Account) {
	p.mu.Lock()
	defer p.mu.Unlock()
	present := make(map[string]bool, len(accts))
	for _, a := range accts {
		if a == nil || a.UID == "" {
			continue
		}
		present[a.UID] = true
		e := p.byUID[a.UID]
		if e == nil {
			e = &entry{}
			p.byUID[a.UID] = e
		}
		p.setCredentialLocked(e, a, false)
	}
	for uid := range p.byUID {
		if !present[uid] {
			delete(p.byUID, uid)
		}
	}
	p.rebuildOrderLocked()
	p.dirtyGen++
	p.signalWaitersLocked()
}

func (p *Pool) AddOrUpdate(a *auth.Account) {
	if a == nil || a.UID == "" {
		return
	}
	p.mu.Lock()
	if e, ok := p.byUID[a.UID]; ok {
		prevCustom := ""
		prevDevice := ""
		if e.acct != nil {
			prevCustom = e.acct.CustomName
			prevDevice = e.acct.DeviceID
		}
		next := a.Clone()
		if strings.TrimSpace(next.CustomName) == "" && prevCustom != "" {
			next.CustomName = prevCustom
		}
		if !auth.IsDeviceID(next.DeviceID) && auth.IsDeviceID(prevDevice) {
			next.DeviceID = prevDevice
		}
		p.setCredentialLocked(e, next, false)
		e.disabled = false
		e.disabledReason = ""
		e.cooldownUntil = time.Time{}
		e.cooldownReason = ""
		e.consecFails = 0
		e.softHits = 0
	} else {
		e := &entry{}
		p.setCredentialLocked(e, a, false)
		p.byUID[a.UID] = e
	}
	p.rebuildOrderLocked()
	p.dirtyGen++
	p.signalWaitersLocked()
	p.mu.Unlock()
	_ = p.Flush()
}

func (p *Pool) Remove(uid string) {
	p.mu.Lock()
	delete(p.byUID, uid)
	p.rebuildOrderLocked()
	p.dirtyGen++
	p.signalWaitersLocked()
	p.mu.Unlock()
	_ = p.Flush()
}

func (p *Pool) AuthByUID(uid string) *auth.Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok || e.acct == nil {
		return nil
	}
	return e.acct.Clone()
}

func (p *Pool) AllAccounts(includeDisabled bool) []*auth.Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*auth.Account, 0, len(p.order))
	for _, uid := range p.order {
		e := p.byUID[uid]
		if e == nil || e.acct == nil {
			continue
		}
		if !includeDisabled && e.disabled {
			continue
		}
		out = append(out, e.acct.Clone())
	}
	return out
}

func (p *Pool) updateRefreshedAccount(updated *auth.Account, pending bool) *auth.Account {
	if updated == nil || updated.UID == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[updated.UID]
	if !ok {
		return nil
	}
	cp := updated.Clone()
	if e.acct != nil && strings.TrimSpace(cp.CustomName) == "" {
		cp.CustomName = e.acct.CustomName
	}
	if e.acct != nil && !auth.IsDeviceID(cp.DeviceID) && auth.IsDeviceID(e.acct.DeviceID) {
		cp.DeviceID = e.acct.DeviceID
	}
	p.setCredentialLocked(e, cp, pending)
	if e.disabled && strings.Contains(strings.ToLower(e.disabledReason), "token") {
		e.disabled = false
		e.disabledReason = ""
	}
	p.dirtyGen++
	p.signalWaitersLocked()
	return e.acct.Clone()
}

// UpdateQuota replaces the cached quota snapshot for uid. AdvancedEnabled is taken
// from q only when it is authoritative (q.AdvancedKnown, or a positive q.AdvancedEnabled);
// otherwise the previous value is kept. UnavailableReason is credential-scrubbed.
func (p *Pool) UpdateQuota(uid string, q QuotaInfo) {
	q.UnavailableReason = reqlog.ScrubCredentials(q.UnavailableReason)
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		switch {
		case q.AdvancedEnabled:
			q.AdvancedKnown = true
		case !q.AdvancedKnown:
			q.AdvancedEnabled = e.quota.AdvancedEnabled
			q.AdvancedKnown = e.quota.AdvancedKnown
		}
		e.quota = q
		if q.Known && !q.IsExhausted() && e.cooldownReason == "quota_exhausted" {
			e.cooldownUntil = time.Time{}
			e.cooldownReason = ""
		}
		p.dirtyGen++
		p.signalWaitersLocked()
	}
	p.mu.Unlock()
}

// MarkQuotaError records a transient quota-fetch failure for uid without discarding
// the last cached quota snapshot; only UnavailableReason (credential-scrubbed) is set.
func (p *Pool) MarkQuotaError(uid, reason string) {
	reason = reqlog.ScrubCredentials(strings.TrimSpace(reason))
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		if !e.quota.Known && e.quota.UpdatedAt == 0 {
			e.quota.UpdatedAt = time.Now().UnixMilli()
		}
		e.quota.UnavailableReason = reason
		p.dirtyGen++
	}
	p.mu.Unlock()
}

// QuotaOf returns the cached quota snapshot for uid.
func (p *Pool) QuotaOf(uid string) (QuotaInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byUID[uid]
	if !ok || e == nil {
		return QuotaInfo{}, false
	}
	return e.quota, true
}

func (p *Pool) SetAdvancedEnabled(uid string, enabled bool) {
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		e.quota.AdvancedEnabled = enabled
		e.quota.AdvancedKnown = true
		p.dirtyGen++
		p.signalWaitersLocked()
	}
	p.mu.Unlock()
}

// HasAttachmentAccount reports whether a configured account can upload images.
func (p *Pool) HasAttachmentAccount(requireAdvanced bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.byUID {
		if e.acct != nil && !e.acct.IsGateway() && (!requireAdvanced || e.quota.AdvancedEnabled) {
			return true
		}
	}
	return false
}

func (p *Pool) HasAdvancedAccount() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.byUID {
		if e != nil && !e.disabled && e.quota.AdvancedEnabled {
			return true
		}
	}
	return false
}

func (p *Pool) Disable(uid, reason string) {
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		e.disabled = true
		e.disabledReason = reqlog.ScrubCredentials(strings.TrimSpace(reason))
		p.dirtyGen++
	}
	p.mu.Unlock()
	_ = p.Flush()
}

func (p *Pool) Revive(uid string) bool {
	p.mu.Lock()
	e, ok := p.byUID[uid]
	if !ok {
		p.mu.Unlock()
		return false
	}
	e.disabled = false
	e.disabledReason = ""
	e.cooldownUntil = time.Time{}
	e.cooldownReason = ""
	e.consecFails = 0
	e.softHits = 0
	p.dirtyGen++
	p.signalWaitersLocked()
	p.mu.Unlock()
	_ = p.Flush()
	return true
}

// MarkSuccess resets consecutive failures and updates usage counters.
func (p *Pool) MarkSuccess(uid string, totalTokens int) {
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		e.consecFails = 0
		e.softHits = 0
		e.totalReqs++
		if totalTokens > 0 {
			e.totalTokens += int64(totalTokens)
		}
		p.dirtyGen++
	}
	p.mu.Unlock()
}

// MarkSoftFailure applies exponential backoff cooldown and trips the circuit breaker
// after BreakerThresh consecutive failures.
func (p *Pool) MarkSoftFailure(uid, reason string) time.Duration {
	p.mu.Lock()
	e, ok := p.byUID[uid]
	if !ok {
		p.mu.Unlock()
		return 0
	}
	e.consecFails++
	e.softHits++
	var dur time.Duration
	if e.consecFails >= p.cfg.BreakerThresh {
		dur = p.cfg.BreakerCooldown
		e.cooldownReason = "circuit_breaker: " + reason
		e.consecFails = 0
	} else {
		mult := 1 << min(e.softHits-1, 6)
		dur = p.cfg.SoftCooldown * time.Duration(mult)
		if dur > p.cfg.SoftCooldownMax {
			dur = p.cfg.SoftCooldownMax
		}
		e.cooldownReason = reason
	}
	e.cooldownUntil = time.Now().Add(dur)
	p.dirtyGen++
	p.mu.Unlock()
	return dur
}

// MarkRateLimited cools an account for an explicit retryAfter duration (e.g., from quota reset time).
func (p *Pool) MarkRateLimited(uid, reason string, retryAfter time.Duration) time.Duration {
	p.mu.Lock()
	e, ok := p.byUID[uid]
	if !ok {
		p.mu.Unlock()
		return 0
	}
	if retryAfter <= 0 {
		e.softHits++
		mult := 1 << min(e.softHits-1, 6)
		retryAfter = p.cfg.SoftCooldown * time.Duration(mult)
		if retryAfter > p.cfg.SoftCooldownMax {
			retryAfter = p.cfg.SoftCooldownMax
		}
	}
	const maxRest = 6 * time.Hour
	if retryAfter > maxRest {
		retryAfter = maxRest
	}
	e.cooldownUntil = time.Now().Add(retryAfter)
	e.cooldownReason = reason
	p.dirtyGen++
	p.mu.Unlock()
	return retryAfter
}

// Lease represents an acquired concurrency slot on an account.
type Lease struct {
	pool     *Pool
	Account  *auth.Account
	released bool
	mu       sync.Mutex
}

func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.released = true
	uid := ""
	if l.Account != nil {
		uid = l.Account.UID
	}
	l.mu.Unlock()

	if uid != "" && l.pool != nil {
		l.pool.release(uid)
	}
}

func (p *Pool) release(uid string) {
	p.mu.Lock()
	if e, ok := p.byUID[uid]; ok {
		if e.inFlight > 0 {
			e.inFlight--
		}
	}
	p.signalWaitersLocked()
	p.mu.Unlock()
}

// AcquireOptions configures AcquireWith.
type AcquireOptions struct {
	// PreferredUID is tried first (sticky sessions) when eligible and below MaxInFlight.
	PreferredUID string
	// Exclude lists account UIDs that must not be selected.
	Exclude map[string]bool
	// WaitTimeout bounds how long to wait for a free slot when all candidates are busy.
	WaitTimeout time.Duration
	// MaxWaiters caps concurrent waiters (0 = unlimited); beyond it ErrPoolBusy is returned.
	MaxWaiters int
	// RequireAdvanced restricts selection to accounts whose quota reports AdvancedEnabled.
	// When no such account is eligible, ErrNoAdvancedAccounts is returned without waiting.
	RequireAdvanced    bool
	RequireAttachments bool
}

// Acquire selects a healthy account with free concurrency capacity. If all healthy accounts
// are currently at MaxInFlight, it waits up to waitTimeout (or ctx cancellation).
// It is equivalent to AcquireWith with the corresponding options.
func (p *Pool) Acquire(ctx context.Context, preferredUID string, exclude map[string]bool, waitTimeout time.Duration, maxWaiters int) (*Lease, error) {
	return p.AcquireWith(ctx, AcquireOptions{
		PreferredUID: preferredUID,
		Exclude:      exclude,
		WaitTimeout:  waitTimeout,
		MaxWaiters:   maxWaiters,
	})
}

// AcquireWith selects an account according to opts. Accounts whose cached quota is
// exhausted are skipped while any non-exhausted candidate is eligible (even if that
// candidate is busy, in which case it waits). Only when every eligible candidate is
// exhausted does it fall back to them, because cached quota may be stale and upstream
// remains the final authority (a real exhaustion then triggers MarkRateLimited).
func (p *Pool) AcquireWith(ctx context.Context, opts AcquireOptions) (*Lease, error) {
	deadline := time.Now().Add(opts.WaitTimeout)
	for {
		p.mu.Lock()
		now := time.Now()
		acct, anyEligible := p.pickLocked(now, opts)
		if acct != nil {
			p.mu.Unlock()
			return &Lease{pool: p, Account: acct}, nil
		}
		if !anyEligible {
			p.mu.Unlock()
			if opts.RequireAdvanced {
				return nil, ErrNoAdvancedAccounts
			}
			return nil, ErrNoHealthyAccounts
		}
		if opts.WaitTimeout <= 0 || time.Now().After(deadline) {
			p.mu.Unlock()
			return nil, ErrPoolBusy
		}
		if opts.MaxWaiters > 0 && p.waiters >= opts.MaxWaiters {
			p.mu.Unlock()
			return nil, ErrPoolBusy
		}
		ch := p.notifyCh
		p.waiters++
		p.mu.Unlock()

		rem := time.Until(deadline)
		if rem <= 0 {
			p.mu.Lock()
			p.waiters--
			p.mu.Unlock()
			return nil, ErrPoolBusy
		}
		timer := time.NewTimer(rem)
		select {
		case <-ctx.Done():
			timer.Stop()
			p.mu.Lock()
			p.waiters--
			p.mu.Unlock()
			return nil, ctx.Err()
		case <-timer.C:
			p.mu.Lock()
			p.waiters--
			p.mu.Unlock()
			return nil, ErrPoolBusy
		case <-ch:
			timer.Stop()
			p.mu.Lock()
			p.waiters--
			p.mu.Unlock()
		}
	}
}

// IsEligible reports whether uid is currently enabled and not cooling down.
func (p *Pool) IsEligible(uid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.isEligibleLocked(p.byUID[uid], time.Now())
}

// IsEligibleWith reports whether uid is enabled, not cooling down and, when
// requireAdvanced is set, has advanced models enabled.
func (p *Pool) IsEligibleWith(uid string, requireAdvanced bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.byUID[uid]
	if !p.isEligibleLocked(e, time.Now()) {
		return false
	}
	return !requireAdvanced || e.quota.AdvancedEnabled
}

func (p *Pool) isEligibleLocked(e *entry, now time.Time) bool {
	if e == nil || e.acct == nil || e.disabled {
		return false
	}
	if !e.cooldownUntil.IsZero() && now.Before(e.cooldownUntil) {
		return false
	}
	if !e.cooldownUntil.IsZero() && !now.Before(e.cooldownUntil) {
		e.cooldownUntil = time.Time{}
		e.cooldownReason = ""
	}
	return true
}

// pickLocked claims an account for opts. anyEligible reports whether at least one
// candidate exists (so the caller should wait instead of failing) even if all are busy.
func (p *Pool) pickLocked(now time.Time, opts AcquireOptions) (acct *auth.Account, anyEligible bool) {
	var fresh, exhausted []*entry
	for _, uid := range p.order {
		if opts.Exclude[uid] {
			continue
		}
		e := p.byUID[uid]
		if !p.isEligibleLocked(e, now) {
			continue
		}
		if (opts.RequireAdvanced && !e.quota.AdvancedEnabled) || (opts.RequireAttachments && e.acct.IsGateway()) {
			continue
		}
		if e.quota.IsExhausted() {
			exhausted = append(exhausted, e)
		} else {
			fresh = append(fresh, e)
		}
	}
	candidates := fresh
	if len(candidates) == 0 {
		candidates = exhausted
	}
	if len(candidates) == 0 {
		return nil, false
	}

	if opts.PreferredUID != "" {
		for _, e := range candidates {
			if e.acct.UID == opts.PreferredUID {
				if e.inFlight < p.cfg.MaxInFlight {
					return p.claimLocked(e, now), true
				}
				break
			}
		}
	}

	var ready []*entry
	for _, e := range candidates {
		if e.inFlight < p.cfg.MaxInFlight {
			ready = append(ready, e)
		}
	}
	if len(ready) == 0 {
		return nil, true
	}
	return p.claimLocked(p.chooseLocked(ready), now), true
}

// chooseLocked applies the configured strategy to a non-empty ready set.
func (p *Pool) chooseLocked(ready []*entry) *entry {
	var chosen *entry
	switch p.cfg.Strategy {
	case StrategySequential:
		chosen = ready[0]
	case StrategyRoundRobin:
		if len(p.order) > 0 {
			for i := 0; i < len(p.order); i++ {
				uid := p.order[(p.rrIdx+i)%len(p.order)]
				for _, e := range ready {
					if e.acct.UID == uid {
						chosen = e
						p.rrIdx = (p.rrIdx + i + 1) % len(p.order)
						break
					}
				}
				if chosen != nil {
					break
				}
			}
		}
		if chosen == nil {
			chosen = ready[0]
		}
	default: // weighted: prefer lower in-flight and higher remaining quota headroom
		minFlight := math.MaxInt
		for _, e := range ready {
			if e.inFlight < minFlight {
				minFlight = e.inFlight
			}
		}
		var tier []*entry
		totalW := 0.0
		for _, e := range ready {
			if e.inFlight == minFlight {
				tier = append(tier, e)
				totalW += e.quota.RemainingFraction()
			}
		}
		if len(tier) == 1 || totalW <= 0 {
			chosen = tier[0]
		} else {
			r := rand.Float64() * totalW
			acc := 0.0
			for _, e := range tier {
				acc += e.quota.RemainingFraction()
				if r <= acc {
					chosen = e
					break
				}
			}
			if chosen == nil {
				chosen = tier[len(tier)-1]
			}
		}
	}
	return chosen
}

func (p *Pool) claimLocked(e *entry, now time.Time) *auth.Account {
	e.inFlight++
	p.pickSeq++
	e.usedSeq = p.pickSeq
	e.lastUsed = now
	return e.acct.Clone()
}

func (p *Pool) rebuildOrderLocked() {
	order := make([]string, 0, len(p.byUID))
	for uid := range p.byUID {
		order = append(order, uid)
	}
	sort.Strings(order)
	p.order = order
}

func (p *Pool) signalWaitersLocked() {
	close(p.notifyCh)
	p.notifyCh = make(chan struct{})
}

// WithRefreshLock serializes token refreshes per account UID so concurrent 401s
// never issue duplicate refresh requests or race on rotated refresh tokens.
func (p *Pool) WithRefreshLock(uid string, fn func() error) error {
	return p.withUIDLock(p.refreshLocks, uid, fn)
}

func (p *Pool) withUIDLock(locks map[string]*refLock, uid string, fn func() error) error {
	p.refreshMu.Lock()
	rl, ok := locks[uid]
	if !ok {
		rl = &refLock{}
		locks[uid] = rl
	}
	rl.refs++
	p.refreshMu.Unlock()

	rl.mu.Lock()
	defer func() {
		rl.mu.Unlock()
		p.refreshMu.Lock()
		rl.refs--
		if rl.refs <= 0 {
			delete(locks, uid)
		}
		p.refreshMu.Unlock()
	}()
	return fn()
}

// Snapshot returns sanitized AccountView snapshots for all accounts.
func (p *Pool) Snapshot() []AccountView {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	out := make([]AccountView, 0, len(p.order))
	for _, uid := range p.order {
		e := p.byUID[uid]
		if e == nil || e.acct == nil {
			continue
		}
		cooling := !e.cooldownUntil.IsZero() && now.Before(e.cooldownUntil)
		var cdUntil int64
		cdReason := ""
		if cooling {
			cdUntil = e.cooldownUntil.UnixMilli()
			cdReason = e.cooldownReason
		}
		out = append(out, AccountView{
			UID:            e.acct.UID,
			DisplayName:    e.acct.DisplayName(),
			CustomName:     e.acct.CustomName,
			Email:          e.acct.Email,
			AccountName:    e.acct.AccountName,
			AWSAccountID:   e.acct.AWSAccountID,
			Provider:       e.acct.Provider,
			ProviderLabel:  e.acct.ProviderLabel(),
			Region:         e.acct.Region,
			DeviceID:       e.acct.DeviceID,
			ExpiresAt:      e.acct.ExpiresAt,
			HasRefresh:     strings.TrimSpace(e.acct.RefreshToken) != "" && e.acct.RefreshToken != "none",
			Disabled:       e.disabled,
			DisabledReason: e.disabledReason,
			Healthy:        !e.disabled && !cooling,
			CooldownUntil:  cdUntil,
			CooldownReason: cdReason,
			InFlight:       e.inFlight,
			Quota:          e.quota,
			TotalReqs:      e.totalReqs,
			TotalTokens:    e.totalTokens,
		})
	}
	return out
}

// Summary aggregates overall pool counts and monthly credit totals.
func (p *Pool) Summary() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	var s Summary
	s.Total = len(p.order)
	for _, uid := range p.order {
		e := p.byUID[uid]
		if e == nil {
			continue
		}
		s.InFlight += e.inFlight
		s.TotalReqs += e.totalReqs
		s.TotalTokens += e.totalTokens
		if e.disabled {
			s.Disabled++
			continue
		}
		if !e.cooldownUntil.IsZero() && now.Before(e.cooldownUntil) {
			s.Cooling++
		} else {
			s.Healthy++
		}
		if e.quota.Known {
			s.QuotaKnownCount++
			if e.quota.MonthlyLimit > 0 {
				s.TotalMonthlyLimit += e.quota.MonthlyLimit
				s.TotalMonthlyUsed += e.quota.MonthlyUsed
				avail := e.quota.MonthlyLimit - e.quota.MonthlyUsed
				if avail > 0 {
					s.TotalMonthlyAvail += avail
				}
			}
		}
	}
	return s
}

// Sentinel pool acquisition errors.
type poolError string

func (e poolError) Error() string { return string(e) }

const (
	ErrNoHealthyAccounts = poolError("no healthy Amazon Quick accounts available")
	ErrPoolBusy          = poolError("all healthy Amazon Quick accounts are currently at max concurrency")
	// ErrNoAdvancedAccounts is returned by AcquireWith(RequireAdvanced) when no eligible
	// account has advanced models enabled.
	ErrNoAdvancedAccounts = poolError("no healthy Amazon Quick accounts with advanced models enabled")
)

var _ = log.Printf
