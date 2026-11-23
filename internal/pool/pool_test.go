package pool

import (
	"context"
	"path/filepath"
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
