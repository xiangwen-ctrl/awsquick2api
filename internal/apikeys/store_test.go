package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"awsquick2api/internal/safefile"
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

func TestConcurrentFlushDoesNotWriteStaleSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	var clockMu sync.Mutex
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	view, _, err := st.Create(CreateInput{Name: "v0"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	write1Entered := make(chan struct{})
	releaseWrite1 := make(chan struct{})
	var writeSeq atomic.Int32
	var writtenMu sync.Mutex
	var written []storeFile

	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		seq := writeSeq.Add(1)
		if seq == 1 {
			close(write1Entered)
			<-releaseWrite1
		}
		var sf storeFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return err
		}
		writtenMu.Lock()
		written = append(written, sf)
		writtenMu.Unlock()
		return safefile.WriteAtomic(p, data, perm)
	}

	// G0 holds the persistence lock inside write #1.
	nameV1 := "v1"
	updateDone := make(chan error, 1)
	go func() {
		_, uerr := st.Update(view.ID, UpdatePatch{Name: &nameV1})
		updateDone <- uerr
	}()
	<-write1Entered

	// Advance past usageFlushWindow AFTER G0 started writing so G1 triggers a concurrent flush.
	clockMu.Lock()
	now = now.Add(usageFlushWindow + time.Second)
	clockMu.Unlock()

	// G1 records usage (+10) past the flush window, so it must flush after G0.
	usageDone := make(chan struct{})
	go func() {
		defer close(usageDone)
		st.RecordUsage(view.ID, 10)
	}()

	// Deterministically wait until G1 has updated in-memory counters.
	for {
		list := st.List()
		if len(list) == 1 && list[0].TotalTokens == 10 {
			break
		}
		runtime.Gosched()
	}

	// While G0 is STILL paused in write #1, record another usage (+20 -> total 30).
	// Because G1's disk write has not started yet, G1 must snapshot the latest state (30),
	// not a stale snapshot (10) captured before waiting for the disk lock.
	st.RecordUsage(view.ID, 20)

	close(releaseWrite1)
	if err := <-updateDone; err != nil {
		t.Fatalf("Update: %v", err)
	}
	<-usageDone

	writtenMu.Lock()
	if len(written) != 2 {
		writtenMu.Unlock()
		t.Fatalf("expected 2 disk writes, got %d", len(written))
	}
	for i := 1; i < len(written); i++ {
		if written[i].Keys[0].TotalTokens < written[i-1].Keys[0].TotalTokens ||
			written[i].Keys[0].TotalRequests < written[i-1].Keys[0].TotalRequests {
			writtenMu.Unlock()
			t.Fatalf("disk writes regressed: write[%d]=%+v -> write[%d]=%+v", i-1, written[i-1], i, written[i])
		}
	}
	writtenMu.Unlock()

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	list := reloaded.List()
	if len(list) != 1 || list[0].Name != "v1" || list[0].TotalRequests != 2 || list[0].TotalTokens != 30 {
		t.Fatalf("stale snapshot persisted on disk: got %+v, want Name=v1 TotalRequests=2 TotalTokens=30", list)
	}

	// Store should now be clean; another Flush must not write to disk again.
	before := writeSeq.Load()
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush when clean: %v", err)
	}
	if writeSeq.Load() != before {
		t.Fatalf("expected 0 writes on clean Flush, got %d", writeSeq.Load()-before)
	}
}

func TestConcurrentUpdateOrderingPreservesLatestState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return now }

	view, _, err := st.Create(CreateInput{Name: "v0"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	write1Entered := make(chan struct{})
	releaseWrite1 := make(chan struct{})
	var writeSeq atomic.Int32
	var writtenMu sync.Mutex
	var written []storeFile

	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		seq := writeSeq.Add(1)
		if seq == 1 {
			close(write1Entered)
			<-releaseWrite1
		}
		var sf storeFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return err
		}
		writtenMu.Lock()
		written = append(written, sf)
		writtenMu.Unlock()
		return safefile.WriteAtomic(p, data, perm)
	}

	nameV1 := "v1"
	u1Done := make(chan error, 1)
	go func() {
		_, uerr := st.Update(view.ID, UpdatePatch{Name: &nameV1})
		u1Done <- uerr
	}()
	<-write1Entered

	// Queue a second Update while write #1 is in flight, and record usage in memory.
	// Because Update serializes snapshot+write under flushMu, u2 cannot take a snapshot
	// until after u1 releases flushMu (which happens after RecordUsage completes).
	nameV2 := "v2"
	disabled := false
	u2Done := make(chan error, 1)
	go func() {
		_, uerr := st.Update(view.ID, UpdatePatch{Name: &nameV2, Enabled: &disabled})
		u2Done <- uerr
	}()
	st.RecordUsage(view.ID, 20)

	close(releaseWrite1)
	if err := <-u1Done; err != nil {
		t.Fatalf("Update v1: %v", err)
	}
	if err := <-u2Done; err != nil {
		t.Fatalf("Update v2: %v", err)
	}

	writtenMu.Lock()
	if len(written) != 2 {
		writtenMu.Unlock()
		t.Fatalf("expected 2 disk writes, got %d", len(written))
	}
	if written[0].Keys[0].Name != "v1" || !written[0].Keys[0].Enabled {
		writtenMu.Unlock()
		t.Fatalf("unexpected write #1: %+v", written[0].Keys[0])
	}
	if written[1].Keys[0].Name != "v2" || written[1].Keys[0].Enabled || written[1].Keys[0].TotalTokens != 20 {
		writtenMu.Unlock()
		t.Fatalf("unexpected write #2: %+v", written[1].Keys[0])
	}
	writtenMu.Unlock()

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	disk := reloaded.List()
	if len(disk) != 1 || disk[0].Name != "v2" || disk[0].Enabled || disk[0].TotalRequests != 1 || disk[0].TotalTokens != 20 {
		t.Fatalf("reloaded state mismatch: %+v", disk)
	}
}

func TestUpdateFailurePreservesConcurrentAndPriorUsage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return now }

	view, plain, err := st.Create(CreateInput{Name: "orig"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Buffered usage within usageFlushWindow (not yet flushed to disk).
	st.RecordUsage(view.ID, 10)

	enteredWrite := make(chan struct{})
	releaseWrite := make(chan struct{})
	var failWrites atomic.Bool
	failWrites.Store(true)
	var writeCount atomic.Int32

	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		writeCount.Add(1)
		if failWrites.Load() {
			close(enteredWrite)
			<-releaseWrite
			return errors.New("disk full")
		}
		return safefile.WriteAtomic(p, data, perm)
	}

	newName := "renamed"
	disabled := false
	updateErrCh := make(chan error, 1)
	go func() {
		_, uerr := st.Update(view.ID, UpdatePatch{Name: &newName, Enabled: &disabled})
		updateErrCh <- uerr
	}()
	<-enteredWrite

	// While Update's disk write has not succeeded, the key must stay active.
	if authRes := st.Authenticate(plain); !authRes.Matched || authRes.DeniedStatus != 0 {
		t.Fatalf("uncommitted Update exposed disabled key before disk commit: %+v", authRes)
	}

	// Concurrent usage update during the failing Update must survive rollback.
	st.RecordUsage(view.ID, 25)

	close(releaseWrite)
	if err := <-updateErrCh; err == nil {
		t.Fatal("expected Update to fail on injected disk error")
	}

	// In-memory state must keep original metadata and BOTH usage updates (10 + 25 = 35).
	mem := st.List()
	if len(mem) != 1 || mem[0].Name != "orig" || !mem[0].Enabled || mem[0].TotalRequests != 2 || mem[0].TotalTokens != 35 {
		t.Fatalf("failed Update corrupted in-memory state: %+v", mem)
	}

	// Disk recovers; Flush must still consider the store dirty and persist both usage updates.
	failWrites.Store(false)
	writesBefore := writeCount.Load()
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}
	if writeCount.Load() == writesBefore {
		t.Fatal("expected Flush to retry dirty usage updates after failed Update")
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	disk := reloaded.List()
	if len(disk) != 1 || disk[0].Name != "orig" || !disk[0].Enabled || disk[0].TotalRequests != 2 || disk[0].TotalTokens != 35 {
		t.Fatalf("reloaded state lost confirmed usage after failed Update: %+v", disk)
	}
}

func TestIdleDirtyUsageNotFlushedAutomaticallyWithoutPeriodicFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	view, _, err := st.Create(CreateInput{Name: "idle-key"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// RecordUsage within usageFlushWindow after Create leaves dirty data only in memory.
	st.RecordUsage(view.ID, 50)
	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	disk := reloaded.List()
	if len(disk) != 1 || disk[0].TotalRequests != 0 || disk[0].TotalTokens != 0 {
		t.Fatalf("expected buffered usage not yet written synchronously, got %+v", disk)
	}
}

func TestFailedCreateDeleteAndSucceedingUpdatePreserveUsage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return now }

	view, _, err := st.Create(CreateInput{Name: "k1"})
	if err != nil {
		t.Fatalf("Create k1: %v", err)
	}

	// 1. Failing Create must not leak uncommitted key or clear prior dirty usage.
	st.RecordUsage(view.ID, 15)
	st.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, _, err := st.Create(CreateInput{Name: "k2"}); err == nil {
		t.Fatal("expected Create error on failing disk")
	}
	if len(st.List()) != 1 {
		t.Fatalf("failed Create leaked key into memory: %+v", st.List())
	}
	st.writeFile = safefile.WriteAtomic
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush after failed Create: %v", err)
	}
	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload after failed Create: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalTokens != 15 {
		t.Fatalf("prior dirty usage lost after failed Create: %+v", got)
	}

	// 2. Failing Delete must not remove key or clear prior dirty usage.
	st.RecordUsage(view.ID, 25) // total 40
	st.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if err := st.Delete(view.ID); err == nil {
		t.Fatal("expected Delete error on failing disk")
	}
	if got := st.List(); len(got) != 1 || got[0].TotalTokens != 40 {
		t.Fatalf("failed Delete corrupted memory: %+v", got)
	}
	st.writeFile = safefile.WriteAtomic
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush after failed Delete: %v", err)
	}
	reloaded, err = NewStore(path)
	if err != nil {
		t.Fatalf("reload after failed Delete: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalTokens != 40 {
		t.Fatalf("prior dirty usage lost after failed Delete: %+v", got)
	}

	// 3. Concurrent RecordUsage during a SUCCEEDING Update must survive in memory
	// and keep the store dirty for the next Flush.
	entered := make(chan struct{})
	release := make(chan struct{})
	var hooked atomic.Bool
	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		if hooked.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return safefile.WriteAtomic(p, data, perm)
	}

	nameV2 := "k1-v2"
	done := make(chan error, 1)
	go func() {
		_, uerr := st.Update(view.ID, UpdatePatch{Name: &nameV2})
		done <- uerr
	}()
	<-entered
	st.RecordUsage(view.ID, 30) // total 70 while Update is writing snapshot with 40
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Update k1-v2: %v", err)
	}

	if got := st.List(); len(got) != 1 || got[0].Name != "k1-v2" || got[0].TotalTokens != 70 {
		t.Fatalf("succeeding Update clobbered concurrent usage: %+v", got)
	}
	if err := st.Flush(); err != nil {
		t.Fatalf("Flush concurrent usage after Update: %v", err)
	}
	reloaded, err = NewStore(path)
	if err != nil {
		t.Fatalf("reload after concurrent usage + Update: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Name != "k1-v2" || got[0].TotalTokens != 70 {
		t.Fatalf("reloaded state missed concurrent usage after Update: %+v", got)
	}
}

func TestRecordUsageFlushFailureRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return now }

	view, _, err := st.Create(CreateInput{Name: "retry-key"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	now = now.Add(usageFlushWindow + time.Second)
	var attempts atomic.Int32
	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		if attempts.Add(1) == 1 {
			return errors.New("transient io error")
		}
		return safefile.WriteAtomic(p, data, perm)
	}

	// First RecordUsage triggers Flush which fails; dirtyGen must remain ahead of flushedGen.
	st.RecordUsage(view.ID, 33)
	if attempts.Load() != 1 {
		t.Fatalf("expected 1 failed write attempt, got %d", attempts.Load())
	}

	// Explicit Flush must retry and succeed.
	if err := st.Flush(); err != nil {
		t.Fatalf("retry Flush: %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected 2 total write attempts after retry, got %d", attempts.Load())
	}

	// Clean Flush must not write again.
	if err := st.Flush(); err != nil {
		t.Fatalf("clean Flush: %v", err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("expected no extra write when clean, got %d", attempts.Load())
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalRequests != 1 || got[0].TotalTokens != 33 {
		t.Fatalf("reloaded state mismatch after retry: %+v", got)
	}
}

func TestPeriodicFlushIdleUsageNoRedundantWritesAndRetry(t *testing.T) {
	// Edge cases: nil store, empty path, nil/cancelled ctx must return immediately.
	var nilStore *Store
	nilStore.RunPeriodicFlush(context.Background(), 10*time.Millisecond)
	memStore, err := NewStore("")
	if err != nil {
		t.Fatalf("NewStore empty: %v", err)
	}
	memStore.RunPeriodicFlush(context.Background(), 10*time.Millisecond)

	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")
	fixedNow := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return fixedNow }
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	st.RunPeriodicFlush(cancelledCtx, 10*time.Millisecond)

	view, _, err := st.Create(CreateInput{Name: "periodic-key"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var writeAttempts atomic.Int32
	var writeSuccesses atomic.Int32
	var failRemaining atomic.Int32
	writeDoneCh := make(chan int32, 16)

	st.writeFile = func(p string, data []byte, perm os.FileMode) error {
		writeAttempts.Add(1)
		if failRemaining.Load() > 0 && failRemaining.Add(-1) >= 0 {
			return errors.New("temporary write error")
		}
		if err := safefile.WriteAtomic(p, data, perm); err != nil {
			return err
		}
		n := writeSuccesses.Add(1)
		select {
		case writeDoneCh <- n:
		default:
		}
		return nil
	}

	// 1. Buffer a usage update within usageFlushWindow (not persisted synchronously).
	st.RecordUsage(view.ID, 50)
	if writeAttempts.Load() != 0 {
		t.Fatalf("expected 0 synchronous writes within flush window, got %d", writeAttempts.Load())
	}

	// 2. Start RunPeriodicFlush: idle dirty data must be persisted automatically with no new requests.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		st.RunPeriodicFlush(ctx, 15*time.Millisecond)
	}()

	select {
	case <-writeDoneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for periodic flush of idle dirty usage")
	}

	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload after idle periodic flush: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalRequests != 1 || got[0].TotalTokens != 50 {
		t.Fatalf("idle usage not persisted by periodic flush: %+v", got)
	}

	// 3. No dirty data -> subsequent ticks and explicit Flush must not write to disk again.
	attemptsAfterFirst := writeAttempts.Load()
	time.Sleep(60 * time.Millisecond)
	if err := st.Flush(); err != nil {
		t.Fatalf("clean Flush: %v", err)
	}
	if got := writeAttempts.Load(); got != attemptsAfterFirst {
		t.Fatalf("expected no redundant disk writes while clean, attempts grew %d -> %d", attemptsAfterFirst, got)
	}

	// 4. Write failures must stay dirty and be retried automatically on later ticks.
	failRemaining.Store(2)
	attemptsBeforeRetry := writeAttempts.Load()
	st.RecordUsage(view.ID, 70) // total 120, buffered within usageFlushWindow

	select {
	case <-writeDoneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for periodic flush retry to succeed")
	}
	if delta := writeAttempts.Load() - attemptsBeforeRetry; delta < 3 {
		t.Fatalf("expected at least 3 attempts (2 failures + 1 success), got %d", delta)
	}

	reloaded, err = NewStore(path)
	if err != nil {
		t.Fatalf("reload after retry periodic flush: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalRequests != 2 || got[0].TotalTokens != 120 {
		t.Fatalf("retried usage mismatch on disk: %+v", got)
	}

	// 5. Cancelling ctx stops the background task promptly; final shutdown Flush still works.
	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPeriodicFlush did not exit after context cancellation")
	}

	attemptsAfterStop := writeAttempts.Load()
	st.RecordUsage(view.ID, 80) // total 200
	time.Sleep(45 * time.Millisecond)
	if got := writeAttempts.Load(); got != attemptsAfterStop {
		t.Fatalf("stopped periodic flusher still wrote to disk: %d -> %d", attemptsAfterStop, got)
	}

	if err := st.Flush(); err != nil {
		t.Fatalf("final shutdown Flush: %v", err)
	}
	reloaded, err = NewStore(path)
	if err != nil {
		t.Fatalf("reload after shutdown Flush: %v", err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].TotalRequests != 3 || got[0].TotalTokens != 200 {
		t.Fatalf("final shutdown Flush mismatch: %+v", got)
	}
}

func TestConcurrentMutationsAndPeriodicFlushReloadMatchesMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-keys.json")

	fixedNow := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	st, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st.now = func() time.Time { return fixedNow }

	// Seed a few keys to update and record usage against.
	seedIDs := make([]string, 4)
	seedPlains := make([]string, 4)
	for i := range seedIDs {
		v, p, cerr := st.Create(CreateInput{Name: fmt.Sprintf("seed-%d", i)})
		if cerr != nil {
			t.Fatalf("seed Create %d: %v", i, cerr)
		}
		seedIDs[i] = v.ID
		seedPlains[i] = p
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		st.RunPeriodicFlush(ctx, 5*time.Millisecond)
	}()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 12; i++ {
				id := seedIDs[(worker+i)%len(seedIDs)]
				plain := seedPlains[(worker+i)%len(seedPlains)]
				switch (worker + i) % 5 {
				case 0:
					st.RecordUsage(id, 10)
				case 1:
					name := fmt.Sprintf("w%d-i%d", worker, i)
					enabled := i%2 == 0
					_, _ = st.Update(id, UpdatePatch{Name: &name, Enabled: &enabled})
				case 2:
					v, _, cerr := st.Create(CreateInput{Name: fmt.Sprintf("tmp-%d-%d", worker, i)})
					if cerr == nil {
						st.RecordUsage(v.ID, 5)
						_ = st.Delete(v.ID)
					}
				case 3:
					_ = st.Authenticate(plain)
					_ = st.List()
				case 4:
					_ = st.Flush()
				}
			}
		}(g)
	}
	wg.Wait()
	cancel()
	<-loopDone

	if err := st.Flush(); err != nil {
		t.Fatalf("final Flush: %v", err)
	}
	reloaded, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload NewStore: %v", err)
	}
	reloaded.now = func() time.Time { return fixedNow }
	if !reflect.DeepEqual(reloaded.List(), st.List()) {
		t.Fatalf("reloaded state differs from memory:\ndisk=%+v\nmem =%+v", reloaded.List(), st.List())
	}

	// Metadata-only concurrent mutations must persist the latest committed state
	// without needing an extra Flush call.
	var metaWG sync.WaitGroup
	for g := 0; g < 6; g++ {
		metaWG.Add(1)
		go func(worker int) {
			defer metaWG.Done()
			for i := 0; i < 8; i++ {
				id := seedIDs[(worker+i)%len(seedIDs)]
				name := fmt.Sprintf("meta-%d-%d", worker, i)
				enabled := (worker+i)%2 == 0
				if _, uerr := st.Update(id, UpdatePatch{Name: &name, Enabled: &enabled}); uerr != nil {
					t.Errorf("concurrent metadata Update: %v", uerr)
				}
			}
		}(g)
	}
	metaWG.Wait()

	reloadedMeta, err := NewStore(path)
	if err != nil {
		t.Fatalf("reload after metadata updates: %v", err)
	}
	reloadedMeta.now = func() time.Time { return fixedNow }
	if !reflect.DeepEqual(reloadedMeta.List(), st.List()) {
		t.Fatalf("metadata-only reloaded state differs from memory without Flush:\ndisk=%+v\nmem =%+v", reloadedMeta.List(), st.List())
	}
}
