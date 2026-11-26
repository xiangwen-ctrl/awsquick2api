package server

import (
	"log"
	"sync"
	"time"
)

const (
	upHealthWindow    = 5 * time.Minute
	upHealthBuckets   = 20
	upHealthBucket    = upHealthWindow / upHealthBuckets // 15s
	upHealthWarnEvery = 10 * time.Minute
	upHealthMinSample = 10
	upHealthSlowTTFB  = 8 * time.Second
	upHealthSlowRatio = 0.30
	upHealthFailRatio = 0.10
	upHealthMinFail   = 3
)

// UpstreamHealthSnapshot summarizes recent upstream latency/5xx health over a 5m sliding window.
type UpstreamHealthSnapshot struct {
	WindowSeconds int   `json:"window_seconds"`
	Samples       int   `json:"samples"`
	SlowCount     int   `json:"slow_count"`
	SlowPercent   int   `json:"slow_percent"`
	FailCount     int   `json:"fail_count"`
	FailPercent   int   `json:"fail_percent"`
	WorstTTFBMs   int64 `json:"worst_ttfb_ms"`
	Degraded      bool  `json:"degraded"`
}

type upHealthBucketEntry struct {
	id                int64
	total, slow, fail int
	worst             time.Duration
}

// UpstreamHealthTracker detects silent upstream degradation (e.g. HTTP 200 turns with
// persistently slow TTFB, or rising 5xx rates) using a fixed-size ring of time buckets.
type UpstreamHealthTracker struct {
	mu       sync.Mutex
	buckets  [upHealthBuckets]upHealthBucketEntry
	lastWarn time.Time
	now      func() time.Time
}

func NewUpstreamHealthTracker() *UpstreamHealthTracker {
	return &UpstreamHealthTracker{now: time.Now}
}

func (u *UpstreamHealthTracker) clock() time.Time {
	if u != nil && u.now != nil {
		return u.now()
	}
	return time.Now()
}

// Record ingests one completed inference turn. Client cancellations (499) and 4xx
// caller errors are excluded so caller behavior never triggers false upstream alarms.
func (u *UpstreamHealthTracker) Record(status int, ttfb time.Duration) {
	if u == nil || status == 0 || status == 499 {
		return
	}
	okSample := status >= 200 && status < 300 && ttfb > 0
	fail := status >= 500
	if !okSample && !fail {
		return
	}
	now := u.clock()
	id := now.UnixNano() / int64(upHealthBucket)

	u.mu.Lock()
	b := &u.buckets[id%upHealthBuckets]
	if b.id != id {
		*b = upHealthBucketEntry{id: id}
	}
	b.total++
	if fail {
		b.fail++
	} else {
		if ttfb >= upHealthSlowTTFB {
			b.slow++
		}
		if ttfb > b.worst {
			b.worst = ttfb
		}
	}

	snap := u.snapshotLocked(id)
	shouldWarn := false
	if snap.Degraded && (u.lastWarn.IsZero() || now.Sub(u.lastWarn) >= upHealthWarnEvery) {
		u.lastWarn = now
		shouldWarn = true
	}
	u.mu.Unlock()

	if shouldWarn {
		log.Printf("WARN: [server] upstream degraded over last %s: samples=%d slow(>=%s)=%d%% worst_ttfb=%dms 5xx=%d%%",
			upHealthWindow, snap.Samples, upHealthSlowTTFB, snap.SlowPercent, snap.WorstTTFBMs, snap.FailPercent)
	}
}

// Snapshot returns the current 5-minute sliding window health summary.
func (u *UpstreamHealthTracker) Snapshot() UpstreamHealthSnapshot {
	if u == nil {
		return UpstreamHealthSnapshot{WindowSeconds: int(upHealthWindow / time.Second)}
	}
	id := u.clock().UnixNano() / int64(upHealthBucket)
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.snapshotLocked(id)
}

func (u *UpstreamHealthTracker) snapshotLocked(cur int64) UpstreamHealthSnapshot {
	var total, slow, fail int
	var worst time.Duration
	for _, b := range u.buckets {
		if b.total == 0 || b.id <= cur-upHealthBuckets || b.id > cur {
			continue
		}
		total += b.total
		slow += b.slow
		fail += b.fail
		if b.worst > worst {
			worst = b.worst
		}
	}
	slowPct, failPct := 0, 0
	if total > 0 {
		slowPct = slow * 100 / total
		failPct = fail * 100 / total
	}
	slowBad := total >= upHealthMinSample && float64(slow) >= float64(total)*upHealthSlowRatio
	failBad := total >= upHealthMinSample && fail >= upHealthMinFail && float64(fail) >= float64(total)*upHealthFailRatio
	return UpstreamHealthSnapshot{
		WindowSeconds: int(upHealthWindow / time.Second),
		Samples:       total,
		SlowCount:     slow,
		SlowPercent:   slowPct,
		FailCount:     fail,
		FailPercent:   failPct,
		WorstTTFBMs:   worst.Milliseconds(),
		Degraded:      slowBad || failBad,
	}
}
