package server

import (
	"context"
	"sync"
	"time"
)

const sseKeepaliveInterval = 15 * time.Second

// sseKeepalive runs a periodic heartbeat callback until Stop() or ctx cancellation,
// guaranteeing via WaitGroup that no heartbeat writes occur after Stop() returns.
type sseKeepalive struct {
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func startSSEKeepalive(ctx context.Context, interval time.Duration, send func()) *sseKeepalive {
	if interval <= 0 {
		interval = sseKeepaliveInterval
	}
	k := &sseKeepalive{
		stopCh: make(chan struct{}),
	}
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		tk := time.NewTicker(interval)
		defer tk.Stop()
		for {
			select {
			case <-k.stopCh:
				return
			case <-ctx.Done():
				return
			case <-tk.C:
				if send != nil {
					send()
				}
			}
		}
	}()
	return k
}

// Stop halts the heartbeat and blocks until any in-flight send() has returned.
func (k *sseKeepalive) Stop() {
	if k == nil {
		return
	}
	k.stopOnce.Do(func() { close(k.stopCh) })
	k.wg.Wait()
}
