// Package health periodically logs server health metrics to the application log.
package health

import (
	"log"
	"runtime"
	"time"
)

// HubStats exposes the subset of hub metrics needed by the health monitor.
type HubStats interface {
	MsgTotal() uint64
	SubCount() int64
}

// Monitor collects and logs server health metrics on a regular interval.
type Monitor struct {
	hub    HubStats
	ticker *time.Ticker
	done   chan struct{}
}

// New creates a Monitor. Call Start to begin periodic logging.
func New(hub HubStats) *Monitor {
	return &Monitor{
		hub: hub,
	}
}

// Start begins periodic health logging in a background goroutine.
func (m *Monitor) Start(interval time.Duration) {
	m.ticker = time.NewTicker(interval)
	m.done = make(chan struct{})

	// Rate tracking state.
	var prevMsg uint64
	var prevTime time.Time
	var peakMsgRate float64

	go func() {
		log.Print("health: monitor started")
		for {
			select {
			case <-m.done:
				log.Print("health: monitor stopped")
				return
			case now := <-m.ticker.C:
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)

				goroutines := runtime.NumGoroutine()
				subs := int64(0)
				msgTotal := uint64(0)
				if m.hub != nil {
					subs = m.hub.SubCount()
					msgTotal = m.hub.MsgTotal()
				}

				// Message rate over the tick interval (average).
				var msgRate float64
				if !prevTime.IsZero() {
					elapsed := now.Sub(prevTime).Seconds()
					if elapsed > 0 {
						msgRate = float64(msgTotal-prevMsg) / elapsed
					}
					if msgRate > peakMsgRate {
						peakMsgRate = msgRate
					}
				}
				prevMsg = msgTotal
				prevTime = now

				log.Printf(
					"health: goroutines=%d heap=%dMiB inuse=%dMiB sys=%dMiB objects=%d msgs=%d msg/s=%.1f peak=%.1f subs=%d gc=%d pause=%dms",
					goroutines,
					mem.Alloc/1024/1024,
					mem.HeapInuse/1024/1024,
					mem.Sys/1024/1024,
					mem.HeapObjects,
					msgTotal,
					msgRate,
					peakMsgRate,
					subs,
					mem.NumGC,
					mem.PauseNs[(mem.NumGC+255)%256]/1_000_000,
				)
			}
		}
	}()
}

// Stop terminates the background health logging goroutine.
func (m *Monitor) Stop() {
	if m.ticker != nil {
		m.ticker.Stop()
	}
	if m.done == nil {
		return
	}
	select {
	case <-m.done:
		// already stopped
	default:
		close(m.done)
	}
}
