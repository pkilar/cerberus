package api

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
)

const (
	// healthProbeInterval is how often the background monitor refreshes the
	// cached enclave health snapshot.
	healthProbeInterval = 5 * time.Second
	// healthProbeTimeout caps each probe so a hung Ping can't delay the
	// next refresh past one tick.
	healthProbeTimeout = 2 * time.Second
	// healthStaleAfter is the maximum age of a cached snapshot before the
	// handler reports unhealthy. ~6 intervals tolerates a couple of missed
	// probes; longer and the monitor goroutine is probably stuck.
	healthStaleAfter = 30 * time.Second
)

// healthSnapshot is the cached result of one enclave Ping.
type healthSnapshot struct {
	SignerLoaded bool
	LastError    string
	LastChecked  time.Time
}

// HealthMonitor caches a recent answer to "is the enclave OK?" and refreshes
// it in the background. /health reads from the cache without ever opening a
// VSOCK connection on the request path, so a flood of unauthenticated health
// requests cannot consume the signer's bounded connection budget.
type HealthMonitor struct {
	signer        enclave.Signer
	probeInterval time.Duration
	probeTimeout  time.Duration
	state         atomic.Pointer[healthSnapshot]
}

// NewHealthMonitor constructs a HealthMonitor wired to signer with the
// package's default probe interval and timeout.
func NewHealthMonitor(signer enclave.Signer) *HealthMonitor {
	return newHealthMonitor(signer, healthProbeInterval, healthProbeTimeout)
}

func newHealthMonitor(signer enclave.Signer, probeInterval, probeTimeout time.Duration) *HealthMonitor {
	return &HealthMonitor{
		signer:        signer,
		probeInterval: probeInterval,
		probeTimeout:  probeTimeout,
	}
}

// Start performs one synchronous probe — so /health has a result the moment
// the server starts serving — then spawns the background refresh loop. The
// loop exits when ctx is cancelled.
func (h *HealthMonitor) Start(ctx context.Context) {
	h.probe(ctx)
	go h.loop(ctx)
}

func (h *HealthMonitor) loop(ctx context.Context) {
	ticker := time.NewTicker(h.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.probe(ctx)
		}
	}
}

// probe runs one Ping with a bounded sub-context and stores the result. The
// log is gated on state transitions (healthy↔unhealthy) so a sustained
// outage doesn't flood the log at probeInterval.
func (h *HealthMonitor) probe(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, h.probeTimeout)
	defer cancel()

	prev := h.state.Load()
	snap := &healthSnapshot{LastChecked: time.Now()}
	pong, err := h.signer.Ping(ctx)
	if err != nil {
		snap.LastError = err.Error()
		if prev == nil || prev.LastError == "" {
			slog.Warn("health.degraded", "error", err)
		}
	} else {
		snap.SignerLoaded = pong.SignerLoaded
		if prev != nil && prev.LastError != "" {
			slog.Info("health.recovered")
		}
	}
	h.state.Store(snap)
}

// Snapshot returns the most recent cached probe result, or nil if no probe
// has completed yet. Callers should treat nil as "not yet ready".
func (h *HealthMonitor) Snapshot() *healthSnapshot {
	return h.state.Load()
}
