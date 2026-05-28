package api

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	cerberusldap "github.com/pkilar/cerberus/ssh-cert-api/internal/ldap"
)

// LDAPBackendSnapshot is the public JSON shape emitted in the /health
// response for one LDAP backend. last_error is empty when the backend is
// healthy and is preserved across the next failed probe.
type LDAPBackendSnapshot struct {
	Name        string    `json:"name"`
	Healthy     bool      `json:"healthy"`
	LastChecked time.Time `json:"last_checked"`
	LastError   string    `json:"last_error,omitempty"`
}

// LDAPHealthMonitor probes each configured LDAP backend on a fixed cadence
// and exposes the latest result via Snapshots(). It is intentionally
// independent of HealthMonitor: LDAP health is ADVISORY — the top-level
// /health status remains tied to enclave staleness. Operators alert on the
// per-backend status separately.
//
// Each probe also updates the BackendUp gauge so dashboards and alert rules
// can consume the same signal as the JSON response.
type LDAPHealthMonitor struct {
	clients       []namedClient // stable iteration order
	metrics       *cerberusldap.Metrics
	probeInterval time.Duration
	probeTimeout  time.Duration

	// snapshots is keyed by backend name and populated once in
	// newLDAPHealthMonitor. The map itself is read-only after construction;
	// per-backend updates go through the atomic.Pointer values.
	snapshots map[string]*atomic.Pointer[LDAPBackendSnapshot]
}

type namedClient struct {
	name   string
	client cerberusldap.Client
}

// NewLDAPHealthMonitor wires a monitor with the same default cadence the
// enclave health monitor uses (5s interval, 2s timeout). clients may be nil
// or empty, in which case the monitor is a no-op and Snapshots returns nil.
func NewLDAPHealthMonitor(clients map[string]cerberusldap.Client, metrics *cerberusldap.Metrics) *LDAPHealthMonitor {
	return newLDAPHealthMonitor(clients, metrics, healthProbeInterval, healthProbeTimeout)
}

func newLDAPHealthMonitor(clients map[string]cerberusldap.Client, metrics *cerberusldap.Metrics, interval, timeout time.Duration) *LDAPHealthMonitor {
	names := make([]string, 0, len(clients))
	for name := range clients {
		names = append(names, name)
	}
	slices.Sort(names)
	ordered := make([]namedClient, 0, len(names))
	snaps := make(map[string]*atomic.Pointer[LDAPBackendSnapshot], len(names))
	for _, name := range names {
		ordered = append(ordered, namedClient{name: name, client: clients[name]})
		snaps[name] = &atomic.Pointer[LDAPBackendSnapshot]{}
	}
	return &LDAPHealthMonitor{
		clients:       ordered,
		metrics:       metrics,
		probeInterval: interval,
		probeTimeout:  timeout,
		snapshots:     snaps,
	}
}

// Start runs one synchronous probe of each backend so /health has data the
// moment the server begins serving, then spawns the background refresh
// loop. The loop exits when ctx is cancelled. Safe to call on a monitor
// with no backends.
func (m *LDAPHealthMonitor) Start(ctx context.Context) {
	if m == nil || len(m.clients) == 0 {
		return
	}
	m.probeAll(ctx)
	go m.loop(ctx)
}

func (m *LDAPHealthMonitor) loop(ctx context.Context) {
	ticker := time.NewTicker(m.probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeAll(ctx)
		}
	}
}

func (m *LDAPHealthMonitor) probeAll(parent context.Context) {
	for _, c := range m.clients {
		m.probeOne(parent, c)
	}
}

func (m *LDAPHealthMonitor) probeOne(parent context.Context, c namedClient) {
	ctx, cancel := context.WithTimeout(parent, m.probeTimeout)
	defer cancel()
	prev := m.snapshots[c.name].Load()
	snap := &LDAPBackendSnapshot{Name: c.name, LastChecked: time.Now()}
	if err := c.client.HealthCheck(ctx); err != nil {
		snap.LastError = err.Error()
		if prev == nil || prev.Healthy {
			slog.Warn("ldap.health.degraded", "backend", c.name, "error", err)
		}
	} else {
		snap.Healthy = true
		if prev != nil && !prev.Healthy {
			slog.Info("ldap.health.recovered", "backend", c.name)
		}
	}
	m.snapshots[c.name].Store(snap)
	if m.metrics != nil {
		up := 0.0
		if snap.Healthy {
			up = 1.0
		}
		m.metrics.BackendUp.WithLabelValues(c.name).Set(up)
	}
}

// Snapshots returns the latest probe result per backend, in stable
// alphabetical order. Returns nil for a monitor with no backends so the
// /health response can elide the field entirely.
func (m *LDAPHealthMonitor) Snapshots() []LDAPBackendSnapshot {
	if m == nil || len(m.clients) == 0 {
		return nil
	}
	out := make([]LDAPBackendSnapshot, 0, len(m.clients))
	for _, c := range m.clients {
		if s := m.snapshots[c.name].Load(); s != nil {
			out = append(out, *s)
		}
	}
	return out
}
