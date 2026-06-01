package api

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
)

const (
	// enclaveMetricsProbeTimeout caps each VSOCK call so a hung enclave
	// can't delay the next refresh past one tick. Generous relative to a
	// /proc read but still well below the default poll interval.
	enclaveMetricsProbeTimeout = 2 * time.Second
)

// enclaveMetricsSnapshot is the cached result of one successful poll.
type enclaveMetricsSnapshot struct {
	CPU       messages.EnclaveCPUTimes
	Memory    messages.EnclaveMemoryStats
	SampledAt time.Time
}

// EnclaveMetricsCollector polls the enclave for CPU/memory snapshots on a
// fixed interval and exposes them as Prometheus metrics. Implements
// prometheus.Collector so labeled series (cpu_seconds_total{mode=...},
// memory_bytes{type=...}) emit cleanly without needing one CounterFunc per
// label value.
//
// Failed polls leave the previous snapshot in place — stale metrics beat
// missing metrics, and operators can detect staleness via
// cerberus_enclave_metrics_last_scrape_timestamp_seconds.
type EnclaveMetricsCollector struct {
	signer   enclave.Signer
	interval time.Duration
	timeout  time.Duration

	state           atomic.Pointer[enclaveMetricsSnapshot]
	scrapeErrors    atomic.Uint64
	lastProbeFailed atomic.Bool

	cpuDesc          *prometheus.Desc
	memDesc          *prometheus.Desc
	scrapeErrorsDesc *prometheus.Desc
	lastScrapeDesc   *prometheus.Desc
}

// NewEnclaveMetricsCollector constructs a collector wired to signer with the
// given poll interval. The caller is responsible for registering it with a
// Prometheus registry (e.g. prometheus.MustRegister) and for calling Start.
func NewEnclaveMetricsCollector(signer enclave.Signer, interval time.Duration) *EnclaveMetricsCollector {
	return &EnclaveMetricsCollector{
		signer:   signer,
		interval: interval,
		timeout:  enclaveMetricsProbeTimeout,
		cpuDesc: prometheus.NewDesc(
			"cerberus_enclave_cpu_seconds_total",
			"Cumulative CPU time per mode inside the Nitro Enclave, in seconds.",
			[]string{"mode"}, nil,
		),
		memDesc: prometheus.NewDesc(
			"cerberus_enclave_memory_bytes",
			"Enclave memory usage by category, in bytes.",
			[]string{"type"}, nil,
		),
		scrapeErrorsDesc: prometheus.NewDesc(
			"cerberus_enclave_metrics_scrape_errors_total",
			"Total VSOCK or decode errors encountered while polling enclave metrics.",
			nil, nil,
		),
		lastScrapeDesc: prometheus.NewDesc(
			"cerberus_enclave_metrics_last_scrape_timestamp_seconds",
			"Unix timestamp (seconds) of the most recent successful enclave metrics poll. 0 until the first successful probe; staleness alerts of the form `time() - X > threshold` fire from process start until then, which is the intended behavior.",
			nil, nil,
		),
	}
}

// Start performs one synchronous probe so /metrics has data on the first
// scrape, then spawns the background refresh loop. The loop exits when ctx
// is cancelled.
func (c *EnclaveMetricsCollector) Start(ctx context.Context) {
	c.probe(ctx)
	go c.loop(ctx)
}

func (c *EnclaveMetricsCollector) loop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.probe(ctx)
		}
	}
}

// probe runs one bounded VSOCK call. On success it replaces the cached
// snapshot; on failure it increments scrapeErrors and leaves the snapshot
// alone. Logs are gated on healthy<->degraded transitions so a sustained
// outage doesn't flood at the poll interval, but the first failure (and
// the eventual recovery) are visible at the default log level - matching
// the HealthMonitor pattern in health.go.
func (c *EnclaveMetricsCollector) probe(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	prevFailed := c.lastProbeFailed.Load()
	resp, err := c.signer.GetEnclaveMetrics(ctx)
	if err != nil {
		c.scrapeErrors.Add(1)
		c.lastProbeFailed.Store(true)
		if !prevFailed {
			slog.Warn("enclave_metrics.degraded", "error", err)
		}
		return
	}
	c.state.Store(&enclaveMetricsSnapshot{
		CPU:       resp.CPU,
		Memory:    resp.Memory,
		SampledAt: time.Now(),
	})
	c.lastProbeFailed.Store(false)
	if prevFailed {
		slog.Info("enclave_metrics.recovered")
	}
}

// Describe implements prometheus.Collector.
func (c *EnclaveMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cpuDesc
	ch <- c.memDesc
	ch <- c.scrapeErrorsDesc
	ch <- c.lastScrapeDesc
}

// Collect implements prometheus.Collector. Emits the scrape-error counter
// and last-scrape-timestamp gauge unconditionally so staleness alerts
// (`time() - last_scrape > threshold`) fire from process start until the
// first successful probe; the cpu/memory series are only emitted once a
// snapshot exists, since labeled series with no underlying data have no
// meaningful zero value.
func (c *EnclaveMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		c.scrapeErrorsDesc,
		prometheus.CounterValue,
		float64(c.scrapeErrors.Load()),
	)

	snap := c.state.Load()
	var lastScrapeUnix float64
	if snap != nil {
		lastScrapeUnix = float64(snap.SampledAt.Unix())
	}

	ch <- prometheus.MustNewConstMetric(
		c.lastScrapeDesc,
		prometheus.GaugeValue,
		lastScrapeUnix,
	)

	if snap == nil {
		return
	}

	cpuModes := []struct {
		mode  string
		value float64
	}{
		{"user", snap.CPU.User},
		{"nice", snap.CPU.Nice},
		{"system", snap.CPU.System},
		{"idle", snap.CPU.Idle},
		{"iowait", snap.CPU.IOWait},
		{"irq", snap.CPU.IRQ},
		{"softirq", snap.CPU.SoftIRQ},
	}
	for _, m := range cpuModes {
		ch <- prometheus.MustNewConstMetric(
			c.cpuDesc,
			prometheus.CounterValue,
			m.value,
			m.mode,
		)
	}

	memTypes := []struct {
		kind  string
		value uint64
	}{
		{"total", snap.Memory.TotalBytes},
		{"available", snap.Memory.AvailableBytes},
		{"free", snap.Memory.FreeBytes},
		{"buffers", snap.Memory.BuffersBytes},
		{"cached", snap.Memory.CachedBytes},
	}
	for _, m := range memTypes {
		ch <- prometheus.MustNewConstMetric(
			c.memDesc,
			prometheus.GaugeValue,
			float64(m.value),
			m.kind,
		)
	}
}
