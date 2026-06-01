package api

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/pkilar/cerberus/messages"
)

func TestEnclaveMetricsCollector_PopulatesSnapshotOnSuccess(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{
		metricsResp: &messages.EnclaveMetricsResponse{
			CPU: messages.EnclaveCPUTimes{
				User: 12.5, Nice: 0, System: 3.25, Idle: 1000,
				IOWait: 0.5, IRQ: 0.1, SoftIRQ: 0.2,
			},
			Memory: messages.EnclaveMemoryStats{
				TotalBytes:     2 * 1024 * 1024 * 1024,
				AvailableBytes: 1 * 1024 * 1024 * 1024,
				FreeBytes:      512 * 1024 * 1024,
				BuffersBytes:   64 * 1024 * 1024,
				CachedBytes:    256 * 1024 * 1024,
			},
		},
	}
	c := NewEnclaveMetricsCollector(signer, time.Hour)

	c.probe(t.Context())

	snap := c.state.Load()
	if snap == nil {
		t.Fatal("snapshot is nil after successful probe")
	}
	if snap.CPU.User != 12.5 {
		t.Errorf("CPU.User = %v, want 12.5", snap.CPU.User)
	}
	if snap.Memory.TotalBytes != 2*1024*1024*1024 {
		t.Errorf("Memory.TotalBytes = %d", snap.Memory.TotalBytes)
	}
	if c.scrapeErrors.Load() != 0 {
		t.Errorf("scrapeErrors = %d, want 0", c.scrapeErrors.Load())
	}
	if signer.metricsCount.Load() != 1 {
		t.Errorf("metricsCount = %d, want 1", signer.metricsCount.Load())
	}
}

func TestEnclaveMetricsCollector_FailureKeepsPreviousSnapshot(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{
		metricsResp: &messages.EnclaveMetricsResponse{
			CPU:    messages.EnclaveCPUTimes{User: 7},
			Memory: messages.EnclaveMemoryStats{TotalBytes: 1024},
		},
	}
	c := NewEnclaveMetricsCollector(signer, time.Hour)

	// First probe succeeds.
	c.probe(t.Context())
	first := c.state.Load()
	if first == nil || first.CPU.User != 7 {
		t.Fatalf("first probe didn't seed snapshot: %+v", first)
	}

	// Switch the fake to error mode and probe again.
	signer.metricsResp = nil
	signer.metricsErr = errors.New("vsock dial: connection refused")
	c.probe(t.Context())

	if c.scrapeErrors.Load() != 1 {
		t.Errorf("scrapeErrors = %d, want 1", c.scrapeErrors.Load())
	}
	// Snapshot must still be the first successful one.
	got := c.state.Load()
	if got == nil || got.CPU.User != 7 {
		t.Errorf("snapshot was clobbered on failure: %+v", got)
	}
}

func TestEnclaveMetricsCollector_PrometheusOutput(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{
		metricsResp: &messages.EnclaveMetricsResponse{
			CPU: messages.EnclaveCPUTimes{
				User: 1, Nice: 2, System: 3, Idle: 4, IOWait: 5, IRQ: 6, SoftIRQ: 7,
			},
			Memory: messages.EnclaveMemoryStats{
				TotalBytes: 100, AvailableBytes: 80, FreeBytes: 50,
				BuffersBytes: 10, CachedBytes: 20,
			},
		},
	}
	c := NewEnclaveMetricsCollector(signer, time.Hour)
	c.probe(t.Context())

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	families := indexFamilies(mfs)

	wantCPU := map[string]float64{
		"user": 1, "nice": 2, "system": 3, "idle": 4,
		"iowait": 5, "irq": 6, "softirq": 7,
	}
	checkLabeled(t, families, "cerberus_enclave_cpu_seconds_total", "mode", wantCPU, dto.MetricType_COUNTER)

	wantMem := map[string]float64{
		"total": 100, "available": 80, "free": 50, "buffers": 10, "cached": 20,
	}
	checkLabeled(t, families, "cerberus_enclave_memory_bytes", "type", wantMem, dto.MetricType_GAUGE)

	if got := scalarValue(t, families, "cerberus_enclave_metrics_scrape_errors_total"); got != 0 {
		t.Errorf("scrape_errors_total = %v, want 0", got)
	}
}

func indexFamilies(mfs []*dto.MetricFamily) map[string]*dto.MetricFamily {
	out := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

func checkLabeled(t *testing.T, families map[string]*dto.MetricFamily, name, label string, want map[string]float64, wantType dto.MetricType) {
	t.Helper()
	mf, ok := families[name]
	if !ok {
		t.Fatalf("metric family %q absent from gather output", name)
	}
	if mf.GetType() != wantType {
		t.Errorf("%s: type = %v, want %v", name, mf.GetType(), wantType)
	}
	got := make(map[string]float64)
	for _, m := range mf.GetMetric() {
		var key string
		for _, lp := range m.GetLabel() {
			if lp.GetName() == label {
				key = lp.GetValue()
				break
			}
		}
		switch wantType {
		case dto.MetricType_COUNTER:
			got[key] = m.GetCounter().GetValue()
		case dto.MetricType_GAUGE:
			got[key] = m.GetGauge().GetValue()
		}
	}
	for k, v := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("%s{%s=%q} missing", name, label, k)
		} else if g != v {
			t.Errorf("%s{%s=%q} = %v, want %v", name, label, k, g, v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: got %d series, want %d (got=%v)", name, len(got), len(want), got)
	}
}

func scalarValue(t *testing.T, families map[string]*dto.MetricFamily, name string) float64 {
	t.Helper()
	mf, ok := families[name]
	if !ok {
		t.Fatalf("metric family %q absent", name)
	}
	if len(mf.GetMetric()) != 1 {
		t.Fatalf("%s: expected 1 series, got %d", name, len(mf.GetMetric()))
	}
	m := mf.GetMetric()[0]
	if c := m.GetCounter(); c != nil {
		return c.GetValue()
	}
	if g := m.GetGauge(); g != nil {
		return g.GetValue()
	}
	t.Fatalf("%s: neither counter nor gauge", name)
	return 0
}

func TestEnclaveMetricsCollector_NoSnapshotEmitsErrorAndZeroTimestamp(t *testing.T) {
	t.Parallel()
	signer := &fakeSigner{metricsErr: errors.New("never connected")}
	c := NewEnclaveMetricsCollector(signer, time.Hour)
	c.probe(t.Context())

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Before the first successful probe: scrape_errors_total and
	// last_scrape_timestamp_seconds (=0) are both present so staleness
	// alerts of the form `time() - X > threshold` can fire from process
	// start. The cpu/memory labeled series stay absent because they have
	// no meaningful zero value.
	got, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	families := indexFamilies(got)
	if _, ok := families["cerberus_enclave_metrics_scrape_errors_total"]; !ok {
		t.Error("expected scrape_errors_total to be present")
	}
	if v := scalarValue(t, families, "cerberus_enclave_metrics_last_scrape_timestamp_seconds"); v != 0 {
		t.Errorf("last_scrape_timestamp_seconds = %v, want 0 (no successful probe yet)", v)
	}
	for _, forbidden := range []string{
		"cerberus_enclave_cpu_seconds_total",
		"cerberus_enclave_memory_bytes",
	} {
		if _, present := families[forbidden]; present {
			t.Errorf("did not expect %s before first successful probe", forbidden)
		}
	}
}

func TestEnclaveMetricsCollector_LogsTransitions(t *testing.T) {
	// captureLogs swaps the global slog default, so this test cannot run in
	// parallel (same constraint as TestAuthMiddleware_LogClassification).
	records := captureLogs(t)

	// countLevel returns how many captured records carry msg at level.
	countLevel := func(msg string, level slog.Level) int {
		n := 0
		for _, rec := range records() {
			if rec.Message == msg && rec.Level == level {
				n++
			}
		}
		return n
	}

	signer := &fakeSigner{
		metricsResp: &messages.EnclaveMetricsResponse{
			CPU:    messages.EnclaveCPUTimes{User: 1},
			Memory: messages.EnclaveMemoryStats{TotalBytes: 1024},
		},
	}
	c := NewEnclaveMetricsCollector(signer, time.Hour)

	// Initial state: no probe yet, lastProbeFailed defaults to false.
	if c.lastProbeFailed.Load() {
		t.Fatal("lastProbeFailed should default to false")
	}

	// Successful probe from a clean start: no transition, so nothing logged.
	c.probe(t.Context())
	if c.lastProbeFailed.Load() {
		t.Fatal("lastProbeFailed should remain false after a successful probe")
	}
	if n := len(records()); n != 0 {
		t.Fatalf("clean successful probe should emit no transition logs, got %d", n)
	}

	// First failure: enclave_metrics.degraded logged once at Warn.
	signer.metricsResp = nil
	signer.metricsErr = errors.New("vsock dial: connection refused")
	c.probe(t.Context())
	if !c.lastProbeFailed.Load() {
		t.Fatal("lastProbeFailed should be true after a failed probe")
	}
	if n := countLevel("enclave_metrics.degraded", slog.LevelWarn); n != 1 {
		t.Fatalf("first failure: enclave_metrics.degraded@Warn count = %d, want 1", n)
	}

	// Sustained outage: a second consecutive failure must NOT re-log — the
	// prevFailed gate exists precisely to avoid flooding at the poll interval.
	c.probe(t.Context())
	if n := countLevel("enclave_metrics.degraded", slog.LevelWarn); n != 1 {
		t.Fatalf("sustained outage re-logged: enclave_metrics.degraded@Warn count = %d, want 1", n)
	}

	// Recovery: enclave_metrics.recovered logged once at Info.
	signer.metricsErr = nil
	signer.metricsResp = &messages.EnclaveMetricsResponse{
		CPU:    messages.EnclaveCPUTimes{User: 2},
		Memory: messages.EnclaveMemoryStats{TotalBytes: 2048},
	}
	c.probe(t.Context())
	if c.lastProbeFailed.Load() {
		t.Fatal("lastProbeFailed should be false after recovery")
	}
	if n := countLevel("enclave_metrics.recovered", slog.LevelInfo); n != 1 {
		t.Fatalf("recovery: enclave_metrics.recovered@Info count = %d, want 1", n)
	}
}
