package vsockwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Kind distinguishes a vsock-connect anomaly from a "someone is tampering
// with the detector itself" meta-alert (docs/vsock-connect-detection.md
// §4.4). Both are shipped through the same Shipper set at the same
// "critical" severity.
type Kind string

const (
	KindVSockAnomaly   Kind = "vsock_connect_anomaly"
	KindDetectorTamper Kind = "detector_tampering"
)

// Alert is the structured payload shipped on every alert-worthy Event or
// detector-tampering condition. Fields are exported so it marshals cleanly
// to JSON, matching Cerberus's LOG_FORMAT=json convention elsewhere in the
// codebase (logging/logging.go).
type Alert struct {
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	Kind     Kind      `json:"kind"`
	Reason   string    `json:"reason"`
	Detector Source    `json:"detector,omitempty"`

	// Event fields, flattened rather than nested, so a log-line grep for
	// e.g. "uid=0" works without a JSON path query. Zero-valued when the
	// alert isn't about a specific Event (e.g. KindDetectorTamper).
	PID      uint32 `json:"pid,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	GID      uint32 `json:"gid,omitempty"`
	Comm     string `json:"comm,omitempty"`
	Exe      string `json:"exe,omitempty"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
}

// NewAnomalyAlert builds an Alert for an Anomalous or Indeterminate
// classification of ev.
func NewAnomalyAlert(ev Event, cls Classification) Alert {
	return Alert{
		Time:     time.Now(),
		Severity: "critical",
		Kind:     KindVSockAnomaly,
		Reason:   fmt.Sprintf("%s: %s", cls.Verdict, cls.Reason),
		Detector: ev.Source,
		PID:      ev.PID,
		UID:      ev.UID,
		GID:      ev.GID,
		Comm:     ev.Comm,
		Exe:      ev.Exe,
		CgroupID: ev.CgroupID,
	}
}

// NewTamperAlert builds a KindDetectorTamper alert — used when one of the two
// detectors (auditd rule, eBPF watcher) is observed to have stopped or been
// removed. See docs/vsock-connect-detection.md §4.4: this alert exists
// precisely because a genuine root attacker CAN disable either detector, so
// doing so must itself be loud.
func NewTamperAlert(detector Source, reason string) Alert {
	return Alert{
		Time:     time.Now(),
		Severity: "critical",
		Kind:     KindDetectorTamper,
		Reason:   reason,
		Detector: detector,
	}
}

// Shipper delivers an Alert somewhere. Multiple Shippers are combined via
// Shippers so that no single delivery channel is a single point of failure —
// see docs/vsock-connect-detection.md §4.2 ("send-alert-first, log-second").
type Shipper interface {
	Ship(ctx context.Context, a Alert) error
}

// Shippers fires every configured Shipper for each Alert, independently: one
// failing does not stop the others from being attempted, and all errors are
// joined and returned so the caller can log them, rather than one channel's
// outage silently swallowing an alert on every other channel too.
type Shippers []Shipper

func (s Shippers) Ship(ctx context.Context, a Alert) error {
	var errs []error
	for _, shipper := range s {
		if err := shipper.Ship(ctx, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LogShipper writes the Alert as a structured slog record. This is the
// lowest-common-denominator channel — always available, but on a fully
// compromised host its destination (local disk, or a forwarder process) can
// itself be tampered with, which is why it should never be the only Shipper
// configured in production (pair with WebhookShipper or equivalent).
type LogShipper struct {
	Logger *slog.Logger
}

func (l LogShipper) Ship(_ context.Context, a Alert) error {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("vsockwatch.alert",
		"kind", a.Kind,
		"severity", a.Severity,
		"reason", a.Reason,
		"detector", a.Detector,
		"pid", a.PID,
		"uid", a.UID,
		"gid", a.GID,
		"comm", a.Comm,
		"exe", a.Exe,
		"cgroup_id", a.CgroupID,
	)
	return nil
}

// WebhookShipper POSTs the Alert as JSON to URL — intended for an external,
// out-of-band alert channel (PagerDuty/SNS/generic webhook) that does not sit
// behind the same local log pipeline a host-resident attacker might also
// control. Per docs/vsock-connect-detection.md §4.2, this is fired in
// parallel with (not instead of) the log channel, and should be attempted
// before local acknowledgment.
type WebhookShipper struct {
	URL    string
	Client *http.Client
}

// webhookTimeout bounds the default client's request when Client is nil. Both
// detector loops call Ship synchronously for every alert-worthy event, so a
// webhook peer that accepts a connection but never responds must not be able
// to block a detector from consuming any further events indefinitely. A var,
// not a const, so tests can shorten it rather than waiting out the default.
var webhookTimeout = 10 * time.Second

func (w WebhookShipper) Ship(ctx context.Context, a Alert) error {
	if w.URL == "" {
		return fmt.Errorf("vsockwatch: WebhookShipper has no URL configured")
	}
	body, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("vsockwatch: marshal alert: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vsockwatch: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: webhookTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vsockwatch: webhook delivery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vsockwatch: webhook returned status %d", resp.StatusCode)
	}
	return nil
}
