package vsockwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
	// KindVSockLSMBlock is a would-deny (monitor mode) or actually-denied
	// (enforce mode) event from the preventive LSM gate (§4.6). Deliberately
	// a DISTINCT Kind from KindVSockAnomaly: the LSM gate's cgroup-only
	// in-kernel decision is an architecturally coarser signal than the
	// detective path's full exe/uid/cgroup classification, and conflating
	// them under one Kind would mislead anyone triaging alerts.
	KindVSockLSMBlock Kind = "vsock_lsm_block"
	// KindLSMEnforcementDown fires when the preventive LSM gate was explicitly
	// requested to enforce (--lsm-enforce) but is no longer running — whether
	// it never attached at startup, or stopped later. Distinct from both
	// KindDetectorTamper (an already-running detector being interfered with)
	// and KindVSockLSMBlock (a specific connect event): this alert means "the
	// blocking guarantee the operator explicitly asked for is not currently
	// active," which is a materially different and higher-stakes condition
	// than either — see cmd/cerberus-vsock-watch/main.go's wiring.
	KindLSMEnforcementDown Kind = "lsm_enforcement_down"
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

	// LSMMode and LSMDenied are set only on a KindVSockLSMBlock alert:
	// LSMMode is "monitor" or "enforce" (which mode the gate was running in
	// when this event fired), LSMDenied reports whether the connect() was
	// actually denied (always false in monitor mode). omitempty on both
	// means zero shape change to every other alert kind's JSON.
	LSMMode   string `json:"lsm_mode,omitempty"`
	LSMDenied bool   `json:"lsm_denied,omitempty"`
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

// NewLSMBlockAlert builds an Alert for a cgroup-mismatch event from the
// preventive LSM gate. cls comes from calling Allowlist.Classify(ev) purely
// for alert-message enrichment (a rich Reason using the existing
// Expected/Anomalous/Indeterminate vocabulary) — it is NEVER used for the
// in-kernel allow/deny decision itself, which is cgroup-only (see
// vsockwatch/ebpf/lsm.go and docs/vsock-connect-detection.md §4.6). mode is
// "monitor" or "enforce"; denied reports whether this specific event was
// actually blocked (always false in monitor mode, by construction).
func NewLSMBlockAlert(ev Event, cls Classification, mode string, denied bool) Alert {
	return Alert{
		Time:      time.Now(),
		Severity:  "critical",
		Kind:      KindVSockLSMBlock,
		Reason:    fmt.Sprintf("lsm cgroup mismatch (%s): %s", cls.Verdict, cls.Reason),
		Detector:  ev.Source,
		PID:       ev.PID,
		UID:       ev.UID,
		GID:       ev.GID,
		Comm:      ev.Comm,
		Exe:       ev.Exe,
		CgroupID:  ev.CgroupID,
		LSMMode:   mode,
		LSMDenied: denied,
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

// NewLSMEnforcementDownAlert builds a KindLSMEnforcementDown alert — used
// when --lsm-enforce was explicitly requested but the LSM gate is not
// currently running (see cmd/cerberus-vsock-watch/main.go). reason should
// explain why (e.g. the underlying LSMGuard.Run error).
func NewLSMEnforcementDownAlert(reason string) Alert {
	return Alert{
		Time:     time.Now(),
		Severity: "critical",
		Kind:     KindLSMEnforcementDown,
		Reason:   reason,
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
		"lsm_mode", a.LSMMode,
		"lsm_denied", a.LSMDenied,
	)
	return nil
}

// WebhookFormat selects the JSON shape WebhookShipper sends. Slack's
// Incoming Webhooks API (and Slack-compatible receivers, e.g. Mattermost)
// reject the raw Alert JSON — they require a payload with a "text" field —
// so posting an Alert unmodified to a Slack webhook URL fails outright
// (Slack returns a 400 "no_text" body), silently dropping every alert.
type WebhookFormat string

const (
	// WebhookFormatAuto detects the shape from URL: a hooks.slack.com URL
	// gets WebhookFormatSlack, anything else gets WebhookFormatGeneric. The
	// zero value, so existing configuration (URL only, no Format) keeps
	// working exactly as before for non-Slack receivers.
	WebhookFormatAuto WebhookFormat = ""
	// WebhookFormatSlack sends {"text": "..."}, Slack's Incoming Webhook
	// contract. Also selected automatically for hooks.slack.com URLs.
	WebhookFormatSlack WebhookFormat = "slack"
	// WebhookFormatGeneric sends the Alert struct as JSON (PagerDuty/SNS/a
	// custom receiver).
	WebhookFormatGeneric WebhookFormat = "generic"
)

// WebhookShipper POSTs the Alert to URL — intended for an external,
// out-of-band alert channel (Slack, PagerDuty, SNS, a generic webhook) that
// does not sit behind the same local log pipeline a host-resident attacker
// might also control. Per docs/vsock-connect-detection.md §4.2, this is
// fired in parallel with (not instead of) the log channel, and should be
// attempted before local acknowledgment.
type WebhookShipper struct {
	URL    string
	Client *http.Client
	// Format overrides auto-detection — set WebhookFormatSlack for a
	// Slack-compatible receiver whose URL isn't literally hooks.slack.com
	// (e.g. a Mattermost incoming webhook, or an internal relay in front of
	// Slack), or WebhookFormatGeneric to force the raw Alert JSON even
	// against a hooks.slack.com URL. Leave as WebhookFormatAuto (the zero
	// value) for the common case.
	Format WebhookFormat
}

// webhookTimeout bounds the default client's request when Client is nil.
// AsyncShipper (vsockwatch/ship_async.go) delivers alerts on its own
// goroutine, decoupled from the detectors' event-consumption loops, but that
// goroutine still calls Ship synchronously for each queued alert — so a
// webhook peer that accepts a connection but never responds must not be able
// to block delivery of any further queued alerts indefinitely. A var, not a
// const, so tests can shorten it rather than waiting out the default.
var webhookTimeout = 10 * time.Second

func (w WebhookShipper) Ship(ctx context.Context, a Alert) error {
	if w.URL == "" {
		return fmt.Errorf("vsockwatch: WebhookShipper has no URL configured")
	}

	format := w.Format
	if format == WebhookFormatAuto {
		format = WebhookFormatGeneric
		if isSlackWebhookURL(w.URL) {
			format = WebhookFormatSlack
		}
	}

	var payload any = a
	if format == WebhookFormatSlack {
		payload = slackPayload(a)
	}
	body, err := json.Marshal(payload)
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

// isSlackWebhookURL reports whether rawURL's host is Slack's Incoming
// Webhook endpoint. An unparseable URL is treated as not-Slack; WebhookShipper
// will still attempt delivery and let the HTTP client surface the real error.
func isSlackWebhookURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Hostname() == "hooks.slack.com"
}

// slackWebhookPayload is Slack's Incoming Webhook message contract: a "text"
// field is required (mrkdwn formatting is on by default for incoming
// webhooks), everything else is optional and not needed here.
type slackWebhookPayload struct {
	Text string `json:"text"`
}

// slackPayload renders a as a Slack mrkdwn message. Fields that can contain
// attacker-influenced content (Reason, Comm, Exe — an Anomalous event's exe
// path or TASK_COMM come directly from the misbehaving process) are escaped
// per Slack's formatting rules before being embedded, so a hostile process
// can't inject Slack markup or break the message structure.
func slackPayload(a Alert) slackWebhookPayload {
	var b strings.Builder
	fmt.Fprintf(&b, ":rotating_light: *%s* — `%s`\n", strings.ToUpper(a.Severity), a.Kind)
	fmt.Fprintf(&b, "*Reason:* %s\n", slackEscape(a.Reason))
	if a.Detector != "" {
		fmt.Fprintf(&b, "*Detector:* %s\n", a.Detector)
	}
	if a.PID != 0 || a.UID != 0 || a.GID != 0 {
		fmt.Fprintf(&b, "*PID:* %d  *UID:* %d  *GID:* %d\n", a.PID, a.UID, a.GID)
	}
	if a.Comm != "" {
		fmt.Fprintf(&b, "*Comm:* `%s`\n", slackEscape(a.Comm))
	}
	if a.Exe != "" {
		fmt.Fprintf(&b, "*Exe:* `%s`\n", slackEscape(a.Exe))
	}
	if a.CgroupID != 0 {
		fmt.Fprintf(&b, "*Cgroup ID:* %d\n", a.CgroupID)
	}
	if a.LSMMode != "" {
		fmt.Fprintf(&b, "*LSM mode:* %s  *Denied:* %t\n", a.LSMMode, a.LSMDenied)
	}
	fmt.Fprintf(&b, "*Time:* %s", a.Time.Format(time.RFC3339))
	return slackWebhookPayload{Text: b.String()}
}

// slackEscape applies Slack's required mrkdwn escaping
// (https://api.slack.com/reference/surfaces/formatting#escaping) so
// untrusted text can't break the message structure or be mistaken for
// Slack markup.
func slackEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}
