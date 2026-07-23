package vsockwatch

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// This file implements the "detection tampering" meta-alert from
// docs/vsock-connect-detection.md §4.4: a genuine root attacker CAN disable
// either detector (stop this process, or `auditctl -D`/remove the audit
// rule), so doing so must itself be loud. Neither check here is unbeatable —
// an attacker who also kills this process outright silences both — but see
// §4.4 and §8: pairing this with an EXTERNAL dead-man's-switch heartbeat
// (Heartbeat, below) covers that case, since the absence of a heartbeat is
// judged by a system the host does not control.

// AuditRuleKey is the -k value the auditctl rule in
// docs/vsock-connect-detection.md is installed with. Used both to install
// the rule (packaging, not this package's concern) and to verify it's still
// present.
const AuditRuleKey = "cerberus_vsock_watch"

// listAuditRules runs `auditctl -l` and returns its stdout lines. Declared as
// a var so tests can substitute a fake without invoking a real auditctl
// binary (which requires CAP_AUDIT_CONTROL and won't be present in most
// dev/CI environments).
var listAuditRules = func(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "auditctl", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("vsockwatch: auditctl -l: %w", err)
	}
	return strings.Split(string(out), "\n"), nil
}

// AuditRulePresent reports whether any auditctl rule carries AuditRuleKey.
func AuditRulePresent(ctx context.Context) (bool, error) {
	lines, err := listAuditRules(ctx)
	if err != nil {
		return false, err
	}
	for _, line := range lines {
		if strings.Contains(line, "key="+AuditRuleKey) || strings.Contains(line, "-k "+AuditRuleKey) {
			return true, nil
		}
	}
	return false, nil
}

// TamperWatch periodically confirms the auditd rule is still installed,
// shipping a KindDetectorTamper alert (detector=SourceAuditd) the first time
// it observes the rule having disappeared after having previously observed
// it present. It intentionally does not alert if the rule was never observed
// present in the first place (e.g. auditd isn't installed on this host at
// all, or this watcher started before the rule was installed) — that's a
// deployment gap to catch at rollout time (docs/vsock-connect-detection.md
// §6 testing plan), not an in-flight tampering event.
type TamperWatch struct {
	Shipper  Shipper
	Interval time.Duration

	everPresent bool
}

// RunAuditRuleCheck blocks, checking on Interval until ctx is canceled. A
// check failure (e.g. auditctl not installed) is treated as "unknown", not
// as tampering — see the type doc.
func (t *TamperWatch) RunAuditRuleCheck(ctx context.Context) error {
	interval := t.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			present, err := AuditRulePresent(ctx)
			if err != nil {
				continue // auditctl unavailable/erroring; not evidence of tampering
			}
			if present {
				t.everPresent = true
				continue
			}
			if t.everPresent && t.Shipper != nil {
				if err := t.Shipper.Ship(ctx, NewTamperAlert(SourceAuditd,
					fmt.Sprintf("auditctl rule with key=%s is no longer present (was present at a prior check)", AuditRuleKey))); err != nil {
					slog.Error("vsockwatch.ship.failed", "detector", SourceAuditd, "error", err)
				}
				// Only alert once per disappearance, not on every tick,
				// so a sustained outage doesn't spam the alert channel.
				// Re-arms once the rule is observed present again.
				t.everPresent = false
			}
		}
	}
}

// Heartbeat periodically pings an external URL so a monitoring system NOT
// running on this host can alert on the heartbeat's absence — the strongest
// tamper signal available, since it doesn't depend on the (possibly
// compromised) host to self-report anything at all. See
// docs/vsock-connect-detection.md §4.4 and §8.
type Heartbeat struct {
	URL      string
	Client   httpDoer
	Interval time.Duration
}

type httpDoer interface {
	Do(ctx context.Context, url string) error
}

// Run blocks, POSTing a heartbeat on Interval until ctx is canceled. A single
// failed ping is logged (via the returned error, up to the caller) but does
// not stop the loop — a transient network blip must not stop future
// heartbeats from at least being attempted.
func (h *Heartbeat) Run(ctx context.Context, onError func(error)) error {
	interval := h.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	client := h.Client
	if client == nil {
		client = defaultHeartbeatClient{}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := client.Do(ctx, h.URL); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
