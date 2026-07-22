// Command cerberus-vsock-watch is the detective control described in
// docs/vsock-connect-detection.md: it runs both independent detectors
// (auditd log correlation and an eBPF tracepoint probe) side by side,
// classifies every observed AF_VSOCK connect() to the enclave against an
// allowlist of the known-good ssh-cert-api process, and ships an alert for
// anything else. It also watches for the auditd rule itself disappearing
// (the "detection tampering" meta-alert, §4.4) and, if configured, pings an
// external heartbeat endpoint so a monitoring system that does not run on
// this host can notice this process going silent.
//
// This binary does NOT authorize or block signing requests — see
// docs/THREAT-MODEL.md SIGN-1 for why no host-side control fully closes that
// gap. It only makes an out-of-band signing attempt observable.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	_ "github.com/pkilar/cerberus/logging" // configures slog process-wide (LOG_FORMAT, DEBUG)
	"github.com/pkilar/cerberus/vsockwatch"
	vsockebpf "github.com/pkilar/cerberus/vsockwatch/ebpf"
)

// recoverDetector logs and swallows a panic from a detector goroutine so a
// bug in one detector cannot silently take down the whole process — and with
// it, the other, deliberately independent detectors (see
// docs/vsock-connect-detection.md §4.4). Without this, an unrecovered panic
// anywhere in the call graph is indistinguishable, from the outside, from an
// attacker successfully disabling every detector at once.
func recoverDetector(name string) {
	if r := recover(); r != nil {
		slog.Error("vsockwatch.detector.panic",
			"detector", name,
			"panic", fmt.Sprintf("%v", r),
			"stack", string(debug.Stack()))
	}
}

// Every flag below can also be set via the correspondingly-named
// CERBERUS_VSOCK_WATCH_* environment variable (flag wins if both are set),
// so the packaged systemd unit's EnvironmentFile
// (/etc/sysconfig|conf.d/cerberus-vsock-watch) can configure this service the
// same way cerberus-api.sysconfig / cerberus-signer.sysconfig do, without
// editing ExecStart.
func main() {
	exePath := flag.String("exe-path", envDefault("CERBERUS_VSOCK_WATCH_EXE_PATH", "/usr/bin/ssh-cert-api"), "expected absolute path of the legitimate ssh-cert-api binary")
	username := flag.String("username", envDefault("CERBERUS_VSOCK_WATCH_USERNAME", "cerberus"), "expected service account ssh-cert-api runs as")
	unit := flag.String("unit", envDefault("CERBERUS_VSOCK_WATCH_UNIT", "cerberus-api.service"), "systemd unit whose cgroup ssh-cert-api runs under (best-effort check)")
	auditLogPath := flag.String("audit-log", envDefault("CERBERUS_VSOCK_WATCH_AUDIT_LOG", "/var/log/audit/audit.log"), "path to the auditd log to tail")
	webhookURL := flag.String("webhook-url", envDefault("CERBERUS_VSOCK_WATCH_WEBHOOK_URL", ""), "out-of-band alert webhook URL (independent of the log pipeline)")
	heartbeatURL := flag.String("heartbeat-url", envDefault("CERBERUS_VSOCK_WATCH_HEARTBEAT_URL", ""), "external dead-man's-switch heartbeat endpoint")
	heartbeatInterval := flag.Duration("heartbeat-interval", envDurationDefault("CERBERUS_VSOCK_WATCH_HEARTBEAT_INTERVAL", 60*time.Second), "how often to ping heartbeat-url")
	tamperCheckInterval := flag.Duration("tamper-check-interval", envDurationDefault("CERBERUS_VSOCK_WATCH_TAMPER_CHECK_INTERVAL", 30*time.Second), "how often to verify the auditd rule is still installed")
	disableEBPF := flag.Bool("disable-ebpf", envBoolDefault("CERBERUS_VSOCK_WATCH_DISABLE_EBPF", false), "run only the auditd detector (for hosts where the eBPF probe can't load — see docs/vsock-connect-detection.md §7)")
	flag.Parse()

	allow := vsockwatch.NewAllowlist(*exePath, *username, *unit)

	shippers := vsockwatch.Shippers{vsockwatch.LogShipper{}}
	if *webhookURL != "" {
		shippers = append(shippers, vsockwatch.WebhookShipper{URL: *webhookURL})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("vsockwatch.starting",
		"exe_path", *exePath, "username", *username, "unit", *unit,
		"audit_log", *auditLogPath, "webhook_configured", *webhookURL != "",
		"heartbeat_configured", *heartbeatURL != "", "ebpf_enabled", !*disableEBPF)

	auditWatcher := &vsockwatch.AuditWatcher{
		Path:      *auditLogPath,
		Allowlist: allow,
		Shipper:   shippers,
	}
	go func() {
		defer recoverDetector("auditd")
		if err := auditWatcher.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("vsockwatch.auditd.stopped", "error", err)
		}
	}()

	// The eBPF detector runs independently: a failure to load/attach (e.g. an
	// unsupported kernel, or missing privilege) is logged but does not stop
	// the auditd detector — see vsockwatch/ebpf.Watcher.Run's doc comment on
	// why this is surfaced as an error rather than a panic.
	if !*disableEBPF {
		ebpfWatcher := &vsockebpf.Watcher{Allowlist: allow, Shipper: shippers}
		go func() {
			defer recoverDetector("ebpf")
			if err := ebpfWatcher.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("vsockwatch.ebpf.stopped", "error", err,
					"hint", "the auditd detector is still running; see docs/vsock-connect-detection.md §7")
			}
		}()
	}

	tamperWatch := &vsockwatch.TamperWatch{Shipper: shippers, Interval: *tamperCheckInterval}
	go func() {
		defer recoverDetector("tamperwatch")
		if err := tamperWatch.RunAuditRuleCheck(ctx); err != nil && ctx.Err() == nil {
			slog.Error("vsockwatch.tamperwatch.stopped", "error", err)
		}
	}()

	if *heartbeatURL != "" {
		hb := &vsockwatch.Heartbeat{URL: *heartbeatURL, Interval: *heartbeatInterval}
		go func() {
			defer recoverDetector("heartbeat")
			err := hb.Run(ctx, func(err error) {
				slog.Warn("vsockwatch.heartbeat.failed", "error", err)
			})
			if err != nil && ctx.Err() == nil {
				slog.Error("vsockwatch.heartbeat.stopped", "error", err)
			}
		}()
	}

	<-ctx.Done()
	slog.Info("vsockwatch.shutting_down")
}

func envDefault(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envDurationDefault(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("vsockwatch.env.invalid_duration", "key", key, "value", v, "error", err)
		return fallback
	}
	return d
}

func envBoolDefault(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("vsockwatch.env.invalid_bool", "key", key, "value", v, "error", err)
		return fallback
	}
	return b
}
