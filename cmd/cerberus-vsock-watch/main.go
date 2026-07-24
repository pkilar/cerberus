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
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/pkilar/cerberus/logging" // configures slog process-wide (LOG_FORMAT, DEBUG)
	"github.com/pkilar/cerberus/version"
	"github.com/pkilar/cerberus/vsockwatch"
	vsockebpf "github.com/pkilar/cerberus/vsockwatch/ebpf"
)

// recoverDetector logs and swallows a panic from a detector goroutine so a
// bug in one detector cannot silently take down the whole process — and with
// it, the other, deliberately independent detectors (see
// docs/vsock-connect-detection.md §4.4). Without this, an unrecovered panic
// anywhere in the call graph is indistinguishable, from the outside, from an
// attacker successfully disabling every detector at once. onPanic, if
// non-nil, runs after logging — auditd/eBPF pass a callback that marks the
// detector down and checks whether every detector is now gone.
func recoverDetector(name string, onPanic func()) {
	if r := recover(); r != nil {
		slog.Error("vsockwatch.detector.panic",
			"detector", name,
			"panic", fmt.Sprintf("%v", r),
			"stack", string(debug.Stack()))
		if onPanic != nil {
			onPanic()
		}
	}
}

// detectorHealth tracks whether the two independent vsock-connect detectors
// are still running. A process that keeps running (and heartbeating) after
// every detector has stopped is providing no detection at all while
// reporting itself healthy — see run()'s use of allDown to fail loudly
// instead.
type detectorHealth struct {
	mu       sync.Mutex
	auditd   bool
	ebpf     bool
	ebpfUsed bool // false when started with --disable-ebpf: eBPF was never a detector to lose.
}

func (h *detectorHealth) markAuditdDown() {
	h.mu.Lock()
	h.auditd = true
	h.mu.Unlock()
}

func (h *detectorHealth) markEBPFDown() {
	h.mu.Lock()
	h.ebpf = true
	h.mu.Unlock()
}

func (h *detectorHealth) allDown() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ebpfUsed {
		return h.auditd && h.ebpf
	}
	return h.auditd
}

// Every flag below can also be set via the correspondingly-named
// CERBERUS_VSOCK_WATCH_* environment variable (flag wins if both are set),
// so the packaged systemd unit's EnvironmentFile
// (/etc/sysconfig|conf.d/cerberus-vsock-watch) can configure this service the
// same way cerberus-api.sysconfig / cerberus-signer.sysconfig do, without
// editing ExecStart.
func main() {
	os.Exit(run())
}

func run() int {
	exePath := flag.String("exe-path", envDefault("CERBERUS_VSOCK_WATCH_EXE_PATH", "/usr/bin/ssh-cert-api"), "expected absolute path of the legitimate ssh-cert-api binary")
	username := flag.String("username", envDefault("CERBERUS_VSOCK_WATCH_USERNAME", "cerberus"), "expected service account ssh-cert-api runs as")
	unit := flag.String("unit", envDefault("CERBERUS_VSOCK_WATCH_UNIT", "cerberus-api.service"), "systemd unit whose cgroup ssh-cert-api runs under (best-effort check)")
	auditLogPath := flag.String("audit-log", envDefault("CERBERUS_VSOCK_WATCH_AUDIT_LOG", "/var/log/audit/audit.log"), "path to the auditd log to tail")
	webhookURL := flag.String("webhook-url", envDefault("CERBERUS_VSOCK_WATCH_WEBHOOK_URL", ""), "out-of-band alert webhook URL (independent of the log pipeline); Slack Incoming Webhook URLs (hooks.slack.com) are auto-detected and formatted correctly")
	webhookFormat := flag.String("webhook-format", envDefault("CERBERUS_VSOCK_WATCH_WEBHOOK_FORMAT", ""), `webhook payload format: "" (auto-detect from URL, default), "slack" (force Slack's {"text": ...} shape — use for a Slack-compatible receiver whose URL isn't hooks.slack.com, e.g. Mattermost), or "generic" (force the raw Alert JSON)`)
	heartbeatURL := flag.String("heartbeat-url", envDefault("CERBERUS_VSOCK_WATCH_HEARTBEAT_URL", ""), "external dead-man's-switch heartbeat endpoint")
	heartbeatInterval := flag.Duration("heartbeat-interval", envDurationDefault("CERBERUS_VSOCK_WATCH_HEARTBEAT_INTERVAL", 60*time.Second), "how often to ping heartbeat-url")
	tamperCheckInterval := flag.Duration("tamper-check-interval", envDurationDefault("CERBERUS_VSOCK_WATCH_TAMPER_CHECK_INTERVAL", 30*time.Second), "how often to verify the auditd rule is still installed")
	disableEBPF := flag.Bool("disable-ebpf", envBoolDefault("CERBERUS_VSOCK_WATCH_DISABLE_EBPF", false), "run only the auditd detector (for hosts where the eBPF probe can't load — see docs/vsock-connect-detection.md §7)")
	block := flag.Bool("block", envBoolDefault("CERBERUS_VSOCK_WATCH_BLOCK", false), "opt-in: best-effort SIGKILL the offending process on a confirmed Anomalous classification (NOT true prevention — see docs/vsock-connect-detection.md §4.5/§7; requires CAP_KILL)")
	lsmMonitor := flag.Bool("lsm-monitor", envBoolDefault("CERBERUS_VSOCK_WATCH_LSM_MONITOR", false), "opt-in: load the preventive LSM gate (socket_connect hook) in log-only mode — never denies a connect() by itself; see docs/vsock-connect-detection.md §4.6")
	lsmEnforce := flag.Bool("lsm-enforce", envBoolDefault("CERBERUS_VSOCK_WATCH_LSM_ENFORCE", false), "actually deny a cgroup-mismatched connect() via the LSM gate (NOT exe/uid-checked — narrower than --block; requires --lsm-monitor; run --lsm-monitor alone across a real cerberus-api.service restart first — see docs/vsock-connect-detection.md §4.6)")
	lsmAPISlice := flag.String("api-slice", envDefault("CERBERUS_VSOCK_WATCH_API_SLICE", ""), "the dedicated systemd slice unit containing ONLY cerberus-api.service (e.g. \"cerberus-api.slice\") — required when --lsm-enforce is set; sharing this slice with any other service weakens the LSM gate's identity check, see docs/vsock-connect-detection.md §4.6. Defaults to <unit base name>.slice derived from --unit if not set")
	lsmEnforceStateFile := flag.String("lsm-enforce-state-file", envDefault("CERBERUS_VSOCK_WATCH_LSM_ENFORCE_STATE_FILE", "/run/cerberus-vsock-watch/lsm-enforce"), `runtime toggle for the LSM gate's enforce mode: contents ("true"/"false") are polled every --lsm-poll-interval and override --lsm-enforce without a restart; missing/malformed content leaves the mode unchanged`)
	lsmPollInterval := flag.Duration("lsm-poll-interval", envDurationDefault("CERBERUS_VSOCK_WATCH_LSM_POLL_INTERVAL", 250*time.Millisecond), "how often the LSM gate's --lsm-enforce-state-file runtime toggle is re-checked (the cgroup pin is resolved once at startup, not polled)")
	showVersion := flag.Bool("V", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Version)
		return 0
	}

	if err := validateLSMFlags(*lsmMonitor, *lsmEnforce); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	apiSlice, err := deriveAPISlice(*lsmAPISlice, *unit, *lsmMonitor)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	allow := vsockwatch.NewAllowlist(*exePath, *username, *unit)

	format, err := parseWebhookFormat(*webhookFormat)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	shippers := vsockwatch.Shippers{vsockwatch.LogShipper{}}
	if *webhookURL != "" {
		shippers = append(shippers, vsockwatch.WebhookShipper{URL: *webhookURL, Format: format})
	}

	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	// A separately cancelable child of the signal context: fatalShutdown
	// below triggers the same shutdown path a SIGTERM would, from inside a
	// detector goroutine, once every detector has stopped.
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	// shipperCtx is deliberately separate from ctx and canceled strictly
	// AFTER every producer goroutine (auditd, eBPF, tamperwatch, heartbeat --
	// tracked by producersWG below) has fully returned. AsyncShipper.Run's
	// shutdown drain (ship_async.go) is only race-free if nothing can enqueue
	// a new alert while it's deciding the queue is empty; phasing shutdown
	// this way -- producers join first, only then is the shipper told to
	// stop -- guarantees that, rather than the shipper racing producers that
	// observe the same cancellation at the same time.
	shipperCtx, cancelShipper := context.WithCancel(context.Background())
	defer cancelShipper()

	slog.Info("vsockwatch.starting",
		"exe_path", *exePath, "username", *username, "unit", *unit,
		"audit_log", *auditLogPath, "webhook_configured", *webhookURL != "",
		"heartbeat_configured", *heartbeatURL != "", "ebpf_enabled", !*disableEBPF,
		"block_enabled", *block, "lsm_monitor_enabled", *lsmMonitor, "lsm_enforce_enabled", *lsmEnforce)

	// blocker stays nil (the interface zero value) when --block is unset, so
	// AuditWatcher/ebpf.Watcher's "if w.Blocker != nil" checks disable the
	// reactive-kill response by default. See docs/vsock-connect-detection.md
	// §4.5 for why this is opt-in and not true prevention.
	var blocker vsockwatch.Blocker
	if *block {
		blocker = vsockwatch.ProcessKiller{}
	}

	// asyncShipper decouples every per-event Ship call (auditd, eBPF,
	// tamperwatch) from actual delivery, so a slow or hung webhook peer can
	// never stall the goroutine reading events -- for the eBPF path, that
	// stall would otherwise let the kernel-side ring buffer silently drop
	// events with no consumer draining it. See vsockwatch/ship_async.go.
	// fatalShutdown's own final alert deliberately bypasses this queue (see
	// below) for an immediate, synchronous best-effort delivery attempt at
	// the moment of process death, not one that could still be sitting
	// queued behind whatever asyncShipper.Run is concurrently tearing down.
	// Runs on shipperCtx (not ctx) and is joined via shipperWG, both for the
	// phased-shutdown reason explained at shipperCtx's declaration above.
	// recoverDetector's onPanic is deliberately nil, unlike auditd/eBPF: a
	// dead shipper means alerts stop being delivered, not that detection
	// itself has stopped, so it does not feed detectorHealth/fatalShutdown.
	// Each detector's own Ship() call still logs a queue-full error once the
	// dead shipper's queue backs up (vsockwatch/ship_async.go), so this
	// degrades to "alerts silently pile up and get individually logged as
	// dropped," not a fully silent failure -- but there is no equivalent of
	// "all detectors down" for "delivery is down" today.
	asyncShipper := vsockwatch.NewAsyncShipper(shippers, 0)
	var shipperWG sync.WaitGroup
	shipperWG.Go(func() {
		defer recoverDetector("shipper", nil)
		_ = asyncShipper.Run(shipperCtx)
	})

	// onReady fires the systemd sd_notify READY=1 signal (Type=notify, see
	// packaging/*/cerberus-vsock-watch.service) the first time EITHER
	// enabled detector reports its own successful startup -- deliberately OR
	// semantics, mirroring detectorHealth.allDown()'s existing policy that
	// single-detector operation is acceptable rather than fatal. Waiting for
	// BOTH would mean a host where eBPF can never attach (unsupported
	// kernel, no BPF LSM) and --disable-ebpf wasn't set would never signal
	// ready at all, potentially blocking cerberus-api.service from starting
	// forever if it's ordered After= this unit -- a materially worse outcome
	// than today's graceful auditd-only degradation. readyGate (unlike a
	// sync.Once) retries on a later call if an earlier one's notify() failed
	// transiently -- see readyNotifier's doc comment.
	readyGate := &readyNotifier{}
	onReady := func() { readyGate.tryNotify(sdNotifyReady) }

	// producersWG tracks every detector/monitor goroutine below (auditd,
	// eBPF, tamperwatch, heartbeat) -- NOT the shipper, which has its own
	// shipperWG and later lifecycle. run() waits for producersWG before
	// telling the shipper to stop, and waits for shipperWG before returning,
	// so os.Exit (main()'s caller) never fires while either is still
	// mid-flight -- see shipperCtx's doc comment for why the ordering
	// between the two matters.
	var producersWG sync.WaitGroup

	health := &detectorHealth{ebpfUsed: !*disableEBPF}
	exitCode := 0
	var fatalOnce sync.Once

	// fatalShutdown fires once every configured detector has stopped: this
	// process would otherwise keep running — and keep heartbeating — while
	// providing no detection at all, which is indistinguishable from an
	// attacker having successfully blinded the system. Shipping the alert
	// before cancel() gives it a chance to actually go out (bounded by
	// WebhookShipper's client timeout) before shutdown proceeds; the
	// packaged unit's Restart=on-failure brings the process back.
	fatalShutdown := func() {
		if ctx.Err() != nil || !health.allDown() {
			return
		}
		// ctx is being torn down right here (cancel() below); the shutdown alert
		// deliberately uses an independent context (context.Background(), inside
		// the closure) so it still has a chance to ship instead of being killed
		// by the same cancellation it's reporting.
		fatalOnce.Do(func() { //nolint:contextcheck
			slog.Error("vsockwatch.all_detectors_down",
				"hint", "no vsock-connect detection remains active; exiting for the process supervisor to restart")
			_ = shippers.Ship(context.Background(), vsockwatch.NewTamperAlert("",
				"all configured vsock-connect detectors (auditd, eBPF) have stopped; no detection is active"))
			exitCode = 1
			cancel()
		})
	}

	// lsmEnforceFatal is a SEPARATE fatal path from fatalShutdown above,
	// deliberately not folded into health/fatalShutdown's "both detectors
	// down" condition: whether the LSM gate is enforcing is orthogonal to
	// whether auditd/eBPF detection is up, so gating this on health.allDown()
	// would mean it never fires while detection is otherwise healthy --
	// exactly the "silently healthy while enforcement is broken" gap this
	// exists to close. Only used when --lsm-enforce was explicitly
	// requested (see the LSM wiring below): a bare --lsm-monitor failure
	// stays log-only, matching eBPF's existing graceful-degradation
	// treatment, since monitor mode carries no operator expectation of an
	// actual blocking guarantee.
	var lsmEnforceFatalOnce sync.Once
	lsmEnforceFatal := func(reason string) {
		if ctx.Err() != nil {
			return
		}
		lsmEnforceFatalOnce.Do(func() { //nolint:contextcheck
			slog.Error("vsockwatch.lsm.enforcement_down",
				"reason", reason,
				"hint", "--lsm-enforce was explicitly requested; exiting so the supervisor can retry rather than silently running without the requested preventive control")
			_ = shippers.Ship(context.Background(), vsockwatch.NewLSMEnforcementDownAlert(reason))
			exitCode = 1
			cancel()
		})
	}

	auditWatcher := &vsockwatch.AuditWatcher{
		Path:      *auditLogPath,
		Allowlist: allow,
		Shipper:   asyncShipper,
		Blocker:   blocker,
	}
	producersWG.Go(func() {
		defer recoverDetector("auditd", func() {
			health.markAuditdDown()
			fatalShutdown()
		})
		if err := auditWatcher.Run(ctx, onReady); err != nil && ctx.Err() == nil {
			slog.Error("vsockwatch.auditd.stopped", "error", err)
		}
		health.markAuditdDown()
		fatalShutdown()
	})

	// The eBPF detector runs independently: a failure to load/attach (e.g. an
	// unsupported kernel, or missing privilege) is logged but does not stop
	// the auditd detector — see vsockwatch/ebpf.Watcher.Run's doc comment on
	// why this is surfaced as an error rather than a panic. If auditd is (or
	// later becomes) down too, fatalShutdown treats the pair as exhausted.
	if !*disableEBPF {
		ebpfWatcher := &vsockebpf.Watcher{Allowlist: allow, Shipper: asyncShipper, Blocker: blocker}
		producersWG.Go(func() {
			defer recoverDetector("ebpf", func() {
				health.markEBPFDown()
				fatalShutdown()
			})
			if err := ebpfWatcher.Run(ctx, onReady); err != nil && ctx.Err() == nil {
				slog.Error("vsockwatch.ebpf.stopped", "error", err,
					"hint", "the auditd detector is still running; see docs/vsock-connect-detection.md §7")
			}
			health.markEBPFDown()
			fatalShutdown()
		})
	}

	// The preventive LSM gate is fully independent of the two detectors
	// above: a different program type, a different attach mechanism, and
	// deliberately NOT wired into the SHARED detectorHealth/fatalShutdown or
	// readyGate, since its narrower (cgroup-only) scope makes it a poor
	// proxy for either "is detection still active" or "has this process
	// finished starting up" -- see lsmEnforceFatal's doc comment above for
	// why folding it into health.allDown() would be actively wrong (it would
	// never fire while auditd/eBPF stay healthy, which is exactly the
	// scenario where an operator most needs to know their explicitly
	// requested --lsm-enforce isn't actually running).
	//
	// Instead: a bare --lsm-monitor failure is log-only (recoverDetector's
	// onPanic is nil, matching tamperwatch/heartbeat) -- it's an optional
	// detective enhancement, and this codebase's whole design philosophy is
	// to degrade gracefully rather than crash-loop over an optional piece
	// (see the Requires=-rejection rationale in packaging/*/cerberus-vsock-watch.service).
	// But when --lsm-enforce was ALSO explicitly requested, the operator
	// asked for an actual blocking guarantee, not just observability -- if
	// LSMGuard.Run ever returns (fails to attach at startup, or errors out
	// later) or panics, lsmEnforceFatal ships a critical alert and exits the
	// whole process so the supervisor restarts it, rather than silently
	// continuing to report healthy with no enforcement active.
	if *lsmMonitor {
		lsmGuard := &vsockebpf.LSMGuard{
			Allowlist:        allow,
			Shipper:          asyncShipper,
			Blocker:          blocker,
			Enforce:          *lsmEnforce,
			APISlice:         apiSlice,
			PollInterval:     *lsmPollInterval,
			EnforceStatePath: *lsmEnforceStateFile,
		}
		producersWG.Go(func() {
			defer recoverDetector("lsm", func() {
				if *lsmEnforce {
					lsmEnforceFatal("panic in LSM gate goroutine")
				}
			})
			if err := lsmGuard.Run(ctx, nil); err != nil && ctx.Err() == nil {
				slog.Error("vsockwatch.lsm.stopped", "error", err)
				if *lsmEnforce {
					lsmEnforceFatal(err.Error())
				}
			}
		})
	}

	tamperWatch := &vsockwatch.TamperWatch{Shipper: asyncShipper, Interval: *tamperCheckInterval}
	producersWG.Go(func() {
		defer recoverDetector("tamperwatch", nil)
		if err := tamperWatch.RunAuditRuleCheck(ctx); err != nil && ctx.Err() == nil {
			slog.Error("vsockwatch.tamperwatch.stopped", "error", err)
		}
	})

	if *heartbeatURL != "" {
		hb := &vsockwatch.Heartbeat{URL: *heartbeatURL, Interval: *heartbeatInterval}
		producersWG.Go(func() {
			defer recoverDetector("heartbeat", nil)
			err := hb.Run(ctx, func(err error) {
				slog.Warn("vsockwatch.heartbeat.failed", "error", err)
			})
			if err != nil && ctx.Err() == nil {
				slog.Error("vsockwatch.heartbeat.stopped", "error", err)
			}
		})
	}

	<-ctx.Done()
	slog.Info("vsockwatch.shutting_down")
	// Phased shutdown: wait for every producer to fully return (so nothing
	// can call Ship() again), only THEN tell the shipper to stop and wait
	// for it -- see shipperCtx's doc comment above for why this ordering is
	// what makes AsyncShipper's shutdown drain race-free.
	producersWG.Wait()
	cancelShipper()
	shipperWG.Wait()
	return exitCode
}

// validateLSMFlags enforces that --lsm-enforce is never accepted without
// --lsm-monitor -- a hard startup error, not a silent auto-promotion. This
// is the structural half of the monitor-first rollout: an operator must
// explicitly opt into loading the LSM gate at all (--lsm-monitor) before
// enforcement can even be considered, and is expected to have watched it run
// clean (see docs/vsock-connect-detection.md §4.6) before ever adding
// --lsm-enforce.
//
// This used to unconditionally refuse --lsm-enforce regardless of
// --lsm-monitor, because the cgroup pin was fundamentally unable to win its
// restart race no matter what an operator did. That's fixed now (the pin is
// resolved once against a stable ancestor slice, not polled against
// ssh-cert-api's own ever-recreated leaf cgroup -- see
// docs/vsock-connect-detection.md §4.6's history) -- monitor-first is
// restored as a cheap operational habit, not a workaround for a structural
// bug.
func validateLSMFlags(monitor, enforce bool) error {
	if enforce && !monitor {
		return fmt.Errorf("vsockwatch: --lsm-enforce requires --lsm-monitor (run --lsm-monitor alone first and confirm it logs cleanly across a real cerberus-api.service restart — see docs/vsock-connect-detection.md §4.6)")
	}
	return nil
}

// deriveAPISlice resolves the effective --api-slice value: the explicit flag
// if set, otherwise <unit base name>.slice derived from --unit (stripping a
// trailing ".service"). The empty-derivation check must happen on the base
// name BEFORE ".slice" is appended -- appending a non-empty literal suffix
// guarantees the concatenated result is never "", so checking apiSlice == ""
// afterwards can never fire, silently letting a misconfigured --unit produce
// the nonsensical slice name ".slice" instead of failing fast. When
// --lsm-monitor is set and the base name is empty, that's returned as an
// error instead. See docs/vsock-connect-detection.md §4.6.
func deriveAPISlice(apiSliceFlag, unit string, lsmMonitor bool) (string, error) {
	if apiSliceFlag != "" {
		return apiSliceFlag, nil
	}
	base := strings.TrimSuffix(unit, ".service")
	if lsmMonitor && base == "" {
		return "", fmt.Errorf("vsockwatch: --api-slice could not be derived from --unit; set it explicitly")
	}
	return base + ".slice", nil
}

// parseWebhookFormat validates the --webhook-format/CERBERUS_VSOCK_WATCH_WEBHOOK_FORMAT
// value. Rejecting an unrecognized value at startup (rather than silently
// falling back to auto-detect) catches a typo like "slcak" before it causes
// alerts to go out malformed.
func parseWebhookFormat(v string) (vsockwatch.WebhookFormat, error) {
	switch vsockwatch.WebhookFormat(v) {
	case vsockwatch.WebhookFormatAuto, vsockwatch.WebhookFormatSlack, vsockwatch.WebhookFormatGeneric:
		return vsockwatch.WebhookFormat(v), nil
	default:
		return "", fmt.Errorf("vsockwatch: invalid --webhook-format %q (want \"\", \"slack\", or \"generic\")", v)
	}
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
