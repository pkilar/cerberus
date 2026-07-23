package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// This file signals readiness to systemd (Type=notify, see
// packaging/*/cerberus-vsock-watch.service) once at least one configured
// detector has completed its own startup sequence — not merely once this
// process has been spawned. Under the previous Type=simple, systemd (and
// anything ordered After= this unit, e.g. cerberus-api.service) considered
// the watcher "up" the instant it forked, even though the auditd log hadn't
// been opened yet or the eBPF program hadn't attached — a real boot-time
// window where a dependent could start before detection was actually
// active. See docs/vsock-connect-detection.md §4.3.

// sdNotifyWriteTimeout bounds the notify-socket dial+write so a hung or
// misbehaving NOTIFY_SOCKET peer can't stall a detector's own startup:
// onReady runs synchronously inside AuditWatcher.Run/ebpf.Watcher.Run before
// either enters its main loop, so an unbounded call here would delay actual
// event consumption starting, not just the readiness signal. A var so tests
// can shorten it.
var sdNotifyWriteTimeout = 2 * time.Second

// sdNotifyReady sends "READY=1" to the systemd notify socket named by the
// NOTIFY_SOCKET environment variable. systemd sets this automatically for
// any unit with Type=notify; it is unset — and this is a documented no-op,
// matching sd_notify(3)'s own contract — when not running under systemd at
// all (a plain `go run`/test invocation, or a unit still using Type=simple).
// Hand-rolled rather than a new module dependency: the protocol is a single
// datagram write to a Unix socket, and every dependency in this binary is
// deliberately justified (see CLAUDE.md).
func sdNotifyReady() error {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return nil
	}

	name := socketPath
	// A leading '@' denotes Linux's abstract socket namespace in systemd's
	// own notation; the kernel expects that as a leading NUL byte in
	// sockaddr_un.sun_path, which Go's net package does not translate for us
	// — see sd_notify(3)'s "Special semantics of NOTIFY_SOCKET" section.
	if after, ok := strings.CutPrefix(name, "@"); ok {
		name = "\x00" + after
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("vsockwatch: dialing NOTIFY_SOCKET %q: %w", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetWriteDeadline(time.Now().Add(sdNotifyWriteTimeout)); err != nil {
		return fmt.Errorf("vsockwatch: setting write deadline for NOTIFY_SOCKET %q: %w", socketPath, err)
	}
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("vsockwatch: writing to NOTIFY_SOCKET %q: %w", socketPath, err)
	}
	return nil
}

// readyNotifier calls notify (sdNotifyReady in production) until it
// succeeds once, then never again. Both detectors share a single
// readyNotifier, since readiness only needs the FIRST configured detector to
// come up, matching detectorHealth.allDown()'s existing policy that
// single-detector operation is acceptable — see
// docs/vsock-connect-detection.md §4.3. Deliberately not a sync.Once: a
// failed attempt must NOT permanently give up. If the first detector's
// onReady call hits a transient NOTIFY_SOCKET failure, a sync.Once would
// silently forfeit READY=1 for the rest of the process's life even though a
// second detector's onReady call moments later could still succeed —
// leaving a perfectly healthy process to time out its systemd start job for
// no real reason.
type readyNotifier struct {
	mu   sync.Mutex
	done bool
}

// tryNotify calls notify unless a previous call already succeeded. Two
// concurrent callers can both observe done=false and both call notify — a
// harmless double-send of READY=1 (systemd treats a redundant one as a
// no-op) rather than serializing socket I/O under the lock, matching this
// package's no-I/O-under-lock convention (see vsockwatch/allowlist.go's
// uid()/cgroupID() for the same pattern).
func (r *readyNotifier) tryNotify(notify func() error) {
	r.mu.Lock()
	already := r.done
	r.mu.Unlock()
	if already {
		return
	}

	if err := notify(); err != nil {
		slog.Warn("vsockwatch.sdnotify.failed", "error", err)
		return
	}

	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
	slog.Info("vsockwatch.ready")
}
