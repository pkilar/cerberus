package vsockwatch

import (
	"context"
	"fmt"
	"math"
	"syscall"
)

// This file implements an OPT-IN, best-effort reactive response, distinct
// from detection: see docs/vsock-connect-detection.md §4.5. Neither detector
// can block the connect() itself — the auditd path only observes the
// syscall after auditd has already logged it, and the eBPF path is attached
// to the sys_enter_connect tracepoint, which has no return value the kernel
// acts on. By the time a Blocker runs, the connect() (and any request the
// offending process already sent to the enclave over it) may have already
// completed. Its value is cutting off a persistent attacker's ability to
// retry, not stopping the first attempt. True prevention would require a
// kernel LSM BPF hook on security_socket_connect, which can actually deny
// the connect — tracked separately in §8 as a larger follow-up, since it
// turns this control from detective into (also) preventive and needs
// real-hardware verification this sandbox cannot provide (same caveat as
// the existing tracepoint probe, per the doc's top-of-file status note).

// Blocker attempts to stop the process behind a Blockworthy Event from doing
// further harm. Both AuditWatcher and ebpf.Watcher call this, if configured,
// only for Verdict.Blockworthy() classifications — never for Indeterminate,
// see that method's doc comment.
type Blocker interface {
	Block(ctx context.Context, ev Event) error
}

// killProcess sends sig to pid. A package-level var, not a direct
// syscall.Kill call, so tests can substitute a fake rather than sending real
// signals to real processes.
var killProcess = func(pid int, sig syscall.Signal) error {
	return syscall.Kill(pid, sig)
}

// ProcessKiller is a Blocker that sends SIGKILL to the offending PID.
// Sending a signal to a process owned by a different uid than this one
// requires CAP_KILL — granted to the packaged cerberus-vsock-watch.service
// units, since cerberus-audit deliberately runs as a different, unprivileged
// service account than ssh-cert-api or any attacker process (see
// docs/vsock-connect-detection.md §4.3).
type ProcessKiller struct{}

// maxKillablePID bounds ev.PID before it is narrowed to int for killProcess.
// Linux's own pid_max tops out at 4,194,304 (2^22) even on its most
// permissive configuration, so any value anywhere near this bound is already
// not a real PID — but the check exists for the conversion itself, not just
// plausibility: int is 32 bits on a 32-bit build, and POSIX kill(2) treats a
// *negative* pid as "send to that process group" instead of one process. An
// unchecked uint32-to-int conversion could turn a corrupted or wildly wrong
// PID into a negative int on such a build, silently escalating a targeted
// kill into a process-group-wide one. Capped at math.MaxInt32 so the
// conversion is provably safe on both 32- and 64-bit int.
const maxKillablePID = math.MaxInt32

// Block sends SIGKILL to ev.PID. PID reuse between observation and this call
// is a known, small residual risk: Linux avoids fast PID reuse but does not
// guarantee it never happens. Event.PID's doc comment already establishes
// PID is never used for identity elsewhere in this package (Classify keys on
// exe/uid/cgroup); here it is unavoidably the only handle a reactive kill
// has, since the process must already be identified by the time this runs.
func (ProcessKiller) Block(_ context.Context, ev Event) error {
	if ev.PID == 0 {
		return fmt.Errorf("vsockwatch: refusing to block: event has no pid")
	}
	if ev.PID > maxKillablePID {
		return fmt.Errorf("vsockwatch: refusing to block: pid %d exceeds a valid process id", ev.PID)
	}
	if err := killProcess(int(ev.PID), syscall.SIGKILL); err != nil {
		return fmt.Errorf("vsockwatch: killing pid %d: %w", ev.PID, err)
	}
	return nil
}
