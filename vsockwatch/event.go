package vsockwatch

import "time"

// Source identifies which detector observed an Event. Running both keeps the
// two code paths independent (see docs/vsock-connect-detection.md §3), so an
// attacker who disables one still leaves a trail in the other.
type Source string

const (
	SourceEBPF   Source = "ebpf"
	SourceAuditd Source = "auditd"
)

// Event is one observed AF_VSOCK connect() to the enclave's (CID, port),
// normalized from whichever detector produced it.
type Event struct {
	Time Time
	// PID is the connecting process's pid at the time of connect. Processes
	// are short-lived and PIDs are reused, so PID alone is never treated as
	// identity — Exe/UID/CgroupID are what Classify actually keys on.
	PID uint32
	UID uint32
	GID uint32
	// Comm is the kernel's TASK_COMM (up to 16 bytes, possibly truncated) —
	// informational only, never used for the allow/deny decision (trivially
	// spoofable via prctl(PR_SET_NAME) or argv[0]).
	Comm string
	// Exe is the resolved target of /proc/<PID>/exe at observation time.
	// Empty if the process had already exited before it could be resolved —
	// itself worth flagging, since a connect-then-immediately-exit pattern is
	// unusual for the legitimate long-running ssh-cert-api process.
	Exe string
	// CgroupID is the cgroup v2 inode identifying the process's cgroup, from
	// bpf_get_current_cgroup_id(). Zero if unavailable (e.g. the auditd path,
	// which does not carry this without additional, less portable audit
	// configuration — see docs/vsock-connect-detection.md §4.1).
	CgroupID uint64
	Addr     VMAddr
	Source   Source
}

// Time is a thin alias so tests can construct Events without importing
// "time" directly in table literals; it is exactly time.Time.
type Time = time.Time

// Verdict is the outcome of classifying an Event against the Allowlist.
type Verdict int

const (
	// Expected: the event matches the known-good ssh-cert-api caller.
	Expected Verdict = iota
	// Anomalous: the event does NOT match — an alert-worthy connection.
	Anomalous
	// Indeterminate: the allowlist itself could not be resolved (e.g. the
	// expected service unit isn't running, or /proc/<pid>/exe already
	// vanished). Fail-secure: treated as alert-worthy, same severity as
	// Anomalous, rather than silently passed through. See Allowlist.Classify.
	Indeterminate
)

func (v Verdict) String() string {
	switch v {
	case Expected:
		return "expected"
	case Anomalous:
		return "anomalous"
	case Indeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}

// Alertworthy reports whether v should trigger an alert (everything except a
// confirmed match against the allowlist).
func (v Verdict) Alertworthy() bool { return v != Expected }

// Blockworthy reports whether v should trigger the opt-in reactive-kill
// response (see block.go). Deliberately narrower than Alertworthy:
// Indeterminate means the allowlist itself could not be resolved (e.g. a
// transient uid-lookup failure) — it says nothing about whether ev's own
// identity actually mismatches. Treating Indeterminate as block-worthy would
// risk killing the legitimate ssh-cert-api process on a transient hiccup, a
// materially worse outcome than the noisy-but-safe alert Indeterminate
// already produces. Only a confirmed Anomalous classification blocks.
func (v Verdict) Blockworthy() bool { return v == Anomalous }
