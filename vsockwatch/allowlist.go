package vsockwatch

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Allowlist decides whether an observed Event came from the known-good
// ssh-cert-api process. Per docs/vsock-connect-detection.md §4.1, a
// connection is expected iff it comes from the configured exe path, the
// configured service account's uid, and — when resolvable — the configured
// systemd unit's cgroup. Nothing here consults Casbin, group config, or any
// other authorization state: this package only answers "was this the right
// PROCESS", never "was this request authorized".
type Allowlist struct {
	// ExePath is the expected absolute path to the ssh-cert-api binary, e.g.
	// "/usr/bin/ssh-cert-api" (the RPM/deb/arch packaged location).
	ExePath string
	// Username is the service account ssh-cert-api runs as (systemd unit's
	// User=), e.g. "cerberus". The uid is resolved dynamically at classify
	// time (cached, see uidTTL) rather than hardcoded, since it differs per
	// install.
	Username string
	// Unit is the systemd unit whose cgroup the caller is expected to be
	// in, e.g. "cerberus-api.service". Used only for the optional, stronger
	// cgroup check (§4.1); if the unit's cgroup can't be resolved (cgroup v1,
	// non-systemd host, unit not running) that check is skipped rather than
	// failing the whole classification, and is noted in the returned reason.
	Unit string
	// CgroupRoot is the cgroup v2 mount point, normally "/sys/fs/cgroup".
	// Overridable for tests.
	CgroupRoot string

	// lookupUID resolves Username to a uid. Defaults to a real os/user
	// lookup; overridden in tests.
	lookupUID func(username string) (uint32, error)
	// statCgroupID resolves the cgroup directory for Unit to its inode
	// (matching what bpf_get_current_cgroup_id() returns for a process in
	// that cgroup). Overridden in tests.
	statCgroupID func(path string) (uint64, error)

	cacheTTL time.Duration

	mu          sync.Mutex
	cachedUID   uint32
	uidResolved bool
	uidAt       time.Time
	cachedCG    uint64
	cgResolved  bool
	cgAt        time.Time
}

// DefaultCacheTTL bounds how long a resolved uid/cgroup is trusted before
// re-resolving, so a service-account change or unit reinstall is picked up
// without restarting the watcher.
const DefaultCacheTTL = 5 * time.Second

// NewAllowlist builds an Allowlist with real (non-test) resolvers.
func NewAllowlist(exePath, username, unit string) *Allowlist {
	return &Allowlist{
		ExePath:      exePath,
		Username:     username,
		Unit:         unit,
		CgroupRoot:   "/sys/fs/cgroup",
		lookupUID:    lookupUIDByUsername,
		statCgroupID: statCgroupIno,
		cacheTTL:     DefaultCacheTTL,
	}
}

// Classification is the result of Classify: a Verdict plus a human-readable
// reason suitable for the alert payload.
type Classification struct {
	Verdict Verdict
	Reason  string
}

// Classify decides whether ev matches the allowlist. It fails secure: any
// resolution failure (uid lookup, exe mismatch) is not fully able to prove a
// match, so the event is treated as Indeterminate (alert-worthy) rather than
// silently passed as Expected.
func (a *Allowlist) Classify(ev Event) Classification {
	if !ev.Addr.IsEnclaveTarget() {
		// Should not happen if the caller only feeds enclave-bound events,
		// but keep this defensive: never alert on traffic that isn't
		// actually headed to the enclave.
		return Classification{Verdict: Expected, Reason: "not an enclave-bound connection"}
	}
	if ev.Exe == "" {
		return Classification{Verdict: Indeterminate, Reason: "process exe could not be resolved (already exited?)"}
	}
	if ev.Exe != a.ExePath {
		return Classification{Verdict: Anomalous, Reason: fmt.Sprintf("exe %q != expected %q", ev.Exe, a.ExePath)}
	}

	uid, err := a.uid()
	if err != nil {
		return Classification{Verdict: Indeterminate, Reason: fmt.Sprintf("could not resolve expected uid for %q: %v", a.Username, err)}
	}
	if ev.UID != uid {
		// The cached expected uid may simply be stale (see cgroup's mismatch
		// handling below for why this matters in practice); one uncached
		// re-check before declaring Anomalous costs a single lookup and only
		// runs on the mismatch path, never on every event.
		fresh, ferr := a.refreshUID()
		if ferr != nil || ev.UID != fresh {
			return Classification{Verdict: Anomalous, Reason: fmt.Sprintf("uid %d != expected %d (%s)", ev.UID, uid, a.Username)}
		}
	}

	// Cgroup is the strongest signal but optional: skip (not alert, not
	// indeterminate) when it can't be resolved, e.g. cgroup v1 hosts.
	if ev.CgroupID != 0 {
		cg, err := a.cgroupID()
		if err == nil && cg != 0 && ev.CgroupID != cg {
			// The cached expected cgroup may be stale: systemd can
			// rmdir+recreate a unit's cgroup across a restart, which changes
			// the inode. A fresh, uncached re-check resolves the common case
			// (the cache was simply a few seconds old).
			fresh, ferr := a.refreshCgroupID()
			if ferr == nil && fresh != 0 && ev.CgroupID == fresh {
				return Classification{Verdict: Expected, Reason: "matches exe/uid/cgroup"}
			}
			// Even a fresh recheck can still race systemd's own cgroup
			// settling: on a real cerberus-api.service restart (confirmed
			// via verify-vsock-watch-hardware.sh's api-restart chaos test),
			// the kernel can assign the new process to its new cgroup before
			// the well-known system.slice/<unit> path stat()s to that same
			// inode -- a single immediate recheck isn't guaranteed to win
			// that race, and retrying with a sleep here would block the hot
			// classification path for every event (the same problem
			// AsyncShipper exists to avoid on the delivery side). exe and
			// uid already matched by this point, so this is not "any random
			// process" -- Indeterminate still alerts at the same critical
			// severity as Anomalous, but is deliberately never Blockworthy
			// (see that method), so --block cannot SIGKILL the legitimate,
			// freshly-restarted ssh-cert-api over a cgroup-settling false
			// positive. A genuine attacker satisfying this narrower bar
			// (same exe, same uid, wrong cgroup) is still loudly alerted on
			// every time, just not auto-killed by this signal alone.
			return Classification{Verdict: Indeterminate, Reason: fmt.Sprintf("cgroup id %d != expected %d (%s)", ev.CgroupID, cg, a.Unit)}
		}
	}

	return Classification{Verdict: Expected, Reason: "matches exe/uid" + cgroupSuffix(ev)}
}

func cgroupSuffix(ev Event) string {
	if ev.CgroupID != 0 {
		return "/cgroup"
	}
	return ""
}

// uid resolves and caches the expected uid. The resolver call itself (real
// impl: os/user.Lookup, which may be NSS/LDAP-backed and hence network-bound)
// runs unlocked: a.mu is only held to read/write the cache, never across the
// lookup itself. This Allowlist is shared between the auditd and eBPF
// watcher goroutines (see cmd/cerberus-vsock-watch/main.go), so holding the
// lock across a slow or hung lookup would delay classification of both
// detectors' events for its duration. A cache miss may race a handful of
// redundant concurrent lookups; that's cheaper than serializing I/O behind
// the mutex.
func (a *Allowlist) uid() (uint32, error) {
	a.mu.Lock()
	if a.uidResolved && time.Since(a.uidAt) < a.cacheTTL {
		cached := a.cachedUID
		a.mu.Unlock()
		return cached, nil
	}
	a.mu.Unlock()
	return a.refreshUID()
}

// refreshUID unconditionally re-resolves the expected uid, bypassing the
// cache, and updates it. Used by uid() on a cache miss, and by Classify to
// double-check a cache-derived mismatch before declaring an event Anomalous.
func (a *Allowlist) refreshUID() (uint32, error) {
	uid, err := a.lookupUID(a.Username)
	if err != nil {
		return 0, err
	}

	a.mu.Lock()
	a.cachedUID, a.uidResolved, a.uidAt = uid, true, time.Now()
	a.mu.Unlock()
	return uid, nil
}

// cgroupID resolves and caches the expected cgroup inode. See uid's doc
// comment: the resolver call (os.Stat) runs unlocked for the same reason.
func (a *Allowlist) cgroupID() (uint64, error) {
	a.mu.Lock()
	if a.cgResolved && time.Since(a.cgAt) < a.cacheTTL {
		cached := a.cachedCG
		a.mu.Unlock()
		return cached, nil
	}
	a.mu.Unlock()
	return a.refreshCgroupID()
}

// refreshCgroupID unconditionally re-resolves the expected cgroup inode,
// bypassing the cache, and updates it. Used by cgroupID() on a cache miss,
// and by Classify to double-check a cache-derived mismatch before declaring
// an event Anomalous.
func (a *Allowlist) refreshCgroupID() (uint64, error) {
	path := a.CgroupRoot + "/system.slice/" + a.Unit
	cg, err := a.statCgroupID(path)
	if err != nil {
		return 0, err
	}

	a.mu.Lock()
	a.cachedCG, a.cgResolved, a.cgAt = cg, true, time.Now()
	a.mu.Unlock()
	return cg, nil
}

// lookupUIDByUsername resolves username via os/user (which itself reads
// /etc/passwd or NSS, whichever the host is configured for).
func lookupUIDByUsername(username string) (uint32, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("vsockwatch: unexpected non-numeric uid %q for %q: %w", u.Uid, username, err)
	}
	return uint32(uid), nil
}

// statCgroupIno returns the inode number of the cgroup v2 directory at path,
// which is exactly the id bpf_get_current_cgroup_id() returns for a process
// in that cgroup (cgroup v2 exposes cgroups as kernfs nodes, and their id is
// their inode number).
func statCgroupIno(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("vsockwatch: cannot determine inode for %q on this platform", path)
	}
	return st.Ino, nil
}
