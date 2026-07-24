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
	// Slice is the systemd slice Unit actually runs under, e.g.
	// "cerberus-api.slice" -- ssh-cert-api's cgroup is expected at
	// SliceCgroupPath(CgroupRoot, Slice) + "/" + Unit, not hardcoded under
	// "system.slice" the way this check originally assumed. Defaults to
	// "system.slice" in NewAllowlist, preserving the original behavior for
	// any deployment that doesn't set Slice= on the unit -- but the packaged
	// cerberus-api.service now sets Slice=cerberus-api.slice unconditionally
	// (see packaging/*/cerberus-api.service and
	// vsockwatch/ebpf/lsm.go's LSMGuard, which pins its OWN ancestor-cgroup
	// check against the same slice), so cmd/cerberus-vsock-watch/main.go
	// overrides this to the same derived value LSMGuard uses -- both
	// consumers must agree on where ssh-cert-api's process actually lives.
	// Getting this wrong doesn't crash anything (an unresolvable path just
	// makes this check silently skip, same as any other unresolvable-cgroup
	// case), but it silently degrades every classification to exe/uid-only,
	// dropping the "stronger, optional" cgroup signal §4.1 describes.
	Slice string
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

// cgroupRevalidateAttempts and cgroupRevalidateInterval bound how hard
// Classify retries a cgroup mismatch before giving up and downgrading to
// Indeterminate (see Classify). A single immediate recheck isn't always
// enough: on a real cerberus-api.service restart, the kernel can assign the
// newly-started process to its new cgroup before the well-known
// system.slice/<unit> path stat()s to that same inode, and confirmed
// real-hardware testing (verify-vsock-watch-hardware.sh's api-restart chaos
// test) showed that settling can outlast one immediate retry. This only
// runs on the mismatch path (rare — in practice, only right around a
// restart), never on every event, so a few hundred milliseconds of bounded
// retry here is a materially different cost than blocking the hot path on
// every event. Vars, not consts, so tests can shrink them rather than
// waiting out the real interval.
var (
	cgroupRevalidateAttempts = 10
	cgroupRevalidateInterval = 50 * time.Millisecond
)

// NewAllowlist builds an Allowlist with real (non-test) resolvers.
func NewAllowlist(exePath, username, unit string) *Allowlist {
	return &Allowlist{
		ExePath:      exePath,
		Username:     username,
		Unit:         unit,
		Slice:        "system.slice",
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
			// The cached expected cgroup may be stale (systemd can
			// rmdir+recreate a unit's cgroup across a restart, which changes
			// the inode), or the restart may still be racing systemd's own
			// cgroup settling (the kernel can assign the newly-started
			// process to its new cgroup before the well-known
			// system.slice/<unit> path stat()s to that same inode). Retry a
			// bounded number of times with a short interval between: this
			// only runs on the rare mismatch path, not on every event, so a
			// few hundred milliseconds here is a materially different cost
			// than blocking the hot path unconditionally (the problem
			// AsyncShipper exists to avoid on the delivery side).
			matched := false
			for attempt := range cgroupRevalidateAttempts {
				if attempt > 0 {
					time.Sleep(cgroupRevalidateInterval)
				}
				fresh, ferr := a.refreshCgroupID()
				if ferr == nil && fresh != 0 && ev.CgroupID == fresh {
					matched = true
					break
				}
			}
			if matched {
				return Classification{Verdict: Expected, Reason: "matches exe/uid/cgroup"}
			}
			// The retry budget above is generous but not unbounded, and
			// can't guarantee it always wins the settling race. exe and uid
			// already matched by this point, so this is not "any random
			// process" -- Indeterminate still alerts at the same critical
			// severity as Anomalous, but is deliberately never Blockworthy
			// (see that method), so --block cannot SIGKILL the legitimate,
			// freshly-restarted ssh-cert-api if the race is ever lost. A
			// genuine attacker satisfying this narrower bar (same exe, same
			// uid, wrong cgroup) is still loudly alerted on every time, just
			// not auto-killed by this signal alone.
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

// CgroupID exposes the same cached cgroup-inode resolution Classify uses
// (see cgroupID/refreshCgroupID below). Suitable for a consumer that can
// tolerate up to DefaultCacheTTL of staleness, the same trade-off Classify
// itself accepts on its non-mismatch path. NOT suitable for a consumer that
// needs to track a cerberus-api.service restart promptly — see
// RefreshCgroupID below, which vsockwatch/ebpf/lsm.go's LSMGuard uses
// instead for exactly that reason.
func (a *Allowlist) CgroupID() (uint64, error) {
	return a.cgroupID()
}

// RefreshCgroupID exposes the same uncached cgroup-inode resolution Classify
// uses on its mismatch-retry path (see refreshCgroupID below), bypassing the
// cache entirely. LSMGuard's poll loop (vsockwatch/ebpf/lsm.go) calls this,
// not CgroupID, specifically so its cgroup pin can actually track a real
// cerberus-api.service restart within one poll tick: CgroupID's cache
// (DefaultCacheTTL, 5s) can outlast an entire restart, which -- confirmed on
// real hardware -- meant the preventive LSM gate denied the legitimate,
// freshly-restarted ssh-cert-api for the whole 5-second staleness window
// every single time, regardless of how tight the poll interval was. The
// detective path can tolerate that staleness because Classify has its own
// separate bounded uncached retry specifically for a cgroup mismatch
// (cgroupRevalidateAttempts/cgroupRevalidateInterval); the preventive path
// has no such fallback -- a mismatch there is an immediate real denial, so
// staleness itself is the bug, not something a retry can paper over after
// the fact.
func (a *Allowlist) RefreshCgroupID() (uint64, error) {
	return a.refreshCgroupID()
}

// StatCgroupID returns the cgroup v2 inode number of the cgroupfs directory
// at path -- the same value bpf_get_current_cgroup_id()/
// bpf_get_current_ancestor_cgroup_id() return for a process in that cgroup.
// Exposed for LSMGuard's one-time API-slice cgroup resolution
// (vsockwatch/ebpf/lsm.go), a different use of the same underlying stat that
// Allowlist's own cgroupID()/RefreshCgroupID() use to resolve ssh-cert-api's
// LEAF cgroup for the detective path.
func StatCgroupID(path string) (uint64, error) {
	return statCgroupIno(path)
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
	slicePath, _, err := SliceCgroupPath(a.CgroupRoot, a.Slice)
	if err != nil {
		return 0, err
	}
	cg, err := a.statCgroupID(slicePath + "/" + a.Unit)
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
