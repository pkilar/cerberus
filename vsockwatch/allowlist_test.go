package vsockwatch

import (
	"errors"
	"os"
	"testing"
	"time"
)

func testAllowlist(uid uint32, uidErr error, cgroupID uint64, cgroupErr error) *Allowlist {
	return &Allowlist{
		ExePath:    "/usr/bin/ssh-cert-api",
		Username:   "cerberus",
		Unit:       "cerberus-api.service",
		Slice:      "system.slice",
		CgroupRoot: "/sys/fs/cgroup",
		lookupUID: func(string) (uint32, error) {
			if uidErr != nil {
				return 0, uidErr
			}
			return uid, nil
		},
		statCgroupID: func(string) (uint64, error) {
			if cgroupErr != nil {
				return 0, cgroupErr
			}
			return cgroupID, nil
		},
		cacheTTL: time.Minute,
	}
}

func baseEvent() Event {
	return Event{
		PID:  1234,
		UID:  999,
		GID:  999,
		Comm: "ssh-cert-api",
		Exe:  "/usr/bin/ssh-cert-api",
		Addr: EnclaveVMAddr(),
	}
}

func TestClassify_ExpectedCaller(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup v2 on this host"))
	cls := a.Classify(baseEvent())
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v (%s), want Expected", cls.Verdict, cls.Reason)
	}
}

func TestClassify_WrongExe(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	ev := baseEvent()
	ev.Exe = "/tmp/evil"
	cls := a.Classify(ev)
	if cls.Verdict != Anomalous {
		t.Fatalf("Verdict = %v, want Anomalous", cls.Verdict)
	}
}

func TestClassify_WrongUID(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	ev := baseEvent()
	ev.UID = 0 // root
	cls := a.Classify(ev)
	if cls.Verdict != Anomalous {
		t.Fatalf("Verdict = %v, want Anomalous", cls.Verdict)
	}
}

func TestClassify_EmptyExe_Indeterminate(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	ev := baseEvent()
	ev.Exe = ""
	cls := a.Classify(ev)
	if cls.Verdict != Indeterminate {
		t.Fatalf("Verdict = %v, want Indeterminate", cls.Verdict)
	}
}

func TestClassify_UIDLookupFails_Indeterminate(t *testing.T) {
	a := testAllowlist(0, errors.New("user lookup failed"), 0, errors.New("no cgroup"))
	cls := a.Classify(baseEvent())
	if cls.Verdict != Indeterminate {
		t.Fatalf("Verdict = %v, want Indeterminate", cls.Verdict)
	}
}

func TestClassify_CgroupMismatch_Indeterminate(t *testing.T) {
	// exe and uid already matched, so a cgroup mismatch that persists even
	// after the full retry budget (same resolver every attempt, so this
	// isn't just a stale cache or a brief settling race) is Indeterminate,
	// not Anomalous -- alert-worthy but never Blockworthy, since even a
	// bounded retry can't guarantee it always wins systemd's cgroup-settling
	// race around a legitimate restart (see Classify's doc comment).
	origAttempts, origInterval := cgroupRevalidateAttempts, cgroupRevalidateInterval
	cgroupRevalidateAttempts, cgroupRevalidateInterval = 2, time.Millisecond
	defer func() { cgroupRevalidateAttempts, cgroupRevalidateInterval = origAttempts, origInterval }()

	a := testAllowlist(999, nil, 777, nil)
	ev := baseEvent()
	ev.CgroupID = 111 // does not match the resolved 777, even after every retry
	cls := a.Classify(ev)
	if cls.Verdict != Indeterminate {
		t.Fatalf("Verdict = %v, want Indeterminate (cgroup mismatch persists after the full retry budget)", cls.Verdict)
	}
	if cls.Verdict.Blockworthy() {
		t.Error("Indeterminate must never be Blockworthy -- a cgroup-settling race must not let --block kill a legitimate process")
	}
}

func TestClassify_CgroupMismatch_MatchesPartwayThroughRetries(t *testing.T) {
	// Simulates systemd's cgroup settling resolving mid-retry (not on the
	// very first recheck, but before the retry budget is exhausted): the
	// resolver reports the stale value for the first two calls, then the
	// event's actual (current) cgroup from then on.
	origAttempts, origInterval := cgroupRevalidateAttempts, cgroupRevalidateInterval
	cgroupRevalidateAttempts, cgroupRevalidateInterval = 5, time.Millisecond
	defer func() { cgroupRevalidateAttempts, cgroupRevalidateInterval = origAttempts, origInterval }()

	calls := 0
	a := &Allowlist{
		ExePath:    "/usr/bin/ssh-cert-api",
		Username:   "cerberus",
		Unit:       "cerberus-api.service",
		Slice:      "system.slice",
		CgroupRoot: "/sys/fs/cgroup",
		lookupUID: func(string) (uint32, error) {
			return 999, nil
		},
		statCgroupID: func(string) (uint64, error) {
			calls++
			if calls <= 2 {
				return 777, nil // still stale, systemd hasn't settled yet
			}
			return 111, nil // settled: matches the event
		},
		cacheTTL: time.Minute,
	}
	ev := baseEvent()
	ev.CgroupID = 111

	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v (%s), want Expected -- a match partway through the retry budget must not be treated as a mismatch", cls.Verdict, cls.Reason)
	}
}

func TestClassify_CgroupMismatch_RevalidatesStaleCacheBeforeAnomalous(t *testing.T) {
	// Simulates a legitimate cerberus-api.service restart that changed its
	// cgroup (systemd can rmdir+recreate an empty transient cgroup between
	// stop and start): the cache holds a STALE value (777) from before the
	// restart, but the resolver now reports the CURRENT cgroup (111), which
	// matches the event. A stale cache alone must not misclassify this as
	// Anomalous once a fresh lookup confirms the match.
	a := &Allowlist{
		ExePath:      "/usr/bin/ssh-cert-api",
		Username:     "cerberus",
		Unit:         "cerberus-api.service",
		Slice:        "system.slice",
		CgroupRoot:   "/sys/fs/cgroup",
		lookupUID:    func(string) (uint32, error) { return 999, nil },
		statCgroupID: func(string) (uint64, error) { return 111, nil }, // the current cgroup
		cacheTTL:     time.Minute,
		cachedCG:     777, // stale, pre-restart value
		cgResolved:   true,
		cgAt:         time.Now(),
	}
	ev := baseEvent()
	ev.CgroupID = 111 // the connecting process's actual, current cgroup

	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v (%s), want Expected -- a stale cached cgroup must not misclassify a legitimate process once a fresh lookup confirms a match", cls.Verdict, cls.Reason)
	}
}

func TestClassify_UIDMismatch_RevalidatesStaleCacheBeforeAnomalous(t *testing.T) {
	a := &Allowlist{
		ExePath:      "/usr/bin/ssh-cert-api",
		Username:     "cerberus",
		lookupUID:    func(string) (uint32, error) { return 999, nil }, // the current uid
		statCgroupID: func(string) (uint64, error) { return 0, errors.New("no cgroup") },
		cacheTTL:     time.Minute,
		cachedUID:    1000, // stale
		uidResolved:  true,
		uidAt:        time.Now(),
	}
	ev := baseEvent()
	ev.UID = 999 // matches the current (fresh) uid, not the stale cached one

	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v (%s), want Expected -- a stale cached uid must not misclassify a legitimate process once a fresh lookup confirms a match", cls.Verdict, cls.Reason)
	}
}

func TestClassify_UIDMismatch_StillAnomalousWhenRefreshAlsoMismatches(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	ev := baseEvent()
	ev.UID = 0 // root: mismatches both the cache and a fresh re-check (same resolver)
	cls := a.Classify(ev)
	if cls.Verdict != Anomalous {
		t.Fatalf("Verdict = %v, want Anomalous (uid mismatch persists after revalidation)", cls.Verdict)
	}
}

func TestClassify_CgroupMatch_Expected(t *testing.T) {
	a := testAllowlist(999, nil, 777, nil)
	ev := baseEvent()
	ev.CgroupID = 777
	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v (%s), want Expected", cls.Verdict, cls.Reason)
	}
}

func TestClassify_CgroupUnresolvable_SkippedNotFailed(t *testing.T) {
	// The auditd path never populates CgroupID, so this must not become
	// Indeterminate just because cgroup resolution errors — it's an optional
	// strengthening, not a requirement.
	a := testAllowlist(999, nil, 0, errors.New("cgroup v1 host"))
	ev := baseEvent()
	ev.CgroupID = 0
	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v, want Expected when cgroup id is unavailable", cls.Verdict)
	}
}

func TestClassify_NotEnclaveTarget_NeverAlerts(t *testing.T) {
	a := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	ev := baseEvent()
	ev.Exe = "/tmp/evil" // would otherwise be Anomalous
	ev.Addr = VMAddr{Family: 2, CID: 0, Port: 443}
	cls := a.Classify(ev)
	if cls.Verdict != Expected {
		t.Fatalf("Verdict = %v, want Expected (non-enclave traffic must never alert)", cls.Verdict)
	}
}

func TestAllowlist_LookupDoesNotBlockOtherCachedReads(t *testing.T) {
	started := make(chan struct{})
	unblock := make(chan struct{})
	a := &Allowlist{
		ExePath:  "/usr/bin/ssh-cert-api",
		Username: "cerberus",
		lookupUID: func(string) (uint32, error) {
			close(started)
			<-unblock // simulates a slow/hung NSS- or LDAP-backed lookup
			return 999, nil
		},
		statCgroupID: func(string) (uint64, error) {
			t.Error("statCgroupID must not be called: cgroupID()'s cache is pre-warmed and valid")
			return 0, errors.New("unexpected call")
		},
		cacheTTL: time.Minute,
		// Pre-warm the cgroup cache so cgroupID() below takes the cached
		// fast path instead of calling statCgroupID.
		cachedCG:   777,
		cgResolved: true,
		cgAt:       time.Now(),
	}

	go func() { _, _ = a.uid() }() // blocks in lookupUID, unlocked
	<-started

	done := make(chan struct{})
	go func() {
		if _, err := a.cgroupID(); err != nil {
			t.Errorf("cgroupID(): %v", err)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cgroupID() blocked while uid()'s lookupUID was in flight — I/O must not run under a.mu")
	}
	close(unblock)
}

func TestAllowlist_UIDCache(t *testing.T) {
	calls := 0
	a := &Allowlist{
		ExePath: "/usr/bin/ssh-cert-api",
		lookupUID: func(string) (uint32, error) {
			calls++
			return 999, nil
		},
		statCgroupID: func(string) (uint64, error) { return 0, errors.New("skip") },
		cacheTTL:     time.Minute,
	}
	for range 3 {
		if _, err := a.uid(); err != nil {
			t.Fatalf("uid(): %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("lookupUID called %d times, want 1 (cached)", calls)
	}
}

// TestAllowlist_CgroupID_ResolvesUnderConfiguredSlice reproduces the bug an
// adversarial review of PR #125 caught: refreshCgroupID used to hardcode
// "system.slice/<Unit>" as ssh-cert-api's expected cgroup path, but the
// packaged cerberus-api.service now sets Slice=cerberus-api.slice
// unconditionally (packaging/*/cerberus-api.service) -- ssh-cert-api's real
// cgroup lives at .../cerberus.slice/cerberus-api.slice/cerberus-api.service,
// two levels below system.slice. With the old hardcoded assumption, EVERY
// packaged deployment would silently fail this resolution and Classify would
// silently drop the cgroup signal, degrading to exe/uid-only classification
// -- not a crash (Classify already treats an unresolvable cgroup as "skip,
// don't alert"), but a silent loss of the "stronger, optional" signal
// docs/vsock-connect-detection.md §4.1 describes, for every install.
//
// This test uses REAL directories (not a faked statCgroupID) so it actually
// exercises SliceCgroupPath + the real os.Stat-based resolution end to end,
// and explicitly proves the OLD (system.slice) assumption would NOT have
// found this path -- confirming Slice is load-bearing, not just plumbed
// through unused.
func TestAllowlist_CgroupID_ResolvesUnderConfiguredSlice(t *testing.T) {
	dir := t.TempDir()
	unitDir := dir + "/cerberus.slice/cerberus-api.slice/cerberus-api.service"
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	a := NewAllowlist("/usr/bin/ssh-cert-api", "cerberus", "cerberus-api.service")
	a.CgroupRoot = dir
	a.Slice = "cerberus-api.slice"

	cg, err := a.CgroupID()
	if err != nil {
		t.Fatalf("CgroupID() with Slice=cerberus-api.slice: %v -- the dedicated-slice packaging change is not resolvable", err)
	}
	if cg == 0 {
		t.Error("cg = 0, want a nonzero inode")
	}

	// The OLD, pre-fix assumption (NewAllowlist's default Slice,
	// "system.slice", left unoverridden here) must NOT resolve this same
	// directory tree -- otherwise this test isn't actually distinguishing
	// the bug from the fix.
	oldAssumption := NewAllowlist("/usr/bin/ssh-cert-api", "cerberus", "cerberus-api.service")
	oldAssumption.CgroupRoot = dir
	if _, err := oldAssumption.CgroupID(); err == nil {
		t.Error("CgroupID() under the old system.slice assumption unexpectedly succeeded -- this test no longer distinguishes the bug from the fix")
	}
}
