package vsockwatch

import (
	"errors"
	"testing"
	"time"
)

func testAllowlist(uid uint32, uidErr error, cgroupID uint64, cgroupErr error) *Allowlist {
	return &Allowlist{
		ExePath:  "/usr/bin/ssh-cert-api",
		Username: "cerberus",
		Unit:     "cerberus-api.service",
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

func TestClassify_CgroupMismatch_Anomalous(t *testing.T) {
	a := testAllowlist(999, nil, 777, nil)
	ev := baseEvent()
	ev.CgroupID = 111 // does not match the resolved 777, even after a fresh re-check (same resolver)
	cls := a.Classify(ev)
	if cls.Verdict != Anomalous {
		t.Fatalf("Verdict = %v, want Anomalous (cgroup mismatch)", cls.Verdict)
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
