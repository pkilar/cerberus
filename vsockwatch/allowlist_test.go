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
	ev.CgroupID = 111 // does not match the resolved 777
	cls := a.Classify(ev)
	if cls.Verdict != Anomalous {
		t.Fatalf("Verdict = %v, want Anomalous (cgroup mismatch)", cls.Verdict)
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
