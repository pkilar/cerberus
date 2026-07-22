package main

import "testing"

// TestRecoverDetector_SwallowsPanic verifies a panic inside a detector
// goroutine does not propagate past recoverDetector. Without this, a bug in
// any single detector (auditd, eBPF, tamper-watch, heartbeat) would crash the
// whole process, taking every other, deliberately independent detector down
// with it.
func TestRecoverDetector_SwallowsPanic(t *testing.T) {
	func() {
		defer recoverDetector("test", nil)
		panic("boom")
	}()
}

// TestRecoverDetector_CallsOnPanic verifies a panicking detector still runs
// its onPanic callback -- auditd/eBPF rely on this to mark themselves down
// and check whether every detector is now gone, even when the goroutine dies
// via panic rather than a normal error return.
func TestRecoverDetector_CallsOnPanic(t *testing.T) {
	called := false
	func() {
		defer recoverDetector("test", func() { called = true })
		panic("boom")
	}()
	if !called {
		t.Error("onPanic was not called")
	}
}

func TestDetectorHealth_AllDown_RequiresBothWhenEBPFUsed(t *testing.T) {
	h := &detectorHealth{ebpfUsed: true}
	if h.allDown() {
		t.Fatal("allDown() = true before either detector stopped")
	}
	h.markAuditdDown()
	if h.allDown() {
		t.Fatal("allDown() = true with eBPF still running")
	}
	h.markEBPFDown()
	if !h.allDown() {
		t.Fatal("allDown() = false once both detectors are down")
	}
}

func TestDetectorHealth_AllDown_AuditdOnlyWhenEBPFDisabled(t *testing.T) {
	h := &detectorHealth{ebpfUsed: false}
	if h.allDown() {
		t.Fatal("allDown() = true before auditd stopped")
	}
	h.markAuditdDown()
	if !h.allDown() {
		t.Fatal("allDown() = false once the only enabled detector (auditd) is down")
	}
}
