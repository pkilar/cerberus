package main

import "testing"

// TestRecoverDetector_SwallowsPanic verifies a panic inside a detector
// goroutine does not propagate past recoverDetector. Without this, a bug in
// any single detector (auditd, eBPF, tamper-watch, heartbeat) would crash the
// whole process, taking every other, deliberately independent detector down
// with it.
func TestRecoverDetector_SwallowsPanic(t *testing.T) {
	func() {
		defer recoverDetector("test")
		panic("boom")
	}()
}
