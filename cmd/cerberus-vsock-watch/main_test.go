package main

import (
	"testing"

	"github.com/pkilar/cerberus/vsockwatch"
)

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

// TestValidateLSMFlags verifies --lsm-enforce is rejected as a hard startup
// error whenever --lsm-monitor isn't also set -- the structural half of the
// monitor-first rollout (docs/vsock-connect-detection.md §4.6): enforcement
// must never be silently auto-promoted, only explicitly opted into on top of
// an already-running monitor mode.
func TestValidateLSMFlags(t *testing.T) {
	tests := []struct {
		name    string
		monitor bool
		enforce bool
		wantErr bool
	}{
		{"neither set", false, false, false},
		{"monitor only", true, false, false},
		{"monitor and enforce", true, true, false},
		{"enforce without monitor", false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLSMFlags(tt.monitor, tt.enforce)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLSMFlags(%v, %v) error = %v, wantErr %v", tt.monitor, tt.enforce, err, tt.wantErr)
			}
		})
	}
}

func TestParseWebhookFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    vsockwatch.WebhookFormat
		wantErr bool
	}{
		{"", vsockwatch.WebhookFormatAuto, false},
		{"slack", vsockwatch.WebhookFormatSlack, false},
		{"generic", vsockwatch.WebhookFormatGeneric, false},
		{"slcak", "", true},
	}
	for _, tt := range tests {
		got, err := parseWebhookFormat(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseWebhookFormat(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseWebhookFormat(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
