package vsockwatch

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSplitAuditKV(t *testing.T) {
	fields := splitAuditKV(` arch=c000003e syscall=42 success=yes exe="/usr/bin/ssh-cert-api" comm="ssh-cert-api" pid=4242 uid=999 gid=999 key="cerberus_vsock_watch"`)
	want := map[string]string{
		"arch":    "c000003e",
		"syscall": "42",
		"success": "yes",
		"exe":     "/usr/bin/ssh-cert-api",
		"comm":    "ssh-cert-api",
		"pid":     "4242",
		"uid":     "999",
		"gid":     "999",
		"key":     "cerberus_vsock_watch",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("fields[%q] = %q, want %q", k, fields[k], v)
		}
	}
}

func TestParseAuditLine_SyscallRecord(t *testing.T) {
	line := `type=SYSCALL msg=audit(1626272718.123:456): arch=c000003e syscall=42 success=yes exit=0 pid=4242 uid=999 gid=999 comm="ssh-cert-api" exe="/usr/bin/ssh-cert-api" key="cerberus_vsock_watch"`
	rec, ok := parseAuditLine(line)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.recordType != "SYSCALL" {
		t.Errorf("recordType = %q, want SYSCALL", rec.recordType)
	}
	if rec.msgID != "1626272718.123:456" {
		t.Errorf("msgID = %q, want 1626272718.123:456", rec.msgID)
	}
	if rec.fields["exe"] != "/usr/bin/ssh-cert-api" {
		t.Errorf("exe = %q", rec.fields["exe"])
	}
}

func TestParseAuditLine_NotAnAuditLine(t *testing.T) {
	if _, ok := parseAuditLine("this is not an audit line"); ok {
		t.Fatal("expected ok=false")
	}
	if _, ok := parseAuditLine(""); ok {
		t.Fatal("expected ok=false for blank line")
	}
}

func sockaddrVMHex(family uint16, port, cid uint32) string {
	return hex.EncodeToString(encodeSockaddrVM(family, port, cid))
}

func TestCorrelator_PairsSyscallAndSockaddr(t *testing.T) {
	c := newCorrelator()
	syscallLine := `type=SYSCALL msg=audit(1.000:1): pid=4242 uid=999 gid=999 comm="evil" exe="/tmp/evil"`
	sockaddrLine := `type=SOCKADDR msg=audit(1.000:1): saddr=` + sockaddrVMHex(40, 5000, 16)

	rec1, _ := parseAuditLine(syscallLine)
	if _, ok := c.feed(rec1); ok {
		t.Fatal("should not emit before the SOCKADDR half arrives")
	}

	rec2, _ := parseAuditLine(sockaddrLine)
	ev, ok := c.feed(rec2)
	if !ok {
		t.Fatal("expected an event once both halves are fed")
	}
	if ev.PID != 4242 || ev.UID != 999 || ev.Exe != "/tmp/evil" {
		t.Errorf("got %+v", ev)
	}
	if !ev.Addr.IsEnclaveTarget() {
		t.Error("expected the decoded addr to match the enclave target")
	}
	if ev.Source != SourceAuditd {
		t.Errorf("Source = %q, want %q", ev.Source, SourceAuditd)
	}
}

func TestCorrelator_OrderIndependent(t *testing.T) {
	// SOCKADDR can arrive before or after SYSCALL in the log; either order
	// must pair correctly.
	c := newCorrelator()
	sockaddrLine := `type=SOCKADDR msg=audit(2.000:2): saddr=` + sockaddrVMHex(40, 5000, 16)
	syscallLine := `type=SYSCALL msg=audit(2.000:2): pid=1 uid=0 gid=0 comm="x" exe="/tmp/x"`

	rec1, _ := parseAuditLine(sockaddrLine)
	if _, ok := c.feed(rec1); ok {
		t.Fatal("should not emit before the SYSCALL half arrives")
	}
	rec2, _ := parseAuditLine(syscallLine)
	if _, ok := c.feed(rec2); !ok {
		t.Fatal("expected an event once both halves are fed")
	}
}

func TestCorrelator_UnrelatedMsgIDsDontCrossPair(t *testing.T) {
	c := newCorrelator()
	rec1, _ := parseAuditLine(`type=SYSCALL msg=audit(1.000:1): pid=1 uid=0 gid=0 comm="a" exe="/a"`)
	rec2, _ := parseAuditLine(`type=SOCKADDR msg=audit(2.000:2): saddr=` + sockaddrVMHex(40, 5000, 16))
	if _, ok := c.feed(rec1); ok {
		t.Fatal("unexpected emit")
	}
	if _, ok := c.feed(rec2); ok {
		t.Fatal("a SOCKADDR for a different msgID must not pair with an unrelated pending SYSCALL")
	}
}

// fakeShipper records every Alert it's given, safe for concurrent use.
type fakeShipper struct {
	mu     sync.Mutex
	alerts []Alert
}

func (f *fakeShipper) Ship(_ context.Context, a Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
	return nil
}

func (f *fakeShipper) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.alerts)
}

func TestAuditWatcher_Run_AlertsOnAnomalousConnect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	shipper := &fakeShipper{}
	allow := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	w := &AuditWatcher{
		Path:         path,
		PollInterval: 10 * time.Millisecond,
		Allowlist:    allow,
		Shipper:      shipper,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	// Give Run a moment to open the file at EOF before we append, so this
	// isn't racing the initial open.
	time.Sleep(30 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	lines := "" +
		`type=SYSCALL msg=audit(3.000:3): pid=666 uid=0 gid=0 comm="evil" exe="/tmp/evil"` + "\n" +
		`type=SOCKADDR msg=audit(3.000:3): saddr=` + sockaddrVMHex(40, 5000, 16) + "\n"
	if _, err := f.WriteString(lines); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	deadline := time.Now().Add(2 * time.Second)
	for shipper.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if shipper.count() != 1 {
		t.Fatalf("got %d alerts, want 1", shipper.count())
	}
	if shipper.alerts[0].Exe != "/tmp/evil" {
		t.Errorf("alert exe = %q, want /tmp/evil", shipper.alerts[0].Exe)
	}
}

func TestAuditWatcher_Run_NoAlertForExpectedCaller(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	shipper := &fakeShipper{}
	allow := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	w := &AuditWatcher{
		Path:         path,
		PollInterval: 10 * time.Millisecond,
		Allowlist:    allow,
		Shipper:      shipper,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	lines := "" +
		`type=SYSCALL msg=audit(4.000:4): pid=1 uid=999 gid=999 comm="ssh-cert-api" exe="/usr/bin/ssh-cert-api"` + "\n" +
		`type=SOCKADDR msg=audit(4.000:4): saddr=` + sockaddrVMHex(40, 5000, 16) + "\n"
	if _, err := f.WriteString(lines); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	time.Sleep(200 * time.Millisecond)
	if shipper.count() != 0 {
		t.Fatalf("got %d alerts, want 0 for the expected caller", shipper.count())
	}
}
