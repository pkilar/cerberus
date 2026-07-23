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

// fakeBlocker records every Event it's asked to block, safe for concurrent use.
type fakeBlocker struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (f *fakeBlocker) Block(_ context.Context, ev Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return f.err
}

func (f *fakeBlocker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
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
	go func() { _ = w.Run(ctx, nil) }()

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

func TestAuditWatcher_Run_LineSplitAcrossPollTicks(t *testing.T) {
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
	go func() { _ = w.Run(ctx, nil) }()
	time.Sleep(30 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	defer f.Close()

	// Split the SYSCALL line mid-field (inside the pid value, before any
	// space or '=' completes it) and let a poll tick observe it with no
	// trailing newline yet, then append the rest. A tailer that treats the
	// no-delimiter read as a complete line would record pid=6 (truncated)
	// and lose uid/gid/comm/exe entirely, since the completing half doesn't
	// start with "type=" and gets rejected as its own line.
	first := `type=SYSCALL msg=audit(5.000:5): pid=6`
	if _, err := f.WriteString(first); err != nil {
		t.Fatalf("append first half: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // let a poll tick observe the partial line

	rest := `66 uid=0 gid=0 comm="evil" exe="/tmp/evil"` + "\n" +
		`type=SOCKADDR msg=audit(5.000:5): saddr=` + sockaddrVMHex(40, 5000, 16) + "\n"
	if _, err := f.WriteString(rest); err != nil {
		t.Fatalf("append rest: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for shipper.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if shipper.count() != 1 {
		t.Fatalf("got %d alerts, want 1 (the split line must still be reassembled and classified)", shipper.count())
	}
	if shipper.alerts[0].PID != 666 {
		t.Errorf("alert PID = %d, want 666 (line split across ticks must be reassembled, not truncated)", shipper.alerts[0].PID)
	}
	if shipper.alerts[0].Exe != "/tmp/evil" {
		t.Errorf("alert exe = %q, want /tmp/evil (line split across ticks must be reassembled, not dropped)", shipper.alerts[0].Exe)
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
	go func() { _ = w.Run(ctx, nil) }()
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

func TestAuditWatcher_Run_BlocksOnAnomalousConnect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	shipper := &fakeShipper{}
	blocker := &fakeBlocker{}
	allow := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	w := &AuditWatcher{
		Path:         path,
		PollInterval: 10 * time.Millisecond,
		Allowlist:    allow,
		Shipper:      shipper,
		Blocker:      blocker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx, nil) }()
	time.Sleep(30 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	lines := "" +
		`type=SYSCALL msg=audit(6.000:6): pid=777 uid=0 gid=0 comm="evil" exe="/tmp/evil"` + "\n" +
		`type=SOCKADDR msg=audit(6.000:6): saddr=` + sockaddrVMHex(40, 5000, 16) + "\n"
	if _, err := f.WriteString(lines); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	deadline := time.Now().Add(2 * time.Second)
	for blocker.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if blocker.count() != 1 {
		t.Fatalf("got %d Block calls, want 1 for an Anomalous classification", blocker.count())
	}
	if blocker.events[0].PID != 777 {
		t.Errorf("blocked pid = %d, want 777", blocker.events[0].PID)
	}
}

func TestAuditWatcher_Run_DoesNotBlockOnIndeterminate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	shipper := &fakeShipper{}
	blocker := &fakeBlocker{}
	allow := testAllowlist(999, nil, 0, errors.New("no cgroup"))
	w := &AuditWatcher{
		Path:         path,
		PollInterval: 10 * time.Millisecond,
		Allowlist:    allow,
		Shipper:      shipper,
		Blocker:      blocker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx, nil) }()
	time.Sleep(30 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	// No exe= field at all -> Classify sees ev.Exe == "" -> Indeterminate,
	// which must still alert but must never block (Verdict.Blockworthy's doc
	// comment: an unresolvable allowlist says nothing about ev's own
	// identity, so blocking here risks killing the legitimate process).
	lines := "" +
		`type=SYSCALL msg=audit(7.000:7): pid=888 uid=0 gid=0 comm="evil"` + "\n" +
		`type=SOCKADDR msg=audit(7.000:7): saddr=` + sockaddrVMHex(40, 5000, 16) + "\n"
	if _, err := f.WriteString(lines); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	deadline := time.Now().Add(2 * time.Second)
	for shipper.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if shipper.count() != 1 {
		t.Fatalf("got %d alerts, want 1 (Indeterminate must still alert)", shipper.count())
	}
	if blocker.count() != 0 {
		t.Fatalf("got %d Block calls, want 0 (Indeterminate must never block)", blocker.count())
	}
}

// readyCounter counts onReady invocations, safe for concurrent use.
type readyCounter struct {
	mu    sync.Mutex
	calls int
}

func (r *readyCounter) mark() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
}

func (r *readyCounter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestAuditWatcher_Run_CallsOnReadyAfterFileOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	w := &AuditWatcher{
		Path:         path,
		PollInterval: 10 * time.Millisecond,
		Allowlist:    testAllowlist(999, nil, 0, errors.New("no cgroup")),
		Shipper:      &fakeShipper{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := &readyCounter{}
	go func() { _ = w.Run(ctx, ready.mark) }()

	deadline := time.Now().Add(2 * time.Second)
	for ready.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := ready.count(); got != 1 {
		t.Fatalf("onReady called %d times, want exactly 1", got)
	}
}

func TestAuditWatcher_Run_DoesNotCallOnReadyIfOpenFails(t *testing.T) {
	w := &AuditWatcher{
		Path:      filepath.Join(t.TempDir(), "does-not-exist", "audit.log"),
		Allowlist: testAllowlist(999, nil, 0, errors.New("no cgroup")),
	}

	ready := &readyCounter{}
	err := w.Run(context.Background(), ready.mark)
	if err == nil {
		t.Fatal("expected an error opening a nonexistent audit log's parent directory")
	}
	if got := ready.count(); got != 0 {
		t.Fatalf("onReady called %d times, want 0 when Run fails before entering its loop", got)
	}
}
