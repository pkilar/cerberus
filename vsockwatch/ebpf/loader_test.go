package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	cilium "github.com/cilium/ebpf"

	"github.com/pkilar/cerberus/vsockwatch"
)

// TestEmbeddedObject_ParsesAsValidELF verifies the embedded vsock_connect.bpf.o
// parses into a well-formed cilium/ebpf CollectionSpec: the expected program
// (attached to the right tracepoint section) and the expected ring buffer
// map are both present. This does NOT load the program into a kernel or
// attach it — that requires real BPF privileges this test environment does
// not have (and, per loader.go's doc comment, has never been exercised
// end-to-end against a live kernel as part of this change). It does catch
// ELF/section-naming mistakes, which is the class of error most likely to
// have been introduced by hand-writing the .c file without libbpf headers.
func TestEmbeddedObject_ParsesAsValidELF(t *testing.T) {
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(programObject))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}

	prog, ok := spec.Programs["handle_sys_enter_connect"]
	if !ok {
		t.Fatalf("embedded object has no handle_sys_enter_connect program; got %v", specProgramNames(spec))
	}
	if prog.Type != cilium.TracePoint {
		t.Errorf("program type = %v, want TracePoint", prog.Type)
	}
	if prog.SectionName != "tracepoint/syscalls/sys_enter_connect" {
		t.Errorf("section name = %q, want tracepoint/syscalls/sys_enter_connect", prog.SectionName)
	}

	m, ok := spec.Maps["events"]
	if !ok {
		t.Fatalf("embedded object has no events map; got %v", specMapNames(spec))
	}
	if m.Type != cilium.RingBuf {
		t.Errorf("map type = %v, want RingBuf", m.Type)
	}
	if m.MaxEntries != 1<<16 {
		t.Errorf("map max entries = %d, want %d", m.MaxEntries, 1<<16)
	}
}

func specProgramNames(spec *cilium.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	return names
}

func specMapNames(spec *cilium.CollectionSpec) []string {
	names := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		names = append(names, name)
	}
	return names
}

// TestDecodeEvent_MatchesCStructLayout builds a synthetic 40-byte record
// matching struct vsock_connect_event's field layout exactly (see
// vsock_connect.c) and verifies decodeEvent extracts each field correctly,
// including a comm string shorter than the fixed 16-byte field (null-padded,
// as bpf_get_current_comm produces).
func TestDecodeEvent_MatchesCStructLayout(t *testing.T) {
	origResolveExe := resolveExe
	resolveExe = func(pid uint32) (string, error) {
		if pid != 4242 {
			t.Fatalf("resolveExe called with pid=%d, want 4242", pid)
		}
		return "/usr/bin/ssh-cert-api", nil
	}
	t.Cleanup(func() { resolveExe = origResolveExe })

	raw := make([]byte, eventSize)
	binary.NativeEndian.PutUint32(raw[0:4], 9999)  // kernel tid, not surfaced
	binary.NativeEndian.PutUint32(raw[4:8], 4242)  // tgid / userspace pid
	binary.NativeEndian.PutUint32(raw[8:12], 1000) // uid
	binary.NativeEndian.PutUint32(raw[12:16], 100) // gid
	binary.NativeEndian.PutUint64(raw[16:24], 555) // cgroup_id
	copy(raw[24:40], "evil\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	ev, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if ev.PID != 4242 {
		t.Errorf("PID = %d, want 4242", ev.PID)
	}
	if ev.UID != 1000 {
		t.Errorf("UID = %d, want 1000", ev.UID)
	}
	if ev.GID != 100 {
		t.Errorf("GID = %d, want 100", ev.GID)
	}
	if ev.CgroupID != 555 {
		t.Errorf("CgroupID = %d, want 555", ev.CgroupID)
	}
	if ev.Comm != "evil" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "evil")
	}
	if ev.Exe != "/usr/bin/ssh-cert-api" {
		t.Errorf("Exe = %q, want /usr/bin/ssh-cert-api", ev.Exe)
	}
	if !ev.Addr.IsEnclaveTarget() {
		t.Error("Addr.IsEnclaveTarget() = false, want true")
	}
}

func TestDecodeEvent_RejectsShortRecord(t *testing.T) {
	if _, err := decodeEvent(make([]byte, eventSize-1)); err == nil {
		t.Fatal("expected an error for a too-short record")
	}
}

// fakeBlocker records every Event it's asked to block, safe for concurrent use.
type fakeBlocker struct {
	mu     sync.Mutex
	events []vsockwatch.Event
}

func (f *fakeBlocker) Block(_ context.Context, ev vsockwatch.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeBlocker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events)
}

// TestDecodeEvent_BlockworthyWiring is a narrow unit check that decodeEvent's
// output, when classified Anomalous, is exactly what Watcher.Run would pass
// to a configured Blocker — Run itself requires a live kernel to exercise
// end-to-end (see this file's and loader.go's doc comments on what this
// sandbox cannot verify), so this only confirms the decoded Event carries the
// PID a Blocker needs.
func TestDecodeEvent_BlockworthyWiring(t *testing.T) {
	origResolveExe := resolveExe
	resolveExe = func(uint32) (string, error) { return "/tmp/evil", nil }
	t.Cleanup(func() { resolveExe = origResolveExe })

	raw := make([]byte, eventSize)
	binary.NativeEndian.PutUint32(raw[4:8], 4242) // tgid / userspace pid
	binary.NativeEndian.PutUint32(raw[8:12], 0)   // uid
	copy(raw[24:40], "evil\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	ev, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}

	allow := &vsockwatch.Allowlist{ExePath: "/usr/bin/ssh-cert-api"}
	blocker := &fakeBlocker{}
	w := &Watcher{Allowlist: allow, Blocker: blocker}

	cls := w.Allowlist.Classify(ev)
	if !cls.Verdict.Blockworthy() {
		t.Fatalf("Verdict = %v, want Anomalous (Blockworthy) for a mismatched exe", cls.Verdict)
	}
	if err := w.Blocker.Block(context.Background(), ev); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if blocker.count() != 1 || blocker.events[0].PID != 4242 {
		t.Fatalf("blocker recorded %+v, want one event with PID 4242", blocker.events)
	}
}
