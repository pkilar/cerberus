// Package ebpf loads and runs the vsock_connect.c probe (see that file for
// the detection rationale) via cilium/ebpf, and feeds decoded events into
// the shared vsockwatch.Allowlist/Shipper pipeline.
//
// IMPORTANT — read before relying on this in production: the object this
// package embeds was compiled and its ELF structure was validated (program/
// map/BTF sections present, see vsock_connect.c's build notes) in a
// development sandbox with no kernel BPF privileges, no BTF, and no debugfs
// tracing tree. It has NOT been load-tested against a live kernel — the
// verifier's acceptance of the program and the correctness of the
// syscalls:sys_enter_connect tracepoint field offsets on the actual target
// kernel are unconfirmed. Run() surfaces load/attach failures as an error
// rather than panicking specifically so a maintainer's first real run on
// target hardware fails loudly and cleanly if something doesn't match — see
// docs/vsock-connect-detection.md §6.
package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"context"

	"github.com/pkilar/cerberus/vsockwatch"
)

//go:embed src/vsock_connect.bpf.o
var programObject []byte

// eventSize matches sizeof(struct vsock_connect_event) in vsock_connect.c:
// 4+4+4+4 (pid, tgid, uid, gid) + 8 (cgroup_id) + 16 (comm) = 40 bytes, no
// padding since cgroup_id falls on an 8-byte-aligned offset already.
const eventSize = 40

// Watcher loads vsock_connect.c, attaches it to the sys_enter_connect
// tracepoint, and classifies every emitted event against Allowlist,
// shipping an Alert via Shipper for anything alert-worthy.
type Watcher struct {
	Allowlist *vsockwatch.Allowlist
	Shipper   vsockwatch.Shipper
}

// Run loads and attaches the program, then blocks reading ring buffer events
// until ctx is canceled or an unrecoverable error occurs. Load/attach
// failures (missing kernel support, insufficient privilege, a verifier
// rejection, or a tracepoint format mismatch on this kernel) are returned as
// an error rather than causing a panic, so a caller running both detectors
// (see cmd/cerberus-vsock-watch) can keep the auditd path running even if
// this one fails to start — the two are deliberately independent.
func (w *Watcher) Run(ctx context.Context) error {
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(programObject))
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: parsing embedded object: %w", err)
	}

	coll, err := cilium.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: loading program into kernel: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["handle_sys_enter_connect"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded object has no handle_sys_enter_connect program")
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: attaching to syscalls:sys_enter_connect: %w", err)
	}
	defer func() { _ = tp.Close() }()

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded object has no events ring buffer map")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: opening ring buffer reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	// ringbuf.Reader.Read blocks; unblock it on ctx cancellation by closing
	// the reader from a side goroutine, matching cilium/ebpf's documented
	// shutdown pattern for ring buffers.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.Close()
		case <-done:
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return fmt.Errorf("vsockwatch/ebpf: reading ring buffer: %w", err)
		}

		ev, err := decodeEvent(record.RawSample)
		if err != nil {
			// A malformed sample shouldn't be possible (we control both
			// sides of this ABI), but never let one bad record kill the
			// watcher — that would itself be an easy DoS against detection.
			continue
		}
		cls := w.Allowlist.Classify(ev)
		if !cls.Verdict.Alertworthy() {
			continue
		}
		if w.Shipper != nil {
			_ = w.Shipper.Ship(ctx, vsockwatch.NewAnomalyAlert(ev, cls))
		}
	}
}

// decodeEvent parses raw ring buffer bytes into a vsockwatch.Event. raw must
// be exactly eventSize bytes, matching struct vsock_connect_event in
// vsock_connect.c field-for-field.
func decodeEvent(raw []byte) (vsockwatch.Event, error) {
	if len(raw) < eventSize {
		return vsockwatch.Event{}, fmt.Errorf("vsockwatch/ebpf: ring buffer record too short: got %d bytes, want %d", len(raw), eventSize)
	}

	// raw[0:4] is the C struct's "pid" field (the kernel tid) — intentionally
	// not decoded; "tgid" below is the userspace-visible pid we actually want.
	tgid := binary.NativeEndian.Uint32(raw[4:8])
	uid := binary.NativeEndian.Uint32(raw[8:12])
	gid := binary.NativeEndian.Uint32(raw[12:16])
	cgroupID := binary.NativeEndian.Uint64(raw[16:24])
	comm := trimComm(raw[24:40])

	exe, _ := resolveExe(tgid)

	return vsockwatch.Event{
		PID:      tgid, // the userspace-visible pid; ev.pid in C is the kernel tid, intentionally not surfaced
		UID:      uid,
		GID:      gid,
		Comm:     comm,
		Exe:      exe,
		CgroupID: cgroupID,
		Addr:     enclaveAddr(),
		Source:   vsockwatch.SourceEBPF,
	}, nil
}

func trimComm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// enclaveAddr is a fixed VMAddr representing the enclave target, since the
// eBPF program only ever emits events that already matched the enclave's
// (CID, port) in-kernel — there's nothing left to decode on this side, but
// Event.Addr is populated for symmetry with the auditd path and so
// Allowlist.Classify's IsEnclaveTarget() defensive check still passes.
func enclaveAddr() vsockwatch.VMAddr {
	return vsockwatch.EnclaveVMAddr()
}

// resolveExe reads /proc/<pid>/exe. Declared as a var so tests can override
// it without needing a real process tree.
var resolveExe = defaultResolveExe
