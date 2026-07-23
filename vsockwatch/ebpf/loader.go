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
	"fmt"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"context"
	"log/slog"

	"github.com/pkilar/cerberus/vsockwatch"
)

//go:embed src/vsock_connect.bpf.o
var programObject []byte

// Watcher loads vsock_connect.c, attaches it to the sys_enter_connect
// tracepoint, and classifies every emitted event against Allowlist,
// shipping an Alert via Shipper for anything alert-worthy.
type Watcher struct {
	Allowlist *vsockwatch.Allowlist
	Shipper   vsockwatch.Shipper
	// Blocker, if set, is invoked for Verdict.Blockworthy() events (the
	// opt-in reactive-kill response; see vsockwatch/block.go). Nil disables
	// blocking, the default.
	Blocker vsockwatch.Blocker
}

// Run loads and attaches the program, then blocks reading ring buffer events
// until ctx is canceled or an unrecoverable error occurs. Load/attach
// failures (missing kernel support, insufficient privilege, a verifier
// rejection, or a tracepoint format mismatch on this kernel) are returned as
// an error rather than causing a panic, so a caller running both detectors
// (see cmd/cerberus-vsock-watch) can keep the auditd path running even if
// this one fails to start — the two are deliberately independent. onReady,
// if non-nil, is called exactly once, immediately after the ring buffer
// reader is successfully opened and before Run starts consuming events —
// callers use this to signal process readiness (e.g. systemd's sd_notify
// READY=1) only once this detector is actually attached, not merely once the
// process has started.
func (w *Watcher) Run(ctx context.Context, onReady func()) error {
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

	if onReady != nil {
		onReady()
	}

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
		// Blocker runs before Ship: an alert-delivery attempt (even an
		// async, non-blocking one) must never be able to delay the reactive
		// kill, which only has value if it happens promptly. See
		// vsockwatch/ship_async.go.
		if w.Blocker != nil && cls.Verdict.Blockworthy() {
			if err := w.Blocker.Block(ctx, ev); err != nil {
				slog.Error("vsockwatch.block.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
			} else {
				slog.Error("vsockwatch.block.killed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe)
			}
		}
		if w.Shipper != nil {
			if err := w.Shipper.Ship(ctx, vsockwatch.NewAnomalyAlert(ev, cls)); err != nil {
				slog.Error("vsockwatch.ship.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
			}
		}
	}
}
