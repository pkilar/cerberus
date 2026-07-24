package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/pkilar/cerberus/vsockwatch"
)

//go:embed src/vsock_lsm.bpf.o
var lsmProgramObject []byte

// defaultLSMPollInterval is used when LSMGuard.PollInterval is zero. It
// governs only how often the --lsm-enforce-state-file runtime toggle is
// checked -- the cgroup pin is no longer polled at all (see Run's
// resolveAPISliceCgroup, called once at startup) after a real-hardware test
// found polling the leaf cgroup structurally unable to win the race against
// ssh-cert-api's near-instant post-restart enclave dial. See
// docs/vsock-connect-detection.md §4.6 for that history.
const defaultLSMPollInterval = 250 * time.Millisecond

// apiSliceResolveAttempts and apiSliceResolveInterval bound how long
// resolveAPISliceCgroup retries the API slice's cgroup before giving up.
// This covers ONLY the first-ever-boot ordering edge case (this process
// starting before systemd has ever instantiated the slice) -- a materially
// easier problem than the restart race this whole file exists to close,
// since after the FIRST successful resolution the slice persists across
// every subsequent cerberus-api.service restart untouched (confirmed by a
// real-hardware check: create a throwaway slice + service, restart the
// service a few times, and diff the slice's cgroup inode against the
// service's own leaf cgroup inode -- the slice's stays constant, the leaf's
// changes every time). Vars, not consts, so tests can shrink them rather
// than waiting out the real interval -- same pattern as Allowlist's
// cgroupRevalidateAttempts.
var (
	apiSliceResolveAttempts = 20
	apiSliceResolveInterval = 250 * time.Millisecond
)

// resolveAPISliceCgroup resolves apiSlice's cgroup ID and ancestor level
// ONCE. LSMGuard.Run calls this a single time at startup, never on a
// recurring timer -- there is nothing to poll for, since the slice's cgroup
// does not change across cerberus-api.service's own restarts.
func resolveAPISliceCgroup(ctx context.Context, cgroupRoot, apiSlice string) (cgroupID uint64, level uint32, err error) {
	path, level, err := vsockwatch.SliceCgroupPath(cgroupRoot, apiSlice)
	if err != nil {
		return 0, 0, err
	}

	var lastErr error
	for attempt := range apiSliceResolveAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, 0, ctx.Err()
			case <-time.After(apiSliceResolveInterval):
			}
		}
		cg, statErr := vsockwatch.StatCgroupID(path)
		if statErr == nil {
			return cg, level, nil
		}
		lastErr = statErr
	}
	return 0, 0, fmt.Errorf("vsockwatch/ebpf: resolving %s cgroup at %s after %d attempts: %w",
		apiSlice, path, apiSliceResolveAttempts, lastErr)
}

// seedInitialPolicySlot is the slot seedInitialPolicy always writes into --
// never 0, which the kernel zero-initializes lsm_active_slot to point at
// (i.e. slot 0 is already live from the moment the program is attached).
const seedInitialPolicySlot = 1

// seedInitialPolicy performs Run's one-time publish of the resolved API
// slice cgroup pin: write the populated policy into the currently-inactive
// slot, then flip lsm_active_slot to it. This is the same
// write-inactive-then-flip discipline pollLoop's mode toggle and every other
// mutation in this file already follows -- see policyMapWriter's doc comment
// and vsock_lsm.c's lsm_policy_slot comment for why a reversed order (or
// writing directly into the already-live slot 0) is a torn-write bug a
// concurrent in-kernel reader could observe. Broken out from Run so this
// exact seed step is unit-testable via fakePolicyWriter without a running
// eBPF LSM program (see TestSeedInitialPolicy_WritesInactiveSlotNotSlotZero).
func seedInitialPolicy(pw policyMapWriter, cgroupID uint64, level uint32) error {
	if err := pw.putPolicySlot(seedInitialPolicySlot, cgroupID, level, true); err != nil {
		return fmt.Errorf("vsockwatch/ebpf: seeding initial lsm_policy: %w", err)
	}
	if err := pw.putActiveSlot(seedInitialPolicySlot); err != nil {
		return fmt.Errorf("vsockwatch/ebpf: seeding initial lsm_active_slot: %w", err)
	}
	return nil
}

// LSMGuard loads vsock_lsm.c, attaches it to the socket_connect LSM hook
// (invoked via the kernel's security_socket_connect() dispatcher — see
// vsock_lsm.c's header comment on why the BPF attach point is always named
// after the bare hook, never the dispatcher), and enforces (or, in monitor
// mode, only logs) a cgroup-based
// allow/deny decision for AF_VSOCK connects to the enclave. See
// docs/vsock-connect-detection.md §4.6 for the full design rationale — most
// importantly:
//
//   - This is a DELIBERATELY NARROWER control than Allowlist's detective
//     classification. An LSM hook decides synchronously, entirely in-kernel;
//     there is no way to resolve /proc/<pid>/exe from there, so the only
//     identity signal available is cgroup membership. Anything sharing
//     ssh-cert-api's cgroup — including a compromised ssh-cert-api itself —
//     still passes. This does not close docs/THREAT-MODEL.md's SIGN-1.
//   - Enforce checks the connecting process's cgroup ANCESTRY against a
//     one-time-resolved, stable slice cgroup (see cgroup_slice.go and
//     resolveAPISliceCgroup below) -- not ssh-cert-api's own leaf cgroup,
//     which systemd destroys and recreates on every restart. This is what
//     makes the check structurally race-free: there is nothing to poll for,
//     since the compared-against value never changes across a restart. An
//     earlier, leaf-cgroup-polling version of this check denied the
//     legitimate, freshly-restarted ssh-cert-api on effectively every
//     restart -- see docs/vsock-connect-detection.md §4.6's history.
//
// LSMGuard is NOT wired into cmd/cerberus-vsock-watch's readyGate or
// detectorHealth/fatalShutdown: a successful attach here says nothing about
// whether detection is active (its narrower scope makes it a poor readiness
// proxy), and its failure changes risk posture, not detection posture — the
// same reasoning that already excludes TamperWatch/Heartbeat from both.
type LSMGuard struct {
	Allowlist *vsockwatch.Allowlist
	Shipper   vsockwatch.Shipper
	// Blocker, if set, is invoked for a denied event. Optional, not core: a
	// denied connect() already stopped that specific attempt, so this only
	// has the same marginal against-retries value block.go's ProcessKiller
	// already documents for the detective path.
	Blocker vsockwatch.Blocker

	// Enforce seeds the initial lsm_mode map value (monitor if false,
	// enforce if true) before the poll loop starts. See EnforceStatePath to
	// change this at runtime without a restart.
	Enforce bool
	// APISlice is the systemd slice unit exclusively containing
	// cerberus-api.service (e.g. "cerberus-api.slice") -- see
	// cgroup_slice.go's sliceCgroupPath doc comment for why this must be a
	// DEDICATED slice (nothing else may run in it: sharing it weakens the
	// ancestry check back toward "any process in this slice") and how its
	// on-disk path/ancestor level are computed, not assumed.
	APISlice string
	// PollInterval controls how often EnforceStatePath is re-checked.
	// Defaults to defaultLSMPollInterval if zero. The cgroup pin itself is
	// resolved once in Run (see resolveAPISliceCgroup), not on this
	// interval -- there is nothing left to poll for.
	PollInterval time.Duration
	// EnforceStatePath, if non-empty, is polled every PollInterval: its
	// content ("true"/"false", whitespace-trimmed) overrides the current
	// enforce mode at runtime. A missing file or unparseable content leaves
	// the mode unchanged — deliberately fail-safe, never guessed. See
	// readEnforceOverride.
	EnforceStatePath string

	// enforceActive is a Go-side snapshot of the enforce mode this process
	// itself last wrote to lsm_mode — read by the ring buffer consumer loop
	// to label each alert (never re-read from the kernel map, since only
	// this process ever writes it). Mode toggles are operator-driven and
	// rare, so the tiny window between a toggle and the consumer loop
	// observing it is a negligible, documented approximation, not a
	// correctness bug.
	enforceActive atomic.Bool
}

// Run loads and attaches the LSM program, seeds its policy maps (resolving
// the API slice's cgroup pin once via resolveAPISliceCgroup), starts the
// enforce-toggle poll loop, then blocks reading ring buffer events until ctx
// is canceled or an unrecoverable error occurs. Load/attach
// failures (missing CONFIG_BPF_LSM / inactive "bpf" LSM, insufficient
// privilege, or a verifier/BTF-attach rejection — see vsock_lsm.c's header
// comment for what is genuinely unconfirmed here) are returned as an error,
// exactly like Watcher.Run, so a caller running the tracepoint detector
// alongside this one is unaffected by this one failing to load. onReady, if
// non-nil, is called once the ring buffer reader is open — main.go does not
// wire this into its shared readiness gate; see LSMGuard's doc comment.
func (g *LSMGuard) Run(ctx context.Context, onReady func()) error {
	if err := features.HaveProgramType(cilium.LSM); err != nil {
		return fmt.Errorf("vsockwatch/ebpf: BPF_PROG_TYPE_LSM unsupported on this kernel (needs CONFIG_BPF_LSM=y and \"bpf\" in the lsm= boot parameter): %w", err)
	}

	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(lsmProgramObject))
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: parsing embedded LSM object: %w", err)
	}

	coll, err := cilium.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: loading LSM program into kernel: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["cerberus_lsm_check_connect"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded LSM object has no cerberus_lsm_check_connect program")
	}

	lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: attaching to socket_connect LSM hook: %w", err)
	}
	defer func() { _ = lnk.Close() }()

	policyMap, ok := coll.Maps["lsm_policy"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded LSM object has no lsm_policy map")
	}
	activeSlotMap, ok := coll.Maps["lsm_active_slot"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded LSM object has no lsm_active_slot map")
	}
	modeMap, ok := coll.Maps["lsm_mode"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded LSM object has no lsm_mode map")
	}
	eventsMap, ok := coll.Maps["lsm_events"]
	if !ok {
		return fmt.Errorf("vsockwatch/ebpf: embedded LSM object has no lsm_events ring buffer map")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: opening LSM ring buffer reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	pw := &lsmMapWriter{policy: policyMap, activeSlot: activeSlotMap, mode: modeMap}

	// Seed the initial mode before anything else, so there is never a
	// window where the program runs with an undefined mode (the map's own
	// zero value is already 0/monitor, matching Enforce's zero value, but
	// seed explicitly so --lsm-enforce takes effect immediately).
	initialMode := uint32(0)
	if g.Enforce {
		initialMode = 1
	}
	if err := pw.putMode(initialMode); err != nil {
		return fmt.Errorf("vsockwatch/ebpf: seeding initial lsm_mode: %w", err)
	}
	g.enforceActive.Store(g.Enforce)

	// Resolve the dedicated API slice's cgroup ID and ancestor level ONCE --
	// see resolveAPISliceCgroup's doc comment for why this eliminates the
	// restart race entirely rather than narrowing it. A failure here (the
	// slice never appears within apiSliceResolveAttempts tries) is returned
	// like any other LSM attach failure -- the caller in
	// cmd/cerberus-vsock-watch/main.go's lsmEnforceFatal treats that the
	// same as a load/attach failure when --lsm-enforce was requested.
	//
	// The kernel zero-initializes lsm_active_slot to 0, so slot 0 is already
	// the LIVE slot the instant the program is attached above (the ring
	// buffer reader is already open at this point, so a concurrent connect
	// is a real possibility, not a theoretical one). seedInitialPolicy
	// therefore follows the exact same write-the-INACTIVE-slot-then-flip
	// discipline as every other publish in this file, rather than writing
	// straight into slot 0 -- which would be a torn write against a live
	// reader, the very thing the double buffer exists to prevent.
	cg, level, err := resolveAPISliceCgroup(ctx, g.Allowlist.CgroupRoot, g.APISlice)
	if err != nil {
		return fmt.Errorf("vsockwatch/ebpf: resolving API slice cgroup pin: %w", err)
	}
	if err := seedInitialPolicy(pw, cg, level); err != nil {
		return err
	}

	pollInterval := g.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultLSMPollInterval
	}

	var pollWG sync.WaitGroup
	pollWG.Go(func() {
		g.pollLoop(ctx, pw, pollInterval)
	})
	defer pollWG.Wait()

	// ringbuf.Reader.Read blocks; unblock it on ctx cancellation by closing
	// the reader from a side goroutine — same shutdown pattern as
	// Watcher.Run (see that method's identical comment).
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
			return fmt.Errorf("vsockwatch/ebpf: reading LSM ring buffer: %w", err)
		}

		ev, err := decodeEvent(record.RawSample)
		if err != nil {
			// See Watcher.Run's identical handling: a malformed sample
			// shouldn't be possible, but must never kill the guard.
			continue
		}

		// vsock_lsm.c only ever emits an event when it detected a cgroup
		// mismatch, so "was this specific connect() denied" is exactly
		// "was enforce mode active at that moment" — see enforceActive's
		// doc comment for the (negligible) approximation this implies.
		enforceNow := g.enforceActive.Load()
		mode := "monitor"
		if enforceNow {
			mode = "enforce"
		}
		denied := enforceNow

		cls := g.Allowlist.Classify(ev)
		if g.Shipper != nil {
			if err := g.Shipper.Ship(ctx, vsockwatch.NewLSMBlockAlert(ev, cls, mode, denied)); err != nil {
				slog.Error("vsockwatch.lsm.ship.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
			}
		}

		if denied && g.Blocker != nil {
			if err := g.Blocker.Block(ctx, ev); err != nil {
				slog.Error("vsockwatch.lsm.block.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
			} else {
				slog.Error("vsockwatch.lsm.block.killed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe)
			}
		}
	}
}

// pollLoop checks EnforceStatePath for a runtime toggle every interval,
// until ctx is done. The cgroup pin itself is resolved once in Run, not
// refreshed here -- see Run's resolveAPISliceCgroup call and
// docs/vsock-connect-detection.md §4.6 for why polling the pin was the
// actual, structurally unwinnable bug this design closes.
func (g *LSMGuard) pollLoop(ctx context.Context, pw policyMapWriter, interval time.Duration) {
	lastMode := uint32(0)
	if g.Enforce {
		lastMode = 1
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if enforce, ok := readEnforceOverride(g.EnforceStatePath); ok {
			mode := uint32(0)
			if enforce {
				mode = 1
			}
			if mode != lastMode {
				if err := pw.putMode(mode); err != nil {
					slog.Error("vsockwatch.lsm.mode_write_failed", "error", err)
				} else {
					lastMode = mode
					g.enforceActive.Store(enforce)
					slog.Info("vsockwatch.lsm.mode_changed", "enforce", enforce)
				}
			}
		}
	}
}

// readEnforceOverride reads path's content and parses it as a bool
// ("true"/"false", whitespace-trimmed). ok is false — meaning "no change" —
// if path is empty, the file doesn't exist, or its content doesn't parse.
// This is deliberately fail-safe: a missing or malformed toggle file must
// never be silently treated as "enable" or "disable", only as "leave alone".
func readEnforceOverride(path string) (enforce bool, ok bool) {
	if path == "" {
		return false, false
	}
	// #nosec G304 -- path is LSMGuard.EnforceStatePath, operator configuration
	// (a systemd EnvironmentFile or CLI flag), not untrusted input.
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	v, err := strconv.ParseBool(strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("vsockwatch.lsm.enforce_state_file.invalid", "path", path, "error", err)
		return false, false
	}
	return v, true
}

// policyMapWriter is the seam LSMGuard's tests assert against: an
// implementation must always write the INACTIVE lsm_policy slot fully, THEN
// flip lsm_active_slot — never the reverse — so an in-kernel reader can
// never observe a torn write straddling allowed_cgroup_id/populated. See
// vsock_lsm.c's lsm_policy_slot/lsm_active_slot doc comments.
type policyMapWriter interface {
	putPolicySlot(slot uint32, cgroupID uint64, level uint32, populated bool) error
	putActiveSlot(slot uint32) error
	putMode(mode uint32) error
}

// lsmMapWriter is policyMapWriter's real, BPF-map-backed implementation.
type lsmMapWriter struct {
	policy     *cilium.Map
	activeSlot *cilium.Map
	mode       *cilium.Map
}

var _ policyMapWriter = (*lsmMapWriter)(nil)

// putPolicySlot writes a struct lsm_policy_slot (vsock_lsm.c) to the given
// map slot; see encodePolicySlot for the byte layout.
func (w *lsmMapWriter) putPolicySlot(slot uint32, cgroupID uint64, level uint32, populated bool) error {
	return w.policy.Put(slot, encodePolicySlot(cgroupID, level, populated))
}

// encodePolicySlot encodes a struct lsm_policy_slot (vsock_lsm.c)
// byte-for-byte: 8-byte allowed_cgroup_id, 4-byte populated, 4-byte
// ancestor_level. A standalone function so its exact layout is
// unit-testable without a real BPF map (this sandbox cannot create one --
// see lsm_test.go).
func encodePolicySlot(cgroupID uint64, level uint32, populated bool) []byte {
	var pop uint32
	if populated {
		pop = 1
	}
	buf := make([]byte, 16)
	binary.NativeEndian.PutUint64(buf[0:8], cgroupID)
	binary.NativeEndian.PutUint32(buf[8:12], pop)
	binary.NativeEndian.PutUint32(buf[12:16], level)
	return buf
}

func (w *lsmMapWriter) putActiveSlot(slot uint32) error {
	return w.activeSlot.Put(uint32(0), slot)
}

func (w *lsmMapWriter) putMode(mode uint32) error {
	return w.mode.Put(uint32(0), mode)
}
