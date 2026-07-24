package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/pkilar/cerberus/vsockwatch"
)

// eventSize matches sizeof(struct vsock_connect_event) in vsock_connect.c
// (and vsock_lsm.c, which reuses the identical struct): 4+4+4+4 (pid, tgid,
// uid, gid) + 8 (cgroup_id) + 16 (comm) = 40 bytes, no padding since
// cgroup_id falls on an 8-byte-aligned offset already.
const eventSize = 40

// decodeEvent parses raw ring buffer bytes into a vsockwatch.Event. raw must
// be exactly eventSize bytes, matching struct vsock_connect_event field-for-
// field. Both Watcher (vsock_connect.c's tracepoint ringbuf) and LSMGuard
// (vsock_lsm.c's lsm_events ringbuf) decode this identical wire format, so
// this lives here rather than duplicated in each file.
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

// enclaveAddr is a fixed VMAddr representing the enclave target, since both
// vsock_connect.c and vsock_lsm.c only ever emit events that already matched
// the enclave's (CID, port) in-kernel — there's nothing left to decode on
// this side, but Event.Addr is populated for symmetry with the auditd path
// and so Allowlist.Classify's IsEnclaveTarget() defensive check still passes.
func enclaveAddr() vsockwatch.VMAddr {
	return vsockwatch.EnclaveVMAddr()
}

// resolveExe reads /proc/<pid>/exe. Declared as a var so tests can override
// it without needing a real process tree.
var resolveExe = defaultResolveExe
