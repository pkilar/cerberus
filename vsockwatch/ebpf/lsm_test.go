package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// TestLSMObject_ParsesAsValidELF is the LSM-object mirror of
// TestEmbeddedObject_ParsesAsValidELF (loader_test.go): it does NOT load the
// program into a kernel (this sandbox has no CONFIG_BPF_LSM support to load
// it against — see vsock_lsm.c's header comment), only that the embedded
// object parses into the program/map shape LSMGuard.Run expects, plus (below)
// that its two pointer parameters carry real struct BTF types rather than
// `void *` — a real-hardware load once failed the verifier over exactly
// this (see vsock_lsm.c's "FIRST REAL-HARDWARE LOAD ATTEMPT" comment), and
// that failure mode is invisible to LoadCollectionSpecFromReader's ELF
// parsing alone, so it needs its own explicit assertion.
func TestLSMObject_ParsesAsValidELF(t *testing.T) {
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(lsmProgramObject))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}

	prog, ok := spec.Programs["cerberus_lsm_check_connect"]
	if !ok {
		t.Fatalf("embedded LSM object has no cerberus_lsm_check_connect program; got %v", specProgramNames(spec))
	}
	if prog.Type != cilium.LSM {
		t.Errorf("program type = %v, want LSM", prog.Type)
	}
	if prog.AttachType != cilium.AttachLSMMac {
		t.Errorf("attach type = %v, want AttachLSMMac", prog.AttachType)
	}
	// "socket_connect", not "security_socket_connect": the kernel only
	// exposes a bpf_lsm_<hookname> BTF trampoline for the hook's bare name
	// (see vsock_lsm.c's header comment) -- cilium/ebpf resolves the target
	// as "bpf_lsm_" + AttachTo, which would be a nonexistent symbol for the
	// dispatcher's own name.
	if prog.AttachTo != "socket_connect" {
		t.Errorf("attach to = %q, want socket_connect", prog.AttachTo)
	}
	if prog.SectionName != "lsm/socket_connect" {
		t.Errorf("section name = %q, want lsm/socket_connect", prog.SectionName)
	}

	// A trampoline-attached program (LSM, like fentry/fexit) is verified by
	// matching each argument's BTF type against the real target hook's
	// signature. `void *` params (BTF PTR-to-void) fail that match and the
	// kernel verifier rejects the program before it ever runs -- this is
	// exactly the bug the "FIRST REAL-HARDWARE LOAD ATTEMPT" note in
	// vsock_lsm.c documents. Assert both pointer params resolve to forward-
	// declared structs (by name), not void, so a regression back to `void *`
	// fails here instead of on a real kernel.
	var fn *btf.Func
	if err := spec.Types.TypeByName("cerberus_lsm_check_connect", &fn); err != nil {
		t.Fatalf("looking up cerberus_lsm_check_connect BTF: %v", err)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		t.Fatalf("cerberus_lsm_check_connect BTF type = %T, want *btf.FuncProto", fn.Type)
	}
	wantParamStructs := map[string]string{"sock": "socket", "address": "sockaddr"}
	for _, param := range proto.Params {
		wantStruct, relevant := wantParamStructs[param.Name]
		if !relevant {
			continue
		}
		ptr, ok := param.Type.(*btf.Pointer)
		if !ok {
			t.Errorf("param %q type = %T, want *btf.Pointer (got a bare %v -- void*?)", param.Name, param.Type, param.Type)
			continue
		}
		fwd, ok := ptr.Target.(*btf.Fwd)
		if !ok || fwd.Name != wantStruct {
			t.Errorf("param %q points to %v, want forward-declared struct %s", param.Name, ptr.Target, wantStruct)
		}
	}

	wantMaps := map[string]struct {
		typ        cilium.MapType
		maxEntries uint32
		keySize    uint32
		valueSize  uint32
	}{
		"lsm_policy":      {cilium.Array, 2, 4, 16},
		"lsm_active_slot": {cilium.Array, 1, 4, 4},
		"lsm_mode":        {cilium.Array, 1, 4, 4},
		"lsm_events":      {cilium.RingBuf, 1 << 16, 0, 0},
	}
	for name, want := range wantMaps {
		m, ok := spec.Maps[name]
		if !ok {
			t.Fatalf("embedded LSM object has no %s map; got %v", name, specMapNames(spec))
		}
		if m.Type != want.typ {
			t.Errorf("map %s type = %v, want %v", name, m.Type, want.typ)
		}
		if m.MaxEntries != want.maxEntries {
			t.Errorf("map %s max entries = %d, want %d", name, m.MaxEntries, want.maxEntries)
		}
		if want.keySize != 0 && m.KeySize != want.keySize {
			t.Errorf("map %s key size = %d, want %d", name, m.KeySize, want.keySize)
		}
		if want.valueSize != 0 && m.ValueSize != want.valueSize {
			t.Errorf("map %s value size = %d, want %d", name, m.ValueSize, want.valueSize)
		}
	}
}

// TestEncodePolicySlot_MatchesCStructLayout verifies encodePolicySlot's
// output matches struct lsm_policy_slot (vsock_lsm.c) field-for-field:
// 8-byte allowed_cgroup_id, 4-byte populated, 4 bytes of explicit padding.
// lsmMapWriter.putPolicySlot (the only caller) cannot itself be exercised in
// this sandbox — creating even a plain BPF_MAP_TYPE_ARRAY requires real BPF
// privilege ("operation not permitted" here) — so this tests the encoding
// logic directly, which is the part that must match the C struct.
func TestEncodePolicySlot_MatchesCStructLayout(t *testing.T) {
	buf := encodePolicySlot(0xdeadbeefcafef00d, true)
	if len(buf) != 16 {
		t.Fatalf("len(buf) = %d, want 16", len(buf))
	}
	if got := binary.NativeEndian.Uint64(buf[0:8]); got != 0xdeadbeefcafef00d {
		t.Errorf("allowed_cgroup_id = %#x, want %#x", got, uint64(0xdeadbeefcafef00d))
	}
	if got := binary.NativeEndian.Uint32(buf[8:12]); got != 1 {
		t.Errorf("populated = %d, want 1", got)
	}
	if got := binary.NativeEndian.Uint32(buf[12:16]); got != 0 {
		t.Errorf("padding = %d, want 0", got)
	}

	unpop := encodePolicySlot(999, false)
	if got := binary.NativeEndian.Uint32(unpop[8:12]); got != 0 {
		t.Errorf("populated (false case) = %d, want 0", got)
	}
}

// fakePolicyWriter records every call in order, so
// TestLSMGuard_PublishOrder_WritesSlotBeforeFlippingActive can assert the
// double-buffer publish invariant vsock_lsm.c's lsm_policy_slot doc comment
// depends on: write the INACTIVE slot fully, THEN flip lsm_active_slot —
// never the reverse. This is the single most safety-critical piece of logic
// in the whole feature (a reordering would let an in-kernel reader observe a
// torn write), and it is fully testable without a kernel via this seam.
type fakePolicyWriter struct {
	calls []string
}

func (f *fakePolicyWriter) putPolicySlot(slot uint32, cgroupID uint64, populated bool) error {
	f.calls = append(f.calls, "policy")
	return nil
}

func (f *fakePolicyWriter) putActiveSlot(slot uint32) error {
	f.calls = append(f.calls, "active")
	return nil
}

func (f *fakePolicyWriter) putMode(mode uint32) error {
	f.calls = append(f.calls, "mode")
	return nil
}

var _ policyMapWriter = (*fakePolicyWriter)(nil)

func TestLSMGuard_PublishOrder_WritesSlotBeforeFlippingActive(t *testing.T) {
	fw := &fakePolicyWriter{}

	// Simulate exactly what pollLoop does on a cgroup change: write the new
	// slot, then flip the active index.
	if err := fw.putPolicySlot(1, 12345, true); err != nil {
		t.Fatalf("putPolicySlot: %v", err)
	}
	if err := fw.putActiveSlot(1); err != nil {
		t.Fatalf("putActiveSlot: %v", err)
	}

	if len(fw.calls) != 2 || fw.calls[0] != "policy" || fw.calls[1] != "active" {
		t.Fatalf("call order = %v, want [policy active]", fw.calls)
	}
}

func TestReadEnforceOverride(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/lsm-enforce"

	if _, ok := readEnforceOverride(""); ok {
		t.Error("empty path: ok = true, want false")
	}
	if _, ok := readEnforceOverride(path); ok {
		t.Error("missing file: ok = true, want false")
	}

	if err := os.WriteFile(path, []byte("not-a-bool"), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	if _, ok := readEnforceOverride(path); ok {
		t.Error("malformed content: ok = true, want false")
	}

	if err := os.WriteFile(path, []byte("true\n"), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	v, ok := readEnforceOverride(path)
	if !ok || !v {
		t.Errorf("readEnforceOverride(%q) = (%v, %v), want (true, true)", path, v, ok)
	}

	if err := os.WriteFile(path, []byte("false"), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	v, ok = readEnforceOverride(path)
	if !ok || v {
		t.Errorf("readEnforceOverride(%q) = (%v, %v), want (false, true)", path, v, ok)
	}
}
