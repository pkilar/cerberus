// vsock_lsm.c — preventive LSM gate for docs/vsock-connect-detection.md §4.6.
//
// Companion to vsock_connect.c (the detective tracepoint probe): this
// program attaches to a BPF_PROG_TYPE_LSM hook which — unlike a tracepoint —
// CAN deny a connect() before it succeeds, by returning a nonzero value. It
// denies an AF_VSOCK connect(2) to the Cerberus enclave's (CID, port) only
// from a process outside the pinned ssh-cert-api cgroup, and only when
// enforcement is turned on. See the Go-side LSMGuard (vsockwatch/ebpf/lsm.go)
// for how the policy maps below get populated and toggled.
//
// WHY CGROUP-ONLY: an LSM hook must decide allow/deny synchronously, entirely
// in-kernel — there is no way to pause the connect() syscall and ask a Go
// userspace process "does /proc/<pid>/exe match?" the way Allowlist.Classify
// does for the detective path. bpf_get_current_ancestor_cgroup_id() is the
// only identity signal that's cheap, available entirely in-kernel, and
// (checked against a stable ANCESTOR slice cgroup rather than
// ssh-cert-api's own ever-recreated leaf cgroup) doesn't require chasing a
// moving target across every cerberus-api.service restart — see
// cgroup_slice.go's doc comment and
// docs/vsock-connect-detection.md §4.6's history for why the leaf-cgroup
// version of this check was fundamentally unwinnable as a poll-based race.
// This control is still DELIBERATELY NARROWER than the detective path:
// anything sharing ssh-cert-api's dedicated slice — including a
// compromised ssh-cert-api itself — still passes. See
// docs/vsock-connect-detection.md §4.6 and docs/THREAT-MODEL.md's SIGN-1:
// this does not close SIGN-1.
//
// WHY THIS STILL NEEDS NO vmlinux.h FOR ITS OWN LOGIC: unlike a CO-RE program
// that reads specific FIELDS of a kernel struct (requiring field-offset
// relocations against the target kernel's BTF), this program only ever
// treats `address` (the hook's sockaddr argument) as an OPAQUE pointer,
// copied with bpf_probe_read_kernel exactly like vsock_connect.c's
// bpf_probe_read_user treats connect(2)'s userspace sockaddr argument — same
// sockaddr_vm decode, same offsets, just a kernel-memory read instead of a
// userspace one (the address is already kernel-copied by the time an LSM
// hook sees it).
//
// SEC NAME: "lsm/socket_connect", NOT "lsm/security_socket_connect". BPF LSM
// programs attach to the kernel's per-hook trampoline, which cilium/ebpf
// resolves as the BTF function "bpf_lsm_" + <the SEC("lsm/...") suffix> (see
// github.com/cilium/ebpf's prog.go, findProgramTargetInKernel: `case
// match{LSM, AttachLSMMac}: typeName = "bpf_lsm_" + name`). The kernel only
// ever generates a bpf_lsm_<hookname> trampoline for the hook's bare name as
// declared in include/linux/lsm_hook_defs.h's LSM_HOOK(...) list (here,
// "socket_connect") — never for security_socket_connect(), which is just the
// C-level dispatcher in security/security.c that calls every registered
// LSM's hook (SELinux's, AppArmor's, and this one) in turn. Using the
// dispatcher's name here would make cilium/ebpf look for a nonexistent
// "bpf_lsm_security_socket_connect" BTF function and fail to attach.
//
// CALLING CONVENTION: the exported SEC("lsm/...") function takes exactly ONE
// parameter, `ctx` — a pointer to an array of `__u64` values, one per
// argument of the underlying hook (here: sock, address, addrlen, in that
// order) — NOT the hook's real arguments passed directly in registers r1,
// r2, r3 as an ordinary multi-parameter C function. This is confirmed by
// docs.ebpf.io's BPF_PROG_TYPE_LSM page: "LSM programs are invoked with an
// array of __u64 values equal in length to the amount of arguments of the
// LSM hook." libbpf's BPF_PROG() macro (tools/lib/bpf/bpf_tracing.h) exists
// specifically to unwrap this ctx array into nicely typed local variables —
// this file deliberately doesn't use that macro (same no-extra-headers
// reason as everywhere else here), so it does the unwrapping by hand below:
// `ctx[0]`/`ctx[1]`/`ctx[2]`, cast to the types documented in the function's
// own comment. A FIRST REAL-HARDWARE LOAD ATTEMPT (2026-07-24) got this
// wrong — the function was declared with three native parameters (`sock`,
// `address`, `addrlen`) instead of the single `ctx` array — and the verifier
// rejected it: "load program: permission denied: 0: (bf) r4 = r2: R2
// !read_ok". That's the BPF verifier, not a capability/SELinux/AppArmor
// denial (CAP_MAC_ADMIN was present and correct): with a 3-parameter native
// signature, clang emits code expecting `address` in r2 per the ordinary BPF
// calling convention, but the LSM trampoline only ever populates r1 (the
// ctx-array pointer) — r2 is simply never written by the caller, hence
// NOT_INIT ("R2 !read_ok"), regardless of what type that unread register was
// declared as. An earlier attempt at this fix (changing `void *` parameters
// to `struct socket *`/`struct sockaddr *`, still as 3 native params) also
// failed identically on real hardware, because it addressed a plausible-but-
// wrong theory (BTF type matching) rather than this actual mismatch — the
// verifier error was byte-for-byte unchanged, which in hindsight makes sense
// since the underlying instructions never changed either: void*-vs-struct*
// only affects a C type annotation, not which registers a plain multi-
// parameter function reads. This IS the fix; see the function definition
// below.
//
// This whole saga incidentally confirms the OTHER item this file used to
// flag as unconfirmed — whether "socket_connect" is even exposed to
// BPF_PROG_TYPE_LSM on this kernel — resolves positively: the verifier could
// only have compared argument types against a real target signature (3
// hook arguments, matching security_socket_connect) if attach_btf_id
// resolution had already succeeded. Had the bpf_lsm_socket_connect
// trampoline not existed, cilium/ebpf's own client-side BTF lookup would
// have failed before ever reaching the kernel's bpf(BPF_PROG_LOAD, ...)
// syscall, and there would be no verifier log at all.
//
// STILL UNCONFIRMED as of this fix: whether the corrected ctx-array
// signature actually loads AND attaches cleanly end-to-end on real
// hardware — this fix has only been verified locally (disassembly/BTF
// inspection, `go test`), NOT via another real load attempt. A maintainer
// MUST re-run the real-hardware items in docs/vsock-connect-detection.md
// §6/§4.6 (automated by the check_lsm_kernel_support /
// check_lsm_monitor_dry_run checks in verify-vsock-watch-hardware.sh)
// before ever enabling --lsm-enforce again.
//
// See vsock_connect.c's header comment for the shared conventions reused
// here: hand-rolled helper declarations against stable numeric BPF_FUNC_*
// ids (no bpf_helpers.h dependency) and the sockaddr_vm decode.

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Generic eBPF helpers, declared directly against the stable numeric helper
// IDs in enum bpf_func_id (linux/bpf.h) — see vsock_connect.c's header
// comment for why this avoids a bpf_helpers.h dependency.
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_kernel;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) =
    (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_ancestor_cgroup_id)(int ancestor_level) =
    (void *)BPF_FUNC_get_current_ancestor_cgroup_id;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

// AF_VSOCK is a stable kernel UAPI constant; see vsock_connect.c for why it's
// spelled out here rather than included from a userspace libc header.
#define AF_VSOCK 40

// MUST match constants.EnclaveCID / constants.EnclaveListeningPort — see
// vsock_connect.c's identical comment on these two #defines.
#ifndef ENCLAVE_CID
#define ENCLAVE_CID 16
#endif
#ifndef ENCLAVE_PORT
#define ENCLAVE_PORT 5000
#endif

// sizeof(struct sockaddr_vm) — see vsock_connect.c and vsockwatch/vsockaddr.go.
#define SOCKADDR_VM_SIZE 16

// Reused byte-for-byte from vsock_connect.c's identical struct: both
// ringbufs are decoded by the same Go-side code
// (vsockwatch/ebpf/event_codec.go), regardless of which one an event
// actually arrived on.
struct vsock_connect_event {
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[16];
};

// lsm_policy_slot is one entry of the double-buffered lsm_policy map below.
// allowed_cgroup_id is the cgroup v2 inode of the DEDICATED systemd slice
// ssh-cert-api's service is expected to run under (see cgroup_slice.go's
// doc comment for why this is a stable ancestor slice, not ssh-cert-api's
// own ever-recreated leaf cgroup). ancestor_level is how many cgroup levels
// up from the connecting process bpf_get_current_ancestor_cgroup_id must
// look to reach that slice -- computed on the Go side (cgroup_slice.go),
// never hardcoded, since it depends on how the configured slice name nests.
// populated distinguishes "userspace has written this slot" from the zero
// value, so an unpopulated or freshly-booted slot is never mistaken for
// "expect cgroup 0" -- this is what makes the fail-open bootstrap below
// structural rather than a convention to remember.
struct lsm_policy_slot {
    __u64 allowed_cgroup_id;
    __u32 populated;
    __u32 ancestor_level;
};

// lsm_policy is double-buffered (2 slots): the Go-side LSMGuard writes a
// full new policy into the currently INACTIVE slot, then flips
// lsm_active_slot as a single-word publish barrier. This avoids an in-kernel
// reader ever observing a torn write straddling allowed_cgroup_id/populated
// during a live cgroup-pin update — most likely to matter exactly during a
// cerberus-api.service restart, the highest-stakes moment for this feature.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct lsm_policy_slot);
    __uint(max_entries, 2);
} lsm_policy SEC(".maps");

// lsm_active_slot: 0 or 1, selecting which lsm_policy index is authoritative.
// A lone aligned word write/read is atomic on every architecture this
// project targets, making this the publish barrier for lsm_policy above.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} lsm_active_slot SEC(".maps");

// lsm_mode: 0 = monitor (log would-deny, never return an error), 1 = enforce.
// Deliberately its own map, independent of lsm_policy, so toggling
// --lsm-enforce at runtime is a single scalar write unrelated to the
// cgroup-pin logic.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} lsm_mode SEC(".maps");

// lsm_events carries a would-deny (monitor mode) or actually-denied (enforce
// mode) event to userspace. Deliberately a SEPARATE ring buffer from
// vsock_connect.c's "events" map: this program lives in a different
// collection/ELF object and attaches via a different mechanism (LSM vs.
// tracepoint), so the two detectors' failure domains stay fully independent.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} lsm_events SEC(".maps");

// ctx is the raw argument array the LSM trampoline actually provides — see
// the file header's "CALLING CONVENTION" note. security_socket_connect's
// real signature is (struct socket *sock, struct sockaddr *address, int
// addrlen), in that order, so ctx[0]/ctx[1]/ctx[2] are exactly those three
// values, each a plain u64 the trampoline copied out of the real call's
// argument registers. sock (ctx[0]) is unused. address (ctx[1]) stays an
// opaque `void *` deliberately (see "WHY THIS STILL NEEDS NO vmlinux.h"
// above) — bpf_probe_read_kernel needs no more than that, and (unlike a
// native-parameter signature) the verifier never tries to type-match a
// ctx-array cast against the kernel's real argument types anyway, so there
// is no reason to forward-declare struct names here. addrlen (ctx[2]) is
// truncated to `int` via a plain C cast, which correctly recovers the
// original 32-bit value's exact bit pattern regardless of how the upper 32
// bits of the saved u64 slot were extended.
SEC("lsm/socket_connect")
int cerberus_lsm_check_connect(unsigned long long *ctx) {
    void *address = (void *)ctx[1];
    int addrlen = (int)ctx[2];

    if (addrlen < SOCKADDR_VM_SIZE) {
        return 0; // too short to be sockaddr_vm; not our concern, allow
    }

    unsigned char buf[SOCKADDR_VM_SIZE];
    // address is already kernel memory at this hook (unlike the tracepoint's
    // userspace uservaddr in vsock_connect.c), hence _kernel not _user.
    if (bpf_probe_read_kernel(buf, sizeof(buf), address) != 0) {
        return 0; // unreadable; allow rather than guess
    }

    __u16 family;
    __builtin_memcpy(&family, buf + 0, sizeof(family));
    if (family != AF_VSOCK) {
        // Not vsock at all — the overwhelming majority of calls through this
        // hook, since security_socket_connect fires for EVERY socket family
        // on the host. This is the single highest-blast-radius line in the
        // whole program: a bug here that let a non-vsock connect reach the
        // mismatch/enforce logic below could deny arbitrary host
        // connectivity, not just fail to alert on one thing.
        return 0;
    }

    __u32 port, cid;
    __builtin_memcpy(&port, buf + 4, sizeof(port));
    __builtin_memcpy(&cid, buf + 8, sizeof(cid));
    if (cid != ENCLAVE_CID || port != ENCLAVE_PORT) {
        return 0; // a vsock connect, but not to the enclave — not our concern
    }

    __u32 zero = 0;
    __u32 *active_idx = bpf_map_lookup_elem(&lsm_active_slot, &zero);
    struct lsm_policy_slot *policy = 0;
    if (active_idx) {
        __u32 idx = *active_idx;
        policy = bpf_map_lookup_elem(&lsm_policy, &idx);
    }
    __u32 *mode_ptr = bpf_map_lookup_elem(&lsm_mode, &zero);
    __u32 enforce = mode_ptr ? *mode_ptr : 0;

    // Fail-open bootstrap: an absent/unpopulated policy slot (before
    // userspace's first publish, or a lookup failure) means "no mismatch",
    // never "deny everything" — see lsm_policy_slot's doc comment. The
    // ancestor level defaults to 0 (the cgroup root) when unpopulated,
    // which is harmless here since the populated check below already
    // short-circuits mismatch to false in that case.
    __u32 level = policy ? policy->ancestor_level : 0;
    __u64 cgroup_id = bpf_get_current_ancestor_cgroup_id((int)level);
    int mismatch = (policy && policy->populated) ? (cgroup_id != policy->allowed_cgroup_id) : 0;

    if (mismatch) {
        // Emit an event in BOTH modes — the ring buffer is the single source
        // of "would-deny" truth regardless of whether enforcement actually
        // denied anything this time.
        struct vsock_connect_event *ev = bpf_ringbuf_reserve(&lsm_events, sizeof(*ev), 0);
        if (ev) {
            __u64 pid_tgid = bpf_get_current_pid_tgid();
            __u64 uid_gid = bpf_get_current_uid_gid();
            ev->pid = (__u32)pid_tgid;
            ev->tgid = (__u32)(pid_tgid >> 32);
            ev->uid = (__u32)uid_gid;
            ev->gid = (__u32)(uid_gid >> 32);
            ev->cgroup_id = cgroup_id;
            bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
            bpf_ringbuf_submit(ev, 0);
        }
    }

    // The ONLY line in this file that can return a denial.
    if (mismatch && enforce) {
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
