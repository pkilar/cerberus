// vsock_connect.c — eBPF probe for docs/vsock-connect-detection.md.
//
// Detects an AF_VSOCK connect(2) targeting the Cerberus enclave's (CID,
// port) from ANY process, by hooking the syscalls:sys_enter_connect
// tracepoint and inspecting the userspace sockaddr the caller passed in.
// Filtering happens entirely in-kernel, so only genuine vsock-to-enclave
// connects ever reach the ring buffer — no post-filtering needed on the Go
// side (contrast with the auditd path in audit.go, which has to post-filter
// because auditd itself can't decode the sockaddr in the rule).
//
// Deliberately NOT a CO-RE program: it reads no kernel-internal struct
// (task_struct, socket, etc.) whose layout could change across kernel
// versions or require BTF relocations. It only touches:
//   - struct sockaddr_vm — a stable UAPI structure (linux/vm_sockets.h),
//     copied from the CALLING PROCESS'S OWN userspace argument to connect(),
//     not a kernel-internal structure at all.
//   - struct trace_event_raw_sys_enter — the tracepoint's argument struct,
//     whose {common_type, common_flags, common_preempt_count, common_pid,
//     id, args[6]} layout has been part of ftrace's stable ABI for well
//     over a decade (used unchanged by bcc/libbpf-tools since long before
//     CO-RE existed).
//   - generic eBPF helpers (bpf_get_current_pid_tgid, bpf_probe_read_user,
//     ringbuf helpers) — never kernel-version-dependent.
//
// This means the compiled object needs NO kernel BTF and no vmlinux.h to
// build, and (unlike a CO-RE program) will load on any kernel with
// BPF_PROG_TYPE_TRACEPOINT + BPF_MAP_TYPE_RINGBUF support (5.8+) — but it
// has NOT been load-tested against a live kernel as part of this change: the
// development sandbox this was written in has no /sys/kernel/btf/vmlinux,
// no debugfs tracing tree, and no privilege to load BPF programs. Before
// deploying, a maintainer MUST:
//   1. Confirm this tracepoint's live format matches the struct below:
//        cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
//      (or /sys/kernel/tracing/... if debugfs isn't mounted at the usual
//      path) and diff the field order/offsets against trace_event_raw_sys_enter.
//   2. Load the compiled object and confirm the verifier accepts it.
//   3. Drive an actual vsock connect (e.g. a throwaway test binary) and
//      confirm an event is emitted with the expected pid/uid/comm.
// See docs/vsock-connect-detection.md §6 (testing plan) and §7 (this is a
// detective, not preventive, control regardless).

#include <linux/bpf.h>
#include <linux/types.h>

// Minimal libbpf-compatible macros, defined here instead of pulling in
// bpf_helpers.h, so this file has no dependency beyond the kernel's own
// UAPI headers (linux/bpf.h, linux/types.h) that any build host already has.
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]

// Generic eBPF helpers, declared directly against the stable numeric helper
// IDs in enum bpf_func_id (linux/bpf.h) — the same technique used by the
// kernel's own samples/bpf/*_kern.c before libbpf's bpf_helpers.h wrappers
// became the norm. Helper IDs are append-only and never renumbered, so this
// is stable across kernel versions.
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_user;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) =
    (void *)BPF_FUNC_get_current_comm;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

// AF_VSOCK is a stable kernel UAPI constant; unlike linux/vm_sockets.h's
// struct sockaddr_vm, the family *number* itself is defined in userspace
// libc headers (sys/socket.h), not a kernel UAPI header, so it's spelled out
// here rather than included.
#define AF_VSOCK 40

// The enclave's VSOCK CID and listening port. These MUST match
// constants.EnclaveCID / constants.EnclaveListeningPort (constants/constants.go)
// — kept as plain #defines (rather than reading them at runtime, which
// BPF programs cannot easily do from Go-side config) so a site that ever
// changes those constants must rebuild this object with matching -D flags;
// see ebpf/Makefile.
#ifndef ENCLAVE_CID
#define ENCLAVE_CID 16
#endif
#ifndef ENCLAVE_PORT
#define ENCLAVE_PORT 5000
#endif

// sizeof(struct sockaddr_vm): 2-byte family + 2-byte reserved + 4-byte port +
// 4-byte cid + 1-byte flags + padding to sizeof(struct sockaddr) (16 bytes).
// See linux/vm_sockets.h and vsockwatch/vsockaddr.go (the Go-side twin of
// this decode).
#define SOCKADDR_VM_SIZE 16

// Mirrors the stable syscalls:sys_enter_connect tracepoint format. See the
// verification step in the file header comment before deploying to a new
// kernel/arch.
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

// vsock_connect_event is the wire format pushed to the Go-side ring buffer
// reader (ebpf/loader.go). All fields are naturally aligned (uint64 at
// offset 16), so there is no compiler-inserted padding to account for on
// either side of the ABI.
struct vsock_connect_event {
    __u32 pid;   // kernel-visible tid (bottom 32 bits of pid_tgid)
    __u32 tgid;  // userspace-visible pid (top 32 bits of pid_tgid)
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[16]; // TASK_COMM_LEN
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    const void *uservaddr = (const void *)ctx->args[1];

    unsigned char buf[SOCKADDR_VM_SIZE];
    if (bpf_probe_read_user(buf, sizeof(buf), uservaddr) != 0) {
        return 0; // unreadable / not our target
    }

    __u16 family;
    __builtin_memcpy(&family, buf + 0, sizeof(family));
    if (family != AF_VSOCK) {
        return 0;
    }

    __u32 port, cid;
    __builtin_memcpy(&port, buf + 4, sizeof(port));
    __builtin_memcpy(&cid, buf + 8, sizeof(cid));
    if (cid != ENCLAVE_CID || port != ENCLAVE_PORT) {
        return 0; // a vsock connect, but not to the enclave — not our concern
    }

    struct vsock_connect_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        return 0; // ring buffer full; drop rather than block the caller
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    ev->pid = (__u32)pid_tgid;
    ev->tgid = (__u32)(pid_tgid >> 32);
    ev->uid = (__u32)uid_gid;
    ev->gid = (__u32)(uid_gid >> 32);
    ev->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
