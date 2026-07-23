# VSOCK-Connect Detection Design

> **Status:** Implemented (Option C — both detectors), plus an opt-in reactive-kill response (§4.5; default off)
> and an opt-in, monitor-first preventive LSM gate (§4.6; default off, dry-run before enforcement).
> Companion to `docs/THREAT-MODEL.md` (`SIGN-1`).
> **Kind of control:** Primarily detective, plus a narrow, opt-in preventive gate (§4.6) that only blocks by
> cgroup identity. See §7 for why no host-side control can fully prevent `SIGN-1` — the LSM gate narrows the gap,
> it does not close it.
> The opt-in reactive kill in §4.5 is a mitigation response, not prevention either — see that section.
> **Code:** `vsockwatch/` (allowlist, alerting, auditd correlator, tamper watch, heartbeat, reactive-kill blocker)
> and `vsockwatch/ebpf/` (the eBPF loader/probe and the LSM gate loader), wired together in
> `cmd/cerberus-vsock-watch/main.go`. Packaged as `cerberus-vsock-watch` (RPM/deb/Arch — see `packaging/`).
>
> **Read before deploying:** the eBPF probe (`vsockwatch/ebpf/src/vsock_connect.c`) was written, compiled, and
> ELF-validated (`go test ./vsockwatch/ebpf/...`) in a development sandbox with no kernel BTF, no debugfs tracing
> tree, and no privilege to load BPF programs. It has genuinely never been load-tested against a live kernel or
> exercised against a real `connect(2)` syscall as part of this change — only its ELF structure (program/map/BTF
> sections, ring buffer event decoding) has been verified. The auditd path, by contrast, HAS been exercised
> end-to-end with the real compiled `cerberus-vsock-watch` binary against a synthetic audit log (§6) and is
> covered by an in-process integration test. Before relying on the eBPF detector in production, a maintainer
> must complete the real-hardware items in §6 — automated by `verify-vsock-watch-hardware.sh` (repo root) and
> walked through in `docs/vsock-connect-verification-runbook.md`. The LSM gate (`vsockwatch/ebpf/src/vsock_lsm.c`,
> §4.6) carries the SAME caveat, plus its own: it has never been attached to a live kernel's
> `security_socket_connect` hook, and even the exact BTF attach-point name and parameter-type compatibility are
> unconfirmed — see that file's header comment. Never enable `--lsm-enforce` without first running
> `--lsm-monitor` alone across at least one real `cerberus-api.service` restart.

## 1. Problem statement

`SIGN-1` in the threat model (`docs/THREAT-MODEL.md`) documents the accepted residual: VSOCK between the EC2
host and the enclave has no transport-layer authentication (`docs/THREAT-MODEL.md:53`), and the enclave only
validates the *structure* of an `EnclaveSigningRequest` (`ssh-cert-signer/internal/handlers/sign-public-key.go:177-198`),
never the *policy* — that happens entirely on the host, inside `ssh-cert-api`. Any process with root on the host
can therefore dial the enclave directly —

```go
vsock.Dial(16 /* enclave CID */, 5000 /* constants.EnclaveListeningPort */, nil)
```

— construct an `EnclaveSigningRequest` with arbitrary `ValidPrincipals`, and mint a certificate the Casbin
authorizer would never have granted. This is architectural: the CID identifies a *VM*, not a *process*, so the
enclave has no way to distinguish `ssh-cert-api` from any other root-owned process on the same host.

This design adds a **detective** control: alert, in near-real-time, whenever a process other than the known-good
`ssh-cert-api` opens a VSOCK connection to the enclave. It does not attempt to block the connection (see §7).

## 2. Goals / non-goals

**Goals**
- Detect any `AF_VSOCK` `connect()` to `(CID=16, port=5000)` from a process other than the legitimate
  `ssh-cert-api`, within seconds.
- Zero false positives against the known-legitimate call sites (see §5).
- Ship the alert off-host before a host-resident attacker could plausibly suppress it.
- Two independent detection paths, so disabling one doesn't blind the system silently.

**Non-goals**
- Not a prevention barrier. A sufficiently patient root attacker can eventually disable any host-side agent —
  see §7 for the honest accounting of that limit, in the same spirit as the existing `KMS-1` writeup. (An opt-in
  reactive-kill response exists — §4.5 — but it is a mitigation, not prevention: see that section for why.)
- Does not replace or interact with Casbin/rate-limiting (different layer).
- Does not decode the *contents* of a rogue request (i.e., which principals it asked for). That would require
  either enclave-side logging changes or a payload-capture layer — out of scope here, noted in §8.

## 3. Detection mechanisms considered

### Option A — `auditd` syscall rule
```
auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch
```
`auditd` can't filter on socket address family in the rule itself, so a consumer must post-process the audit log:
parse the `SOCKADDR` record's `saddr=` hex field, decode `sa_family` (bytes 0-1, little-endian; `AF_VSOCK` = 40)
and, for a `sockaddr_vm`, the CID and port fields, and keep only `cid=16, port=5000`. The rule does **not**
exclude the packaged `ssh-cert-api` binary's own `connect()`s (an earlier draft added `-F exe!=/usr/bin/ssh-cert-api`
to cut log volume) — doing so would discard exactly the case where an attacker runs or bind-mounts that same
binary path under the wrong uid or outside its cgroup: `Allowlist.Classify` would call that `Anomalous`, but
`AuditWatcher` would never see the `connect()` to classify if the rule filtered it out first. See §4.1/§4.2 for
where the real exe+uid+cgroup decision is made, on every observed `connect()`, not just other processes'.

- **Pros:** ubiquitous (Amazon Linux ships `auditd`), integrates with whatever SIEM already ingests audit logs,
  no kernel module or BTF dependency.
- **Cons:** noisy at the raw-rule level (needs a real post-filter); `auditd` is a userspace daemon a root
  attacker can stop.

### Option B — eBPF, attached to `syscalls:sys_enter_connect`
Decode `struct sockaddr_vm` **in-kernel**, filtering `svm_family == 40 && svm_cid == 16 && svm_port == 5000`
before an event is even emitted — so only genuine vsock-to-enclave connects generate output, no post-filtering
needed. Capture `{pid, tgid, uid, gid, comm, cgroup_id}` at the hook; resolve `/proc/<pid>/exe` in userspace at
consume time.

- **Pros:** precise signal, low overhead, single-purpose.
- **Cons:** needs `CAP_BPF`/`CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels) for the loader — itself a
  capability to scope tightly (§4.3).

**Implementation deviates from a CO-RE design on purpose.** The original draft of this section assumed CO-RE
(`vmlinux.h` generated from the target kernel's BTF). The actual program
(`vsockwatch/ebpf/src/vsock_connect.c`) reads no kernel-internal structure at all — only `struct sockaddr_vm`
(a stable UAPI type, and it's the *caller's own userspace argument* to `connect()`, not kernel state) and the
tracepoint's `trace_event_raw_sys_enter` argument struct, whose `{common_type, common_flags,
common_preempt_count, common_pid, id, args[6]}` layout has been part of ftrace's stable ABI for well over a
decade. That means the compiled object needs no kernel BTF/`vmlinux.h` to build or load, and — because eBPF
bytecode is a fixed virtual ISA — the same compiled object is portable across both `x86_64` and `aarch64` without
a separate per-arch build. The tradeoff: the object embedded via `go:embed` in the Go binary is a **checked-in,
prebuilt artifact** (`vsockwatch/ebpf/src/vsock_connect.bpf.o`), not rebuilt from source at package-build time —
see `make vsock-watch-bpf` (root `Makefile`) to regenerate it, and §6 for what must be re-verified after doing so.

### Option C — both (recommended)
Run `auditd` (cheap, ubiquitous, independent code path) **and** the eBPF watcher (precise signal) side by side.
An attacker who wants to fully blind the system now has to find and disable two unrelated mechanisms, and
disabling either one is itself an event worth alerting on (§4.4).

## 4. Chosen design

### 4.1 Allowlist: what "expected" means

A `connect()` to `(CID=16, port=5000)` is **expected** iff all of:

- `exe` resolves to the packaged binary path (`/usr/bin/ssh-cert-api`; configurable per §4.3)
- `uid` matches the `cerberus` service account's uid, resolved dynamically at the watcher's startup (not
  hardcoded — differs per install)
- *(stronger, optional)* the process's cgroup matches `system.slice/cerberus-api.service` — catches an attacker
  who copies the binary to the same path outside systemd, or spoofs `argv[0]`

Anything else connecting to `CID 16, port 5000` is an **anomaly** → alert at `critical` severity immediately.

The expected uid (`os/user.Lookup`) and cgroup inode (`os.Stat` on `system.slice/<Unit>`) are each resolved
dynamically and cached for `DefaultCacheTTL` (5s) rather than fixed at watcher startup, so a service-account
change or unit reinstall is picked up without restarting the watcher.

**Revalidation on a cache-derived uid mismatch**: the cached expected uid can simply be a few seconds stale.
`Classify` does one uncached re-check (`refreshUID`) before declaring a uid mismatch — a single extra lookup,
only on the mismatch path, never on every event — which resolves the common case back to `Expected`. A uid
mismatch that survives that recheck is `Anomalous`: uid is a static `/etc/passwd` entry, not a per-restart kernel
object, so a real mismatch there isn't a timing artifact.

**Bounded retry on a cache-derived cgroup mismatch**: a `cerberus-api.service` restart can change its cgroup —
systemd may `rmdir`+recreate a unit's cgroup once it briefly becomes empty between stop and start — and, unlike
uid, this can still be *in progress* by the time an event is classified: the kernel can assign the newly-started
process to its new cgroup before the well-known `system.slice/<unit>` path `stat()`s to that same inode. A single
immediate recheck (tried first, in an earlier version of this fix) isn't reliably enough to win that race — real
hardware testing (`verify-vsock-watch-hardware.sh`'s `api-restart` chaos test, §6) showed it still produced an
occasional false `Anomalous`. `Classify` now retries `refreshCgroupID` up to `cgroupRevalidateAttempts` times
(default 10, `cgroupRevalidateInterval` apart, default 50ms — vars, not consts, so tests can shrink them), giving
systemd's settling a bounded window to finish before giving up. This only runs on the mismatch path — in
practice, only right around a restart — so a few hundred milliseconds of retry here is a materially different
cost than blocking the hot path on every event the way an unconditional retry would (the same problem
`AsyncShipper`, §4.2, exists to avoid on the delivery side).

**Why a cgroup mismatch that survives the full retry budget downgrades to `Indeterminate`, not `Anomalous`**: the
retry budget is generous but can't be unbounded, and can't guarantee it always wins the race on every host under
every load condition. `exe` and `uid` already matched by this point, so this isn't "any random process" the way
an exe or uid mismatch is. `Indeterminate` still alerts at the same `critical` severity as `Anomalous` (§4.2), but
is deliberately never `Blockworthy` (`event.go`), so `--block` cannot `SIGKILL` the legitimate, freshly-restarted
`ssh-cert-api` if the retry budget is ever exhausted. A genuine attacker satisfying this narrower bar (same exe,
same uid, wrong cgroup — a copied binary running under the right account but outside `cerberus-api.service`) is
still loudly alerted on every time, just not auto-killed by this signal alone.

This went through three real-hardware rounds via `verify-vsock-watch-hardware.sh`'s `api-restart` chaos test
(§6) before landing here: round 1 found the raw cache-staleness false positive; a single-recheck fix closed most
of it but one restart still produced a false `Anomalous`; downgrading a persisting mismatch to `Indeterminate`
closed that safely, but real testing showed it still alerted (safely, but noisily) on essentially every restart,
which the bounded retry above now resolves in the common case without changing the safety net.

### 4.2 Event pipeline

1. **eBPF collector** (`cerberus-vsock-watch`, a small Go binary + embedded object) attaches to the
   `sys_enter_connect` **tracepoint** (§3B; not the `security_socket_connect` LSM hook — see §4.5/§7 for why this
   is deliberately a detective, not a preventive, attach point), filters in-kernel, and pushes one ring-buffer
   event per matching connect.
2. **Userspace consumer** (same binary) enriches each event: resolves `/proc/<pid>/exe` (best-effort — a process
   that's already gone by read time is itself suspicious and logged as such), checks against the allowlist
   (§4.1), and classifies expected vs. anomalous.
3. **`auditd` path**, independently: a companion script/`audisp` plugin tails the audit log, decodes `saddr=` on
   `SOCKADDR` records correlated to the matching `connect()` syscall record, filters to
   `family=40, cid=16, port=5000`, and classifies the same way — a second, structurally independent detector.
4. **Alerting:** on an anomalous classification, both detectors (a) write a structured JSON log line
   (matching Cerberus's existing `LOG_FORMAT=json` convention) and (b) forward it synchronously to the external
   log aggregator (already a trusted component per `docs/THREAT-MODEL.md` Appendix A) **before** local
   acknowledgment. In parallel, fire directly to an out-of-band alert channel (`CERBERUS_VSOCK_WATCH_WEBHOOK_URL`
   — Slack, PagerDuty, SNS, or a generic webhook) from the watch daemon itself, independent of the logging
   pipeline — so a host that kills the log forwarder mid-attack still gets one alert out first. Slack's Incoming
   Webhook contract requires a `{"text": ...}` payload rather than arbitrary JSON; a `hooks.slack.com` URL is
   auto-detected and formatted accordingly (`CERBERUS_VSOCK_WATCH_WEBHOOK_FORMAT` overrides the detection for a
   Slack-compatible receiver on a different host, or to force the raw JSON shape). Untrusted fields (the
   anomalous process's `comm`/`exe`, which it fully controls) are Slack-mrkdwn-escaped before being embedded, so
   a hostile process can't inject formatting or break the alert message.
5. *(Phase 2, not in this design):* snapshot `/proc/<pid>/maps`, open FDs, and cmdline on anomaly detection for
   forensics. Adds complexity and its own risk surface; flagged as a follow-up, not required for v1.

### 4.3 Deployment

- New unit, `cerberus-vsock-watch.service`, packaged alongside `cerberus-api`/`cerberus-signer` in the existing
  RPM/deb/arch packaging. Runs as its **own** restricted service account (e.g. `cerberus-audit`), *not* `cerberus`
  — so a compromise of the `cerberus` account alone can't also blind the watcher.
- Only this unit holds `CAP_BPF`/`CAP_PERFMON` (or `CAP_SYS_ADMIN`); `cerberus-api.service` is unaffected and
  keeps its current hardening (`NoNewPrivileges=yes`, `ProtectSystem=strict`, etc. — see
  `packaging/rpm/cerberus-api.service`).
- Ordering: `cerberus-vsock-watch.service` runs `Type=notify` (not `Type=simple`) and sends systemd `READY=1`
  (`cmd/cerberus-vsock-watch/sdnotify.go`) only once at least one enabled detector has completed its own startup
  sequence (the audit log is open, or the eBPF program is attached) — not merely once the process has forked.
  `cerberus-api.service` declares `After=cerberus-vsock-watch.service` **and** `Wants=cerberus-vsock-watch.service`
  (a soft dependency: a host without the vsock-watch package installed at all is unaffected — `Wants=`/`After=` on
  a nonexistent unit is a no-op), so when the watcher IS installed and enabled, `ssh-cert-api` cannot start dialing
  the enclave while the watcher is still *initializing* — closing the boot-time blind window that `Type=simple`
  ordering alone could not (systemd considers a `Type=simple` unit "started" the instant it's forked, regardless
  of what its goroutines have or haven't finished doing yet). This is **not** an airtight guarantee: `After=` only
  delays `cerberus-api`'s start job until the watcher's start job *concludes*, not until it *succeeds* — if the
  watcher fails outright at boot before ever sending `READY=1` (e.g. missing `CAP_DAC_READ_SEARCH`, a bad audit-log
  path, or an unsupported kernel with auditd also broken — the exhausted-detectors case in §4.4), its start job
  concludes (as failed) almost immediately, and `cerberus-api.service` starts right behind it, unblocked,
  reproducing the same gap this ordering exists to close. `Requires=` would close that too, but was deliberately
  not used here: it would turn the vsock-watch package from an optional bolt-on into a hard dependency of
  `cerberus-api`, so a host that hasn't installed or configured it correctly would have `cerberus-api` refuse to
  start at all rather than degrade — a materially worse operational failure mode than the residual gap it would
  close. `Restart=on-failure` on the watcher unit means this gap is also self-limiting in practice (the watcher
  keeps retrying), but the window exists on every restart attempt, not just the very first boot.
  - Readiness policy is deliberately **OR**, not AND, across the two detectors — matching
    `detectorHealth.allDown()`'s existing policy (§4.4) that single-detector operation is an acceptable degraded
    mode, not a fatal one. Waiting for both auditd AND eBPF before signaling ready would mean a host where eBPF
    can never attach (unsupported kernel: missing `BPF_PROG_TYPE_TRACEPOINT`/`BPF_MAP_TYPE_RINGBUF` support, or
    the loader lacks `CAP_BPF`/`CAP_PERFMON`) but `--disable-ebpf` wasn't set would never send `READY=1` at all —
    and with the `Wants=`/`After=` ordering above, that would block `cerberus-api.service` from starting forever,
    a materially worse outcome than today's graceful auditd-only degradation.
- Config: expected exe path + service unit name, overridable like the rest of Cerberus's config surface;
  defaults baked in.

### 4.4 Tampering with the detector itself

Stated plainly, in the same spirit as the existing `KMS-1` writeup: a genuine root attacker **can**
`systemctl stop cerberus-vsock-watch`, `auditctl -D`, or unload the BPF program. This design's value is:

- (a) doing so is itself a loud, independently-shipped event — treat "watcher process exited" / "audit rule
  deleted" as its own `critical` alert, distinct from a vsock anomaly, and
- (b) pair this with an **external dead-man's-switch heartbeat**: the watcher pushes an "I'm alive" ping on a
  fixed interval, and the *external* monitoring system (not the host) alerts on the ping's absence. This is
  strictly more robust than relying on a compromised host to self-report its own death.

An opportunistic or semi-automated attacker (a compromised dependency, an SSRF-to-RCE chain) is far less likely
to know to disable a bespoke, non-obvious watcher than to just run their exploit — so this meaningfully raises
the bar even though it cannot stop a fully-informed, patient human attacker.

### 4.5 Reactive blocking (opt-in, default off)

`CERBERUS_VSOCK_WATCH_BLOCK=true` (or `--block`) turns on a best-effort mitigation: on a confirmed `Anomalous`
classification (`vsockwatch/block.go`'s `ProcessKiller`), the watcher sends `SIGKILL` to the offending PID. This
is deliberately **not** the same thing as prevention:

- Neither detector can block the `connect()` itself. The auditd path only sees the syscall after auditd has
  already logged it; the eBPF path is attached to the `sys_enter_connect` **tracepoint**, which has no return
  value the kernel acts on to deny a syscall. By the time either detector's userspace consumer classifies the
  event and a `Blocker` runs, the `connect()` — and any `EnclaveSigningRequest` the offending process already
  sent to the enclave over it — may have already completed.
- Its actual value is cutting off a persistent attacker's ability to *retry* (e.g. a shell loop dialing the
  enclave repeatedly), not stopping the first attempt.
- Only `Verdict.Anomalous` triggers a kill — never `Verdict.Indeterminate`. Indeterminate means the allowlist
  itself couldn't be resolved (e.g. a transient uid-lookup failure against NSS/LDAP), which says nothing about
  whether the *connecting* process's identity actually mismatches. Treating Indeterminate as block-worthy would
  risk `SIGKILL`-ing the legitimate `ssh-cert-api` process on a transient hiccup — a materially worse outcome
  than the noisy-but-safe alert Indeterminate already produces. (See `Verdict.Blockworthy()` in `event.go`.)
- PID reuse between observation and the kill is a known, small residual risk (Linux avoids fast PID reuse but
  doesn't guarantee it), inherent to any PID-based response.
- Requires `CAP_KILL` (packaged unconditionally in `cerberus-vsock-watch.service`, alongside the other
  capabilities in §4.3) since `cerberus-audit` runs as a different account than the process being killed.
- Wired independently into both detectors (`AuditWatcher.Blocker`, `ebpf.Watcher.Blocker`) so either one can
  trigger it; a real connect is expected to be observed by both, making a redundant, harmless second `SIGKILL`
  to an already-dead PID the common case rather than the exception.

**True kernel-level prevention is now built — see §4.6.** Actually denying a non-allowlisted `connect()` before
it succeeds requires a BPF program attached to the `security_socket_connect` **LSM** hook (not a tracepoint),
which can return a nonzero value the kernel treats as a deny — unlike the reactive kill above, which cannot stop
the first attempt. §4.6 covers the design, its narrower (cgroup-only) scope, and why it still does not close
`SIGN-1`.

### 4.6 Preventive LSM gate (opt-in, monitor-first, default off)

`CERBERUS_VSOCK_WATCH_LSM_MONITOR=true` (or `--lsm-monitor`) loads a second, independent eBPF program
(`vsockwatch/ebpf/src/vsock_lsm.c`, loaded by `vsockwatch/ebpf/lsm.go`'s `LSMGuard`) attached to the
`security_socket_connect` **LSM** hook rather than a tracepoint. Unlike `sys_enter_connect`, an LSM hook's return
value IS acted on by the kernel: a nonzero return denies the `connect()` before it succeeds. This is the one
piece of this design that is genuinely preventive, not just detective.

**Why this is narrower than the detective path, not a superset of it.** An LSM hook must decide allow/deny
synchronously, entirely in-kernel — there is no way to pause the syscall and ask a Go userspace process "does
`/proc/<pid>/exe` match?" the way `Allowlist.Classify` does. The only identity signal cheap and available
entirely in-kernel is `bpf_get_current_cgroup_id()`. So the LSM gate denies a connect only when the caller is
OUTSIDE the pinned `ssh-cert-api` cgroup — it does NOT check exe path or uid the way the detective path does.
A compromised `ssh-cert-api` itself (or anything sharing its cgroup) still passes the gate untouched. **This
does not close `SIGN-1`** (see §7) — it prevents a rogue, *non*-ssh-cert-api process from reaching the enclave
at all, which the detective path could previously only alert on after the fact.

**Mechanism:**
- `vsock_lsm.c` maintains a double-buffered `lsm_policy` map (2 slots) plus a single-word `lsm_active_slot`
  index: `LSMGuard`'s poll loop writes a full new policy into the currently-INACTIVE slot, then flips the index
  as a publish barrier, so an in-kernel reader never observes a torn write straddling the cgroup id and its
  "populated" flag — the moment this matters most is exactly a `cerberus-api.service` restart, when the pinned
  cgroup id changes.
- A separate `lsm_mode` map (0=monitor, 1=enforce) decouples the enforce toggle from the cgroup pin entirely.
- **Fail-open bootstrap is structural, not a convention**: the maps are zero-initialized by the kernel, so
  before `LSMGuard` ever publishes a policy, `populated=0` and every connect is allowed — there is no window
  where an unconfigured gate denies everything.
- The cgroup pin reuses `Allowlist.CgroupID()` (the same cached resolution `Classify` uses for the detective
  path — see §4.1), refreshed every `--lsm-poll-interval` (default 250ms).

**Rollout is monitor-first by design, not just convention:**
- `--lsm-monitor` alone loads the gate and ships a `vsock_lsm_block` alert (`lsm_mode=monitor`,
  `lsm_denied=false`) on every cgroup mismatch, but the program never returns a deny — this is the only way to
  load the gate at all.
- `--lsm-enforce` is rejected as a hard startup error unless `--lsm-monitor` is also set
  (`cmd/cerberus-vsock-watch/main.go`'s `validateLSMFlags`) — enforcement is never silently auto-promoted.
- An operator is expected to watch `--lsm-monitor` run clean — no `lsm_denied` (impossible in monitor mode
  anyway) and, more importantly, no would-deny alert naming the legitimate `ssh-cert-api`'s own exe — across at
  least one real `cerberus-api.service` restart before ever adding `--lsm-enforce`. `--lsm-enforce-state-file`
  (default `/run/cerberus-vsock-watch/lsm-enforce`, in the unit's `RuntimeDirectory=`) also allows toggling
  enforcement at runtime without a restart, polled the same interval as the cgroup pin.

**Why the restart race is a documented residual risk, not something this design eliminates.** This is
structurally the same race `Allowlist`'s bounded cgroup-revalidation retry (§4.1) exists to paper over for the
detective path — except here, a lost race means a REAL denied `connect()`, not just a noisy `Indeterminate`
alert. `ssh-cert-api` has no dial retry on the signing path (`ssh-cert-api/internal/enclave/client.go`), so a
false deny during a lost race surfaces immediately as a user-visible signing failure, not a silently-absorbed
hiccup. The tight default poll interval and the mandatory monitor-mode practice above mitigate this; neither
eliminates it.

**Kernel prerequisites** (materially higher bar than the tracepoint path): `CONFIG_BPF_LSM=y` and `bpf` present
in the kernel's active `lsm=` list (append, never replace — replacing silently drops SELinux/AppArmor), plus a
new `CAP_MAC_ADMIN` grant (`packaging/*/cerberus-vsock-watch.service`). See `docs/RUNBOOK.md`'s "Preventive LSM
gate prerequisites" for verification commands. Per this doc's top-of-file status note, whether the kernel's
BTF-based LSM attach machinery accepts this program's exact section name and parameter types is genuinely
unconfirmed against a live kernel — see `vsock_lsm.c`'s header comment.

## 5. False-positive inventory

Every legitimate call site that reaches `CID 16, port 5000` today, all from the same exe/uid/cgroup so the
allowlist covers them without special-casing:

- `SignPublicKey` (`ssh-cert-api/internal/enclave/client.go:158`)
- `Ping` / `GetEnclaveMetrics`, polled every 5s by the host-side `HealthMonitor` (`client.go:122,142`)
- `BeginKeyLoad` / `CompleteKeyLoad` at startup (`client.go:184,200`)
- `cerberus-api.service` restarts (new PID each time) — handled by the dynamic MainPID lookup in §4.1

One documented exception: the `CERBERUS_SIGNER_ENDPOINT` override (`ssh-cert-api/internal/enclave/endpoint.go`)
lets an operator point `ssh-cert-api` at a non-enclave signer (e.g. a USB HSM bridge) over TCP/Unix instead of
VSOCK. If that override is in use, the watcher's expected destination should be retuned accordingly — it should
not special-case the override automatically, since an operator using that escape hatch already deviates from the
default trust model and should configure the watcher to match (documented operational note, not silent handling).

## 6. Testing plan

**Done, as part of the implementation:**

- Unit tests for `DecodeSockaddrVM`/`IsEnclaveTarget` (`vsockwatch/vsockaddr_test.go`) covering the negative cases
  (`cid=17`, `port=5001`, `family=AF_INET`, etc.).
- Unit tests for `Allowlist.Classify` (`vsockwatch/allowlist_test.go`) covering exe/uid/cgroup matches and
  mismatches, uid-lookup failure (fail-secure → `Indeterminate`), and non-enclave traffic never alerting.
- Unit tests for the auditd `SYSCALL`/`SOCKADDR` correlator, including out-of-order arrival and cross-`msgID`
  isolation (`vsockwatch/audit_test.go`).
- An in-process integration test (`TestAuditWatcher_Run_*`, same file) that runs the real `AuditWatcher.Run`
  against a temp file being appended to concurrently — the closest thing to an end-to-end test this sandbox can
  run without a real `auditd`.
- A manual smoke test of the actual compiled `cerberus-vsock-watch` binary (not just `go test`): a synthetic
  rogue `connect()` appended to a fake audit log produced a correct structured alert within ~1s; a legitimate
  caller (with the fail-secure uid-lookup-failure path exercised, since this sandbox has no `cerberus` user)
  correctly alerted rather than silently passing.
- `TestEmbeddedObject_ParsesAsValidELF` (`vsockwatch/ebpf/loader_test.go`): loads the compiled
  `vsock_connect.bpf.o` via `cilium/ebpf`'s `LoadCollectionSpecFromReader` and asserts the expected program
  (correct type, correct tracepoint section name) and ring buffer map are present. This validates ELF/BTF
  structure, NOT verifier acceptance or runtime correctness.
- Running the real binary end-to-end: with no kernel privilege available, `vsockwatch/ebpf.Watcher.Run` reached
  the kernel and failed with a genuine, specific error (`neither debugfs nor tracefs are mounted`), confirming
  the loader/attach code path executes correctly up to the point this sandbox can't go further, and that the
  failure degrades gracefully (auditd detector unaffected, no crash).
- Unit tests for `TamperWatch`/`Heartbeat` (`vsockwatch/tamper_test.go`) with a faked `auditctl -l` output and a
  faked HTTP client.

**Verified on real hardware** (RHEL 10, 2026-07-23, via `verify-vsock-watch-hardware.sh`, three runs; see
`docs/vsock-connect-verification-runbook.md`):

- Live tracepoint format matches `struct trace_event_raw_sys_enter` in `vsock_connect.c` — `uservaddr` (the
  second `connect(2)` argument) confirmed at offset 24, size 8, exactly matching `ctx->args[1]`.
- The BPF verifier accepts the compiled object and the tracepoint attaches (`link.Tracepoint` succeeding).
- A real `AF_VSOCK` connect (driven by `cerberus-stress signer -transport vsock`) produced a correctly classified
  `ebpf`-sourced anomaly event.
- `cerberus-api.service` genuinely waits on `cerberus-vsock-watch`'s `Type=notify` `READY=1`, not just its process
  start (§4.3).
- Chaos test (audit-rule removal → tampering meta-alert): confirmed stable across the second and third runs — the
  `detector_tampering` alert fired correctly both times. (The first run's "audit support not in kernel" failure was
  specific to that boot/session on this host, not a Cerberus issue — see the runbook's known-findings log.)
- `--block` + `CAP_KILL`: end-to-end confirmed twice — a `cerberus-stress` process running as a different uid than
  `cerberus-audit` was genuinely `SIGKILL`ed, confirming cross-uid signaling actually works, not just that the
  capability string is present.
- Deployment freshness: `verify-vsock-watch-hardware.sh`'s item 0 confirmed the installed binary was actually
  rebuilt from the fixed source before the third run — ruling out "the fix wasn't deployed" as an explanation for
  `api-restart` still failing that run (see below).

**Found and fixed across three rounds of the `api-restart` chaos test** — this one caught a real gap the check
was specifically designed to catch, and took three fix attempts (two Cerberus code fixes, one verification-script
fix) to fully address:

- Round 1: `Allowlist`'s cached cgroup inode went stale across a restart that changed the unit's cgroup,
  misclassifying the newly-restarted, perfectly legitimate `ssh-cert-api` as `Anomalous` (and, with `--block`
  enabled, would have been killed outright) for the length of the 5s cache window. Fixed with an uncached
  recheck before declaring a mismatch.
- Round 2: the recheck fix reduced the false positives (four alerts down to one) but didn't fully close it — a
  single immediate recheck isn't guaranteed to win the race against systemd's own cgroup settling during a
  restart. Fixed by downgrading a cgroup mismatch that survives the recheck to `Indeterminate` (alerts, never
  auto-kills) rather than trying to outrun the timing race.
- Round 3: the third re-run (with the deployment-freshness check confirming the fix genuinely was deployed) still
  reported `api_restart_chaos` as `FAIL` — but the underlying Cerberus behavior was actually correct
  (`Indeterminate`, not `Anomalous`); `verify-vsock-watch-hardware.sh`'s own check was the bug, grepping for any
  alert mentioning `ssh-cert-api` regardless of verdict. Fixed the script to only fail on `Anomalous` (treating an
  occasional `Indeterminate` as an expected, non-failing warning), and separately improved `Allowlist.Classify` to
  retry the cgroup recheck with a bounded budget (`cgroupRevalidateAttempts`/`cgroupRevalidateInterval`, default
  10× 50ms) instead of a single attempt — see §4.1's "Bounded retry on a cache-derived cgroup mismatch" — so the
  common case resolves to a clean `Expected` with no alert at all, rather than relying on the `Indeterminate`
  safety net on every restart. **Needs a fourth re-run to confirm.**

**Still not done:**

- Chaos test: `systemctl stop cerberus-vsock-watch` (killing both detectors at once) noticed by an external
  heartbeat monitor — depends on operator-side monitoring infrastructure outside this repo (§4.4/§8), flagged as
  a `MANUAL` step in the runbook.
- The documented `Wants=`/`After=` residual gap (§4.3: watcher fails outright before `READY=1`, `cerberus-api`
  starts anyway) — also flagged as a `MANUAL` step, not yet independently reproduced.

## 7. Why this is detection, not prevention

Any secret or agent that lives only on the host is reachable by the same root access this design defends
against — root can read `ssh-cert-api`'s memory, disable `auditd`, or unload an eBPF program (including the
LSM gate itself — a root attacker can unload it exactly as easily as the tracepoint detectors). This is why the
design leans on (a) two independent detection paths, (b) alerting on tampering with the detectors themselves,
(c) an external heartbeat that doesn't depend on the host to self-report, and, additionally, (d) the §4.6
preventive LSM gate — but (d) only ever checks cgroup membership, so it does not change this section's
conclusion for anything running IN ssh-cert-api's own cgroup. None of this closes `SIGN-1`; between the
detective paths and the LSM gate, it makes exploitation by anything else observable and, opt-in, preventable —
but a compromise of ssh-cert-api itself remains fully in scope. Actually *closing* the gap requires moving the
authorization decision into the enclave itself (forwarding the original Kerberos ticket/OIDC token and
re-deriving policy inside the PCR0-measured image) — a materially larger project, tracked separately.

## 8. Open questions / follow-ups

- Capturing the anomalous request's actual payload (which principals it asked for) would need a payload-capture
  layer beyond connect() detection (e.g. hooking `writev`) — likely not worth the added complexity, since
  connect-detection alone already proves an out-of-band dial happened, which is sufficient to trigger incident
  response and cert revocation via `sshd`'s short validity window.
- The external dead-man's-switch heartbeat (§4.4) needs its own home — presumably the same external monitoring
  system already watching `/health` behind the LB, but that's a separate piece of infrastructure to stand up.
- Enclave-side authorization (the actual fix for `SIGN-1`, not just detection of its exploitation) is tracked as
  a separate, larger design.
- True kernel-level prevention is now built — see §4.6. What's still open: closing the cgroup-vs-exe/uid gap
  (denying a connect from a process that shares ssh-cert-api's cgroup but has a different exe/uid) isn't
  feasible without a synchronous userspace round-trip, which an LSM hook cannot do — this is a hard
  architectural ceiling on the gate's precision, not a missing feature to build.
