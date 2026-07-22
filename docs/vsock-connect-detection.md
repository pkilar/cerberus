# VSOCK-Connect Detection Design

> **Status:** Draft — not yet implemented. Companion to `docs/THREAT-MODEL.md` (`SIGN-1`).
> **Kind of control:** Detective, not preventive. See §7 for why no host-side control can fully prevent this.

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
  see §7 for the honest accounting of that limit, in the same spirit as the existing `KMS-1` writeup.
- Does not replace or interact with Casbin/rate-limiting (different layer).
- Does not decode the *contents* of a rogue request (i.e., which principals it asked for). That would require
  either enclave-side logging changes or a payload-capture layer — out of scope here, noted in §8.

## 3. Detection mechanisms considered

### Option A — `auditd` syscall rule
```
auditctl -a always,exit -F arch=b64 -S connect -F exe!=/usr/bin/ssh-cert-api -k cerberus_vsock_watch
```
`auditd` can't filter on socket address family in the rule itself — `-F exe!=` matches *every* `connect()` from
any other process (DNS lookups, LDAP binds, curl, etc.), so a consumer must post-process the audit log: parse the
`SOCKADDR` record's `saddr=` hex field, decode `sa_family` (bytes 0-1, little-endian; `AF_VSOCK` = 40) and, for a
`sockaddr_vm`, the CID and port fields, and keep only `cid=16, port=5000`.

- **Pros:** ubiquitous (Amazon Linux ships `auditd`), integrates with whatever SIEM already ingests audit logs,
  no kernel module or BTF dependency.
- **Cons:** noisy at the raw-rule level (needs a real post-filter); `auditd` is a userspace daemon a root
  attacker can stop.

### Option B — eBPF (CO-RE, attached to `security_socket_connect` or `sys_enter_connect`)
Decode `struct sockaddr_vm` **in-kernel**, filtering `svm_family == 40 && svm_cid == 16 && svm_port == 5000`
before an event is even emitted — so only genuine vsock-to-enclave connects generate output, no post-filtering
needed. Capture `{pid, tgid, uid, gid, comm, cgroup_id}` at the hook; resolve `/proc/<pid>/exe` in userspace at
consume time.

- **Pros:** precise signal, low overhead, single-purpose.
- **Cons:** needs BTF/CO-RE (fine on Amazon Linux 2023; may need a backport on AL2), needs `CAP_BPF`/`CAP_PERFMON`
  (or `CAP_SYS_ADMIN` on older kernels) for the loader — itself a capability to scope tightly (§4.3).

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

The allowlist's MainPID is re-resolved via `systemctl show -p MainPID cerberus-api.service` (cached ~5s) rather
than fixed at watcher startup, so a `cerberus-api.service` restart doesn't produce a false positive during the
PID transition.

### 4.2 Event pipeline

1. **eBPF collector** (`cerberus-vsock-watch`, a small Go binary + embedded CO-RE object) attaches to
   `security_socket_connect` (falls back to `sys_enter_connect` if LSM BPF is unavailable), filters in-kernel as
   in §3B, and pushes one ring-buffer event per matching connect.
2. **Userspace consumer** (same binary) enriches each event: resolves `/proc/<pid>/exe` (best-effort — a process
   that's already gone by read time is itself suspicious and logged as such), checks against the allowlist
   (§4.1), and classifies expected vs. anomalous.
3. **`auditd` path**, independently: a companion script/`audisp` plugin tails the audit log, decodes `saddr=` on
   `SOCKADDR` records correlated to the matching `connect()` syscall record, filters to
   `family=40, cid=16, port=5000`, and classifies the same way — a second, structurally independent detector.
4. **Alerting:** on an anomalous classification, both detectors (a) write a structured JSON log line
   (matching Cerberus's existing `LOG_FORMAT=json` convention) and (b) forward it synchronously to the external
   log aggregator (already a trusted component per `docs/THREAT-MODEL.md` Appendix A) **before** local
   acknowledgment. In parallel, fire directly to an out-of-band alert channel (PagerDuty/SNS/webhook) from the
   watch daemon itself, independent of the logging pipeline — so a host that kills the log forwarder mid-attack
   still gets one alert out first.
5. *(Phase 2, not in this design):* snapshot `/proc/<pid>/maps`, open FDs, and cmdline on anomaly detection for
   forensics. Adds complexity and its own risk surface; flagged as a follow-up, not required for v1.

### 4.3 Deployment

- New unit, `cerberus-vsock-watch.service`, packaged alongside `cerberus-api`/`cerberus-signer` in the existing
  RPM/deb/arch packaging. Runs as its **own** restricted service account (e.g. `cerberus-audit`), *not* `cerberus`
  — so a compromise of the `cerberus` account alone can't also blind the watcher.
- Only this unit holds `CAP_BPF`/`CAP_PERFMON` (or `CAP_SYS_ADMIN`); `cerberus-api.service` is unaffected and
  keeps its current hardening (`NoNewPrivileges=yes`, `ProtectSystem=strict`, etc. — see
  `packaging/rpm/cerberus-api.service`).
- Ordering: `cerberus-api.service` should declare `After=cerberus-vsock-watch.service` so the watcher is always
  up before `ssh-cert-api` starts dialing the enclave — no boot-time blind window.
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

- Unit test the BPF filter logic against synthetic `sockaddr_vm` values, including negative cases that must
  *not* match (`cid=15`, `cid=17`, `port=5001`, `family=AF_INET`).
- Integration test against a fake vsock listener (reusing the non-production loopback fallback already in
  `internal/enclave/endpoint.go`): confirm `ssh-cert-api` connecting produces no alert, and a throwaway
  root-run test binary connecting produces an alert with the correct pid/exe/uid.
- Chaos test: restart `cerberus-api.service` mid-test, confirm no false positive during the MainPID transition.
- Chaos test: `auditctl -D` / `systemctl stop cerberus-vsock-watch`, confirm the tampering meta-alert fires from
  the surviving detector.

## 7. Why this is detection, not prevention

Any secret or agent that lives only on the host is reachable by the same root access this design defends
against — root can read `ssh-cert-api`'s memory, disable `auditd`, or unload an eBPF program. This is why the
design leans on (a) two independent detection paths, (b) alerting on tampering with the detectors themselves, and
(c) an external heartbeat that doesn't depend on the host to self-report. None of this closes `SIGN-1`; it makes
exploitation observable and non-repudiable. Actually *closing* the gap requires moving the authorization decision
into the enclave itself (forwarding the original Kerberos ticket/OIDC token and re-deriving policy inside the
PCR0-measured image) — a materially larger project, tracked separately.

## 8. Open questions / follow-ups

- Capturing the anomalous request's actual payload (which principals it asked for) would need a payload-capture
  layer beyond connect() detection (e.g. hooking `writev`) — likely not worth the added complexity, since
  connect-detection alone already proves an out-of-band dial happened, which is sufficient to trigger incident
  response and cert revocation via `sshd`'s short validity window.
- The external dead-man's-switch heartbeat (§4.4) needs its own home — presumably the same external monitoring
  system already watching `/health` behind the LB, but that's a separate piece of infrastructure to stand up.
- Enclave-side authorization (the actual fix for `SIGN-1`, not just detection of its exploitation) is tracked as
  a separate, larger design.
