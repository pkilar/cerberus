# VSOCK-Connect Detective Control — Real-Hardware Verification Runbook

> Companion to `docs/vsock-connect-detection.md` §6 ("Testing plan") and the automation script
> `verify-vsock-watch-hardware.sh` at the repo root. Everything in §6's "Done, as part of the implementation"
> list was verified in a development sandbox with no kernel BPF privilege, no debugfs/tracefs, and no auditd. The
> items below need a real host and cannot be verified any other way — that is the entire reason this runbook
> exists.

## Who this is for

An operator with root (or passwordless sudo) on a Linux host that can run the packaged `cerberus-vsock-watch`
(and ideally `cerberus-api`) — a staging EC2 instance is the natural fit, a real Nitro Enclave is **not** required
for any of these checks (they exercise the host-side detective control, not enclave signing itself). A repo
checkout with `go` installed is used to build the disposable `cerberus-stress` test client; if you'd rather not
check out the repo on the target host, build `cerberus-stress` elsewhere and point `CERBERUS_STRESS_BIN` at the
binary.

## Safety

`verify-vsock-watch-hardware.sh` stops/restarts `cerberus-vsock-watch.service` and `cerberus-api.service`, and
temporarily removes a live auditd rule (restoring it before exiting each check). **Do not run this against a host
serving real signing traffic** without understanding that. It prompts for confirmation before doing anything
disruptive; pass `--yes` to skip that in a scripted/CI context.

## Prerequisites

- `cerberus-vsock-watch` installed from the packaged artifact (RPM/deb/Arch — see CLAUDE.md's Packaging section),
  or built from source and placed at `/usr/bin/cerberus-vsock-watch`.
- `auditd` installed and running, with `auditctl` on `$PATH`. **On RHEL 10**, that release split the classic audit
  userspace tooling: `auditctl` ships in a separate `audit-rules` package, not the base `audit` package. The RPM
  spec's `cerberus-vsock-watch` subpackage now `Requires: audit-rules` when built with `%{rhel} >= 10` (fixed in
  0.10.1), so installing the packaged RPM on RHEL 10 pulls it in automatically — if you built/installed an older
  RPM, `dnf install audit-rules` (or rebuild from a current checkout) before running this script.
- The `cerberus-audit` service account exists (created by the package's `useradd`/`sysusers.d` scriptlet).
- Kernel ≥ 5.8 with tracefs or debugfs mounted, for the eBPF checks (items 2, 3, 6). If this host intentionally
  runs `--disable-ebpf`, those three items will correctly report as failed/skipped — that's expected, not a bug
  in the runbook.
- For items 4 and 7: `cerberus-api.service` also installed. These two are skipped (not failed) if it isn't.

## Running it

```bash
sudo ./verify-vsock-watch-hardware.sh --yes all
```

Or run one check at a time while iterating:

```bash
sudo ./verify-vsock-watch-hardware.sh --yes freshness
sudo ./verify-vsock-watch-hardware.sh --yes tracepoint
sudo ./verify-vsock-watch-hardware.sh --yes ebpf
sudo ./verify-vsock-watch-hardware.sh --yes api-restart
sudo ./verify-vsock-watch-hardware.sh --yes tamper
sudo ./verify-vsock-watch-hardware.sh --yes block
sudo ./verify-vsock-watch-hardware.sh --yes notify
```

## Redeploying after a code fix, before re-testing

**This script never rebuilds or reinstalls `cerberus-vsock-watch` itself** — it only builds the disposable
`cerberus-stress` test client, and otherwise drives whatever is already installed as
`cerberus-vsock-watch.service`. If a fix landed in this repo (e.g. an `Allowlist.Classify` change) and you `git
pull` the updated script but don't rebuild and reinstall the actual package, the running service is still the
*old* binary — re-running the script will reproduce the exact same failure the fix was supposed to close, which
looks identical to "the fix didn't work." The `freshness` check (item 0, included in `all`) catches this heuristically
by comparing the installed binary's mtime against the latest commit touching `vsockwatch`/`cmd/cerberus-vsock-watch`
— if it fails, redeploy before trusting anything else in the run.

**Why this heuristic works even though file timestamps on an RPM install look "wrong"**: if you `rpm -qi` or
`stat` files from a packaged install (as opposed to the `go build`+`cp` fast path above) and notice every file
dated to the spec's `%changelog` entry rather than "whenever the build actually ran" — that's expected, not a bug
(see the comment above `git archive` in `packaging/rpm/build-rpm.sh` for the full mechanism: Fedora/RHEL's
reproducible-builds tooling clamps installed file mtimes to a `SOURCE_DATE_EPOCH` derived from that changelog
date). This actually makes the `freshness` heuristic *more* reliable on an RPM install, not less — both sides of
the comparison end up anchored to source-derived timestamps rather than wall-clock build time.

To redeploy after pulling a fix:

```bash
# Rebuild just the binary and restart the service in place (fastest iteration loop):
go build -o /tmp/cerberus-vsock-watch ./cmd/cerberus-vsock-watch
sudo cp /tmp/cerberus-vsock-watch /usr/bin/cerberus-vsock-watch
sudo systemctl restart cerberus-vsock-watch.service

# Or rebuild and reinstall the actual package (matches how it'll really ship):
# packaging/rpm/build-rpm.sh (see CLAUDE.md's Packaging section for the other formats)
```

Each check prints `[PASS]`/`[FAIL]`/`[WARN]`/`[SKIP]` lines as it goes and a final summary table. A few steps
also print a `MANUAL:` note for a sub-scenario that depends on infrastructure outside this repo (an external
heartbeat monitor, for example) and can't be scripted — those are called out explicitly below too.

## What each check does and why

### 1. Tracepoint format (`tracepoint`)

`vsock_connect.c` assumes `struct trace_event_raw_sys_enter`'s layout — `common_type`@0(2), `common_flags`@2(1),
`common_preempt_count`@3(1), `common_pid`@4(4), then each syscall argument in an 8-byte-aligned slot starting at
offset 16, so `connect(2)`'s second argument (the `sockaddr` pointer) is read via `ctx->args[1]` at offset 24. This
has been the stable ftrace ABI for over a decade (the same technique bcc/libbpf-tools use), but "stable ABI" is a
claim worth actually checking once against a real kernel rather than trusting blindly. The script reads
`/sys/kernel/tracing/events/syscalls/sys_enter_connect/format` (falling back to the debugfs path) and asserts
each offset/size.

**If this fails**: do not deploy the eBPF path on this kernel/arch until you understand why the offsets differ —
`vsock_connect.c` would silently read the wrong bytes and either crash the verifier or (worse) decode garbage.

### 2 + 3. eBPF verifier acceptance and a real connect (`ebpf`)

Starts `cerberus-vsock-watch.service` and confirms it did **not** log `vsockwatch.ebpf.stopped` (i.e., the BPF
verifier accepted the program and the tracepoint attached — item 2). Then drives a real `AF_VSOCK` `connect(2)`
to the enclave's `(CID=16, port=5000)` using `cerberus-stress signer -transport vsock` and confirms an
`ebpf`-sourced anomaly alert appears in the journal (item 3). `cerberus-stress`'s own exe path isn't
`/usr/bin/ssh-cert-api`, so `Allowlist.Classify` marks it `Anomalous` by construction — no spoofing needed, and
the connect() doesn't need anything actually listening at that CID/port (the tracepoint fires at syscall entry,
before the kernel decides success or failure).

### 4. `cerberus-api` restart chaos test (`api-restart`)

Restarts `cerberus-api.service` (a new `MainPID`, a brief cgroup transition) while `cerberus-vsock-watch` is
running, and confirms no anomaly alert fires naming `ssh-cert-api`'s own exe — a false positive here would mean
`Allowlist`'s dynamic `MainPID`/cgroup re-resolution (§4.1) isn't actually keeping up with a real restart.

### 5. Audit-rule-removal chaos test (`tamper`)

Removes the live auditd rule (`auditctl -d ...`, exact inverse of `packaging/audit-rules/61-cerberus-vsock.rules`),
waits out `TamperWatch`'s check interval (default 30s), and confirms the `detector_tampering` meta-alert fires —
then restores the rule. This also exercises `CAP_AUDIT_CONTROL`: if the de-privileged `cerberus-audit` account
can't run `auditctl -l`, the check silently treats that as "unknown, not evidence of tampering" per the documented
fail-quiet-on-inconclusive design (see `docs/vsock-connect-detection.md` §4.4), so a missing capability here would
otherwise be a silent false negative.

**MANUAL step this leaves for you**: separately confirm `systemctl stop cerberus-vsock-watch` (killing *both*
detectors at once, not just removing one rule) is itself noticed — by an external heartbeat monitor, if you have
one configured. That's infrastructure outside this repo (see `docs/vsock-connect-detection.md` §4.4/§8), so
there's nothing this script can check on its own.

### 6. `--block` + `CAP_KILL` (`block`)

Starts a **transient** `cerberus-vsock-watch-verify.service` (via `systemd-run`, not touching your real unit's
config) with `CERBERUS_VSOCK_WATCH_BLOCK=true`, then runs `cerberus-stress` as `nobody` (a different uid than
`cerberus-audit`, so a successful kill actually proves cross-uid `CAP_KILL` is doing the work, not same-uid
signaling) making repeated vsock connects for 15s. If `--block` and `CAP_KILL` both work, `cerberus-stress` gets
`SIGKILL`ed (exit status 137) well before its own 15-second duration elapses. The real unit is restarted
unmodified afterward.

### 7. `Type=notify` startup ordering (`notify`)

Stops both units, starts `cerberus-api.service`, and confirms `cerberus-vsock-watch.service` (a) got pulled in via
`Wants=` and (b) reached `active` — meaning `READY=1` was actually received, not just that the process forked — at
or before `cerberus-api` did.

**MANUAL step this leaves for you**: the documented residual gap (`docs/vsock-connect-detection.md` §4.3) is that
`After=` only waits for `cerberus-vsock-watch`'s start job to *conclude*, not to *succeed* — if it fails outright
before ever sending `READY=1` (e.g. a bad `--audit-log` path with `--disable-ebpf`), `cerberus-api` starts right
behind it anyway. To confirm this narrow gap is exactly as documented (not wider than expected), deliberately
break the watcher's startup (temporarily point `--audit-log` at a nonexistent path) and confirm `cerberus-api`
does start regardless — expected, already documented, not a new bug to fix.

## Reporting results

Once you've run this, the useful thing to report back is the final summary block (PASS/FAIL/SKIP per item) plus
any `journalctl -u cerberus-vsock-watch` excerpts around a FAIL. If everything passes, `docs/vsock-connect-detection.md`
§6's "NOT done" list should be updated to move these items into "Done" (with a pointer to this runbook and the
host/kernel version they were verified against).

## Known findings from prior runs

**RHEL 10, 2026-07-23** — first real run of this script surfaced three issues, all now fixed (0.10.2):

- **`api-restart` genuinely failed**: a live `cerberus-api.service` restart produced real anomaly alerts for the
  legitimate `ssh-cert-api` (`cgroup id ... != expected ...`) — `Allowlist`'s cached cgroup inode was stale across
  the restart. Fixed in `Allowlist.Classify` (one uncached re-check before declaring a mismatch `Anomalous`; see
  `docs/vsock-connect-detection.md` §4.1). **If you're on an older build, expect this check to fail until you
  update.**
- **`tamper` failed for a host reason, not a Cerberus bug**: `auditctl` itself couldn't reach the kernel audit
  subsystem (`Error - audit support not in kernel`) — this kernel has no `CONFIG_AUDIT` support at all, so no
  audit rule can ever load, independent of the `audit`/`audit-rules` packaging. The script now probes for this
  with `auditctl -s` up front and fails fast with that diagnosis instead of burning 40s on a doomed wait. If you
  hit this, the fix is on the kernel/host side (confirm `CONFIG_AUDIT` is built in and `audit=0` isn't on the
  kernel command line), not in this repo.
- **`block` failed on a script bug, not a real problem**: the check compared `systemctl show`'s `AmbientCapabilities`
  output against uppercase `CAP_KILL`, but systemd renders capability names lowercase (`cap_kill`) in that
  output — the capability was actually present the whole time. Fixed to match case-insensitively.

**RHEL 10, 2026-07-23 (re-run, same host)** — confirmed `tamper` and `block` both genuinely pass now (0.10.2's
fixes were correct). `api-restart` still failed, but with only **one** false-positive alert instead of four —
progress, not a full fix:

- The round-1 "uncached recheck" fix (0.10.2) helped but didn't fully close the gap: a single immediate recheck
  isn't guaranteed to win the race against systemd's own cgroup settling during a restart — the kernel can place
  the new process into its new cgroup before the well-known `system.slice/<unit>` path `stat()`s to that same
  inode. Fixed (0.10.3) by downgrading a cgroup mismatch that survives the recheck to `Indeterminate` (alerts,
  never auto-kills) instead of trying to outrun the timing race with retries/sleeps in the hot classification
  path. See `docs/vsock-connect-detection.md` §4.1.

**RHEL 10, 2026-07-23 (third run, same host, with `freshness` confirming 0.10.3 was actually deployed)** —
`tamper` and `block` still pass. `api-restart` still reported `FAIL`, but for a different reason than either
prior round:

- **The Cerberus fix (0.10.3) was actually working correctly** — the alert firing for `ssh-cert-api` during the
  restart was `Indeterminate` (safe, by design), not `Anomalous`. **The verification script itself had the bug**:
  its check grepped for any alert mentioning `ssh-cert-api`, regardless of verdict, so it reported `FAIL` even
  though nothing dangerous happened. Fixed the script to only fail on a genuine `Anomalous` alert, warning (not
  failing) on `Indeterminate`.
- Separately, since an `Indeterminate` alert firing on every single restart is still undesirable noise (even
  though it's safe), `Allowlist.Classify`'s single recheck became a bounded retry loop (0.10.4:
  `cgroupRevalidateAttempts`/`cgroupRevalidateInterval`, default 10× 50ms) so the common case resolves cleanly to
  `Expected` with no alert at all, rather than relying on the `Indeterminate` safety net every time. See
  `docs/vsock-connect-detection.md` §4.1. **Needs a fourth re-run to confirm** — if you're still seeing
  `api-restart` fail with an `Anomalous` (not `Indeterminate`) reason, that's a genuine regression worth
  re-reporting; an occasional `Indeterminate` warning is expected and not a failure.
