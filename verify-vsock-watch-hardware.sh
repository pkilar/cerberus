#!/bin/bash

# verify-vsock-watch-hardware.sh - real-hardware verification for the
# vsock-connect detective control (cerberus-vsock-watch).
#
# Runs the checklist in docs/vsock-connect-detection.md §6 ("NOT done --
# required before production deploy, on a real target host") plus the two
# items added when reactive-kill blocking and Type=notify readiness were
# built: CAP_KILL sufficiency and the cerberus-api/cerberus-vsock-watch
# startup ordering.
#
# This CANNOT run in a development sandbox: it needs a real Linux kernel with
# BPF_PROG_TYPE_TRACEPOINT + BPF_MAP_TYPE_RINGBUF support (5.8+), auditd,
# systemd, and root (or passwordless sudo). It is meant for a staging host
# with cerberus-vsock-watch (and ideally cerberus-api) installed from the
# packaged RPM/deb/Arch artifacts -- see CLAUDE.md's Packaging section.
#
# SAFETY: several checks stop/restart cerberus-vsock-watch.service and
# cerberus-api.service, and temporarily remove/reinstall a live auditd rule.
# Do not run this against a host serving real signing traffic without
# understanding that. Pass --yes to skip the interactive confirmation.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[PASS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[FAIL]${NC} $1"; }
print_skip()    { echo -e "${YELLOW}[SKIP]${NC} $1"; }

ENCLAVE_CID=16
ENCLAVE_PORT=5000
CERBERUS_STRESS_BIN="${CERBERUS_STRESS_BIN:-}"
STRESS_RUN_USER="${STRESS_RUN_USER:-nobody}"
ASSUME_YES=0

RESULTS=()   # "item_name:PASS|FAIL|SKIP"

record() {
    RESULTS+=("$1:$2")
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "this script must run as root (or via sudo) -- it manipulates systemd units, audit rules, and capabilities"
        exit 1
    fi
}

find_stress_binary() {
    if [ -n "$CERBERUS_STRESS_BIN" ] && [ -x "$CERBERUS_STRESS_BIN" ]; then
        return 0
    fi
    if command -v cerberus-stress >/dev/null 2>&1; then
        CERBERUS_STRESS_BIN="$(command -v cerberus-stress)"
        return 0
    fi
    if [ -x ./bin/cerberus-stress ]; then
        CERBERUS_STRESS_BIN="$(pwd)/bin/cerberus-stress"
        return 0
    fi
    if command -v go >/dev/null 2>&1 && [ -f go.mod ] && [ -d cmd/cerberus-stress ]; then
        print_status "building cerberus-stress from source (cmd/cerberus-stress)..."
        if go build -o /tmp/cerberus-stress-verify ./cmd/cerberus-stress; then
            CERBERUS_STRESS_BIN=/tmp/cerberus-stress-verify
            return 0
        fi
    fi
    return 1
}

unit_installed() {
    systemctl list-unit-files "$1" >/dev/null 2>&1 && systemctl list-unit-files "$1" | grep -q "$1"
}

# Runs "$bin_path -V" and compares its output against $expected (the
# checkout's VERSION). Prints a PASS/FAIL line for $label and returns non-zero
# on a version mismatch, an unsupported -V flag, or any other failure.
check_one_binary_version() {
    local label="$1" bin_path="$2" expected="$3"
    local output status
    output=$("$bin_path" -V 2>&1)
    status=$?
    if [ "$status" -ne 0 ]; then
        if echo "$output" | grep -q "flag provided but not defined: -V"; then
            print_error "$label ($bin_path) does not support -V yet -- installed binary predates the version-flag feature; rebuild and reinstall the package"
        else
            print_error "$label ($bin_path) -V failed (exit $status): $(echo "$output" | head -1)"
        fi
        return 1
    fi
    local got
    got=$(echo "$output" | head -1 | tr -d '[:space:]')
    if [ "$got" != "$expected" ]; then
        print_error "$label ($bin_path) reports version '$got', expected '$expected' (from VERSION) -- installed binary is stale; rebuild and reinstall the package"
        return 1
    fi
    print_status "$label ($bin_path) version matches VERSION: $got"
    return 0
}

# --- Item 0: do the installed cerberus binaries actually match this checkout? ---
# This script never rebuilds or reinstalls cerberus-vsock-watch/ssh-cert-api
# itself (only cerberus-stress, as a disposable test client) -- it only drives
# whatever is already installed. If you pulled a fix but didn't
# rebuild+reinstall the package, the Go-code-dependent checks below
# (api-restart, in particular) will keep failing identically, which looks
# exactly like "the fix didn't work" even though it was never actually
# deployed. Every binary reports its exact build version via -V (stamped from
# the top-level VERSION file at build time -- see version/version.go), so this
# is an exact comparison, not a timestamp-based heuristic.
check_deployment_freshness() {
    echo
    echo "=== 0. Confirm installed cerberus binaries match this checkout's VERSION ==="

    if [ ! -f VERSION ]; then
        print_warning "no VERSION file in the current directory -- not running from a repo checkout root; skipping version check"
        record deployment_freshness SKIP
        return 2
    fi
    local expected
    expected=$(tr -d '[:space:]' < VERSION)
    if [ -z "$expected" ]; then
        print_warning "VERSION file is empty -- skipping version check"
        record deployment_freshness SKIP
        return 2
    fi
    print_status "expected version (from VERSION): $expected"

    local ok=1 checked=0

    # label:path:unit -- the unit name only decides whether "binary missing"
    # is expected (not installed at all -> SKIP) or itself a problem (the unit
    # IS installed but the binary it points at is gone -> FAIL).
    local -a targets=(
        "cerberus-vsock-watch:/usr/bin/cerberus-vsock-watch:cerberus-vsock-watch.service"
        "ssh-cert-api:/usr/bin/ssh-cert-api:cerberus-api.service"
    )
    local entry label rest bin_path unit
    for entry in "${targets[@]}"; do
        label="${entry%%:*}"
        rest="${entry#*:}"
        bin_path="${rest%%:*}"
        unit="${rest#*:}"

        if [ ! -x "$bin_path" ]; then
            if unit_installed "$unit"; then
                print_error "$unit is installed but $bin_path is missing or not executable"
                ok=0
            else
                print_skip "$label not installed at $bin_path -- skipping"
            fi
            continue
        fi
        checked=$((checked + 1))
        check_one_binary_version "$label" "$bin_path" "$expected" || ok=0
    done

    # ssh-cert-signer normally runs only inside the Nitro enclave, not on this
    # host -- there is no VSOCK "report version" message (see messages/), so it
    # can't be checked remotely. Best-effort: only check it if a copy happens
    # to be present on the host (e.g. a non-enclave dev setup).
    if [ -x /usr/bin/ssh-cert-signer ]; then
        checked=$((checked + 1))
        check_one_binary_version "ssh-cert-signer" /usr/bin/ssh-cert-signer "$expected" || ok=0
    else
        print_skip "ssh-cert-signer not present on this host -- expected, it normally runs only inside the Nitro enclave and can't be version-checked remotely"
    fi

    # cerberus-stress is the disposable test client this script itself drives
    # (find_stress_binary) -- report its version for diagnostic context, but
    # don't fail the overall check on a mismatch: it's commonly built ad hoc
    # from source (reporting "dev") rather than installed from a package.
    if find_stress_binary; then
        local stress_output stress_version stress_status
        stress_output=$("$CERBERUS_STRESS_BIN" -V 2>&1)
        stress_status=$?
        if [ "$stress_status" -eq 0 ]; then
            stress_version=$(echo "$stress_output" | head -1 | tr -d '[:space:]')
            if [ "$stress_version" = "$expected" ]; then
                print_status "cerberus-stress ($CERBERUS_STRESS_BIN) version matches VERSION: $stress_version"
            else
                print_warning "cerberus-stress ($CERBERUS_STRESS_BIN) reports version '$stress_version', checkout VERSION is '$expected' -- fine for an ad hoc test client, just informational"
            fi
        else
            print_warning "cerberus-stress ($CERBERUS_STRESS_BIN) does not support -V yet -- predates the version-flag feature; rebuild it (this does not affect the checks above)"
        fi
    fi

    if [ "$checked" -eq 0 ]; then
        print_skip "no relevant cerberus binaries found on this host -- skipping version check"
        record deployment_freshness SKIP
        return 2
    fi

    if [ "$ok" -eq 1 ]; then
        record deployment_freshness PASS
    else
        print_error "rebuild and reinstall the mismatched package(s) (or at least the binary + restart the affected service) before trusting the checks below -- an identical failure across re-runs usually means the fix was never actually deployed, not that it didn't work"
        record deployment_freshness FAIL
    fi
}

# --- Item 1: tracepoint format matches vsock_connect.c's assumptions ---
check_tracepoint_format() {
    echo
    echo "=== 1. Tracepoint format (docs/vsock-connect-detection.md §6, vsock_connect.c) ==="
    local fmt_path=""
    for p in /sys/kernel/tracing/events/syscalls/sys_enter_connect/format \
             /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format; do
        if [ -r "$p" ]; then
            fmt_path="$p"
            break
        fi
    done
    if [ -z "$fmt_path" ]; then
        print_error "tracepoint format file not found/readable at either tracefs or debugfs path -- is tracefs/debugfs mounted? are you root?"
        record tracepoint_format FAIL
        return 1
    fi
    echo "--- $fmt_path ---"
    cat "$fmt_path"
    echo "---"

    local ok=1
    check_field() {
        local name="$1" want_offset="$2" want_size="$3"
        local line offset size
        line=$(grep -E "field:.*[[:space:]]$name;" "$fmt_path" | head -1)
        if [ -z "$line" ]; then
            print_error "field '$name' not found in tracepoint format"
            ok=0
            return
        fi
        offset=$(echo "$line" | grep -oP 'offset:\K[0-9]+')
        size=$(echo "$line" | grep -oP 'size:\K[0-9]+')
        if [ "$offset" != "$want_offset" ] || [ "$size" != "$want_size" ]; then
            print_error "field '$name': got offset=$offset size=$size, want offset=$want_offset size=$want_size"
            ok=0
        else
            print_status "field '$name': offset=$offset size=$size (matches trace_event_raw_sys_enter's common header)"
        fi
    }
    check_field common_type 0 2
    check_field common_flags 2 1
    check_field common_preempt_count 3 1
    check_field common_pid 4 4

    # connect(2)'s 2nd argument (the sockaddr pointer, usually named
    # "uservaddr") is what vsock_connect.c reads via ctx->args[1] -- i.e. it
    # assumes offset 16 + 8*1 = 24, size 8 (an 8-byte-aligned slot per arg,
    # matching the generic args[6] convention bcc/libbpf-tools rely on).
    local uv_line uv_offset uv_size
    uv_line=$(grep -E 'field:.*\*[[:space:]]*uservaddr;' "$fmt_path" | head -1)
    if [ -z "$uv_line" ]; then
        print_warning "no field literally named 'uservaddr' found -- inspect $fmt_path by hand and confirm the SECOND syscall argument (after fd) sits at offset 24, size 8"
    else
        uv_offset=$(echo "$uv_line" | grep -oP 'offset:\K[0-9]+')
        uv_size=$(echo "$uv_line" | grep -oP 'size:\K[0-9]+')
        if [ "$uv_offset" = "24" ] && [ "$uv_size" = "8" ]; then
            print_status "field 'uservaddr': offset=24 size=8 -- matches ctx->args[1] in vsock_connect.c"
        else
            print_error "field 'uservaddr': got offset=$uv_offset size=$uv_size, want offset=24 size=8 -- vsock_connect.c would read the WRONG bytes on this kernel/arch; do not deploy the eBPF path here without fixing the offset"
            ok=0
        fi
    fi

    if [ "$ok" -eq 1 ]; then
        record tracepoint_format PASS
    else
        record tracepoint_format FAIL
    fi
    return $((1 - ok))
}

# --- Items 2+3: BPF verifier accepts the program; a real connect emits a real event ---
check_ebpf_live() {
    echo
    echo "=== 2+3. eBPF verifier acceptance + a real VSOCK connect emits an event ==="
    if ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-vsock-watch.service not installed -- cannot verify"
        record ebpf_verifier SKIP
        record ebpf_live_event SKIP
        return 2
    fi
    systemctl start cerberus-vsock-watch.service
    sleep 2
    if ! systemctl is-active --quiet cerberus-vsock-watch.service; then
        print_error "cerberus-vsock-watch.service failed to start -- see: journalctl -u cerberus-vsock-watch -n 50"
        record ebpf_verifier FAIL
        record ebpf_live_event FAIL
        return 1
    fi
    if journalctl -u cerberus-vsock-watch --since "-15 seconds" --no-pager 2>/dev/null | grep -q 'vsockwatch.ebpf.stopped'; then
        print_error "eBPF detector failed to load/attach -- BPF verifier rejected the program or the kernel lacks support. See: journalctl -u cerberus-vsock-watch"
        print_warning "if this host intentionally runs --disable-ebpf, items 2/3/6 (eBPF-specific) can't be verified here; the auditd-only path is unaffected"
        record ebpf_verifier FAIL
        record ebpf_live_event SKIP
        return 1
    fi
    print_status "no vsockwatch.ebpf.stopped in recent logs -- BPF verifier accepted the program and the tracepoint attached (item 2)"
    record ebpf_verifier PASS

    if ! find_stress_binary; then
        print_error "cerberus-stress binary not found and could not be built -- set CERBERUS_STRESS_BIN or run from a repo checkout with 'go' installed"
        record ebpf_live_event FAIL
        return 1
    fi
    print_status "using cerberus-stress at $CERBERUS_STRESS_BIN to drive a real VSOCK connect(2) to CID=$ENCLAVE_CID port=$ENCLAVE_PORT"
    print_status "(cerberus-stress's own exe path is not /usr/bin/ssh-cert-api, so Allowlist.Classify marks it Anomalous by design -- no spoofing needed)"
    timeout 10 "$CERBERUS_STRESS_BIN" signer -transport vsock -target "${ENCLAVE_CID}:${ENCLAVE_PORT}" -requests 1 -timeout 3s \
        >/tmp/cstress-verify.out 2>&1
    sleep 1

    if journalctl -u cerberus-vsock-watch --since "-15 seconds" --no-pager 2>/dev/null | grep 'vsockwatch.alert' | grep -qi ebpf; then
        print_status "eBPF path emitted and classified a real anomalous event (item 3) -- inspect journalctl -u cerberus-vsock-watch for the pid/uid/comm fields"
        record ebpf_live_event PASS
    else
        print_error "no eBPF-sourced anomaly alert observed within 15s -- check journalctl -u cerberus-vsock-watch and /tmp/cstress-verify.out (did the connect() actually happen? is /dev/vsock present?)"
        record ebpf_live_event FAIL
        return 1
    fi
}

# --- Item 4: cerberus-api restart mid-run does not cause a false positive ---
check_api_restart_chaos() {
    echo
    echo "=== 4. Chaos test: cerberus-api.service restart (MainPID/cgroup transition) ==="
    if ! unit_installed cerberus-api.service; then
        print_skip "cerberus-api.service not installed -- skipping"
        record api_restart_chaos SKIP
        return 2
    fi
    systemctl start cerberus-vsock-watch.service 2>/dev/null
    systemctl start cerberus-api.service || { print_error "failed to start cerberus-api.service"; record api_restart_chaos FAIL; return 1; }
    sleep 2
    # Anchor the log query to the actual restart moment rather than a fixed
    # "-10 seconds" lookback: a fixed window can reach back far enough to pick
    # up an unrelated anomaly alert from an EARLIER check (e.g. item 2+3's
    # deliberate cerberus-stress anomaly), especially when items run quickly
    # back to back.
    local restart_ts
    restart_ts=$(date '+%Y-%m-%d %H:%M:%S')
    print_status "restarting cerberus-api.service (new MainPID) while cerberus-vsock-watch observes..."
    systemctl restart cerberus-api.service
    sleep 3
    # An ANOMALOUS alert naming ssh-cert-api's own exe would be a real
    # regression (it's what --block would act on). An INDETERMINATE alert
    # naming it is expected, by-design, best-effort behavior: Allowlist
    # retries a cgroup mismatch for a bounded window before giving up (see
    # docs/vsock-connect-detection.md §4.1) -- if that retry budget is ever
    # exhausted on a slow-to-settle host, the result is a still-safe
    # Indeterminate alert (never Blockworthy), not a failure of this check.
    #
    # Match on the alert's exe= field specifically, not a bare substring
    # search for "ssh-cert-api" anywhere in the line: every anomaly alert's
    # "reason" text names the *expected* exe path too (e.g. `exe
    # "/tmp/cerberus-stress-verify" != expected "/usr/bin/ssh-cert-api"`), so a
    # bare substring grep also matches alerts about a COMPLETELY different
    # process (like the disposable cerberus-stress test client from an earlier
    # check) merely because ssh-cert-api's path is mentioned as the expectation.
    local restart_alerts
    restart_alerts=$(journalctl -u cerberus-vsock-watch --since "$restart_ts" --no-pager 2>/dev/null | grep 'vsockwatch.alert' | grep -E 'exe=/usr/bin/ssh-cert-api([[:space:]]|$)')
    if echo "$restart_alerts" | grep -qi 'reason="anomalous:'; then
        print_error "a false-positive ANOMALOUS alert fired for the legitimate ssh-cert-api exe during the restart (this would trigger --block) -- see journalctl -u cerberus-vsock-watch"
        record api_restart_chaos FAIL
        return 1
    fi
    if echo "$restart_alerts" | grep -qi 'reason="indeterminate:'; then
        print_warning "an Indeterminate alert fired for ssh-cert-api during the restart -- expected, by-design: Allowlist's cgroup-settling retry budget was exhausted this time, but Indeterminate never triggers --block. Not a failure, but if this happens often, consider raising cgroupRevalidateAttempts/cgroupRevalidateInterval (vsockwatch/allowlist.go)."
    fi
    print_status "no false-positive ANOMALOUS alert during cerberus-api's MainPID/cgroup transition"
    record api_restart_chaos PASS
}

# --- Item 5: audit-rule removal triggers the tampering meta-alert ---
check_tamper_alert() {
    echo
    echo "=== 5. Chaos test: audit rule removal -> tampering meta-alert ==="
    if ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-vsock-watch.service not installed -- skipping"
        record tamper_alert SKIP
        return 2
    fi

    # Fail fast if the kernel itself lacks audit netlink support (CONFIG_AUDIT
    # not built in, or disabled via the audit= kernel command-line parameter).
    # auditctl's add/list/delete calls all fail identically in that case
    # ("Error - audit support not in kernel", "Cannot open netlink audit
    # socket") regardless of the audit-rules package being installed -- this
    # is a kernel/host configuration issue, not something any packaging fix
    # can address, and it's better to say so clearly than to blindly report
    # PASS on rule install and burn 40s waiting for an alert that can never
    # fire (observed on a real RHEL 10 host).
    local probe_err
    if ! probe_err=$(auditctl -s 2>&1 >/dev/null); then
        print_error "auditctl cannot reach the kernel audit subsystem: ${probe_err}"
        print_error "this is a kernel/host configuration issue, not a Cerberus bug -- check that this kernel has CONFIG_AUDIT built in and that 'audit=1' isn't disabled on the kernel command line (cat /proc/cmdline), then retry"
        record tamper_alert FAIL
        return 1
    fi

    systemctl start cerberus-vsock-watch.service
    if ! auditctl -l 2>/dev/null | grep -q cerberus_vsock_watch; then
        print_status "installing the audit rule from packaging/audit-rules/61-cerberus-vsock.rules"
        if ! auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch; then
            print_error "auditctl -a failed to install the arch=b64 rule -- see output above"
            record tamper_alert FAIL
            return 1
        fi
        if ! auditctl -a always,exit -F arch=b32 -S connect -k cerberus_vsock_watch; then
            print_error "auditctl -a failed to install the arch=b32 rule -- see output above"
            record tamper_alert FAIL
            return 1
        fi
    fi
    if ! auditctl -l 2>/dev/null | grep -q cerberus_vsock_watch; then
        print_error "rule installation did not take effect (auditctl -l shows nothing for cerberus_vsock_watch) -- cannot proceed"
        record tamper_alert FAIL
        return 1
    fi
    sleep 2

    print_status "removing the audit rule (simulating tampering)..."
    auditctl -d always,exit -F arch=b64 -S connect -k cerberus_vsock_watch 2>/dev/null
    auditctl -d always,exit -F arch=b32 -S connect -k cerberus_vsock_watch 2>/dev/null
    if auditctl -l 2>/dev/null | grep -q cerberus_vsock_watch; then
        print_error "rule still present after auditctl -d -- syntax mismatch against the installed rule; check auditctl -l output"
        record tamper_alert FAIL
        return 1
    fi

    local interval
    interval=$(systemctl show cerberus-vsock-watch.service -p Environment --value 2>/dev/null | grep -oP 'TAMPER_CHECK_INTERVAL=\K[0-9a-z]+' || echo "30s")
    print_status "waiting ~40s for TamperWatch's check interval (default 30s, configured: ${interval})..."
    sleep 40
    if journalctl -u cerberus-vsock-watch --since "-45 seconds" --no-pager 2>/dev/null | grep -q 'detector_tampering'; then
        print_status "tampering meta-alert fired after audit rule removal"
        record tamper_alert PASS
    else
        print_error "no detector_tampering alert within 45s"
        print_error "self-diagnosing: does cerberus-audit (the de-privileged service account) actually get to run auditctl -l?"
        local cerberus_audit_out
        if cerberus_audit_out=$(sudo -u cerberus-audit auditctl -l 2>&1); then
            print_warning "sudo -u cerberus-audit auditctl -l succeeded (output: '${cerberus_audit_out:-<empty>}') -- CAP_AUDIT_CONTROL itself isn't the problem; check for a TamperWatch-specific issue instead (journalctl -u cerberus-vsock-watch --since '-1 minute')"
        else
            print_error "sudo -u cerberus-audit auditctl -l FAILED: ${cerberus_audit_out}"
            local selinux_mode
            selinux_mode=$(getenforce 2>/dev/null || echo "unknown (getenforce unavailable)")
            print_error "SELinux mode: ${selinux_mode}"
            if [ "$selinux_mode" = "Enforcing" ]; then
                print_error "SELinux is enforcing and may be denying cerberus-audit's audit-control actions independently of the Linux capability grant -- check for AVC denials:"
                (ausearch -m avc -ts recent 2>&1 || journalctl -k --since '-2 minutes' 2>&1 | grep -i avc) | tail -20
            fi
        fi
        record tamper_alert FAIL
    fi

    print_status "restoring the audit rule..."
    auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch || print_warning "failed to restore the arch=b64 rule -- restore it manually"
    auditctl -a always,exit -F arch=b32 -S connect -k cerberus_vsock_watch || print_warning "failed to restore the arch=b32 rule -- restore it manually"

    print_warning "MANUAL: separately confirm 'systemctl stop cerberus-vsock-watch' (killing BOTH detectors at once) is itself noticed operationally -- e.g. via the external heartbeat monitor if configured (docs/vsock-connect-detection.md §4.4/§8). Not scriptable here: it depends on infrastructure outside this repo."
}

# --- Item 6: --block + CAP_KILL actually SIGKILLs a cross-uid process ---
check_block_cap_kill() {
    echo
    echo "=== 6. --block reactive-kill + CAP_KILL (cross-uid signal) ==="
    if ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-vsock-watch.service not installed -- skipping"
        record block_cap_kill SKIP
        return 2
    fi
    if ! find_stress_binary; then
        print_error "cerberus-stress binary not found and could not be built -- set CERBERUS_STRESS_BIN or run from a repo checkout with 'go' installed"
        record block_cap_kill FAIL
        return 1
    fi
    local caps
    caps=$(systemctl show cerberus-vsock-watch.service -p AmbientCapabilities --value 2>/dev/null)
    echo "AmbientCapabilities on cerberus-vsock-watch.service: $caps"
    # systemd renders capability names lowercase (e.g. "cap_kill") in this
    # --value output, NOT the uppercase CAP_KILL form used in unit-file
    # syntax -- match case-insensitively rather than assuming one form.
    if ! echo "$caps" | grep -qi 'cap_kill'; then
        print_error "CAP_KILL NOT present -- --block cannot signal a process it doesn't own. Check packaging/*/cerberus-vsock-watch.service and 'systemctl daemon-reload'"
        record block_cap_kill FAIL
        return 1
    fi
    print_status "CAP_KILL present in the running unit's AmbientCapabilities"

    print_warning "starting a transient cerberus-vsock-watch-verify.service with --block enabled (does not modify the real unit); it WILL SIGKILL the disposable cerberus-stress test process below."
    systemctl stop cerberus-vsock-watch.service 2>/dev/null
    systemd-run --unit=cerberus-vsock-watch-verify --uid=cerberus-audit --gid=cerberus-audit \
        -p AmbientCapabilities='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL' \
        -p CapabilityBoundingSet='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL' \
        -p Environment='CERBERUS_VSOCK_WATCH_BLOCK=true' \
        /usr/bin/cerberus-vsock-watch
    sleep 2

    print_status "running cerberus-stress as user '$STRESS_RUN_USER' (a different uid than cerberus-audit, so a successful kill genuinely proves CAP_KILL is doing the work, not same-uid signaling)"
    runuser -u "$STRESS_RUN_USER" -- "$CERBERUS_STRESS_BIN" signer -transport vsock -target "${ENCLAVE_CID}:${ENCLAVE_PORT}" -concurrency 1 -duration 15s &
    local stress_pid=$!
    local start end elapsed status
    start=$(date +%s)
    wait "$stress_pid"
    status=$?
    end=$(date +%s)
    elapsed=$((end - start))

    systemctl stop cerberus-vsock-watch-verify.service 2>/dev/null
    systemctl start cerberus-vsock-watch.service 2>/dev/null

    if [ "$status" -eq 137 ] && [ "$elapsed" -lt 15 ]; then
        print_status "cerberus-stress was SIGKILLed after ${elapsed}s (before its own 15s -duration) -- --block + CAP_KILL confirmed working cross-uid"
        record block_cap_kill PASS
    else
        print_error "cerberus-stress exited with status=$status after ${elapsed}s (expected: killed by SIGKILL [status 137] well before 15s)"
        record block_cap_kill FAIL
    fi
}

# --- Item 7: cerberus-api actually waits on cerberus-vsock-watch's Type=notify readiness ---
check_systemd_notify_ordering() {
    echo
    echo "=== 7. cerberus-api waits on cerberus-vsock-watch's Type=notify readiness ==="
    if ! unit_installed cerberus-api.service || ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-api.service and/or cerberus-vsock-watch.service not installed -- skipping"
        record systemd_notify_ordering SKIP
        return 2
    fi
    systemctl stop cerberus-api.service cerberus-vsock-watch.service 2>/dev/null
    sleep 1
    print_status "starting cerberus-api.service (should pull in cerberus-vsock-watch.service via Wants= and wait via After=)..."
    systemctl start cerberus-api.service
    sleep 2

    if ! systemctl is-active --quiet cerberus-vsock-watch.service; then
        print_error "cerberus-vsock-watch.service is not active after starting cerberus-api -- Wants= did not pull it in"
        record systemd_notify_ordering FAIL
        return 1
    fi

    local api_start watch_start unit_type
    api_start=$(systemctl show cerberus-api.service -p ActiveEnterTimestampMonotonic --value)
    watch_start=$(systemctl show cerberus-vsock-watch.service -p ActiveEnterTimestampMonotonic --value)
    unit_type=$(systemctl show cerberus-vsock-watch.service -p Type --value)
    echo "cerberus-vsock-watch Type=$unit_type, ActiveEnterTimestampMonotonic=$watch_start"
    echo "cerberus-api          ActiveEnterTimestampMonotonic=$api_start"

    if [ "$unit_type" != "notify" ]; then
        print_error "cerberus-vsock-watch.service Type=$unit_type, want notify -- packaging drifted from what's expected"
        record systemd_notify_ordering FAIL
        return 1
    fi
    if [ "$watch_start" -le "$api_start" ]; then
        print_status "cerberus-vsock-watch reached 'active' (READY=1 received) at or before cerberus-api -- Type=notify + After= ordering held"
        record systemd_notify_ordering PASS
    else
        print_error "cerberus-vsock-watch became active AFTER cerberus-api -- ordering did not hold as expected"
        record systemd_notify_ordering FAIL
    fi

    print_warning "MANUAL: to confirm the documented residual gap (docs/vsock-connect-detection.md §4.3) is exactly as narrow as described, try forcing cerberus-vsock-watch to fail fast before READY=1 (e.g. temporarily point --audit-log at a nonexistent path with --disable-ebpf) and confirm cerberus-api starts anyway right behind the failed unit -- expected and already documented, not a new bug."
}

# --- Item 8: LSM gate kernel support (non-gating, informational) ---
# Per docs/vsock-connect-detection.md §4.6, kernel support for the preventive
# LSM gate (CONFIG_BPF_LSM, an active "bpf" LSM) is a deployment concern to
# document and check, not a gate on the rest of this script -- a FAIL here
# doesn't stop check_lsm_monitor_dry_run/check_lsm_enforce_denies from being
# attempted; they'll simply fail on their own (LSMGuard.Run's own graceful
# load-failure error) if this host genuinely lacks support.
check_lsm_kernel_support() {
    echo
    echo "=== 8. LSM gate kernel support (docs/vsock-connect-detection.md §4.6) ==="
    local ok=1

    if [ -r /sys/kernel/security/lsm ]; then
        local active_lsms
        active_lsms=$(cat /sys/kernel/security/lsm)
        echo "Active LSMs: $active_lsms"
        if echo "$active_lsms" | tr ',' '\n' | grep -qx bpf; then
            print_status "\"bpf\" is active in /sys/kernel/security/lsm"
        else
            print_error "\"bpf\" is NOT active in /sys/kernel/security/lsm -- APPEND (never replace) \"bpf\" to the kernel's lsm= boot parameter and reboot; see docs/RUNBOOK.md's Preventive LSM gate prerequisites"
            ok=0
        fi
    else
        print_error "/sys/kernel/security/lsm not readable -- can't confirm which LSMs are active"
        ok=0
    fi

    local kconfig
    kconfig="/boot/config-$(uname -r)"
    if [ -r "$kconfig" ]; then
        if grep -q '^CONFIG_BPF_LSM=y' "$kconfig"; then
            print_status "CONFIG_BPF_LSM=y in $kconfig"
        else
            print_error "CONFIG_BPF_LSM not enabled in $kconfig -- the LSM gate can never load on this kernel"
            ok=0
        fi
    else
        print_warning "$kconfig not readable -- can't confirm CONFIG_BPF_LSM from here; check your distro's alternate config location"
    fi

    if [ "$ok" -eq 1 ]; then
        record lsm_kernel_support PASS
    else
        record lsm_kernel_support FAIL
    fi
}

# --- Item 9: --lsm-monitor loads, logs would-deny, never denies ---
check_lsm_monitor_dry_run() {
    echo
    echo "=== 9. --lsm-monitor dry run: loads, logs would-deny, connect() still succeeds ==="
    if ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-vsock-watch.service not installed -- skipping"
        record lsm_monitor_dry_run SKIP
        return 2
    fi
    if ! find_stress_binary; then
        print_error "cerberus-stress binary not found and could not be built -- set CERBERUS_STRESS_BIN or run from a repo checkout with 'go' installed"
        record lsm_monitor_dry_run FAIL
        return 1
    fi

    print_warning "starting a transient cerberus-vsock-watch-lsm-verify.service with --lsm-monitor (does not modify the real unit); it does not deny anything by design."
    systemctl stop cerberus-vsock-watch.service 2>/dev/null
    local start_ts
    start_ts=$(date '+%Y-%m-%d %H:%M:%S')
    systemd-run --unit=cerberus-vsock-watch-lsm-verify --uid=cerberus-audit --gid=cerberus-audit \
        -p AmbientCapabilities='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p CapabilityBoundingSet='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p Environment='CERBERUS_VSOCK_WATCH_LSM_MONITOR=true' \
        /usr/bin/cerberus-vsock-watch
    sleep 2

    if ! systemctl is-active --quiet cerberus-vsock-watch-lsm-verify.service; then
        print_error "transient --lsm-monitor unit failed to start -- see: journalctl -u cerberus-vsock-watch-lsm-verify -n 50"
        systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
        systemctl start cerberus-vsock-watch.service 2>/dev/null
        record lsm_monitor_dry_run FAIL
        return 1
    fi
    if journalctl -u cerberus-vsock-watch-lsm-verify --since "$start_ts" --no-pager 2>/dev/null | grep -q 'vsockwatch.lsm.stopped'; then
        print_error "LSM gate failed to load/attach -- likely missing kernel support (see the lsm-kernel-support check) or the unconfirmed BTF attach-point naming in vsock_lsm.c's header comment"
        systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
        systemctl start cerberus-vsock-watch.service 2>/dev/null
        record lsm_monitor_dry_run FAIL
        return 1
    fi
    print_status "--lsm-monitor attached without error"

    print_status "using cerberus-stress at $CERBERUS_STRESS_BIN to drive a real VSOCK connect(2) to CID=$ENCLAVE_CID port=$ENCLAVE_PORT (outside ssh-cert-api's cgroup, so the LSM gate should flag it)"
    local stress_status
    timeout 10 "$CERBERUS_STRESS_BIN" signer -transport vsock -target "${ENCLAVE_CID}:${ENCLAVE_PORT}" -requests 1 -timeout 3s \
        >/tmp/cstress-lsm-verify.out 2>&1
    stress_status=$?
    sleep 1

    local lsm_alerts
    lsm_alerts=$(journalctl -u cerberus-vsock-watch-lsm-verify --since "$start_ts" --no-pager 2>/dev/null | grep 'vsockwatch.alert' | grep 'kind=vsock_lsm_block')

    systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
    systemctl start cerberus-vsock-watch.service 2>/dev/null

    if [ "$stress_status" -ne 0 ]; then
        print_error "cerberus-stress's connect() FAILED (exit $stress_status) even though only --lsm-monitor (not --lsm-enforce) was active -- monitor mode must never deny; see /tmp/cstress-lsm-verify.out"
        record lsm_monitor_dry_run FAIL
        return 1
    fi
    print_status "cerberus-stress's connect() succeeded as expected -- monitor mode never denies"

    if ! echo "$lsm_alerts" | grep -q 'lsm_mode=monitor'; then
        print_error "no vsock_lsm_block alert with lsm_mode=monitor observed -- check journalctl -u cerberus-vsock-watch-lsm-verify"
        record lsm_monitor_dry_run FAIL
        return 1
    fi
    if echo "$lsm_alerts" | grep -q 'lsm_denied=true'; then
        print_error "a would-deny event reported lsm_denied=true while only --lsm-monitor was active -- this would be a real bug in LSMGuard's mode tracking"
        record lsm_monitor_dry_run FAIL
        return 1
    fi
    print_status "would-deny alert observed with lsm_mode=monitor, lsm_denied=false -- monitor mode logging confirmed"
    record lsm_monitor_dry_run PASS
}

# --- Item 10: --lsm-enforce actually denies a cgroup-mismatched connect() ---
check_lsm_enforce_denies() {
    echo
    echo "=== 10. --lsm-enforce actually denies a cgroup-mismatched connect() ==="
    if ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-vsock-watch.service not installed -- skipping"
        record lsm_enforce_denies SKIP
        return 2
    fi
    if ! find_stress_binary; then
        print_error "cerberus-stress binary not found and could not be built -- set CERBERUS_STRESS_BIN or run from a repo checkout with 'go' installed"
        record lsm_enforce_denies FAIL
        return 1
    fi

    print_warning "starting a transient cerberus-vsock-watch-lsm-verify.service with --lsm-monitor --lsm-enforce (does not modify the real unit); it WILL deny the disposable cerberus-stress connect() below."
    systemctl stop cerberus-vsock-watch.service 2>/dev/null
    systemd-run --unit=cerberus-vsock-watch-lsm-verify --uid=cerberus-audit --gid=cerberus-audit \
        -p AmbientCapabilities='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p CapabilityBoundingSet='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p Environment='CERBERUS_VSOCK_WATCH_LSM_MONITOR=true CERBERUS_VSOCK_WATCH_LSM_ENFORCE=true' \
        /usr/bin/cerberus-vsock-watch
    sleep 2

    if ! systemctl is-active --quiet cerberus-vsock-watch-lsm-verify.service; then
        print_error "transient --lsm-enforce unit failed to start -- see: journalctl -u cerberus-vsock-watch-lsm-verify -n 50"
        systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
        systemctl start cerberus-vsock-watch.service 2>/dev/null
        record lsm_enforce_denies FAIL
        return 1
    fi

    print_status "using cerberus-stress at $CERBERUS_STRESS_BIN to drive a real VSOCK connect(2) that should now be DENIED"
    local stress_status
    timeout 10 "$CERBERUS_STRESS_BIN" signer -transport vsock -target "${ENCLAVE_CID}:${ENCLAVE_PORT}" -requests 1 -timeout 3s \
        >/tmp/cstress-lsm-enforce-verify.out 2>&1
    stress_status=$?

    systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
    systemctl start cerberus-vsock-watch.service 2>/dev/null

    if [ "$stress_status" -eq 0 ]; then
        print_error "cerberus-stress's connect() SUCCEEDED even with --lsm-enforce active -- the LSM gate did not deny it; see /tmp/cstress-lsm-enforce-verify.out and confirm CONFIG_BPF_LSM/lsm=bpf are actually active (the lsm-kernel-support check)"
        record lsm_enforce_denies FAIL
        return 1
    fi
    print_status "cerberus-stress's connect() was denied (exit $stress_status) -- --lsm-enforce confirmed working"
    record lsm_enforce_denies PASS
}

# --- Item 11: cerberus-api restart under --lsm-enforce never denies the legitimate process ---
# The single highest-stakes check in this script: a failure here means a
# real, self-inflicted signing outage during every cerberus-api restart, not
# just a noisy false-positive alert (see docs/vsock-connect-detection.md
# §4.6's "restart race" discussion).
check_lsm_restart_chaos() {
    echo
    echo "=== 11. Chaos test: cerberus-api.service restart under --lsm-enforce ==="
    if ! unit_installed cerberus-api.service || ! unit_installed cerberus-vsock-watch.service; then
        print_skip "cerberus-api.service and/or cerberus-vsock-watch.service not installed -- skipping"
        record lsm_restart_chaos SKIP
        return 2
    fi

    print_warning "starting a transient cerberus-vsock-watch-lsm-verify.service with --lsm-monitor --lsm-enforce (does not modify the real unit) to watch cerberus-api's restart."
    systemctl stop cerberus-vsock-watch.service 2>/dev/null
    systemd-run --unit=cerberus-vsock-watch-lsm-verify --uid=cerberus-audit --gid=cerberus-audit \
        -p AmbientCapabilities='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p CapabilityBoundingSet='CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_AUDIT_CONTROL CAP_DAC_READ_SEARCH CAP_KILL CAP_MAC_ADMIN' \
        -p Environment='CERBERUS_VSOCK_WATCH_LSM_MONITOR=true CERBERUS_VSOCK_WATCH_LSM_ENFORCE=true' \
        /usr/bin/cerberus-vsock-watch
    sleep 2
    if ! systemctl is-active --quiet cerberus-vsock-watch-lsm-verify.service; then
        print_error "transient --lsm-enforce unit failed to start -- see: journalctl -u cerberus-vsock-watch-lsm-verify -n 50"
        systemctl start cerberus-vsock-watch.service 2>/dev/null
        record lsm_restart_chaos FAIL
        return 1
    fi

    systemctl start cerberus-api.service || {
        print_error "failed to start cerberus-api.service"
        systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
        systemctl start cerberus-vsock-watch.service 2>/dev/null
        record lsm_restart_chaos FAIL
        return 1
    }
    sleep 2
    local restart_ts
    restart_ts=$(date '+%Y-%m-%d %H:%M:%S')
    print_status "restarting cerberus-api.service (new MainPID/cgroup) while the --lsm-enforce transient unit observes..."
    systemctl restart cerberus-api.service
    sleep 3

    local ok=1

    # (a) no lsm_denied=true alert naming ssh-cert-api's own exe -- exactly
    # the self-inflicted-DoS case this check exists to catch. Matches on the
    # exe= field specifically for the same reason check_api_restart_chaos
    # does (see that function's comment).
    if journalctl -u cerberus-vsock-watch-lsm-verify --since "$restart_ts" --no-pager 2>/dev/null \
        | grep 'vsockwatch.alert' | grep -E 'exe=/usr/bin/ssh-cert-api([[:space:]]|$)' | grep -q 'lsm_denied=true'; then
        print_error "the LSM gate DENIED the legitimate ssh-cert-api during its own restart -- a real, self-inflicted signing outage. See journalctl -u cerberus-vsock-watch-lsm-verify and consider raising --lsm-poll-interval's default, or investigate the cgroup-settling race (docs/vsock-connect-detection.md §4.6)"
        ok=0
    else
        print_status "no lsm_denied=true alert naming ssh-cert-api's own exe during the restart"
    fi

    # (b) best-effort cross-check: a real signing request across the restart
    # window should succeed too -- catches a denial that doesn't even surface
    # as a clean alert line. Not fatal on its own (may need Kerberos/SPNEGO
    # setup this script doesn't manage), so a failure here only warns.
    if find_stress_binary; then
        print_status "issuing a real signing request through the restarted cerberus-api to cross-check (a) above..."
        if timeout 10 "$CERBERUS_STRESS_BIN" api -requests 1 -timeout 5s >/tmp/cstress-lsm-restart-verify.out 2>&1; then
            print_status "signing request succeeded across the restart window"
        else
            print_warning "signing request failed -- inspect /tmp/cstress-lsm-restart-verify.out; may be an unrelated cerberus-stress/API-auth setup issue rather than the LSM gate (cross-check against (a) above)"
        fi
    fi

    systemctl stop cerberus-vsock-watch-lsm-verify.service 2>/dev/null
    systemctl start cerberus-vsock-watch.service 2>/dev/null

    if [ "$ok" -eq 1 ]; then
        record lsm_restart_chaos PASS
    else
        record lsm_restart_chaos FAIL
    fi
}

print_summary() {
    echo
    echo "=================== SUMMARY ==================="
    local overall=0
    for r in "${RESULTS[@]}"; do
        local name="${r%%:*}" status="${r##*:}"
        case "$status" in
            PASS) echo -e "  ${GREEN}PASS${NC}  $name" ;;
            FAIL) echo -e "  ${RED}FAIL${NC}  $name"; overall=1 ;;
            SKIP) echo -e "  ${YELLOW}SKIP${NC}  $name" ;;
        esac
    done
    echo "================================================"
    return $overall
}

usage() {
    cat <<'EOF'
Usage: sudo ./verify-vsock-watch-hardware.sh [--yes] {all|freshness|tracepoint|ebpf|api-restart|tamper|block|notify|lsm-kernel-support|lsm-monitor|lsm-enforce|lsm-restart-chaos}

  all                 run every check in sequence (default if no argument given)
  freshness           item 0: installed cerberus-vsock-watch/ssh-cert-api/ssh-cert-signer -V matches this checkout's VERSION
  tracepoint          item 1: tracepoint format matches vsock_connect.c
  ebpf                items 2+3: BPF verifier acceptance + a real connect emits an event
  api-restart         item 4: cerberus-api restart does not cause a false positive
  tamper              item 5: audit rule removal triggers the tampering meta-alert
  block               item 6: --block + CAP_KILL SIGKILLs a cross-uid process
  notify              item 7: cerberus-api waits on Type=notify readiness
  lsm-kernel-support  item 8: CONFIG_BPF_LSM + active "bpf" LSM (non-gating, informational)
  lsm-monitor         item 9: --lsm-monitor loads, logs would-deny, connect() still succeeds
  lsm-enforce         item 10: --lsm-enforce actually denies a cgroup-mismatched connect()
  lsm-restart-chaos   item 11: cerberus-api restart under --lsm-enforce never denies the legitimate process

  --yes         skip the interactive confirmation before disruptive checks
EOF
}

main() {
    local targets=()
    for arg in "$@"; do
        case "$arg" in
            --yes) ASSUME_YES=1 ;;
            -h|--help) usage; exit 0 ;;
            *) targets+=("$arg") ;;
        esac
    done
    [ "${#targets[@]}" -eq 0 ] && targets=(all)

    require_root

    if [ "$ASSUME_YES" -ne 1 ]; then
        print_warning "This script stops/restarts cerberus-vsock-watch.service and cerberus-api.service, and temporarily removes a live auditd rule. Do not run against a host serving real signing traffic without understanding that."
        read -r -p "Continue? [y/N] " reply
        case "$reply" in
            [yY]*) ;;
            *) echo "aborted"; exit 1 ;;
        esac
    fi

    for target in "${targets[@]}"; do
        case "$target" in
            all)
                check_deployment_freshness
                check_tracepoint_format
                check_ebpf_live
                check_api_restart_chaos
                check_tamper_alert
                check_block_cap_kill
                check_systemd_notify_ordering
                check_lsm_kernel_support
                check_lsm_monitor_dry_run
                check_lsm_enforce_denies
                check_lsm_restart_chaos
                ;;
            freshness) check_deployment_freshness ;;
            tracepoint) check_tracepoint_format ;;
            ebpf) check_ebpf_live ;;
            api-restart) check_api_restart_chaos ;;
            tamper) check_tamper_alert ;;
            block) check_block_cap_kill ;;
            notify) check_systemd_notify_ordering ;;
            lsm-kernel-support) check_lsm_kernel_support ;;
            lsm-monitor) check_lsm_monitor_dry_run ;;
            lsm-enforce) check_lsm_enforce_denies ;;
            lsm-restart-chaos) check_lsm_restart_chaos ;;
            *) print_error "unknown target: $target"; usage; exit 1 ;;
        esac
    done

    print_summary
}

main "$@"
