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
    print_status "restarting cerberus-api.service (new MainPID) while cerberus-vsock-watch observes..."
    systemctl restart cerberus-api.service
    sleep 3
    if journalctl -u cerberus-vsock-watch --since "-10 seconds" --no-pager 2>/dev/null | grep 'vsockwatch.alert' | grep -q 'ssh-cert-api'; then
        print_error "a false-positive anomaly alert fired for the legitimate ssh-cert-api exe during the restart -- see journalctl -u cerberus-vsock-watch"
        record api_restart_chaos FAIL
        return 1
    fi
    print_status "no false positive during cerberus-api's MainPID/cgroup transition"
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
    systemctl start cerberus-vsock-watch.service
    if ! auditctl -l 2>/dev/null | grep -q cerberus_vsock_watch; then
        print_status "installing the audit rule from packaging/audit-rules/61-cerberus-vsock.rules"
        auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch
        auditctl -a always,exit -F arch=b32 -S connect -k cerberus_vsock_watch
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
        print_error "no detector_tampering alert within 45s -- confirm CAP_AUDIT_CONTROL lets cerberus-audit run 'auditctl -l': try 'sudo -u cerberus-audit auditctl -l'"
        record tamper_alert FAIL
    fi

    print_status "restoring the audit rule..."
    auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch
    auditctl -a always,exit -F arch=b32 -S connect -k cerberus_vsock_watch

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
    case "$caps" in
        *CAP_KILL*) print_status "CAP_KILL present in the running unit's AmbientCapabilities" ;;
        *) print_error "CAP_KILL NOT present -- --block cannot signal a process it doesn't own. Check packaging/*/cerberus-vsock-watch.service and 'systemctl daemon-reload'"
           record block_cap_kill FAIL
           return 1 ;;
    esac

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
Usage: sudo ./verify-vsock-watch-hardware.sh [--yes] {all|tracepoint|ebpf|api-restart|tamper|block|notify}

  all           run every check in sequence (default if no argument given)
  tracepoint    item 1: tracepoint format matches vsock_connect.c
  ebpf          items 2+3: BPF verifier acceptance + a real connect emits an event
  api-restart   item 4: cerberus-api restart does not cause a false positive
  tamper        item 5: audit rule removal triggers the tampering meta-alert
  block         item 6: --block + CAP_KILL SIGKILLs a cross-uid process
  notify        item 7: cerberus-api waits on Type=notify readiness

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
                check_tracepoint_format
                check_ebpf_live
                check_api_restart_chaos
                check_tamper_alert
                check_block_cap_kill
                check_systemd_notify_ordering
                ;;
            tracepoint) check_tracepoint_format ;;
            ebpf) check_ebpf_live ;;
            api-restart) check_api_restart_chaos ;;
            tamper) check_tamper_alert ;;
            block) check_block_cap_kill ;;
            notify) check_systemd_notify_ordering ;;
            *) print_error "unknown target: $target"; usage; exit 1 ;;
        esac
    done

    print_summary
}

main "$@"
