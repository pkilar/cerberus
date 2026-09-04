#!/usr/bin/env bash
# Tests for cssh's certificate-cache sidecar, <privkey>-cert.requested.
#
# The sidecar exists because a group may map a requested principal to another
# one (`root: global-root` in allowed_principals), so a cert's own principal
# list is not a record of what was asked for. Every caching decision cssh makes
# for a mapped cert routes through this file; none of it was covered.
#
# These tests drive the real cssh function from packaging/profile.d/cssh.sh
# against real ssh-keygen-minted certificates, with curl, klist and ssh replaced
# by stubs on PATH. No network, no Kerberos, no Cerberus server, no writes
# outside a temp sandbox (HOME is redirected into it).
#
# cssh supports bash and zsh, so this suite is portable shell and runs under
# both:
#     tests/cssh_sidecar_test.sh
#     zsh tests/cssh_sidecar_test.sh
#
# Set CSSH_TEST_KEEP=1 to leave each sandbox behind for inspection.
#
# Lives in tests/ rather than beside cssh.sh because packaging/profile.d/ is
# staged into /etc/profile.d/. All three packagings install cssh.sh by explicit
# path today, but a test file in that directory would be one glob away from
# being sourced by every login shell on an installed host.

# shellcheck disable=SC2329  # every function below is invoked indirectly: the
# runner dispatches test bodies through "$_t", and helpers are called from them.

unset CDPATH  # keep `cd` from resolving the script path somewhere else
REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
CSSH_SH="$REPO_ROOT/packaging/profile.d/cssh.sh"

if [ ! -r "$CSSH_SH" ]; then
    printf 'cssh_sidecar_test: cannot read %s\n' "$CSSH_SH" >&2
    exit 1
fi

for _dep in ssh-keygen jq awk date mktemp; do
    if ! command -v "$_dep" >/dev/null 2>&1; then
        printf 'cssh_sidecar_test: missing required tool: %s\n' "$_dep" >&2
        exit 1
    fi
done

# Resolve the real ssh-keygen before any stub shadows it on PATH.
REAL_SSH_KEYGEN=$(command -v ssh-keygen)

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../packaging/profile.d/cssh.sh
. "$CSSH_SH"

if ! command -v cssh >/dev/null 2>&1; then
    printf 'cssh_sidecar_test: sourcing %s did not define cssh\n' "$CSSH_SH" >&2
    exit 1
fi

TESTS_RUN=0
TESTS_FAILED=0

# fail aborts the current test. Each test body runs in its own subshell, so
# exiting here fails exactly one test rather than the whole suite.
fail() {
    printf '      %s\n' "$1" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

# write_stubs installs fake curl, klist and ssh, plus an ssh-keygen wrapper that
# delegates to the real binary. Behaviour is steered entirely by STUB_* env vars
# read at call time, so a test can change the server's answers between runs.
write_stubs() {
    cat >"$SANDBOX/bin/curl" <<'STUB'
#!/bin/sh
# Fake curl. cssh always passes -o <file> and -w '%{http_code}', so write the
# body to that file and print the status code. The URL is the last argument.
outfile=""
url=""
prev=""
for a in "$@"; do
    if [ "$prev" = "-o" ]; then outfile=$a; fi
    prev=$a
    url=$a
done
case "$url" in
    */policy)
        code=${STUB_POLICY_CODE:-200}
        if [ "$code" = 200 ]; then
            printf '{"policy_fingerprint":"%s"}\n' "${STUB_POLICY_FP:-}" >"$outfile"
        else
            : >"$outfile"
        fi
        printf '%s' "$code"
        ;;
    */sign)
        # Record that a signing round trip happened; tests assert on this.
        echo sign >>"$STUB_SIGN_MARKER"
        jq -n --arg k "$(cat "$STUB_SIGNED_CERT")" --arg f "${STUB_SIGN_FP:-}" \
            '{signed_key:$k, policy_fingerprint:$f}' >"$outfile"
        printf '200'
        ;;
    *)
        : >"$outfile"
        printf '404'
        ;;
esac
exit 0
STUB

    cat >"$SANDBOX/bin/klist" <<'STUB'
#!/bin/sh
# Fake klist. STUB_KLIST_RC=0 means "a valid TGT is cached".
rc=${STUB_KLIST_RC:-0}
if [ "${1:-}" = "-s" ]; then exit "$rc"; fi
if [ "$rc" -eq 0 ]; then
    echo "Default principal: tester@EXAMPLE.TEST"
    exit 0
fi
exit 1
STUB

    cat >"$SANDBOX/bin/ssh" <<'STUB'
#!/bin/sh
# Fake ssh. Only `ssh -G` is reachable in these tests (--sign-only never
# connects); anything else is a no-op so an escape cannot dial out.
if [ "${1:-}" = "-G" ]; then
    printf 'user %s\n' "${STUB_SSH_G_USER:-nobody}"
fi
exit 0
STUB

    # ssh-keygen passes through to the real binary. With STUB_STRIP_SERIAL set,
    # `-L` output loses its Serial: line, simulating a certificate that parses
    # but whose serial cssh cannot extract.
    cat >"$SANDBOX/bin/ssh-keygen" <<STUB
#!/bin/sh
if [ "\${1:-}" = "-L" ] && [ -n "\${STUB_STRIP_SERIAL:-}" ]; then
    out=\$("$REAL_SSH_KEYGEN" "\$@") || exit \$?
    printf '%s\n' "\$out" | grep -v 'Serial:'
    exit 0
fi
exec "$REAL_SSH_KEYGEN" "\$@"
STUB

    chmod 0755 "$SANDBOX/bin/curl" "$SANDBOX/bin/klist" \
        "$SANDBOX/bin/ssh" "$SANDBOX/bin/ssh-keygen"
}

# Sandbox cleanup. Deliberately NOT armed inside setup(): zsh scopes an EXIT
# trap set within a function to that function, so the trap would fire the moment
# setup() returned and delete the sandbox out from under the test. bash defers it
# to shell exit. The runner arms it at subshell top level, where both shells
# agree.
cssh_test_cleanup() {
    if [ -n "${SANDBOX:-}" ] && [ -z "${CSSH_TEST_KEEP:-}" ]; then
        rm -rf "$SANDBOX"
    fi
    return 0
}

setup() {
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/cssh-sidecar-test.XXXXXX") || exit 1
    [ -z "${CSSH_TEST_KEEP:-}" ] || printf '      sandbox: %s\n' "$SANDBOX" >&2

    mkdir -p "$SANDBOX/bin" "$SANDBOX/.ssh"
    write_stubs
    PATH="$SANDBOX/bin:$PATH"
    export PATH

    # Redirect HOME so nothing can touch the real ~/.ssh or the OIDC cache.
    HOME="$SANDBOX"
    export HOME
    XDG_CACHE_HOME="$SANDBOX/cache"
    export XDG_CACHE_HOME

    "$REAL_SSH_KEYGEN" -q -t ed25519 -N '' -C cssh-test-ca -f "$SANDBOX/ca" \
        || fail "could not generate a test CA key"
    "$REAL_SSH_KEYGEN" -q -t ed25519 -N '' -C cssh-test-user \
        -f "$SANDBOX/.ssh/id_ed25519" \
        || fail "could not generate a test user key"

    PRIVKEY="$SANDBOX/.ssh/id_ed25519"
    PUBKEY="$PRIVKEY.pub"
    CERT="$PRIVKEY-cert.pub"
    SIDECAR="$PRIVKEY-cert.requested"
    SIGN_MARKER="$SANDBOX/signed"
    SERVER_CERT="$SANDBOX/server-cert.pub"

    CSSH_PUBKEY="$PUBKEY"
    CERBERUS_URL="https://cerberus.test"
    CSSH_AUTH=kerberos
    export CSSH_PUBKEY CERBERUS_URL CSSH_AUTH
    unset CSSH_PRINCIPALS CERBERUS_CACERT CSSH_REFRESH_BEFORE CSSH_AUTOGEN

    STUB_KLIST_RC=0
    STUB_POLICY_CODE=200
    STUB_POLICY_FP=fp-current
    STUB_SIGN_FP=fp-current
    STUB_SIGN_MARKER="$SIGN_MARKER"
    STUB_SIGNED_CERT="$SERVER_CERT"
    export STUB_KLIST_RC STUB_POLICY_CODE STUB_POLICY_FP STUB_SIGN_FP \
        STUB_SIGN_MARKER STUB_SIGNED_CERT
    unset STUB_STRIP_SERIAL

    # Every test that reaches the signing path needs something for the stub
    # server to hand back; individual tests override it.
    mint_cert "$SERVER_CERT" 7777 global-root +1h
}

# mint_cert <dest> <serial> <principals> <validity>
mint_cert() {
    _dest=$1
    _serial=$2
    _princ=$3
    _valid=$4
    cp "$PUBKEY" "$SANDBOX/mint.pub" || fail "could not stage a key to sign"
    "$REAL_SSH_KEYGEN" -q -s "$SANDBOX/ca" -I cssh-test \
        -n "$_princ" -z "$_serial" -V "$_valid" "$SANDBOX/mint.pub" \
        || fail "ssh-keygen could not mint a certificate"
    mv "$SANDBOX/mint-cert.pub" "$_dest" || fail "could not place the minted cert"
    rm -f "$SANDBOX/mint.pub"
}

# run_cssh clears the signing marker, then calls cssh with the given arguments.
# The exit status lands in CSSH_RC; stderr is kept for failure messages.
run_cssh() {
    rm -f "$SIGN_MARKER"
    cssh "$@" >"$SANDBOX/out" 2>"$SANDBOX/err"
    CSSH_RC=$?
    return 0
}

assert_ok() {
    [ "$CSSH_RC" -eq 0 ] || fail "cssh exited $CSSH_RC: $(cat "$SANDBOX/err")"
}

assert_signed() {
    [ -f "$SIGN_MARKER" ] \
        || fail "expected a re-sign; cssh reused the cached certificate"
}

assert_not_signed() {
    if [ -f "$SIGN_MARKER" ]; then
        fail "expected the cached certificate to be reused; cssh re-signed"
    fi
    return 0
}

# assert_sidecar <serial> <fingerprint> <requested-set>
assert_sidecar() {
    [ -r "$SIDECAR" ] || fail "expected a sidecar at $SIDECAR"
    read -r _s _f _r <"$SIDECAR"
    [ "$_s" = "$1" ] || fail "sidecar serial: want $1, got ${_s:-<empty>}"
    [ "$_f" = "$2" ] || fail "sidecar fingerprint: want $2, got ${_f:-<empty>}"
    [ "$_r" = "$3" ] || fail "sidecar requested set: want $3, got ${_r:-<empty>}"
}

cert_serial() {
    "$REAL_SSH_KEYGEN" -L -f "$1" | awk '/Serial:/ {print $2; exit}'
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# The whole point of the sidecar: the cert says global-root, the request says
# root, and that must still count as a cache hit.
test_v2_sidecar_keeps_mapped_cert_cached() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 fp-current root,\n' >"$SIDECAR"

    run_cssh --sign-only --principals root
    assert_ok
    assert_not_signed
}

# A v1 sidecar (serial + set, written before policy fingerprints existed) has no
# fingerprint to compare, so the first call re-signs once to record one — and
# what it writes must be v1's successor, not another v1 line.
test_v1_sidecar_resigns_once_to_record_a_fingerprint() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 root,\n' >"$SIDECAR"

    run_cssh --sign-only --principals root
    assert_ok
    assert_signed
    assert_sidecar 7777 fp-current 'root,'
}

# The v1 parse itself: with the policy probe unable to run, the only thing that
# can keep this cert is reading field 2 as the requested set. Misreading it as a
# fingerprint would compare against the cert's own global-root and re-sign.
test_v1_sidecar_field_two_is_the_requested_set() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 root,\n' >"$SIDECAR"
    STUB_KLIST_RC=1  # no TGT: the probe is skipped rather than prompting

    run_cssh --sign-only --principals root
    assert_ok
    assert_not_signed
}

# A sidecar describing some other certificate must not be believed. The policy
# probe is taken out of the picture (a server predating /policy answers 404) so
# only the principal comparison can decide.
test_serial_mismatch_falls_back_to_cert_principals() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '9999 fp-current root,\n' >"$SIDECAR"
    STUB_POLICY_CODE=404

    run_cssh --sign-only --principals root
    assert_ok
    assert_signed
}

# ...but the fallback is a comparison, not a blanket re-sign: an unmapped cert
# whose own principals match the request still gets reused.
test_serial_mismatch_still_reuses_an_unmapped_cert() {
    setup
    mint_cert "$CERT" 4242 root +1h
    printf '9999 fp-current root,\n' >"$SIDECAR"
    STUB_POLICY_CODE=404

    run_cssh --sign-only --principals root
    assert_ok
    assert_not_signed
}

# A sidecar cssh could not refresh must not outlive the cert it described:
# stripping the Serial: line leaves a cert that parses but yields no serial, so
# no new record can be written and the stale one has to go.
test_unrecordable_sidecar_is_removed_not_left_stale() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 fp-old root,\n' >"$SIDECAR"
    STUB_STRIP_SERIAL=1
    export STUB_STRIP_SERIAL

    run_cssh --sign-only --force --principals root
    assert_ok
    assert_signed
    if [ -e "$SIDECAR" ]; then
        fail "stale sidecar survived a sign whose serial could not be recorded"
    fi
    return 0
}

# A policy change (e.g. a mapping switched on) must not let a cert issued under
# the old policy ride out its validity window.
test_policy_fingerprint_change_forces_a_resign() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 fp-old root,\n' >"$SIDECAR"
    STUB_POLICY_FP=fp-new
    STUB_SIGN_FP=fp-new

    run_cssh --sign-only --principals root
    assert_ok
    assert_signed
    assert_sidecar 7777 fp-new 'root,'
}

# --all-principals has no fixed requested set (the server derives it), so the
# sidecar records "-" and the cert is cached on expiry and policy alone.
test_all_principals_records_a_dash() {
    setup
    mint_cert "$CERT" 4242 alice,bob +1h
    mint_cert "$SERVER_CERT" 7777 alice,bob +1h

    run_cssh --sign-only --force --all-principals
    assert_ok
    assert_signed
    assert_sidecar 7777 fp-current '-'

    # Second call: nothing to compare principals against, so it reuses.
    run_cssh --sign-only --all-principals
    assert_ok
    assert_not_signed
}

# Switching the requested principal must re-sign even though the cached cert was
# legitimately mapped: a cert for global-root cannot authenticate as deploy.
test_principal_switch_resigns_despite_mapping() {
    setup
    mint_cert "$CERT" 4242 global-root +1h
    printf '4242 fp-current root,\n' >"$SIDECAR"
    mint_cert "$SERVER_CERT" 7777 deploy +1h

    run_cssh --sign-only --principals deploy
    assert_ok
    assert_signed
    assert_sidecar 7777 fp-current 'deploy,'
}

# An expiring cert re-signs regardless of a matching sidecar.
test_expiring_mapped_cert_resigns() {
    setup
    mint_cert "$CERT" 4242 global-root +2m
    printf '4242 fp-current root,\n' >"$SIDECAR"
    CSSH_REFRESH_BEFORE=300
    export CSSH_REFRESH_BEFORE

    run_cssh --sign-only --principals root
    assert_ok
    assert_signed
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

printf 'cssh sidecar tests (%s)\n' "$(ps -p $$ -o comm= 2>/dev/null || echo shell)"

for _t in \
    test_v2_sidecar_keeps_mapped_cert_cached \
    test_v1_sidecar_resigns_once_to_record_a_fingerprint \
    test_v1_sidecar_field_two_is_the_requested_set \
    test_serial_mismatch_falls_back_to_cert_principals \
    test_serial_mismatch_still_reuses_an_unmapped_cert \
    test_unrecordable_sidecar_is_removed_not_left_stale \
    test_policy_fingerprint_change_forces_a_resign \
    test_all_principals_records_a_dash \
    test_principal_switch_resigns_despite_mapping \
    test_expiring_mapped_cert_resigns
do
    TESTS_RUN=$((TESTS_RUN + 1))
    if ( SANDBOX=""; trap cssh_test_cleanup EXIT; "$_t" ); then
        printf '  ok    %s\n' "$_t"
    else
        printf '  FAIL  %s\n' "$_t"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done

printf '\n%d test(s), %d failure(s)\n' "$TESTS_RUN" "$TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ] || exit 1
exit 0
