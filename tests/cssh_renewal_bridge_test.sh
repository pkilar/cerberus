#!/usr/bin/env bash
# Tests for cssh's warning when a renewable certificate has no renewal bridge.
#
# A certificate carrying permit-session-renewal@cerberus can be extended from
# inside the session with `cssh --extend`, but only through the local half of
# the bridge: the cerberus-session helper, which forwards a private socket and
# sets CERBERUS_RENEW_SOCKET on the connection. When the helper is missing, cssh
# falls back to plain ssh and the session opens without a bridge. Before this
# warning nothing said so until `logsh extend` failed on the server with "this
# session has no renewal bridge", far from the workstation where the fix is.
#
# The tests drive the real cssh function from packaging/profile.d/cssh.sh
# against real ssh-keygen-minted certificates, with curl, klist and ssh (and,
# where a test needs it, cerberus-session) replaced by stubs on PATH. No
# network, no Kerberos, no Cerberus server, no writes outside a temp sandbox
# (HOME is redirected into it).
#
# cssh supports bash and zsh, so this suite is portable shell and runs under
# both:
#     tests/cssh_renewal_bridge_test.sh
#     zsh tests/cssh_renewal_bridge_test.sh
#
# Set CSSH_TEST_KEEP=1 to leave each sandbox behind for inspection.

# shellcheck disable=SC2329  # every function below is invoked indirectly: the
# runner dispatches test bodies through "$_t", and helpers are called from them.

unset CDPATH  # keep `cd` from resolving the script path somewhere else
REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
CSSH_SH="$REPO_ROOT/packaging/profile.d/cssh.sh"

if [ ! -r "$CSSH_SH" ]; then
    printf 'cssh_renewal_bridge_test: cannot read %s\n' "$CSSH_SH" >&2
    exit 1
fi

for _dep in ssh-keygen jq awk grep mktemp; do
    if ! command -v "$_dep" >/dev/null 2>&1; then
        printf 'cssh_renewal_bridge_test: missing required tool: %s\n' "$_dep" >&2
        exit 1
    fi
done

# Resolve the real ssh-keygen before any stub shadows it on PATH.
REAL_SSH_KEYGEN=$(command -v ssh-keygen)

# A cerberus-session already installed on this machine would stand in for the
# missing helper the warning is about. Found once, before any sandbox stub.
INSTALLED_HELPER=$(command -v cerberus-session 2>/dev/null || true)

# The extensions under test. Kept as literals so a rename in cssh.sh, the
# helper or logsh has to be made here too, on purpose.
RENEW_EXT="permit-session-renewal@cerberus"
TERMINATE_EXT="terminate-on-cert-expiry@cerberus"
WARNING="cerberus-session is not installed"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../packaging/profile.d/cssh.sh
. "$CSSH_SH"

if ! command -v cssh >/dev/null 2>&1; then
    printf 'cssh_renewal_bridge_test: sourcing %s did not define cssh\n' "$CSSH_SH" >&2
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

# write_stubs installs a fake curl, klist and ssh, plus an ssh-keygen wrapper
# that delegates to the real binary. The ssh stub records every invocation so a
# test can tell whether cssh connected over plain ssh.
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
        printf '{"policy_fingerprint":"%s"}\n' "${STUB_POLICY_FP:-fp}" >"$outfile"
        printf '200'
        ;;
    */sign)
        jq -n --arg k "$(cat "$STUB_SIGNED_CERT")" --arg f "${STUB_POLICY_FP:-fp}" \
            '{signed_key: $k, policy_fingerprint: $f}' >"$outfile"
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
exit 0
STUB

    # Records the full argument list of every call and answers `ssh -G` so cssh
    # can resolve the login name it would use.
    cat >"$SANDBOX/bin/ssh" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_SSH_LOG"
if [ "${1:-}" = "-G" ]; then
    printf 'user %s\n' "${STUB_SSH_G_USER:-nobody}"
fi
exit 0
STUB

    cat >"$SANDBOX/bin/ssh-keygen" <<STUB
#!/bin/sh
exec "$REAL_SSH_KEYGEN" "\$@"
STUB

    chmod +x "$SANDBOX/bin/curl" "$SANDBOX/bin/klist" "$SANDBOX/bin/ssh" \
        "$SANDBOX/bin/ssh-keygen" || fail "could not make the stubs executable"
}

# install_helper puts a stub cerberus-session on PATH that records being called.
install_helper() {
    cat >"$SANDBOX/bin/cerberus-session" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_HELPER_LOG"
exit 0
STUB
    chmod +x "$SANDBOX/bin/cerberus-session" || fail "could not make the helper stub executable"
}

# require_no_installed_helper skips a test that needs the helper to be ABSENT
# when this machine has a real one on PATH: the sandbox can shadow a binary, but
# not hide one without also hiding the tools cssh needs.
require_no_installed_helper() {
    if [ -n "$INSTALLED_HELPER" ]; then
        printf '      skipped: cerberus-session is installed at %s\n' "$INSTALLED_HELPER" >&2
        exit 0
    fi
}

cssh_test_cleanup() {
    if [ -n "${SANDBOX:-}" ] && [ -z "${CSSH_TEST_KEEP:-}" ]; then
        rm -rf "$SANDBOX"
    fi
    return 0
}

setup() {
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/cssh-renewal-bridge-test.XXXXXX") || exit 1
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

    PUBKEY="$SANDBOX/.ssh/id_ed25519.pub"
    SERVER_CERT="$SANDBOX/server-cert.pub"
    SSH_LOG="$SANDBOX/ssh-invocations"
    HELPER_LOG="$SANDBOX/helper-invocations"
    : >"$SSH_LOG"
    : >"$HELPER_LOG"

    CSSH_PUBKEY="$PUBKEY"
    CERBERUS_URL="https://cerberus.test"
    CSSH_AUTH=kerberos
    export CSSH_PUBKEY CERBERUS_URL CSSH_AUTH
    unset CSSH_PRINCIPALS CERBERUS_CACERT CSSH_REFRESH_BEFORE CSSH_AUTOGEN

    STUB_SIGNED_CERT="$SERVER_CERT"
    STUB_SSH_LOG="$SSH_LOG"
    STUB_HELPER_LOG="$HELPER_LOG"
    STUB_SSH_G_USER=root-ro
    export STUB_SIGNED_CERT STUB_SSH_LOG STUB_HELPER_LOG STUB_SSH_G_USER
}

# mint_cert <dest> <serial> [extension...]
# Each extension is added as an empty-valued flag, as Cerberus issues them.
mint_cert() {
    _dest=$1
    _serial=$2
    shift 2
    # Turn the extension names into "-O extension:NAME" pairs in "$@". Built in
    # the positional parameters rather than a string because zsh, unlike bash
    # and sh, does not word-split an unquoted variable.
    _n=$#
    for _ext in "$@"; do
        set -- "$@" -O "extension:$_ext"
    done
    shift "$_n"
    cp "$PUBKEY" "$SANDBOX/mint.pub" || fail "could not stage a key to sign"
    "$REAL_SSH_KEYGEN" -q -s "$SANDBOX/ca" -I cssh-test -n root-ro \
        -z "$_serial" -V +1h "$@" "$SANDBOX/mint.pub" \
        || fail "ssh-keygen could not mint a certificate"
    mv "$SANDBOX/mint-cert.pub" "$_dest" || fail "could not place the minted cert"
    rm -f "$SANDBOX/mint.pub"
}

# run_cssh clears the logs, then calls cssh with the given arguments.
run_cssh() {
    : >"$SSH_LOG"
    : >"$HELPER_LOG"
    cssh "$@" >"$SANDBOX/out" 2>"$SANDBOX/err"
    CSSH_RC=$?
    return 0
}

assert_ok() {
    [ "$CSSH_RC" -eq 0 ] || fail "cssh exited $CSSH_RC: $(cat "$SANDBOX/err")"
}

# The connect call is the one that is not `ssh -G`.
connect_args() {
    grep -v '^-G ' "$SSH_LOG" | tail -n 1
}

assert_connected_over_plain_ssh() {
    [ -n "$(connect_args)" ] || fail "expected cssh to connect over plain ssh"
}

assert_stderr_contains() {
    grep -Fq "$1" "$SANDBOX/err" || fail "stderr missing '$1': $(cat "$SANDBOX/err")"
}

assert_stderr_lacks() {
    if grep -Fq "$1" "$SANDBOX/err"; then
        fail "stderr should not mention '$1': $(cat "$SANDBOX/err")"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# The headline case: a renewable certificate, no helper. The session must still
# open -- the warning explains a missing feature, it does not block a login.
test_warns_when_the_helper_is_missing() {
    require_no_installed_helper
    setup
    mint_cert "$SERVER_CERT" 200 "$RENEW_EXT" "$TERMINATE_EXT"
    run_cssh host
    assert_ok
    assert_connected_over_plain_ssh
    assert_stderr_contains "$WARNING"
    assert_stderr_contains "cssh --extend"
}

# A certificate that does not permit renewal has nothing to lose without the
# helper, which is every deployment that has not opted in.
test_no_warning_without_the_renewal_extension() {
    require_no_installed_helper
    setup
    mint_cert "$SERVER_CERT" 201 "$TERMINATE_EXT"
    run_cssh host
    assert_ok
    assert_connected_over_plain_ssh
    assert_stderr_lacks "$WARNING"
}

# With the helper installed the bridge exists, so there is nothing to warn
# about, and the connection goes through the helper rather than plain ssh.
test_no_warning_when_the_helper_is_installed() {
    setup
    install_helper
    mint_cert "$SERVER_CERT" 202 "$RENEW_EXT" "$TERMINATE_EXT"
    run_cssh host
    assert_ok
    [ -s "$HELPER_LOG" ] || fail "expected cssh to connect through cerberus-session"
    [ -z "$(connect_args)" ] || fail "expected no plain ssh connection: $(connect_args)"
    assert_stderr_lacks "$WARNING"
}

# --sign-only never connects, so there is no session to warn about.
test_sign_only_does_not_warn() {
    require_no_installed_helper
    setup
    mint_cert "$SERVER_CERT" 203 "$RENEW_EXT" "$TERMINATE_EXT"
    run_cssh --sign-only host
    assert_ok
    [ -z "$(connect_args)" ] || fail "--sign-only must not connect: $(connect_args)"
    assert_stderr_lacks "$WARNING"
}

for _t in \
    test_warns_when_the_helper_is_missing \
    test_no_warning_without_the_renewal_extension \
    test_no_warning_when_the_helper_is_installed \
    test_sign_only_does_not_warn
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
