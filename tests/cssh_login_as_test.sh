#!/usr/bin/env bash
# Tests for cssh's login-as-principal behaviour.
#
# A group may set `login_as_issued: true`, which puts the flag extension
# login-as-principal@cerberus on its certificates. That tells cssh the cert's
# single principal is the account to log into, so a request for a mode name can
# land on the account the mapping actually issued: `cssh root-ro@host` against a
# `root-ro: $self` mapping yields a cert for your own uid and the session should
# go to your account, not to a non-existent "root-ro".
#
# The risk this covers is a silent account switch, so the tests assert on both
# halves: the exact ssh invocation, and the notice printed when the login name
# changes.
#
# These tests drive the real cssh function from packaging/profile.d/cssh.sh
# against real ssh-keygen-minted certificates, with curl, klist and ssh replaced
# by stubs on PATH. No network, no Kerberos, no Cerberus server, no writes
# outside a temp sandbox (HOME is redirected into it).
#
# cssh supports bash and zsh, so this suite is portable shell and runs under
# both:
#     tests/cssh_login_as_test.sh
#     zsh tests/cssh_login_as_test.sh
#
# Set CSSH_TEST_KEEP=1 to leave each sandbox behind for inspection.

# shellcheck disable=SC2329  # every function below is invoked indirectly: the
# runner dispatches test bodies through "$_t", and helpers are called from them.

unset CDPATH  # keep `cd` from resolving the script path somewhere else
REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
CSSH_SH="$REPO_ROOT/packaging/profile.d/cssh.sh"

if [ ! -r "$CSSH_SH" ]; then
    printf 'cssh_login_as_test: cannot read %s\n' "$CSSH_SH" >&2
    exit 1
fi

for _dep in ssh-keygen jq awk grep mktemp; do
    if ! command -v "$_dep" >/dev/null 2>&1; then
        printf 'cssh_login_as_test: missing required tool: %s\n' "$_dep" >&2
        exit 1
    fi
done

# Resolve the real ssh-keygen before any stub shadows it on PATH.
REAL_SSH_KEYGEN=$(command -v ssh-keygen)

# The extension under test. Kept as a literal so a rename in cssh.sh or in
# internal/config has to be made here too, on purpose.
LOGIN_AS_EXT="login-as-principal@cerberus"

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../packaging/profile.d/cssh.sh
. "$CSSH_SH"

if ! command -v cssh >/dev/null 2>&1; then
    printf 'cssh_login_as_test: sourcing %s did not define cssh\n' "$CSSH_SH" >&2
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
# test can assert on the exact argument list cssh built.
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
        echo sign >>"$STUB_SIGN_MARKER"
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
exit "${STUB_KLIST_RC:-0}"
STUB

    # Records the full argument list of every call, one call per line, and
    # answers `ssh -G` so cssh can resolve the login name it would use.
    cat >"$SANDBOX/bin/ssh" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"$STUB_SSH_LOG"
if [ "${1:-}" = "-G" ]; then
    printf 'user %s\n' "${STUB_SSH_G_USER:-nobody}"
    exit 0
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

cssh_test_cleanup() {
    if [ -n "${SANDBOX:-}" ] && [ -z "${CSSH_TEST_KEEP:-}" ]; then
        rm -rf "$SANDBOX"
    fi
    return 0
}

setup() {
    SANDBOX=$(mktemp -d "${TMPDIR:-/tmp}/cssh-login-as-test.XXXXXX") || exit 1
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
    SSH_LOG="$SANDBOX/ssh-invocations"
    : >"$SSH_LOG"

    CSSH_PUBKEY="$PUBKEY"
    CERBERUS_URL="https://cerberus.test"
    CSSH_AUTH=kerberos
    export CSSH_PUBKEY CERBERUS_URL CSSH_AUTH
    unset CSSH_PRINCIPALS CERBERUS_CACERT CSSH_REFRESH_BEFORE CSSH_AUTOGEN

    STUB_KLIST_RC=0
    STUB_POLICY_FP=fp-current
    STUB_SIGN_MARKER="$SIGN_MARKER"
    STUB_SIGNED_CERT="$SERVER_CERT"
    STUB_SSH_LOG="$SSH_LOG"
    STUB_SSH_G_USER=root-ro
    export STUB_KLIST_RC STUB_POLICY_FP STUB_SIGN_MARKER STUB_SIGNED_CERT \
        STUB_SSH_LOG STUB_SSH_G_USER
}

# mint_cert <dest> <serial> <principals> [extension]
# principals is passed to ssh-keygen -n, so "a,b" mints two principals.
mint_cert() {
    _dest=$1
    _serial=$2
    _princ=$3
    _ext=${4:-}
    cp "$PUBKEY" "$SANDBOX/mint.pub" || fail "could not stage a key to sign"
    if [ -n "$_ext" ]; then
        "$REAL_SSH_KEYGEN" -q -s "$SANDBOX/ca" -I cssh-test \
            -n "$_princ" -z "$_serial" -V +1h -O "extension:$_ext" \
            "$SANDBOX/mint.pub" || fail "ssh-keygen could not mint a certificate"
    else
        "$REAL_SSH_KEYGEN" -q -s "$SANDBOX/ca" -I cssh-test \
            -n "$_princ" -z "$_serial" -V +1h \
            "$SANDBOX/mint.pub" || fail "ssh-keygen could not mint a certificate"
    fi
    mv "$SANDBOX/mint-cert.pub" "$_dest" || fail "could not place the minted cert"
    rm -f "$SANDBOX/mint.pub"
}

# run_cssh clears the markers, then calls cssh with the given arguments.
run_cssh() {
    rm -f "$SIGN_MARKER"
    : >"$SSH_LOG"
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

assert_connected_as() {
    _want="-o User=$1"
    case "$(connect_args)" in
        *"$_want"*) : ;;
        *) fail "ssh invocation missing '$_want': $(connect_args)" ;;
    esac
}

assert_no_user_override() {
    case "$(connect_args)" in
        *"-o User="*) fail "ssh invocation should carry no User override: $(connect_args)" ;;
        *) : ;;
    esac
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

# The headline case: the user asks for a mode name, the cert names their own
# account, and the session has to go to that account.
test_extension_switches_the_login_name() {
    setup
    mint_cert "$SERVER_CERT" 100 jsmith "$LOGIN_AS_EXT"
    run_cssh root-ro@host
    assert_ok
    assert_connected_as jsmith
    assert_stderr_contains "connecting as jsmith"
}

# Without the extension nothing changes, which is every deployment that has not
# opted in.
test_without_the_extension_nothing_changes() {
    setup
    mint_cert "$SERVER_CERT" 101 jsmith
    run_cssh root-ro@host
    assert_ok
    assert_no_user_override
    assert_stderr_lacks "connecting as"
}

# Several principals leave no single account to choose, so the switch is
# refused rather than guessed, and the user is told why.
test_multiple_principals_are_refused() {
    setup
    mint_cert "$SERVER_CERT" 102 jsmith,deploy "$LOGIN_AS_EXT"
    run_cssh root-ro@host
    assert_ok
    assert_no_user_override
    assert_stderr_contains "carries 2 principals"
}

# The switch is silent when it is not a switch: asking for your own account and
# getting a cert for it should not print anything.
test_no_notice_when_the_name_is_unchanged() {
    setup
    STUB_SSH_G_USER=jsmith
    export STUB_SSH_G_USER
    mint_cert "$SERVER_CERT" 103 jsmith "$LOGIN_AS_EXT"
    run_cssh jsmith@host
    assert_ok
    assert_connected_as jsmith
    assert_stderr_lacks "connecting as"
}

# --sign-only never connects, so it must not resolve or announce a login name.
test_sign_only_does_not_connect() {
    setup
    mint_cert "$SERVER_CERT" 104 jsmith "$LOGIN_AS_EXT"
    run_cssh --sign-only root-ro@host
    assert_ok
    [ -z "$(connect_args)" ] || fail "--sign-only must not connect: $(connect_args)"
    assert_stderr_lacks "connecting as"
}

# A cached certificate carries the extension just as a fresh one does: the
# behaviour must not depend on having just signed.
test_extension_honoured_on_a_cached_certificate() {
    setup
    mint_cert "$SERVER_CERT" 105 jsmith "$LOGIN_AS_EXT"
    run_cssh root-ro@host
    assert_ok
    [ -f "$SIGN_MARKER" ] || fail "expected the first call to sign"
    run_cssh root-ro@host
    assert_ok
    if [ -f "$SIGN_MARKER" ]; then
        fail "expected the second call to reuse the cached certificate"
    fi
    assert_connected_as jsmith
    assert_stderr_contains "connecting as jsmith"
}

for _t in \
    test_extension_switches_the_login_name \
    test_without_the_extension_nothing_changes \
    test_multiple_principals_are_refused \
    test_no_notice_when_the_name_is_unchanged \
    test_sign_only_does_not_connect \
    test_extension_honoured_on_a_cached_certificate
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
