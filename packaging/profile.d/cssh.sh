# cssh — Cerberus-signed SSH wrapper (system-wide, bash + zsh).
#
# Fetches a short-lived OpenSSH user certificate from the Cerberus signing API
# and drops it next to the matching private key as <key>-cert.pub, where ssh(1)
# auto-loads it. Caches the cert and re-signs only when it is missing,
# unreadable, or about to expire. If the user has no SSH key yet, cssh generates
# an ed25519 keypair first (opt out: CSSH_AUTOGEN=0).
#
# Authenticates to the API with Kerberos/SPNEGO by default. Set CSSH_AUTH=oidc
# (or pass --oauth) to authenticate with an OIDC identity provider instead, via
# the OAuth 2.0 Device Authorization Grant (RFC 8628): cssh prints a URL + code
# to visit in a browser, then caches the resulting bearer token (with silent
# refresh) so subsequent calls don't re-prompt. See "OIDC authentication" below.
#
# ── Install ──────────────────────────────────────────────────────────────────
#   sudo install -m 0644 cssh.sh /etc/profile.d/cssh.sh
#
# ── Loading (login vs interactive) ───────────────────────────────────────────
# /etc/profile.d/*.sh runs for LOGIN shells only. This file only DEFINES the
# cssh function and runs nothing at load time, so it is safe to source from any
# POSIX shell (bash, zsh, dash/sh).
#
#   bash — login shells source /etc/profile, which sources /etc/profile.d/*.sh.
#          To also cover non-login interactive bash (e.g. new terminal tabs),
#          source it from /etc/bashrc (RHEL/Fedora/Amazon Linux) or
#          /etc/bash.bashrc (Debian/Ubuntu):
#              [ -r /etc/profile.d/cssh.sh ] && . /etc/profile.d/cssh.sh
#
#   zsh  — reads /etc/profile.d/*.sh ONLY if the system's zsh startup sources
#          /etc/profile. Debian/Ubuntu/Arch do this via /etc/zprofile
#          (`emulate sh -c 'source /etc/profile'`). On RHEL/Fedora/Amazon Linux,
#          add one line to /etc/zshrc (or /etc/zsh/zshrc):
#              [ -r /etc/profile.d/cssh.sh ] && . /etc/profile.d/cssh.sh
#
# ── Site configuration ───────────────────────────────────────────────────────
# This file is plain code and is REPLACED on package upgrade — do NOT edit it for
# site config. Set your Cerberus endpoint for all users in the companion file
# /etc/profile.d/cerberus-env.sh (shipped %config(noreplace), so edits survive
# upgrades), or export the variables from your own environment / config
# management:
#   export CERBERUS_URL=https://cerberus.example.com:8443
#   export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem
# Users may still override per-shell (export CERBERUS_URL) or per-call (--url).
# With CERBERUS_URL unset, cssh errors clearly rather than guessing an endpoint.
#
# ── Environment variables ────────────────────────────────────────────────────
#   CERBERUS_URL          Base URL of the signing API (required; /sign appended).
#   CERBERUS_CACERT       CA bundle to trust for the API's TLS cert (optional;
#                         defaults to the system trust store).
#   CSSH_PUBKEY           Public key to sign (default ~/.ssh/id_ed25519.pub).
#   CSSH_REFRESH_BEFORE   Re-sign if the cert expires within N seconds (default 300).
#   CSSH_PRINCIPALS       Comma-separated principals to request. If unset, cssh
#                         asks `ssh -G` for the login user of the destination
#                         (covers user@host, -l user, and ssh_config User).
#   CSSH_AUTOGEN          Auto-generate a passphraseless ed25519 keypair when the
#                         key is missing (default on). Set to 0/false/no/off to
#                         disable and error instead.
#   CSSH_AUTH             Authentication method: "kerberos" (default) or "oidc".
#                         --oauth forces "oidc" for a single call.
#
# ── OIDC authentication (CSSH_AUTH=oidc / --oauth) ───────────────────────────
# For users without Kerberos, cssh can authenticate to the API with an OIDC
# bearer token obtained via the OAuth 2.0 Device Authorization Grant: it prints a
# verification URL + user code, you approve in a browser, and cssh polls for the
# token. The token (and its refresh token, when the IdP grants offline_access) is
# cached at ${XDG_CACHE_HOME:-~/.cache}/cerberus/oidc-token.json (mode 0600) and
# renewed silently, so you approve once and then ssh/scp/rsync for as long as the
# refresh token lives. Requires jq and curl (already cssh dependencies).
#
#   CSSH_OIDC_ISSUER      OIDC issuer URL (required for OIDC; discovery base).
#   CSSH_OIDC_CLIENT_ID   OAuth public client ID registered for the device flow.
#   CSSH_OIDC_SCOPE       Scopes to request. Default
#                         "openid profile email groups offline_access"
#                         (offline_access is what enables silent refresh).
#   CSSH_OIDC_AUDIENCE    Requested token audience — set this if your IdP needs it
#                         to mint an access token carrying the Cerberus API's aud
#                         (e.g. Auth0). Optional.
#   CSSH_OIDC_TOKEN       Which token to send: "access" (default) or "id".
#   CSSH_OIDC_CACERT      CA bundle to trust for the IdP's TLS (optional).
#   CSSH_OIDC_CLIENT_SECRET  Client secret, if the IdP requires one (optional).
#   CSSH_OIDC_OPEN        Try to open the verification URL in a browser
#                         (xdg-open/open); default off (the URL is always printed).
#
# ── Per-call flags (consumed before the rest is passed to ssh) ───────────────
#   --principals u1,u2    override CSSH_PRINCIPALS for this call
#   --pubkey PATH         override CSSH_PUBKEY for this call
#   --url URL             override CERBERUS_URL for this call
#   --cacert PATH         override CERBERUS_CACERT for this call
#   --force               re-sign even if the cached cert is still valid
#   --sign-only           fetch/refresh the cert and exit WITHOUT running ssh
#                         (pre-authenticate, then use scp/rsync/sftp/git/etc.).
#                         Silent by default; add --verbose to print the cert
#                         path. HOST is optional and, if given, is used only to
#                         resolve the principal.
#   --all-principals      request a cert for EVERY principal in your first
#                         Cerberus group (the server expands the group's finite
#                         allowed_principals). Requires --sign-only and is
#                         mutually exclusive with --principals. Refused server-
#                         side if that group grants "*" (unbounded).
#   --self                fetch a cert for your OWN identity (the server issues
#                         for the short uid of your Kerberos principal) and exit.
#                         Requires --sign-only, and the server's self_principal
#                         to be enabled for your realm. Mutually exclusive with
#                         --principals and --all-principals. To just connect as
#                         yourself, run cssh normally — the server accepts a
#                         request for your own uid without any flag.
#   --oauth               authenticate with OIDC (device flow) for this call
#                         instead of Kerberos (same as CSSH_AUTH=oidc). Requires
#                         CSSH_OIDC_ISSUER and CSSH_OIDC_CLIENT_ID.
#   --verbose             print the cert path to stdout in --sign-only mode
#                         (otherwise --sign-only is silent).
#   --                    end of cssh flags; remaining args go to ssh verbatim

# ── OIDC device-flow helpers (file-level on purpose) ─────────────────────────
# Unlike the small nested helpers inside cssh() (which are unset on return to
# keep the shell namespace clean), the OIDC device-flow logic is large enough
# that carrying it as two _cssh_-prefixed module functions — defined once when
# this file is sourced — is clearer and avoids per-call define/unset bookkeeping.
# They are only invoked when the caller opts into OIDC (CSSH_AUTH=oidc / --oauth)
# AND a fresh certificate is actually needed.

# _cssh_oidc_store persists an OAuth token-endpoint response to the on-disk cache
# (mode 0600) and prints the token to send (per CSSH_OIDC_TOKEN) to stdout.
#   $1 = path to the token-endpoint JSON response
#   $2 = fallback refresh_token to keep when the response omits a new one
# Returns 1 if the requested token type is absent from the response. A cache
# write failure is non-fatal — the token is still returned so signing proceeds.
_cssh_oidc_store() {
    local _resp="$1" _fallback_refresh="$2"
    local _issuer="$CSSH_OIDC_ISSUER" _cid="$CSSH_OIDC_CLIENT_ID"
    local _scope="${CSSH_OIDC_SCOPE:-openid profile email groups offline_access}"
    local _aud="${CSSH_OIDC_AUDIENCE:-}"
    local _want="${CSSH_OIDC_TOKEN:-access}"
    local _dir="${XDG_CACHE_HOME:-$HOME/.cache}/cerberus"
    local _file="$_dir/oidc-token.json"

    local _at _it _rt _exp_in _now _expiry _send
    _at=$(jq -r '.access_token // empty' "$_resp" 2>/dev/null)
    _it=$(jq -r '.id_token // empty' "$_resp" 2>/dev/null)
    _rt=$(jq -r '.refresh_token // empty' "$_resp" 2>/dev/null)
    _exp_in=$(jq -r '.expires_in // empty' "$_resp" 2>/dev/null)
    case "$_exp_in" in ''|*[!0-9]*) _exp_in=300 ;; esac
    [ -n "$_rt" ] || _rt="$_fallback_refresh"
    _now=$(date +%s); _expiry=$((_now + _exp_in))

    if [ "$_want" = id ]; then _send="$_it"; else _send="$_at"; fi
    if [ -z "$_send" ]; then
        printf 'cssh: OIDC token response has no %s token\n' "$_want" >&2
        return 1
    fi

    # Cache both tokens + refresh token so a later CSSH_OIDC_TOKEN change reuses
    # the same response. Expiry tracks the access token's expires_in; a stale
    # token is caught by the sign path's one-shot 401 retry regardless.
    [ -d "$_dir" ] || { mkdir -p "$_dir" 2>/dev/null && chmod 700 "$_dir" 2>/dev/null; }
    local _tmp
    if _tmp=$(mktemp "${_file}.XXXXXX" 2>/dev/null); then
        if jq -nc \
            --arg iss "$_issuer" --arg cid "$_cid" --arg aud "$_aud" --arg scope "$_scope" \
            --arg at "$_at" --arg it "$_it" --arg rt "$_rt" --argjson exp "$_expiry" \
            '{issuer:$iss, client_id:$cid, audience:$aud, scope:$scope, access_token:$at, id_token:$it, refresh_token:$rt, expiry:$exp}' \
            >| "$_tmp" 2>/dev/null
        then
            chmod 600 "$_tmp" 2>/dev/null
            mv -f "$_tmp" "$_file" 2>/dev/null || rm -f "$_tmp"
        else
            rm -f "$_tmp"
        fi
    fi
    printf '%s' "$_send"
    return 0
}

# _cssh_oidc_token obtains an OIDC bearer token for the Cerberus API via the
# OAuth 2.0 Device Authorization Grant (RFC 8628), with a cached-token fast path
# and silent refresh-token renewal. It prints the token to stdout; every prompt
# and diagnostic goes to stderr, so `tok=$(_cssh_oidc_token)` captures only the
# token. Requires CSSH_OIDC_ISSUER and CSSH_OIDC_CLIENT_ID.
#   $1 = force (1 = skip the cached access token; renew via refresh_token, else
#        run the device flow). Used by the sign path's 401 retry.
_cssh_oidc_token() {
    local _force="${1:-0}"
    local _issuer="${CSSH_OIDC_ISSUER:-}" _cid="${CSSH_OIDC_CLIENT_ID:-}"
    local _scope="${CSSH_OIDC_SCOPE:-openid profile email groups offline_access}"
    local _aud="${CSSH_OIDC_AUDIENCE:-}"
    local _secret="${CSSH_OIDC_CLIENT_SECRET:-}"
    local _want="${CSSH_OIDC_TOKEN:-access}"
    local _cacert="${CSSH_OIDC_CACERT:-}"
    local _skew="${CSSH_OIDC_SKEW:-30}"
    case "$_skew" in ''|*[!0-9]*) _skew=30 ;; esac

    if [ -z "$_issuer" ] || [ -z "$_cid" ]; then
        printf 'cssh: OIDC auth needs CSSH_OIDC_ISSUER and CSSH_OIDC_CLIENT_ID (set them in /etc/profile.d/cerberus-env.sh)\n' >&2
        return 1
    fi

    local _dir="${XDG_CACHE_HOME:-$HOME/.cache}/cerberus"
    local _file="$_dir/oidc-token.json"
    local _now _tmp _code _cached_refresh="" _match=0
    _now=$(date +%s)

    # Cache is reusable only when issuer/client/audience/scope all still match.
    if [ -r "$_file" ]; then
        local _m
        _m=$(jq -r --arg iss "$_issuer" --arg cid "$_cid" --arg aud "$_aud" --arg scope "$_scope" \
            'if (.issuer==$iss and .client_id==$cid and (.audience//"")==$aud and (.scope//"")==$scope) then "1" else "0" end' \
            "$_file" 2>/dev/null)
        [ "$_m" = 1 ] && _match=1
    fi

    # 1) Fast path: a still-valid cached token (unless the caller forced renewal).
    if [ "$_force" -eq 0 ] && [ "$_match" -eq 1 ]; then
        local _exp _send
        _exp=$(jq -r '.expiry // 0' "$_file" 2>/dev/null)
        case "$_exp" in ''|*[!0-9]*) _exp=0 ;; esac
        if [ "$_exp" -gt $((_now + _skew)) ]; then
            if [ "$_want" = id ]; then _send=$(jq -r '.id_token // empty' "$_file" 2>/dev/null)
            else _send=$(jq -r '.access_token // empty' "$_file" 2>/dev/null); fi
            if [ -n "$_send" ]; then printf '%s' "$_send"; return 0; fi
        fi
    fi
    [ "$_match" -eq 1 ] && _cached_refresh=$(jq -r '.refresh_token // empty' "$_file" 2>/dev/null)

    # OIDC discovery — locate the device-authorization and token endpoints.
    _tmp=$(mktemp "${TMPDIR:-/tmp}/cssh-oidc.XXXXXX") || return 1
    _code=$(
        set -- --silent --show-error -o "$_tmp" -w '%{http_code}'
        [ -n "$_cacert" ] && set -- "$@" --cacert "$_cacert"
        curl "$@" "${_issuer%/}/.well-known/openid-configuration"
    )
    if [ "$_code" != 200 ]; then
        printf 'cssh: OIDC discovery failed (HTTP %s) at %s/.well-known/openid-configuration\n' "$_code" "${_issuer%/}" >&2
        rm -f "$_tmp"; return 1
    fi
    local _dev_ep _tok_ep
    _dev_ep=$(jq -r '.device_authorization_endpoint // empty' "$_tmp" 2>/dev/null)
    _tok_ep=$(jq -r '.token_endpoint // empty' "$_tmp" 2>/dev/null)
    if [ -z "$_dev_ep" ] || [ -z "$_tok_ep" ]; then
        printf 'cssh: issuer advertises no device_authorization_endpoint (device flow unsupported)\n' >&2
        rm -f "$_tmp"; return 1
    fi

    # 2) Silent refresh, when we hold a cached refresh token.
    if [ -n "$_cached_refresh" ]; then
        printf 'cssh: refreshing OIDC token...\n' >&2
        _code=$(
            set -- --silent --show-error -o "$_tmp" -w '%{http_code}' \
                --data-urlencode "grant_type=refresh_token" \
                --data-urlencode "client_id=$_cid" \
                --data-urlencode "refresh_token=$_cached_refresh" \
                --data-urlencode "scope=$_scope"
            [ -n "$_aud" ] && set -- "$@" --data-urlencode "audience=$_aud"
            [ -n "$_secret" ] && set -- "$@" --data-urlencode "client_secret=$_secret"
            [ -n "$_cacert" ] && set -- "$@" --cacert "$_cacert"
            curl "$@" "$_tok_ep"
        )
        if [ "$_code" = 200 ]; then
            local _out; _out=$(_cssh_oidc_store "$_tmp" "$_cached_refresh"); local _rc=$?
            rm -f "$_tmp"
            [ "$_rc" -eq 0 ] && [ -n "$_out" ] && { printf '%s' "$_out"; return 0; }
            return 1
        fi
        printf 'cssh: OIDC refresh failed (HTTP %s); falling back to device login\n' "$_code" >&2
    fi

    # 3) Device Authorization Grant.
    _code=$(
        set -- --silent --show-error -o "$_tmp" -w '%{http_code}' \
            --data-urlencode "client_id=$_cid" \
            --data-urlencode "scope=$_scope"
        [ -n "$_aud" ] && set -- "$@" --data-urlencode "audience=$_aud"
        [ -n "$_secret" ] && set -- "$@" --data-urlencode "client_secret=$_secret"
        [ -n "$_cacert" ] && set -- "$@" --cacert "$_cacert"
        curl "$@" "$_dev_ep"
    )
    if [ "$_code" != 200 ]; then
        local _e; _e=$(jq -r '.error_description // .error // empty' "$_tmp" 2>/dev/null)
        printf 'cssh: device authorization request failed (HTTP %s): %s\n' "$_code" "${_e:-unknown}" >&2
        rm -f "$_tmp"; return 1
    fi
    local _device_code _user_code _vuri _vuri_complete _interval _expires
    _device_code=$(jq -r '.device_code // empty' "$_tmp" 2>/dev/null)
    _user_code=$(jq -r '.user_code // empty' "$_tmp" 2>/dev/null)
    _vuri=$(jq -r '.verification_uri // .verification_url // empty' "$_tmp" 2>/dev/null)
    _vuri_complete=$(jq -r '.verification_uri_complete // empty' "$_tmp" 2>/dev/null)
    _interval=$(jq -r '.interval // 5' "$_tmp" 2>/dev/null)
    _expires=$(jq -r '.expires_in // 600' "$_tmp" 2>/dev/null)
    case "$_interval" in ''|*[!0-9]*) _interval=5 ;; esac
    case "$_expires" in ''|*[!0-9]*) _expires=600 ;; esac
    if [ -z "$_device_code" ] || [ -z "$_user_code" ] || [ -z "$_vuri" ]; then
        printf 'cssh: incomplete device authorization response\n' >&2
        rm -f "$_tmp"; return 1
    fi

    printf '\ncssh: to authenticate, open this URL in a browser:\n\n    %s\n\nand enter the code:  %s\n\n' "$_vuri" "$_user_code" >&2
    [ -n "$_vuri_complete" ] && printf 'cssh: (or open this direct link, code pre-filled)\n\n    %s\n\n' "$_vuri_complete" >&2
    case "${CSSH_OIDC_OPEN:-0}" in
        1|true|yes|on|TRUE|YES|ON)
            local _opener
            for _opener in xdg-open open sensible-browser; do
                if command -v "$_opener" >/dev/null 2>&1; then
                    "$_opener" "${_vuri_complete:-$_vuri}" >/dev/null 2>&1 &
                    break
                fi
            done
            ;;
    esac
    printf 'cssh: waiting for authorization (Ctrl-C to abort)...\n' >&2

    local _deadline=$((_now + _expires))
    while :; do
        sleep "$_interval"
        if [ "$(date +%s)" -ge "$_deadline" ]; then
            printf 'cssh: device code expired before authorization; run cssh --oauth again\n' >&2
            rm -f "$_tmp"; return 1
        fi
        _code=$(
            set -- --silent --show-error -o "$_tmp" -w '%{http_code}' \
                --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
                --data-urlencode "device_code=$_device_code" \
                --data-urlencode "client_id=$_cid"
            [ -n "$_secret" ] && set -- "$@" --data-urlencode "client_secret=$_secret"
            [ -n "$_cacert" ] && set -- "$@" --cacert "$_cacert"
            curl "$@" "$_tok_ep"
        )
        if [ "$_code" = 200 ]; then
            local _out2; _out2=$(_cssh_oidc_store "$_tmp" ""); local _rc2=$?
            rm -f "$_tmp"
            [ "$_rc2" -eq 0 ] && [ -n "$_out2" ] && { printf '%s' "$_out2"; return 0; }
            return 1
        fi
        local _err; _err=$(jq -r '.error // empty' "$_tmp" 2>/dev/null)
        case "$_err" in
            authorization_pending) : ;;
            slow_down) _interval=$((_interval + 5)) ;;
            access_denied) printf 'cssh: authorization denied at the identity provider\n' >&2; rm -f "$_tmp"; return 1 ;;
            expired_token) printf 'cssh: device code expired; run cssh --oauth again\n' >&2; rm -f "$_tmp"; return 1 ;;
            *) printf 'cssh: OIDC token error: %s\n' "${_err:-HTTP $_code}" >&2; rm -f "$_tmp"; return 1 ;;
        esac
    done
}

cssh() {
    _cssh_usage() {
        cat >&2 <<'EOF'
Usage: cssh [--principals u1,u2] [--pubkey PATH] [--url URL] [--cacert PATH] [--force] [--sign-only] [--all-principals] [--self] [--oauth] [--verbose] [--] HOST [SSH_ARGS...]

Flags:
  --principals u1,u2  request specific cert principals
  --pubkey PATH       sign this public key (overrides CSSH_PUBKEY)
  --url URL           Cerberus base URL (overrides CERBERUS_URL)
  --cacert PATH       CA bundle for the API's TLS cert (overrides CERBERUS_CACERT)
  --force             re-sign even if the cached cert is still valid
  --sign-only         fetch/refresh the cert and exit without running ssh;
                      silent unless --verbose (HOST optional, used for principal)
  --all-principals    cert for every principal in your first group; requires
                      --sign-only, mutually exclusive with --principals
  --self              fetch a cert for your own identity (server issues for your
                      uid); requires --sign-only, excl. --principals/--all-principals
  --oauth             authenticate with OIDC (device flow) instead of Kerberos
                      (needs CSSH_OIDC_ISSUER + CSSH_OIDC_CLIENT_ID)
  --verbose           print the cert path in --sign-only mode
  --                  end of cssh flags; remainder passed to ssh

Env: CERBERUS_URL CERBERUS_CACERT CSSH_PUBKEY CSSH_REFRESH_BEFORE CSSH_PRINCIPALS
     CSSH_AUTH CSSH_OIDC_ISSUER CSSH_OIDC_CLIENT_ID CSSH_OIDC_SCOPE CSSH_OIDC_AUDIENCE
EOF
    }

    _cssh_check_krb() {
        # `klist -s` exits 0 only when the cache holds a non-expired TGT
        # (krbtgt/REALM@REALM). It silently lumps together "no cache",
        # "cache with no TGT", and "TGT expired" — fine for the gating
        # decision, useless for the user. Distinguish them so the error
        # tells them what to fix, not just that something is wrong.
        if ! command -v klist >/dev/null 2>&1; then
            printf 'cssh: klist not found; install krb5-workstation (or krb5-user)\n' >&2
            return 1
        fi
        if klist -s 2>/dev/null; then
            return 0
        fi
        local out princ tgt_line tgt_expiry
        if ! out=$(klist 2>/dev/null); then
            printf 'cssh: no Kerberos credential cache (run: kinit)\n' >&2
            return 1
        fi
        princ=$(printf '%s\n' "$out" | awk -F': +' '/Default principal/ {print $2; exit}')
        # MIT and Heimdal both put two timestamps before "krbtgt/...".
        # Pull the second one (the expiry) for the error message.
        tgt_line=$(printf '%s\n' "$out" \
            | awk '/krbtgt\// {sub(/^[[:space:]]+/,""); print; exit}')
        tgt_expiry=$(printf '%s\n' "$tgt_line" | awk '{print $3, $4}')
        if [ -n "$princ" ] && [ -n "$tgt_line" ]; then
            printf 'cssh: TGT for %s is expired (expired %s) — run: kinit\n' \
                "$princ" "${tgt_expiry:-unknown}" >&2
        elif [ -n "$princ" ]; then
            printf 'cssh: no valid TGT for %s — run: kinit\n' "$princ" >&2
        else
            printf 'cssh: Kerberos cache has no valid TGT — run: kinit\n' >&2
        fi
        return 1
    }

    if [ $# -eq 0 ]; then
        _cssh_usage
        unset -f _cssh_usage _cssh_check_krb
        return 2
    fi

    local pubkey="${CSSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"
    local cerberus_url="${CERBERUS_URL:-}"
    local cacert="${CERBERUS_CACERT:-}"
    local refresh_before="${CSSH_REFRESH_BEFORE:-300}"
    local principals="${CSSH_PRINCIPALS:-}"
    local force=0
    local sign_only=0
    local all_principals=0
    local self_req=0
    local principals_set_by_flag=0
    local verbose=0
    local auth_mode="${CSSH_AUTH:-kerberos}"

    # Reject a non-integer CSSH_REFRESH_BEFORE before it reaches arithmetic.
    case "$refresh_before" in
        ''|*[!0-9]*) refresh_before=300 ;;
    esac

    while [ $# -gt 0 ]; do
        case "$1" in
            --principals)   principals="$2"; principals_set_by_flag=1; shift 2 ;;
            --principals=*) principals="${1#--principals=}"; principals_set_by_flag=1; shift ;;
            --pubkey)       pubkey="$2"; shift 2 ;;
            --pubkey=*)     pubkey="${1#--pubkey=}"; shift ;;
            --url)          cerberus_url="$2"; shift 2 ;;
            --url=*)        cerberus_url="${1#--url=}"; shift ;;
            --cacert)       cacert="$2"; shift 2 ;;
            --cacert=*)     cacert="${1#--cacert=}"; shift ;;
            --force)        force=1; shift ;;
            --sign-only)    sign_only=1; shift ;;
            --all-principals) all_principals=1; shift ;;
            --self)         self_req=1; shift ;;
            --oauth)        auth_mode=oidc; shift ;;
            --verbose)      verbose=1; shift ;;
            -h|--help)      _cssh_usage; unset -f _cssh_usage _cssh_check_krb; return 0 ;;
            --)             shift; break ;;
            *)              break ;;
        esac
    done
    unset -f _cssh_usage

    # Authentication method: kerberos (default, SPNEGO) or oidc (Bearer token via
    # the OAuth device flow). --oauth sets oidc for one call; CSSH_AUTH sets the
    # default. Anything else is an operator typo — fail loudly.
    case "$auth_mode" in
        kerberos|oidc) ;;
        *)
            printf 'cssh: invalid CSSH_AUTH=%s (expected "kerberos" or "oidc")\n' "$auth_mode" >&2
            unset -f _cssh_check_krb
            return 2
            ;;
    esac

    # --all-principals mints a broad cert (every principal in your first Cerberus
    # group) for pre-authentication. Require --sign-only (you're staging a cert
    # for other tools, not opening one interactive session), and forbid pairing
    # it with an explicit --principals. A CSSH_PRINCIPALS default is simply
    # ignored (not an error) so this works in a shell that exports one.
    if [ "$all_principals" -ne 0 ]; then
        if [ "$sign_only" -eq 0 ]; then
            printf 'cssh: --all-principals requires --sign-only\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        if [ "$principals_set_by_flag" -ne 0 ]; then
            printf 'cssh: --all-principals and --principals are mutually exclusive\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        principals=   # the server expands the whole group; send no principals
    fi

    # --self explicitly requests a cert for your own identity (the server derives
    # the uid from your Kerberos principal). Require --sign-only: it means "hand
    # me my own cert", not "connect". To simply connect as yourself, run cssh
    # normally (cssh you@host / cssh host) — the server accepts a request for your
    # own uid via self_principal without any flag. Mutually exclusive with
    # --all-principals and --principals; a CSSH_PRINCIPALS default is ignored.
    if [ "$self_req" -ne 0 ]; then
        if [ "$sign_only" -eq 0 ]; then
            printf 'cssh: --self requires --sign-only (to connect as yourself, run cssh normally)\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        if [ "$all_principals" -ne 0 ]; then
            printf 'cssh: --self and --all-principals are mutually exclusive\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        if [ "$principals_set_by_flag" -ne 0 ]; then
            printf 'cssh: --self and --principals are mutually exclusive\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        principals=   # the server issues for the caller's own uid
    fi

    # If the caller didn't pin principals, ask ssh itself who the target login
    # user is. This handles user@host, -l USER, and ssh_config User blocks
    # uniformly — re-parsing ssh's arg grammar in shell would be fragile. Fall
    # back to the local login name (USER, or `id -un` if USER is unset). Skipped
    # for --all-principals / --self, which send no principals at all.
    if [ "$all_principals" -eq 0 ] && [ "$self_req" -eq 0 ] && [ -z "$principals" ]; then
        if [ $# -gt 0 ]; then
            principals=$(ssh -G "$@" 2>/dev/null \
                | awk '/^user /{print $2; exit}')
        fi
        : "${principals:=${USER:-$(id -un 2>/dev/null)}}"
    fi

    if [ -z "$cerberus_url" ]; then
        printf 'cssh: CERBERUS_URL not set (set it in /etc/profile.d/cerberus-env.sh, export CERBERUS_URL, or use --url)\n' >&2
        unset -f _cssh_check_krb
        return 2
    fi
    local privkey="${pubkey%.pub}"

    # Auto-generate an ed25519 keypair when NEITHER half exists, so a first-time
    # user doesn't have to run ssh-keygen by hand. Only when both are absent — a
    # half-present key (one file missing) is left alone and surfaces as the
    # readability error below, never silently clobbered. Opt out with
    # CSSH_AUTOGEN=0 (or false/no/off). The generated key is passphraseless:
    # cssh is non-interactive and the short-lived cert is the real credential.
    if [ ! -e "$pubkey" ] && [ ! -e "$privkey" ]; then
        case "${CSSH_AUTOGEN:-1}" in
            0|false|no|off|FALSE|NO|OFF) : ;; # disabled — fall through to the error
            *)
                local keydir
                keydir=$(dirname "$privkey")
                if [ ! -d "$keydir" ] && ! mkdir -p "$keydir" 2>/dev/null; then
                    printf 'cssh: cannot create key directory: %s\n' "$keydir" >&2
                    unset -f _cssh_check_krb
                    return 1
                fi
                chmod 700 "$keydir" 2>/dev/null
                printf 'cssh: no SSH key at %s; generating an ed25519 keypair (set CSSH_AUTOGEN=0 to disable)\n' "$privkey" >&2
                if ! ssh-keygen -t ed25519 -f "$privkey" -N '' \
                    -C "cssh ${USER:-$(id -un 2>/dev/null)}" >/dev/null 2>&1; then
                    printf 'cssh: failed to generate SSH key at %s\n' "$privkey" >&2
                    unset -f _cssh_check_krb
                    return 1
                fi
                ;;
        esac
    fi

    if [ ! -r "$pubkey" ]; then
        printf 'cssh: public key not readable: %s\n' "$pubkey" >&2
        unset -f _cssh_check_krb
        return 2
    fi
    if [ ! -r "$privkey" ]; then
        printf 'cssh: matching private key not readable: %s\n' "$privkey" >&2
        unset -f _cssh_check_krb
        return 2
    fi

    local cert="${privkey}-cert.pub"
    # Cerberus may issue a different principal than the one requested when the
    # matched group maps it (`root: global-root` in allowed_principals), so the
    # cert's own principal list is not a reliable record of what we asked for.
    # After each explicit sign we record "<serial> <requested-set>" here and use
    # it for the refresh decision below; see docs/cssh.md "Cache".
    local sidecar="${privkey}-cert.requested"

    # Sorted, deduplicated requested set (comma-joined, trailing comma), used by
    # the refresh decision and recorded in the sidecar after an explicit sign.
    local req_princ=""
    if [ "$all_principals" -eq 0 ] && [ "$self_req" -eq 0 ]; then
        req_princ=$(printf '%s' "$principals" | tr ',' '\n' | awk 'NF' | sort -u | tr '\n' ',')
    fi

    # Refresh decision, from ssh-keygen -L on the cached cert. Re-sign when the
    # cert is missing/unparseable, when its principal set no longer matches what
    # we're requesting, or when it is expiring within refresh_before. Any parse
    # failure re-signs rather than reuse a cert we can't reason about.
    #
    # The principal check is what makes a principalA -> principalB switch work:
    # a cert minted for principalA cannot authenticate a request for principalB.
    # We compare sorted sets, so order and duplicates don't matter. Because the
    # server may issue a mapped name (root -> global-root), the comparison
    # target is the sidecar's record of what the cached cert was requested for
    # when available, else the cert's own principals.
    local need_sign=$force
    if [ "$need_sign" -eq 0 ]; then
        if [ ! -s "$cert" ]; then
            need_sign=1
        else
            local cert_info
            cert_info=$(ssh-keygen -L -f "$cert" 2>/dev/null)
            if [ -z "$cert_info" ]; then
                need_sign=1
            else
                local cert_princ
                # Extract the cert's principal list: the lines indented under
                # "Principals:" up to the next "<Header>:" line (principal names
                # carry no colon, so a ':' marks the end of the block).
                cert_princ=$(printf '%s\n' "$cert_info" | awk '
                    /^[[:space:]]*Principals:/ {
                        rest=$0; sub(/^[[:space:]]*Principals:[[:space:]]*/,"",rest)
                        if (rest!="" && rest!="(none)") print rest
                        p=1; next
                    }
                    p && /:/ { p=0; next }
                    p { gsub(/^[[:space:]]+/,""); if ($0!="") print }
                ' | sort -u | tr '\n' ',')
                # Prefer the sidecar's record of what this exact cert (by serial)
                # was requested for; a missing/stale/unparseable sidecar falls back
                # to comparing against the cert's own principals — never to reuse.
                # Certs cached by an older cssh therefore re-sign at most once.
                local cert_serial cached_req
                cert_serial=$(printf '%s\n' "$cert_info" | awk '/^[[:space:]]+Serial:/ {print $2; exit}')
                cached_req=$cert_princ
                if [ -n "$cert_serial" ] && [ -r "$sidecar" ]; then
                    local sc_serial="" sc_princ=""
                    read -r sc_serial sc_princ < "$sidecar" 2>/dev/null
                    if [ "$sc_serial" = "$cert_serial" ] && [ -n "$sc_princ" ]; then
                        cached_req=$sc_princ
                    fi
                fi
                # --all-principals / --self have no fixed requested set to compare
                # against (the server derives the principals), so their certs are
                # cached on expiry alone; entitlement changes are picked up on the
                # next re-sign (expiry or --force).
                if [ "$all_principals" -eq 0 ] && [ "$self_req" -eq 0 ] && [ "$req_princ" != "$cached_req" ]; then
                    need_sign=1
                else
                    local valid_to
                    valid_to=$(printf '%s\n' "$cert_info" \
                        | awk '/^[[:space:]]+Valid:/ {print $NF; exit}')
                    if [ -z "$valid_to" ]; then
                        need_sign=1
                    elif [ "$valid_to" = "forever" ]; then
                        : # never expires; reuse
                    else
                        local valid_epoch now
                        # GNU date first (`-d`), then BSD/macOS (`-j -f`); if
                        # neither parses the timestamp we fall back to 0, which
                        # forces a re-sign.
                        valid_epoch=$(date -d "$valid_to" +%s 2>/dev/null \
                            || date -j -f '%Y-%m-%dT%H:%M:%S' "$valid_to" +%s 2>/dev/null \
                            || printf '0')
                        now=$(date +%s)
                        if [ "$valid_epoch" -le $((now + refresh_before)) ]; then
                            need_sign=1
                        fi
                    fi
                fi
            fi
        fi
    fi

    if [ "$need_sign" -ne 0 ]; then
        if ! command -v jq >/dev/null 2>&1; then
            printf 'cssh: jq is required for JSON parsing\n' >&2
            unset -f _cssh_check_krb
            return 1
        fi
        # Build the request body first so an empty principal set fails fast,
        # before any (possibly interactive) authentication.
        local req_json
        if [ "$self_req" -ne 0 ]; then
            req_json=$(jq -nc --rawfile k "$pubkey" '{ssh_key: $k, self_principal: true}')
        elif [ "$all_principals" -ne 0 ]; then
            req_json=$(jq -nc --rawfile k "$pubkey" '{ssh_key: $k, all_principals: true}')
        else
            local principals_json
            principals_json=$(printf '%s' "$principals" \
                | jq -Rc 'split(",") | map(select(length > 0))')
            if [ "$(printf '%s' "$principals_json" | jq 'length')" -eq 0 ]; then
                printf 'cssh: principals list is empty (set CSSH_PRINCIPALS or pass --principals)\n' >&2
                unset -f _cssh_check_krb
                return 2
            fi
            req_json=$(jq -nc --rawfile k "$pubkey" --argjson p "$principals_json" '{ssh_key: $k, principals: $p}')
        fi

        # Resolve the Authorization credential. Kerberos uses curl's SPNEGO
        # negotiate; OIDC obtains a bearer token via the device flow (cached and
        # silently refreshed) and sends it as an Authorization: Bearer header.
        local auth_header="" token=""
        if [ "$auth_mode" = oidc ]; then
            token=$(_cssh_oidc_token 0)
            if [ $? -ne 0 ] || [ -z "$token" ]; then
                unset -f _cssh_check_krb
                return 1
            fi
            auth_header="Bearer $token"
        else
            if ! _cssh_check_krb; then
                unset -f _cssh_check_krb
                return 1
            fi
        fi

        local resp http_code curl_rc sign_try=0
        resp=$(mktemp "${TMPDIR:-/tmp}/cssh.XXXXXX") || { unset -f _cssh_check_krb; return 1; }
        # curl args are assembled with `set --` inside a command substitution so
        # the optional --cacert and the auth style are appended without the
        # ${cacert:+...} word-splitting idiom (which native zsh does not split).
        # `set --` runs in the $(...) subshell, so cssh's own positional args
        # (the ssh command line) are left intact. A rejected OIDC token (401) may
        # be stale/expired-early, so refresh once and retry the request.
        while :; do
            http_code=$(
                set -- --silent --show-error \
                    -H 'Content-Type: application/json' \
                    --data-binary "$req_json" \
                    -o "$resp" -w '%{http_code}'
                [ -n "$cacert" ] && set -- "$@" --cacert "$cacert"
                if [ -n "$auth_header" ]; then
                    set -- "$@" -H "Authorization: $auth_header"
                else
                    set -- "$@" --negotiate -u :
                fi
                curl "$@" "${cerberus_url%/}/sign"
            )
            curl_rc=$?
            if [ "$auth_mode" = oidc ] && [ "$curl_rc" -eq 0 ] && [ "$http_code" = 401 ] && [ "$sign_try" -eq 0 ]; then
                sign_try=1
                token=$(_cssh_oidc_token 1)
                if [ $? -eq 0 ] && [ -n "$token" ]; then
                    auth_header="Bearer $token"
                    continue
                fi
            fi
            break
        done

        if [ "$curl_rc" -ne 0 ] || [ "$http_code" != "200" ]; then
            local err
            err=$(jq -r '.error // empty' < "$resp" 2>/dev/null)
            [ -z "$err" ] && err=$(cat "$resp")
            printf 'cssh: signing failed (HTTP %s, curl=%d): %s\n' \
                "$http_code" "$curl_rc" "$err" >&2
            rm -f "$resp"
            unset -f _cssh_check_krb
            return 1
        fi

        local signed_key
        signed_key=$(jq -r '.signed_key // empty' < "$resp")
        rm -f "$resp"
        if [ -z "$signed_key" ]; then
            printf 'cssh: empty signed_key in response\n' >&2
            unset -f _cssh_check_krb
            return 1
        fi

        # Atomic write so a partial cert never lands on disk. mktemp on the
        # destination FS keeps `mv` atomic; $$ alone collides on parallel calls
        # from the same shell. `>|` overrides zsh noclobber for the mktemp'd file.
        local tmp_cert
        tmp_cert=$(mktemp "${cert}.XXXXXX") || { unset -f _cssh_check_krb; return 1; }
        if ! printf '%s\n' "$signed_key" >| "$tmp_cert"; then
            rm -f "$tmp_cert"
            unset -f _cssh_check_krb
            return 1
        fi
        # Validate that what we got is actually a parseable cert before publishing.
        if ! ssh-keygen -L -f "$tmp_cert" >/dev/null 2>&1; then
            printf 'cssh: server returned unparseable certificate; discarding\n' >&2
            rm -f "$tmp_cert"
            unset -f _cssh_check_krb
            return 1
        fi
        chmod 0600 "$tmp_cert"
        if ! mv -f "$tmp_cert" "$cert"; then
            rm -f "$tmp_cert"
            unset -f _cssh_check_krb
            return 1
        fi

        # Record what this cert was requested for (see the refresh decision
        # above). Best-effort: a failure here only costs one extra re-sign later.
        # Explicit mode only — --all-principals / --self have no fixed requested
        # set, so drop any sidecar left behind by an earlier explicit sign.
        if [ "$all_principals" -eq 0 ] && [ "$self_req" -eq 0 ]; then
            local new_serial tmp_side
            new_serial=$(ssh-keygen -L -f "$cert" 2>/dev/null | awk '/^[[:space:]]+Serial:/ {print $2; exit}')
            if [ -n "$new_serial" ] && tmp_side=$(mktemp "${sidecar}.XXXXXX" 2>/dev/null); then
                if printf '%s %s\n' "$new_serial" "$req_princ" >| "$tmp_side" \
                    && chmod 0600 "$tmp_side" && mv -f "$tmp_side" "$sidecar"; then
                    :
                else
                    rm -f "$tmp_side" "$sidecar" 2>/dev/null
                fi
            fi
        else
            rm -f "$sidecar" 2>/dev/null
        fi
    fi

    unset -f _cssh_check_krb

    # Pre-authenticate mode: the cert is now on disk at $cert (adjacent to the
    # private key), so ssh/scp/sftp/rsync -e ssh/git pick it up automatically
    # when they use $privkey. Do NOT connect. Any HOST/SSH_ARGS were only used
    # above to resolve the principal. Stay silent by default; print the cert path
    # only with --verbose (so `cert=$(cssh --sign-only --verbose)` still works).
    if [ "$sign_only" -ne 0 ]; then
        if [ "$verbose" -ne 0 ]; then
            printf '%s\n' "$cert"
        fi
        return 0
    fi

    # The Cerberus-signed cert is the only identity cssh uses. IdentitiesOnly=yes
    # prevents ssh from trying agent keys or any IdentityFile entries from
    # ~/.ssh/config; -i pins the key, and CertificateFile is passed explicitly so
    # the binding survives a non-standard CSSH_PUBKEY path.
    command ssh \
        -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey \
        -i "$privkey" \
        -o CertificateFile="$cert" \
        "$@"
}
