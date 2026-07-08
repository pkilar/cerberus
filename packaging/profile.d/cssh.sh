# cssh — Cerberus-signed SSH wrapper (system-wide, bash + zsh).
#
# Fetches a short-lived OpenSSH user certificate from the Cerberus signing API
# (Kerberos/SPNEGO-authenticated) and drops it next to the matching private key
# as <key>-cert.pub, where ssh(1) auto-loads it. Caches the cert and re-signs
# only when it is missing, unreadable, or about to expire.
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
#
# ── Per-call flags (consumed before the rest is passed to ssh) ───────────────
#   --principals u1,u2    override CSSH_PRINCIPALS for this call
#   --pubkey PATH         override CSSH_PUBKEY for this call
#   --url URL             override CERBERUS_URL for this call
#   --cacert PATH         override CERBERUS_CACERT for this call
#   --force               re-sign even if the cached cert is still valid
#   --sign-only           fetch/refresh the cert and exit WITHOUT running ssh
#                         (pre-authenticate, then use scp/rsync/sftp/git/etc.);
#                         prints the cert path to stdout. HOST is optional and,
#                         if given, is used only to resolve the principal.
#   --                    end of cssh flags; remaining args go to ssh verbatim

cssh() {
    _cssh_usage() {
        cat >&2 <<'EOF'
Usage: cssh [--principals u1,u2] [--pubkey PATH] [--url URL] [--cacert PATH] [--force] [--sign-only] [--] HOST [SSH_ARGS...]

Flags:
  --principals u1,u2  request specific cert principals
  --pubkey PATH       sign this public key (overrides CSSH_PUBKEY)
  --url URL           Cerberus base URL (overrides CERBERUS_URL)
  --cacert PATH       CA bundle for the API's TLS cert (overrides CERBERUS_CACERT)
  --force             re-sign even if the cached cert is still valid
  --sign-only         fetch/refresh the cert and exit without running ssh;
                      prints the cert path (HOST optional, used for principal)
  --                  end of cssh flags; remainder passed to ssh

Env: CERBERUS_URL CERBERUS_CACERT CSSH_PUBKEY CSSH_REFRESH_BEFORE CSSH_PRINCIPALS
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

    # Reject a non-integer CSSH_REFRESH_BEFORE before it reaches arithmetic.
    case "$refresh_before" in
        ''|*[!0-9]*) refresh_before=300 ;;
    esac

    while [ $# -gt 0 ]; do
        case "$1" in
            --principals)   principals="$2"; shift 2 ;;
            --principals=*) principals="${1#--principals=}"; shift ;;
            --pubkey)       pubkey="$2"; shift 2 ;;
            --pubkey=*)     pubkey="${1#--pubkey=}"; shift ;;
            --url)          cerberus_url="$2"; shift 2 ;;
            --url=*)        cerberus_url="${1#--url=}"; shift ;;
            --cacert)       cacert="$2"; shift 2 ;;
            --cacert=*)     cacert="${1#--cacert=}"; shift ;;
            --force)        force=1; shift ;;
            --sign-only)    sign_only=1; shift ;;
            -h|--help)      _cssh_usage; unset -f _cssh_usage _cssh_check_krb; return 0 ;;
            --)             shift; break ;;
            *)              break ;;
        esac
    done
    unset -f _cssh_usage

    # If the caller didn't pin principals, ask ssh itself who the target login
    # user is. This handles user@host, -l USER, and ssh_config User blocks
    # uniformly — re-parsing ssh's arg grammar in shell would be fragile. Fall
    # back to the local login name (USER, or `id -un` if USER is unset).
    if [ -z "$principals" ]; then
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
    if [ ! -r "$pubkey" ]; then
        printf 'cssh: public key not readable: %s\n' "$pubkey" >&2
        unset -f _cssh_check_krb
        return 2
    fi

    local privkey="${pubkey%.pub}"
    if [ ! -r "$privkey" ]; then
        printf 'cssh: matching private key not readable: %s\n' "$privkey" >&2
        unset -f _cssh_check_krb
        return 2
    fi

    local cert="${privkey}-cert.pub"

    # Refresh decision: parse "Valid: from X to Y" out of ssh-keygen -L. If
    # parsing fails for any reason we re-sign rather than reuse a cert we
    # can't reason about.
    local need_sign=$force
    if [ "$need_sign" -eq 0 ]; then
        if [ ! -s "$cert" ]; then
            need_sign=1
        else
            local valid_to
            valid_to=$(ssh-keygen -L -f "$cert" 2>/dev/null \
                | awk '/^[[:space:]]+Valid:/ {print $NF; exit}')
            if [ -z "$valid_to" ]; then
                need_sign=1
            elif [ "$valid_to" = "forever" ]; then
                : # never expires; reuse
            else
                local valid_epoch now
                # GNU date first (`-d`), then BSD/macOS (`-j -f`); if neither
                # parses the timestamp we fall back to 0, which forces a re-sign.
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

    if [ "$need_sign" -ne 0 ]; then
        if ! command -v jq >/dev/null 2>&1; then
            printf 'cssh: jq is required for JSON parsing\n' >&2
            unset -f _cssh_check_krb
            return 1
        fi
        if ! _cssh_check_krb; then
            unset -f _cssh_check_krb
            return 1
        fi

        local req_json principals_json
        principals_json=$(printf '%s' "$principals" \
            | jq -Rc 'split(",") | map(select(length > 0))')
        if [ "$(printf '%s' "$principals_json" | jq 'length')" -eq 0 ]; then
            printf 'cssh: principals list is empty (set CSSH_PRINCIPALS or pass --principals)\n' >&2
            unset -f _cssh_check_krb
            return 2
        fi
        req_json=$(jq -nc --rawfile k "$pubkey" --argjson p "$principals_json" '{ssh_key: $k, principals: $p}')

        local resp http_code curl_rc
        resp=$(mktemp "${TMPDIR:-/tmp}/cssh.XXXXXX") || { unset -f _cssh_check_krb; return 1; }
        # The optional --cacert is passed via an explicit branch rather than the
        # ${cacert:+--cacert "$cacert"} idiom: that relies on word-splitting an
        # unquoted expansion, which bash does but native zsh does NOT — under zsh
        # curl would receive "--cacert /path" as a single mangled argument.
        if [ -n "$cacert" ]; then
            http_code=$(curl --silent --show-error \
                --negotiate -u : \
                --cacert "$cacert" \
                -H 'Content-Type: application/json' \
                --data-binary "$req_json" \
                -o "$resp" -w '%{http_code}' \
                "${cerberus_url%/}/sign")
            curl_rc=$?
        else
            http_code=$(curl --silent --show-error \
                --negotiate -u : \
                -H 'Content-Type: application/json' \
                --data-binary "$req_json" \
                -o "$resp" -w '%{http_code}' \
                "${cerberus_url%/}/sign")
            curl_rc=$?
        fi

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
    fi

    unset -f _cssh_check_krb

    # Pre-authenticate mode: the cert is now on disk at $cert (adjacent to the
    # private key), so ssh/scp/sftp/rsync -e ssh/git pick it up automatically
    # when they use $privkey. Print the cert path (for scripting) and do NOT
    # connect. Any HOST/SSH_ARGS were only used above to resolve the principal.
    if [ "$sign_only" -ne 0 ]; then
        printf '%s\n' "$cert"
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
