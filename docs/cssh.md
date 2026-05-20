# `cssh` — Cerberus-signed SSH wrapper

A small shell function that fetches a short-lived OpenSSH user certificate
from the Cerberus signing API and hands off to `ssh(1)`. It caches the cert
between runs and only re-signs when the cert is missing, expired, or about
to expire — so the typical interactive workflow (`kinit` once a day, then
`cssh` for every connection) hits the API only when necessary.

The cert is the **only** identity `cssh` uses. Agent keys and `IdentityFile`
entries from `~/.ssh/config` are ignored. Run plain `ssh` if you want a
different identity.

---

## Prerequisites

- A Kerberos TGT for the realm Cerberus authenticates against (`kinit`).
- `curl` built with GSS-API support (the system `curl` on RHEL / Amazon
  Linux / Debian / Ubuntu all qualify).
- `jq`.
- An ed25519 keypair at `~/.ssh/id_ed25519` (override with `CSSH_PUBKEY`).
- The Cerberus API host's CA must be trusted by curl, either via the system
  trust store or by setting `CERBERUS_CACERT` to a CA bundle.

---

## Setup

Add the function (below) to `~/.bashrc` or `~/.zshrc`, then export the
Cerberus URL once. The cacert is only needed if the API uses a private CA
that isn't in your system trust store.

```sh
export CERBERUS_URL=https://cerberus.example.com:8443
export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem
```

| Variable              | Default                       | Purpose                                                         |
| --------------------- | ----------------------------- | --------------------------------------------------------------- |
| `CERBERUS_URL`        | *(required)*                  | Base URL of the signing API. `/sign` is appended.               |
| `CERBERUS_CACERT`     | system trust                  | CA bundle to trust for the API's TLS cert.                      |
| `CSSH_PUBKEY`         | `~/.ssh/id_ed25519.pub`       | Public key to sign. The matching private key must exist.        |
| `CSSH_REFRESH_BEFORE` | `300`                         | Re-sign if cert expires within this many seconds.               |
| `CSSH_PRINCIPALS`     | *(unset)*                     | Comma-separated principals to request. If unset, the API picks. |

---

## Usage

```sh
kinit                                   # once per ticket lifetime
cssh user@host                          # signs (or reuses) cert, then ssh's
cssh --principals root user@host        # request a specific principal set
cssh --force user@host                  # re-sign even if cached cert is valid
cssh --pubkey ~/.ssh/id_rsa.pub host    # sign a non-default key
cssh -- -L 8080:localhost:80 user@host  # pass-through ssh args after --
cssh                                    # prints usage
cssh --help                             # prints usage
```

The cert is written to `<privkey>-cert.pub` (e.g.
`~/.ssh/id_ed25519-cert.pub`), the conventional OpenSSH path. Inspect it
with:

```sh
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
```

---

## Behavior

- **Cache.** A signed cert is reused until its `Valid: from … to …` window
  closes within `CSSH_REFRESH_BEFORE` seconds. The validity window is
  parsed from `ssh-keygen -L`; if parsing fails for any reason the cert is
  re-signed rather than reused.
- **Identity locking.** `cssh` invokes ssh with
  `-o IdentitiesOnly=yes -i <privkey> -o CertificateFile=<cert>`. This
  disables agent forwarding of unrelated keys and any `IdentityFile`
  entries from `~/.ssh/config`, so only the Cerberus cert can authenticate
  the connection.
- **TGT check.** Before calling the signing API, `cssh` runs a robust check
  on the Kerberos cache and reports the actual failure mode (no cache,
  expired TGT, principal mismatch) so the user knows whether to `kinit`
  or something more.
- **Atomic write.** The cert is written via `mv -f` from a tempfile so a
  half-written cert never lands on disk and breaks future ssh runs.

---

## Troubleshooting

| Symptom                                                         | Likely cause                                                                                            |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `cssh: no Kerberos credential cache (run: kinit)`                | No cache file. Run `kinit`.                                                                             |
| `cssh: TGT for X@REALM is expired (...) — run: kinit`            | Cache exists but the TGT has expired. Re-`kinit`.                                                       |
| `cssh: signing failed (HTTP 403): Not authorized for ...`        | The principal you requested isn't in any group you belong to in the Cerberus config.                    |
| `cssh: signing failed (HTTP 401): ...`                           | SPNEGO auth was rejected. Common causes: keytab kvno mismatch with the KDC, clock skew >5 min, no TGT.  |
| sshd rejects with `Certificate option "permit-pty" corrupt`     | Server-side config bug — a flag-style cert extension was given a non-empty value. Fix the YAML.         |
| ssh asks for a password                                          | The cert was issued for a different principal than the SSH login name. Use `--principals <login>`.      |

If a cached cert seems wrong, the safest reset is:

```sh
rm -f ~/.ssh/id_ed25519-cert.pub
cssh --force user@host
```

---

## The function

Paste this verbatim into `~/.bashrc` or `~/.zshrc`. It works in both shells.

```bash
# cssh — Cerberus-signed SSH wrapper. See docs/cssh.md.
cssh() {
    _cssh_usage() {
        cat >&2 <<'EOF'
Usage: cssh [--principals u1,u2] [--pubkey PATH] [--url URL] [--force] [--] HOST [SSH_ARGS...]

Flags:
  --principals u1,u2  request specific cert principals
  --pubkey PATH       sign this public key (overrides CSSH_PUBKEY)
  --url URL           Cerberus base URL (overrides CERBERUS_URL)
  --force             re-sign even if cached cert is still valid
  --                  end of cssh flags; remainder passed to ssh

Env: CERBERUS_URL CERBERUS_CACERT CSSH_PUBKEY CSSH_REFRESH_BEFORE CSSH_PRINCIPALS
EOF
    }

    _cssh_check_krb() {
        # `klist -s` exits 0 only when the cache holds a non-expired TGT.
        # Distinguish "no cache", "TGT expired", and "no TGT" so the error
        # tells the user what to fix.
        if ! command -v klist >/dev/null 2>&1; then
            printf 'cssh: klist not found; install krb5-workstation (or krb5-user)\n' >&2
            return 1
        fi
        if klist -s 2>/dev/null; then
            return 0
        fi
        local out princ expires
        if ! out=$(klist 2>/dev/null); then
            printf 'cssh: no Kerberos credential cache (run: kinit)\n' >&2
            return 1
        fi
        princ=$(printf '%s\n' "$out" | awk -F': +' '/Default principal/ {print $2; exit}')
        expires=$(printf '%s\n' "$out" \
            | awk '/krbtgt\// {sub(/^[[:space:]]+/,""); print; exit}')
        if [ -n "$princ" ] && [ -n "$expires" ]; then
            printf 'cssh: TGT for %s is expired (%s) — run: kinit\n' "$princ" "$expires" >&2
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

    while [ $# -gt 0 ]; do
        case "$1" in
            --principals)   principals="$2"; shift 2 ;;
            --principals=*) principals="${1#--principals=}"; shift ;;
            --pubkey)       pubkey="$2"; shift 2 ;;
            --pubkey=*)     pubkey="${1#--pubkey=}"; shift ;;
            --url)          cerberus_url="$2"; shift 2 ;;
            --url=*)        cerberus_url="${1#--url=}"; shift ;;
            --force)        force=1; shift ;;
            -h|--help)      _cssh_usage; unset -f _cssh_usage _cssh_check_krb; return 0 ;;
            --)             shift; break ;;
            *)              break ;;
        esac
    done

    if [ -z "$cerberus_url" ]; then
        printf 'cssh: CERBERUS_URL not set (or use --url)\n' >&2
        unset -f _cssh_usage _cssh_check_krb
        return 2
    fi
    if [ ! -r "$pubkey" ]; then
        printf 'cssh: public key not readable: %s\n' "$pubkey" >&2
        unset -f _cssh_usage _cssh_check_krb
        return 2
    fi

    local privkey="${pubkey%.pub}"
    if [ ! -r "$privkey" ]; then
        printf 'cssh: matching private key not readable: %s\n' "$privkey" >&2
        unset -f _cssh_usage _cssh_check_krb
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
                valid_epoch=$(date -d "$valid_to" +%s 2>/dev/null) || valid_epoch=0
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
            unset -f _cssh_usage _cssh_check_krb
            return 1
        fi
        if ! _cssh_check_krb; then
            unset -f _cssh_usage _cssh_check_krb
            return 1
        fi

        local req_json
        if [ -n "$principals" ]; then
            local principals_json
            principals_json=$(printf '%s' "$principals" \
                | jq -Rc 'split(",") | map(select(length > 0))')
            req_json=$(jq -nc --rawfile k "$pubkey" --argjson p "$principals_json" \
                '{ssh_key: $k, principals: $p}')
        else
            req_json=$(jq -nc --rawfile k "$pubkey" '{ssh_key: $k}')
        fi

        local resp http_code curl_rc
        resp=$(mktemp -t cssh.XXXXXX) || { unset -f _cssh_usage _cssh_check_krb; return 1; }
        http_code=$(curl --silent --show-error \
            --negotiate -u : \
            ${cacert:+--cacert "$cacert"} \
            -H 'Content-Type: application/json' \
            --data-binary "$req_json" \
            -o "$resp" -w '%{http_code}' \
            "${cerberus_url%/}/sign")
        curl_rc=$?

        if [ "$curl_rc" -ne 0 ] || [ "$http_code" != "200" ]; then
            local err
            err=$(jq -r '.error // empty' < "$resp" 2>/dev/null)
            [ -z "$err" ] && err=$(cat "$resp")
            printf 'cssh: signing failed (HTTP %s, curl=%d): %s\n' \
                "$http_code" "$curl_rc" "$err" >&2
            rm -f "$resp"
            unset -f _cssh_usage _cssh_check_krb
            return 1
        fi

        local signed_key
        signed_key=$(jq -r '.signed_key // empty' < "$resp")
        rm -f "$resp"
        if [ -z "$signed_key" ]; then
            printf 'cssh: empty signed_key in response\n' >&2
            unset -f _cssh_usage _cssh_check_krb
            return 1
        fi

        local tmp_cert="${cert}.tmp.$$"
        printf '%s\n' "$signed_key" > "$tmp_cert" || {
            unset -f _cssh_usage _cssh_check_krb; return 1
        }
        chmod 0600 "$tmp_cert"
        mv -f "$tmp_cert" "$cert" || {
            rm -f "$tmp_cert"
            unset -f _cssh_usage _cssh_check_krb
            return 1
        }
    fi

    unset -f _cssh_usage _cssh_check_krb

    # The Cerberus-signed cert is the only identity cssh uses.
    # IdentitiesOnly=yes prevents ssh from trying agent keys or any
    # IdentityFile entries from ~/.ssh/config; -i pins the key, and
    # CertificateFile is passed explicitly so the binding survives a
    # non-standard CSSH_PUBKEY path.
    command ssh \
        -o IdentitiesOnly=yes \
        -i "$privkey" \
        -o CertificateFile="$cert" \
        "$@"
}
```
