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
- An ed25519 keypair at `~/.ssh/id_ed25519` (override with `CSSH_PUBKEY`). If you
  don't have one, `cssh` generates it for you on first use (disable with
  `CSSH_AUTOGEN=0`).
- The Cerberus API host's CA must be trusted by curl, either via the system
  trust store or by setting `CERBERUS_CACERT` to a CA bundle.

---

## Setup

Install `cssh` (see [Installing](#installing)), then export the Cerberus URL
once. The cacert is only needed if the API uses a private CA that isn't in your
system trust store.

```sh
export CERBERUS_URL=https://cerberus.example.com:8443
export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem
```

| Variable              | Default                 | Purpose                                                         |
| --------------------- | ----------------------- | --------------------------------------------------------------- |
| `CERBERUS_URL`        | *(required)*            | Base URL of the signing API. `/sign` is appended.               |
| `CERBERUS_CACERT`     | system trust            | CA bundle to trust for the API's TLS cert.                      |
| `CSSH_PUBKEY`         | `~/.ssh/id_ed25519.pub` | Public key to sign. The matching private key must exist.        |
| `CSSH_REFRESH_BEFORE` | `300`                   | Re-sign if cert expires within this many seconds.               |
| `CSSH_PRINCIPALS`     | *(unset)*               | Comma-separated principals to request. If unset, `cssh` requests the destination's login user, resolved via `ssh -G` (falling back to your local login name). |
| `CSSH_AUTOGEN`        | `1` (on)                | Auto-generate a passphraseless ed25519 keypair when the key is missing. Set `0`/`false`/`no`/`off` to disable and error instead. |
| `CSSH_AUTH`           | `kerberos`              | Authentication method: `kerberos` (SPNEGO) or `oidc` (device flow). See [OIDC authentication](#oidc-authentication-device-flow). |

---

## OIDC authentication (device flow)

By default `cssh` authenticates to the API with your Kerberos ticket. If your
Cerberus deployment has OIDC enabled (server-side `oauth:` block), users
**without Kerberos** can authenticate with an OIDC identity provider instead,
via the OAuth 2.0 Device Authorization Grant (RFC 8628).

Point `cssh` at your issuer and client, then opt in with `CSSH_AUTH=oidc` (or
`--oauth` per call):

```sh
export CSSH_AUTH=oidc
export CSSH_OIDC_ISSUER=https://idp.example.com
export CSSH_OIDC_CLIENT_ID=cerberus-cssh
cssh user@host
```

The first sign triggers the device flow:

```
cssh: to authenticate, open this URL in a browser:

    https://idp.example.com/device

and enter the code:  WXYZ-1234

cssh: waiting for authorization (Ctrl-C to abort)...
```

Approve in the browser and `cssh` obtains a bearer token, caches it at
`~/.cache/cerberus/oidc-token.json` (mode `0600`), and completes the request.
Subsequent calls reuse the cached token and — when the IdP grants
`offline_access` — silently refresh it, so you approve **once** and then
`ssh`/`scp`/`rsync` for as long as the refresh token lives. Authorization is by
the token's groups claim mapped to the server's `oidc_groups:`; requested
principals work exactly as with Kerberos.

| Variable                  | Default                                      | Purpose                                                        |
| ------------------------- | -------------------------------------------- | -------------------------------------------------------------- |
| `CSSH_AUTH`               | `kerberos`                                   | `oidc` selects the device flow (or pass `--oauth` per call).   |
| `CSSH_OIDC_ISSUER`        | *(required for OIDC)*                         | OIDC issuer URL; its discovery document is fetched.            |
| `CSSH_OIDC_CLIENT_ID`     | *(required for OIDC)*                         | Public client ID registered for the device grant.             |
| `CSSH_OIDC_SCOPE`         | `openid profile email groups offline_access` | Scopes to request (`offline_access` enables silent refresh).   |
| `CSSH_OIDC_AUDIENCE`      | *(unset)*                                     | Requested token audience; set it if your IdP needs it to mint an access token carrying the API's `aud` (e.g. Auth0). |
| `CSSH_OIDC_TOKEN`         | `access`                                      | Which token to send: `access` or `id`.                        |
| `CSSH_OIDC_CACERT`        | system trust                                  | CA bundle to trust for the IdP's TLS.                          |
| `CSSH_OIDC_CLIENT_SECRET` | *(unset)*                                     | Client secret, if the IdP requires one.                       |
| `CSSH_OIDC_OPEN`          | off                                           | Try to open the verification URL in a browser (`xdg-open`/`open`). |

The cached token file holds the access token and (if issued) a long-lived
refresh token — protect it like any credential. Delete it to force a fresh
browser login: `rm ~/.cache/cerberus/oidc-token.json`.

---

## Usage

```sh
kinit                                   # once per ticket lifetime
cssh user@host                          # signs (or reuses) cert, then ssh's
cssh --principals root user@host        # request a specific principal set
cssh --force user@host                  # re-sign even if cached cert is valid
cssh --pubkey ~/.ssh/id_rsa.pub host    # sign a non-default key
cssh --cacert /path/to/ca.pem user@host # trust a private CA for the API's TLS
cssh --sign-only                        # refresh the cert silently; don't connect
cssh --sign-only --verbose              # refresh, then print the cert path
cssh --sign-only user@host              # refresh a cert for host's login user
cssh --sign-only --all-principals       # cert for every principal in your group
cssh --self --sign-only                 # fetch a cert for your own identity; don't connect
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

An explicit sign also writes `<privkey>-cert.requested` — one line with the cert's serial and the principal set
you asked for — which `cssh` uses for its cache decision (see **Cache** below). It is safe to delete; the next
sign recreates it.

---

## Pre-authenticating (scp, rsync, sftp, git…)

`cssh --sign-only` fetches or refreshes the certificate and **exits without
connecting**. It is silent by default; add `--verbose` to print the cert path
(e.g. `cert=$(cssh --sign-only --verbose)`). Use it to authenticate once and
then run other OpenSSH-based tools:

```sh
cssh --sign-only                 # refresh ~/.ssh/id_ed25519-cert.pub
scp bigfile user@host:/tmp/      # picks up the adjacent cert automatically
rsync -avz dir/ user@host:/dest/ # rsync runs ssh, which loads the cert
sftp user@host
git clone ssh://git@host/repo.git
```

Because the cert is written next to the private key as `<privkey>-cert.pub`,
OpenSSH loads it automatically **when the tool uses that key as a default
identity** — i.e. the default `~/.ssh/id_ed25519` (or another default name such
as `id_rsa`, `id_ecdsa`). The common case needs no extra flags.

If you signed a **non-default** key (via `CSSH_PUBKEY`/`--pubkey`), or your
`~/.ssh/config` pins a different identity, point the tool at the key explicitly —
OpenSSH then loads the adjacent `<key>-cert.pub`:

```sh
cssh --sign-only --pubkey ~/.ssh/work_key.pub
scp -i ~/.ssh/work_key file user@host:
rsync -e 'ssh -i ~/.ssh/work_key' dir/ user@host:/dest/
```

To force the Cerberus cert and nothing else (mirroring how `cssh` itself
connects — no agent keys, no other identities), pass the same options `cssh`
uses:

```sh
scp -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 \
    -o CertificateFile=~/.ssh/id_ed25519-cert.pub file user@host:
```

`--sign-only` still honors caching: it re-signs only when the cert is missing or
within `CSSH_REFRESH_BEFORE` of expiry, so calling it before each command is
cheap. `HOST` is optional in this mode — supply one only to resolve the login
principal from `ssh -G`, or pass `--principals` to mint a cert for the login
names you'll use across tools.

### `--all-principals`

If a single Cerberus group grants you several principals, `--all-principals`
mints one cert covering **all** of them, so you can act as any of those logins
without re-signing per principal:

```sh
cssh --sign-only --all-principals   # e.g. a cert valid for root, ec2-user, deploy
scp file user@host:                 # use whichever principal the target expects
ssh -i ~/.ssh/id_ed25519 root@host2
```

- The server expands the **first group (alphabetically)** you belong to into its
  full `allowed_principals` set — you don't enumerate them.
- It **requires `--sign-only`** (a broad, multi-identity cert is for staging, not
  a single interactive session) and is **mutually exclusive** with
  `--principals`.
- If that first group grants `allowed_principals: ["*"]` (any principal), the
  request is **refused** — an unbounded set can't be enumerated into a cert.
  Request explicit `--principals` instead.
- The broad cert is cached on expiry alone (there's no fixed requested set to
  compare); entitlement changes are picked up on the next re-sign (expiry or
  `--force`).

### Connecting as yourself, and `--self`

If the server has `self_principal` enabled for your realm, you can get a cert for
**your own identity** — the short uid of your Kerberos principal
(`jsmith@FOO.COM` → `jsmith`) — without being enumerated in any group. Two ways:

```sh
cssh jsmith@host             # connect as yourself — accepted implicitly, no flag
cssh host                    # same, when the login equals your Kerberos uid
cssh --self --sign-only      # explicitly fetch your own cert; don't connect
```

- **Just connect.** A normal `cssh jsmith@host` requests principal `jsmith`; the
  server accepts it via the self path because it equals your authenticated uid —
  no group needed, no flag needed. `cssh host` works the same way when the
  resolved login matches your uid (otherwise it requests that other login, which
  still needs a group).
- **`--self`** explicitly fetches a cert for your own uid and **requires
  `--sign-only`** (it means "hand me my cert", not "connect"). It is mutually
  exclusive with `--principals` and `--all-principals`.
- **Combining with `--principals`.** Your own uid can also ride along inside an
  explicit `--principals` list: `cssh --principals root,jsmith --sign-only`
  (as `jsmith`) succeeds as long as some single group grants `root`, even if
  that group doesn't list `jsmith` itself — `self_principal` supplies your own
  uid for free. A principal that is neither your own uid nor covered by a
  single group is still refused.
- Either way the server enforces `self_principal`'s realm allowlist and
  operator-configured denylist (there is no hardcoded `root` floor — self
  issuance for `root` is allowed by default, since this path is how Cerberus
  replaces static root SSH keys), and the issued cert only lets you into
  accounts the server maps to your principal (the account named after your
  uid, or an `AuthorizedPrincipalsFile` entry).

---

## Behavior

- **Key auto-generation.** If **neither** half of the key exists, `cssh`
  generates a passphraseless ed25519 keypair at the target path (creating
  `~/.ssh` as `0700`, the key as `0600`) before signing. A half-present key (one
  file missing) is left untouched and surfaces as an error rather than being
  clobbered. Disable with `CSSH_AUTOGEN=0` to require a pre-existing key.
- **Cache.** A signed cert is reused only when it still covers the request:
  the set of principals it was **requested for** matches the one being
  requested now, its `Valid: from … to …` window doesn't close within
  `CSSH_REFRESH_BEFORE` seconds, **and** the server's authorization policy has
  not changed since it was issued. After every sign `cssh` records
  `<serial> <policy-fingerprint> <requested-set>` in `<privkey>-cert.requested`
  (`-` stands for an all-principals/self request or a server that sent no
  fingerprint). When the serial matches the cached cert, that record is what
  the request is compared against; then `cssh` asks the server for its current
  fingerprint (`GET /policy` — authenticated, cheap, no enclave work, not
  rate-limited) and re-signs if the recorded one is missing or different. The
  probe never prompts: without a Kerberos ticket or a cached OIDC token, or
  against a server that predates `/policy`, it is skipped and the cert is
  reused as before. Without a matching record (a cert signed by an older
  `cssh`, or one you copied in by hand) it falls back to comparing against the
  cert's own principal list and re-signs once to record a fingerprint. Any
  parse failure re-signs rather than reuses.
  A pre-sidecar `cssh` (before this feature) has no such record and re-signs
  on every call once the server maps the requested name — upgrade the
  client before enabling mapping server-side.
- **Principal switching.** A cert issued for `principalA` cannot authenticate
  as `principalB`, so `cssh alice@host` then `cssh deploy@host` (both in one
  Cerberus group) transparently re-signs on the switch instead of reusing
  alice's cert. The cert's principals may legitimately differ from what you
  requested: a group can map a requested name to a role principal
  (`root: global-root` in `allowed_principals`), in which case `cssh root@host`
  yields a cert whose principal is `global-root` — that is what the sidecar
  above is for. A server-side mapping change is picked up on your next `cssh`
  call (the policy fingerprint changes), or immediately with `--force`.
- **Principal selection.** With `CSSH_PRINCIPALS`/`--principals` unset, `cssh`
  asks `ssh -G <args>` for the login user it would use for the destination —
  covering `user@host`, `-l user`, and `ssh_config` `User` directives — and
  requests a cert for that principal. If `ssh -G` yields nothing it falls back
  to your local login name.
- **Identity locking.** `cssh` invokes ssh with
  `-o IdentitiesOnly=yes -o PreferredAuthentications=publickey -i <privkey>
  -o CertificateFile=<cert>`. This disables agent forwarding of unrelated keys
  and any `IdentityFile` entries from `~/.ssh/config`, so only the Cerberus cert
  can authenticate the connection.
- **TGT check.** Before calling the signing API, `cssh` runs a robust check
  on the Kerberos cache and reports the actual failure mode (no cache,
  expired TGT, principal mismatch) so the user knows whether to `kinit`
  or something more.
- **Atomic write.** The signed cert is written to a `mktemp` file on the
  destination filesystem, validated with `ssh-keygen -L` (an unparseable
  response is discarded, never published), then `mv -f`'d into place — so a
  partial or malformed cert never lands on disk and breaks future ssh runs.

---

## Troubleshooting

| Symptom                                                     | Likely cause                                                                                           |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `cssh: no Kerberos credential cache (run: kinit)`           | No cache file. Run `kinit`.                                                                            |
| `cssh: TGT for X@REALM is expired (...) — run: kinit`       | Cache exists but the TGT has expired. Re-`kinit`.                                                      |
| `cssh: signing failed (HTTP 403): Not authorized for ...`   | The principal you requested isn't in any group you belong to in the Cerberus config.                   |
| `cssh: signing failed (HTTP 401): ...`                      | SPNEGO auth was rejected. Common causes: keytab kvno mismatch with the KDC, clock skew >5 min, no TGT. |
| sshd rejects with `Certificate option "permit-pty" corrupt` | Server-side config bug — a flag-style cert extension was given a non-empty value. Fix the YAML.        |
| ssh asks for a password                                     | The cert was issued for a different principal than the SSH login name. Use `--principals <login>`.     |
| `cssh: OIDC auth needs CSSH_OIDC_ISSUER and CSSH_OIDC_CLIENT_ID` | `CSSH_AUTH=oidc`/`--oauth` but the issuer/client aren't set. Set them (see [OIDC authentication](#oidc-authentication-device-flow)). |
| `cssh: issuer advertises no device_authorization_endpoint`  | The IdP's discovery doc lacks device-grant support, or the client isn't allowed to use it. Enable the device flow for the client. |
| `cssh: device code expired ...`                             | You didn't approve in the browser in time. Run `cssh --oauth` again.                                   |
| OIDC user gets `signing failed (HTTP 403)`                  | The token's groups claim matches no `oidc_groups:` group for the principal requested.                  |

If a cached cert seems wrong, the safest reset is:

```sh
rm -f ~/.ssh/id_ed25519-cert.pub ~/.ssh/id_ed25519-cert.requested
cssh --force user@host
```

---

## Installing

The canonical script lives at
[`packaging/profile.d/cssh.sh`](../packaging/profile.d/cssh.sh). It only
*defines* the `cssh` function — sourcing it runs nothing — so it is safe to load
from bash, zsh, or dash/sh.

### System-wide (`/etc/profile.d`)

```sh
sudo install -m 0644 packaging/profile.d/cssh.sh /etc/profile.d/cssh.sh
```

`/etc/profile.d/*.sh` is sourced for **login** shells:

- **bash** picks it up via `/etc/profile`. To also cover non-login interactive
  bash (new terminal tabs), source it from `/etc/bashrc` (RHEL / Fedora /
  Amazon Linux) or `/etc/bash.bashrc` (Debian / Ubuntu):
  ```sh
  [ -r /etc/profile.d/cssh.sh ] && . /etc/profile.d/cssh.sh
  ```
- **zsh** reads `/etc/profile.d/*.sh` **only** if the system's zsh startup
  sources `/etc/profile`. Debian / Ubuntu / Arch do this via `/etc/zprofile`
  (`emulate sh -c 'source /etc/profile'`). On RHEL / Fedora / Amazon Linux, add
  the same one-liner to `/etc/zshrc` (or `/etc/zsh/zshrc`).

Set the site endpoint once for all users in `/etc/profile.d/cerberus-env.sh`
(shipped alongside `cssh.sh` by the `cerberus-client` package). That file is
`%config(noreplace)`, so your edits survive package upgrades — whereas `cssh.sh`
itself is plain code that is replaced on upgrade, so fixes always apply. Don't
put site config in `cssh.sh`.

```sh
# /etc/profile.d/cerberus-env.sh
export CERBERUS_URL=https://cerberus.example.com:8443
export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem
```

If you install `cssh.sh` by hand (not via the package), export the same
variables from wherever you manage environment — your own
`/etc/profile.d/cerberus-env.sh`, `~/.bashrc`/`~/.zshrc`, or config management.

### Per-user

Source the script from your rc file (works in both shells):

```sh
echo '. /etc/profile.d/cssh.sh' >> ~/.bashrc    # or ~/.zshrc
```

or, if you are not installing it system-wide, drop `cssh.sh` anywhere and source
that path instead.

### Notes on shell portability

- The script is quoted so it behaves identically under bash and **native** zsh.
  In particular, the optional `--cacert` argument is passed via an explicit
  branch rather than the `${cacert:+--cacert "$cacert"}` idiom, which
  word-splits in bash but **not** in native zsh (there curl would receive
  `--cacert <path>` as a single mangled argument).
- Certificate freshness is computed with GNU `date -d`, falling back to BSD/macOS
  `date -j -f`; if neither can parse the timestamp, `cssh` re-signs rather than
  trust an unparseable window.
