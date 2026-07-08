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

---

## Usage

```sh
kinit                                   # once per ticket lifetime
cssh user@host                          # signs (or reuses) cert, then ssh's
cssh --principals root user@host        # request a specific principal set
cssh --force user@host                  # re-sign even if cached cert is valid
cssh --pubkey ~/.ssh/id_rsa.pub host    # sign a non-default key
cssh --cacert /path/to/ca.pem user@host # trust a private CA for the API's TLS
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

If a cached cert seems wrong, the safest reset is:

```sh
rm -f ~/.ssh/id_ed25519-cert.pub
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

Set the site endpoint once for all users by editing the marked block at the top
of the installed file, or by exporting it globally (e.g. in the same
`/etc/profile.d/cssh.sh` or a companion `/etc/profile.d/cerberus-env.sh`):

```sh
export CERBERUS_URL=https://cerberus.example.com:8443
export CERBERUS_CACERT=/etc/pki/ca-trust/source/anchors/cerberus-ca.pem
```

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
