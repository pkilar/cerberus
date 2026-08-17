# Debian / Ubuntu packaging

A `debhelper` multi-binary source package that mirrors the RPM packaging in
[`../rpm/`](../rpm/). Like the Arch packaging, it reuses the generic assets from
the tree (the `run-enclave.sh` wrapper, the `Dockerfile`, `config-example.yaml`,
and the two sysconfig env files); only the systemd units and the packaging
metadata are Debian-specific.

## Packages produced

| Package               | Contents                                                                       | Architecture |
| --------------------- | ------------------------------------------------------------------------------ | ------------ |
| `cerberus-api`        | `ssh-cert-api` binary, systemd unit, `config.yaml.example` (in `/usr/share`), sysusers/tmpfiles  | amd64/arm64  |
| `cerberus-signer`     | `ssh-cert-signer` binary, systemd unit, `run-enclave.sh`, `Dockerfile`         | amd64/arm64  |
| `cerberus-vsock-watch`| VSOCK-connect detective control (`docs/vsock-connect-detection.md`): binary, systemd unit, auditd rule, sysusers | amd64/arm64  |
| `cerberus-client`     | the `cssh` shell wrapper (`/etc/profile.d/`)                                    | all          |
| `cerberus-signer-eif` | **opt-in**, prebuilt EIF — carries per-deployment CA key material              | amd64/arm64  |

## Build

```sh
# Prerequisites: build-essential debhelper dpkg-dev fakeroot, plus Go >= 1.26 on
# PATH (newer than the distro golang-go — use the golang:1.26 image or a manual
# toolchain install).
./packaging/debian/build-deb.sh
# → packages land in ./debbuild/*.deb

# Opt-in: also build cerberus-signer-eif from a prebuilt EIF
./packaging/debian/build-deb.sh --eif ssh-cert-signer/ssh-cert-signer-amd64.eif

sudo apt install ./debbuild/cerberus-client_*.deb   # or dpkg -i + apt -f install
```

`build-deb.sh` stages a source snapshot from the working tree and pins the
`debian/changelog` version from the top-level `VERSION` file. It uses the
`3.0 (native)` source format, so there is no separate upstream tarball to manage
— convenient for local/in-house builds. (Switch to `3.0 (quilt)` if you ever
upload to a Debian archive.)

## Layout conventions (vs. the RPM)

| Item                 | RPM path                          | Debian path                        |
| -------------------- | --------------------------------- | ---------------------------------- |
| systemd units        | `/usr/lib/systemd/system`         | `/lib/systemd/system` (dh default) |
| service env files    | `/etc/sysconfig/cerberus-*`       | `/etc/default/cerberus-*`          |
| enclave wrapper      | `/usr/libexec/cerberus/`          | `/usr/lib/cerberus/`               |
| system user + logdir | `useradd` + `install -d` scriptlet | `sysusers.d` + `tmpfiles.d`        |
| config-noreplace     | `%config(noreplace)`              | dpkg conffiles (automatic for `/etc`) |

Files under `/etc` (the env files, `cssh.sh`,
`cerberus-env.sh`) are automatically dpkg **conffiles**: operator edits are
preserved (dpkg prompts / saves `.dpkg-dist`), and an unmodified file is updated
on upgrade. `cssh.sh` is program code shipped as a conffile so fixes still apply
when it is unmodified; site config lives in `cerberus-env.sh`.

The services are installed **without being enabled or started**
(`dh_installsystemd --no-enable --no-start`) because they need site config and a
Nitro host. The `cerberus` user and `/var/log/cerberus` are created by
`systemd-sysusers`/`systemd-tmpfiles` (debhelper 13 wires these into the
`postinst`). Requires debhelper >= 13.6 (Debian 12 / Ubuntu 22.04+).

## Security note (EIF)

Like the RPM's `cerberus-signer-eif`, the opt-in EIF package bakes in the
KMS-encrypted CA private key and pins a deployment-specific PCR0. It is
per-deployment and per-architecture — distribute it only over an
operator-controlled channel, never a shared or public repository.
