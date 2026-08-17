# Arch Linux packaging

A `makepkg` split package that mirrors the RPM packaging in [`../rpm/`](../rpm/).
The build reuses the same generic assets from the tree (the `run-enclave.sh`
wrapper, the `Dockerfile`, `config-example.yaml`, and the two sysconfig env
files); only the systemd units and the packaging metadata are Arch-specific.

## Packages produced

| Package               | Contents                                                                 | arch          |
| --------------------- | ------------------------------------------------------------------------ | ------------- |
| `cerberus-api`        | `ssh-cert-api` binary, systemd unit, `config.yaml.example` (in `/usr/share`), sysusers/tmpfiles | x86_64/aarch64 |
| `cerberus-signer`     | `ssh-cert-signer` binary, systemd unit, `run-enclave.sh`, `Dockerfile`   | x86_64/aarch64 |
| `cerberus-vsock-watch`| VSOCK-connect detective control (`docs/vsock-connect-detection.md`): binary, systemd unit, auditd rule, sysusers | x86_64/aarch64 |
| `cerberus-client`     | the `cssh` shell wrapper (`/etc/profile.d/`)                             | any           |
| `cerberus-signer-eif` | **opt-in**, prebuilt EIF — carries per-deployment CA key material         | x86_64/aarch64 |

## Build

```sh
# From the repo root, as a regular user (makepkg refuses to run as root):
./packaging/arch/build-arch.sh
# → packages land in ./archbuild/*.pkg.tar.zst

# Opt-in: also bundle a prebuilt EIF into cerberus-signer-eif
./packaging/arch/build-arch.sh --eif ssh-cert-signer/ssh-cert-signer-amd64.eif
```

`build-arch.sh` stages a source tarball from the working tree (the same snapshot
`build-rpm.sh` produces), pins `pkgver` from the top-level `VERSION` file, and
runs `makepkg` in a throwaway `./archbuild/` directory. Prerequisites:
`pacman -S --needed base-devel go`.

Install a built package with `sudo pacman -U ./archbuild/cerberus-client-*.pkg.tar.zst`.

## Layout conventions (vs. the RPM)

The Arch packages follow Arch/systemd conventions, which differ from the RPM in
a few places:

| Item                 | RPM path                          | Arch path                          |
| -------------------- | --------------------------------- | ---------------------------------- |
| systemd units        | `/usr/lib/systemd/system`         | `/usr/lib/systemd/system` (same)   |
| service env files    | `/etc/sysconfig/cerberus-*`       | `/etc/conf.d/cerberus-*`           |
| enclave wrapper      | `/usr/libexec/cerberus/`          | `/usr/lib/cerberus/`               |
| system user + logdir | `useradd` + `install -d` scriptlet | `sysusers.d` + `tmpfiles.d`        |
| config-noreplace     | `%config(noreplace)`              | `backup=()`                        |

The `cerberus` system user and `/var/log/cerberus` are created declaratively by
`systemd-sysusers`/`systemd-tmpfiles`, which pacman runs through its shipped
hooks — no imperative `post_install` user creation. `.install` scriptlets only
print operator guidance; `daemon-reload` is handled by systemd's pacman hook.

## Security note (EIF)

Like the RPM's `cerberus-signer-eif`, the opt-in EIF package bakes in the
KMS-encrypted CA private key and pins a deployment-specific PCR0. It is
per-deployment and per-architecture — distribute it only over an
operator-controlled channel, never a shared or public repository.
