%global goipath     cerberus
%global debug_package %{nil}

Name:           cerberus
Version:        %{rpm_version}
Release:        1%{?dist}
Summary:        SSH Certificate Authority for AWS Nitro Enclaves

License:        MIT
URL:            https://github.com/pkilar/cerberus
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.26
BuildRequires:  make
BuildRequires:  systemd-rpm-macros

ExclusiveArch:  x86_64 aarch64

%description
Cerberus is an SSH Certificate Authority that runs inside an AWS Nitro Enclave.
The CA private key is KMS-encrypted and only decrypted inside the enclave,
ensuring the key never exists in plaintext on the host.

Supported distributions: Amazon Linux 2023, Amazon Linux 2, Fedora, RHEL 8+.

# ---------------------------------------------------------------------------
# Subpackage: cerberus-api
# ---------------------------------------------------------------------------
%package api
Summary:        Cerberus SSH Certificate API service
Requires:       krb5-libs
Requires(pre):  shadow-utils
%{?systemd_requires}

%description api
The HTTPS API service for Cerberus. Runs on the EC2 host and provides
Kerberos/SPNEGO authenticated endpoints for SSH certificate signing.
Forwards signing requests to the signer running inside a Nitro Enclave
over VSOCK and performs the attested KMS Decrypt on the enclave's behalf
(the enclave has no network).

# ---------------------------------------------------------------------------
# Subpackage: cerberus-signer
# ---------------------------------------------------------------------------
%package signer
Summary:        Cerberus SSH Certificate Signer (Nitro Enclave)
Requires:       aws-nitro-enclaves-cli
%{?systemd_requires}

%description signer
The SSH certificate signer for Cerberus. Packaged as a Nitro Enclave Image
File (EIF) that runs inside an AWS Nitro Enclave. Receives the host-mediated,
attested KMS Decrypt result over VSOCK (the enclave has no network of its own),
decrypts the CMS envelope to install the in-memory CA signer, and signs SSH
certificates received over VSOCK.

# ---------------------------------------------------------------------------
# Subpackage: cerberus-client
#
# End-user workstation helper: the `cssh` shell function (bash + zsh) installed
# to /etc/profile.d/. Pure shell, so it is noarch and independent of the API and
# signer services. Carries no key material and no server config.
# ---------------------------------------------------------------------------
%package client
Summary:        Cerberus SSH client helper (cssh) for bash and zsh
BuildArch:      noarch
Requires:       openssh-clients
Requires:       curl
Requires:       jq
Requires:       krb5-workstation

%description client
The `cssh` shell wrapper for end-user workstations. Using the caller's Kerberos
credentials (SPNEGO), it fetches a short-lived OpenSSH user certificate from the
Cerberus signing API, caches it next to the matching private key as
<key>-cert.pub, and hands off to ssh(1), re-signing only when the cached cert is
missing or about to expire.

Installed as /etc/profile.d/cssh.sh; it defines the `cssh` function for login
shells (bash directly; zsh where the system sources /etc/profile). Set the site
endpoint with CERBERUS_URL (and CERBERUS_CACERT for a private CA). See the cssh
howto in %{_docdir}/%{name}-client/cssh.md.

# ---------------------------------------------------------------------------
# Subpackage: cerberus-signer-eif  (OPTIONAL, opt-in)
#
# Bundles a prebuilt Enclave Image File so a deployment can ship as a single
# artifact. Produced ONLY when the build is invoked with
#   --define "eif_file /abs/path/to/ssh-cert-signer-<arch>.eif"
# (the build-rpm.sh --eif flag). It is NOT part of a default build.
#
# SECURITY: the EIF bakes in the KMS-encrypted CA private key (ca_key.enc) and
# the PCR0-pinned CA public key (ca_key.pub), so this package carries
# per-deployment CA key material through the RPM channel and pins a
# deployment-specific PCR0. It is per-deployment and per-architecture — NOT a
# redistributable artifact. Publish it only to an operator-controlled channel,
# never to a shared or public repository.
# ---------------------------------------------------------------------------
%if %{defined eif_file}
%package signer-eif
Summary:        Cerberus signer Enclave Image File (per-deployment; carries CA key material)
Requires:       cerberus-signer = %{version}-%{release}

%description signer-eif
Prebuilt Nitro Enclave Image File for the Cerberus signer, installed at
%{_datadir}/cerberus/ssh-cert-signer.eif. OPT-IN and per-deployment: the EIF
bakes in the KMS-encrypted CA private key and the PCR0-pinned CA public key, so
this package carries CA key material and pins a deployment-specific PCR0. It is
per-architecture and must be distributed only over an operator-controlled
channel, never a shared or public repository. Built only when the RPM build is
invoked with --define "eif_file <path>" (note the space, not '='), normally via
build-rpm.sh --eif.
%endif

# ---------------------------------------------------------------------------
# prep / build / install
# ---------------------------------------------------------------------------
%prep
%setup -q

%build
# Detect the rpm build architecture and map to Go architecture.
%ifarch x86_64
    export GOARCH=amd64
%endif
%ifarch aarch64
    export GOARCH=arm64
%endif
export GOOS=linux
export CGO_ENABLED=0

# Build the API binary.
cd ssh-cert-api
go build -ldflags="-s -w" -o ssh-cert-api ./cmd/ssh-cert-api
cd ..

# Build the signer binary.
cd ssh-cert-signer
go build -ldflags="-s -w" -o ssh-cert-signer ./cmd/ssh-cert-signer
cd ..

%install
rm -rf %{buildroot}

# --- cerberus-api ---
install -D -m 0755 ssh-cert-api/ssh-cert-api \
    %{buildroot}%{_bindir}/ssh-cert-api

install -D -m 0644 packaging/rpm/cerberus-api.service \
    %{buildroot}%{_unitdir}/cerberus-api.service

install -D -m 0640 packaging/rpm/cerberus-api.sysconfig \
    %{buildroot}%{_sysconfdir}/sysconfig/cerberus-api

install -D -m 0640 ssh-cert-api/configs/config-example.yaml \
    %{buildroot}%{_sysconfdir}/cerberus/config.yaml.example

install -d -m 0750 %{buildroot}%{_localstatedir}/log/cerberus

# --- cerberus-signer ---
install -D -m 0755 ssh-cert-signer/ssh-cert-signer \
    %{buildroot}%{_bindir}/ssh-cert-signer

install -D -m 0644 packaging/rpm/cerberus-signer.service \
    %{buildroot}%{_unitdir}/cerberus-signer.service

install -D -m 0640 packaging/rpm/cerberus-signer.sysconfig \
    %{buildroot}%{_sysconfdir}/sysconfig/cerberus-signer

install -D -m 0755 packaging/rpm/run-enclave.sh \
    %{buildroot}%{_libexecdir}/cerberus/run-enclave.sh

install -D -m 0644 ssh-cert-signer/Dockerfile \
    %{buildroot}%{_datadir}/cerberus/Dockerfile

# Stage the EIF directory. By default it is left EMPTY: the Enclave Image File
# bakes in the KMS-encrypted CA key (Dockerfile COPYs ca_key.enc) + PCR0 pin, so
# it is per-deployment and is NOT shipped in the default cerberus-signer RPM.
# Operators normally build the EIF separately and drop it here post-install
# (see docs/RUNBOOK.md, Post-Install Setup). The OPTIONAL cerberus-signer-eif
# subpackage (built only with --define "eif_file <path>") bundles a prebuilt EIF
# into this directory for single-artifact, per-deployment installs.
install -d -m 0755 %{buildroot}%{_datadir}/cerberus

%if %{defined eif_file}
install -D -m 0644 %{eif_file} \
    %{buildroot}%{_datadir}/cerberus/ssh-cert-signer.eif
%endif

# --- cerberus-client ---
# cssh.sh is plain code (replaced on upgrade so fixes always apply); site config
# lives in the companion cerberus-env.sh, shipped %config(noreplace).
install -D -m 0644 packaging/profile.d/cssh.sh \
    %{buildroot}%{_sysconfdir}/profile.d/cssh.sh
install -D -m 0644 packaging/profile.d/cerberus-env.sh \
    %{buildroot}%{_sysconfdir}/profile.d/cerberus-env.sh

# ---------------------------------------------------------------------------
# cerberus-api scriptlets
# ---------------------------------------------------------------------------
%pre api
getent group cerberus >/dev/null || groupadd -r cerberus
getent passwd cerberus >/dev/null || \
    useradd -r -g cerberus -d /etc/cerberus -s /sbin/nologin \
    -c "Cerberus SSH CA" cerberus
exit 0

%post api
%systemd_post cerberus-api.service

%preun api
%systemd_preun cerberus-api.service

%postun api
%systemd_postun_with_restart cerberus-api.service

# ---------------------------------------------------------------------------
# cerberus-signer scriptlets
# ---------------------------------------------------------------------------
%post signer
%systemd_post cerberus-signer.service

%preun signer
%systemd_preun cerberus-signer.service

%postun signer
%systemd_postun_with_restart cerberus-signer.service

# ---------------------------------------------------------------------------
# File lists
# ---------------------------------------------------------------------------
%files api
%license LICENSE
%doc docs/RUNBOOK.md
%{_bindir}/ssh-cert-api
%{_unitdir}/cerberus-api.service
%config(noreplace) %attr(0640,root,cerberus) %{_sysconfdir}/sysconfig/cerberus-api
%config(noreplace) %attr(0640,root,cerberus) %{_sysconfdir}/cerberus/config.yaml.example
%dir %attr(0750,cerberus,cerberus) %{_localstatedir}/log/cerberus
# Ghost-declare the optional LDAP simple-bind password file so `rpm -V` flags
# accidentally world-readable rotations. The file is NOT shipped — operators
# create it (mode 0600) only if they configure an LDAP backend with
# bind.method=simple. If unused, the ghost entry is harmless.
%ghost %attr(0600,cerberus,cerberus) %config(noreplace) %{_sysconfdir}/cerberus/ldap.pw

%files signer
%license LICENSE
%{_bindir}/ssh-cert-signer
%{_unitdir}/cerberus-signer.service
%config(noreplace) %attr(0640,root,root) %{_sysconfdir}/sysconfig/cerberus-signer
%{_libexecdir}/cerberus/run-enclave.sh
%dir %{_datadir}/cerberus
%{_datadir}/cerberus/Dockerfile

%files client
%license LICENSE
%doc docs/cssh.md
# cssh.sh is plain code: NOT %config, so security/functionality fixes always
# apply on upgrade. Site config (CERBERUS_URL) lives in cerberus-env.sh, shipped
# %config(noreplace) so operator edits survive upgrades.
%{_sysconfdir}/profile.d/cssh.sh
%config(noreplace) %{_sysconfdir}/profile.d/cerberus-env.sh

%if %{defined eif_file}
%files signer-eif
%{_datadir}/cerberus/ssh-cert-signer.eif
%endif

# ---------------------------------------------------------------------------
# Changelog
# ---------------------------------------------------------------------------
%changelog
* Fri Jul 10 2026 Paul Kilar <pkilar@gmail.com> - 0.9.0-1
- LDAP backends can now discover servers via DNS SRV records (srv: block with
  tls_mode) and fail over across them per RFC 2782, in addition to a fixed
  url:.

* Thu Jul 09 2026 Paul Kilar <pkilar@gmail.com> - 0.8.0-1
- cssh OIDC device-code login (cerberus-client): cssh can now authenticate to
  the signing API with an OIDC identity provider instead of Kerberos, via the
  OAuth 2.0 Device Authorization Grant (RFC 8628). Opt in per-shell with
  CSSH_AUTH=oidc or per-call with --oauth; the Kerberos path is unchanged by
  default. cssh prints a verification URL + user code, polls for the token, and
  sends it as an Authorization: Bearer header to /sign.
- The token (and, when the IdP grants offline_access, a refresh token) is cached
  at ~/.cache/cerberus/oidc-token.json (mode 0600) and refreshed silently, so
  the browser step happens once and later ssh/scp/rsync calls reuse or renew the
  token without re-prompting. A rejected token (HTTP 401) is refreshed and the
  request retried once. New site config lives in cerberus-env.sh: CSSH_OIDC_ISSUER,
  CSSH_OIDC_CLIENT_ID, CSSH_OIDC_SCOPE, CSSH_OIDC_AUDIENCE, CSSH_OIDC_TOKEN,
  CSSH_OIDC_CACERT, CSSH_OIDC_CLIENT_SECRET, CSSH_OIDC_OPEN. See docs/cssh.md.
* Thu Jul 09 2026 Paul Kilar <pkilar@gmail.com> - 0.7.0-1
- OIDC bearer-token authentication (optional, opt-in via the new top-level
  oauth: config block): the API now accepts Authorization: Bearer <JWT> from an
  OIDC identity provider (Okta, Azure AD, Google, Keycloak, any OIDC IdP) as a
  second authentication method alongside Kerberos/SPNEGO. The middleware
  dispatches on the Authorization scheme (Negotiate -> Kerberos, Bearer ->
  OIDC); when oauth is disabled the service behaves exactly as before.
- Tokens are validated entirely offline: issuer discovery at startup fetches and
  caches the JWKS (refreshed on key rotation); every request verifies the JWT
  signature, iss, aud, and exp/nbf/iat with a configurable clock-skew leeway.
  Accepted signing algorithms are restricted to an asymmetric allowlist
  (default RS256); none and any HMAC HS* algorithm are rejected at config load
  and again at verification to defeat algorithm-confusion attacks.
- Authorization for OIDC users comes from the token's groups claim, matched
  against a new per-group oidc_groups: binding (parallel to ldap_groups:). The
  username_claim plus a configured synthetic realm form the Username@Realm
  identity used for the cert KeyID, audit logs, and rate limiting. A group has
  exactly one membership source: members, ldap_groups, or oidc_groups.
- Server-side only in this release: there is no cssh device flow yet; callers
  send a token obtained out-of-band. See docs/RUNBOOK.md (OIDC / OAuth Bearer
  Authentication) and docs/THREAT-MODEL.md (OIDC-1..OIDC-6).
* Wed Jul 08 2026 Paul Kilar <pkilar@gmail.com> - 0.6.0-1
- New cerberus-client subpackage (noarch): installs the cssh SSH wrapper to
  /etc/profile.d/cssh.sh. cssh fetches a short-lived OpenSSH user certificate
  from the signing API with the caller's Kerberos credentials, caches it, and
  hands off to ssh(1). Requires openssh-clients, curl, jq, krb5-workstation.
  cssh.sh is plain code (replaced on upgrade so fixes always apply); site config
  (CERBERUS_URL/CERBERUS_CACERT) lives in the companion /etc/profile.d/
  cerberus-env.sh, shipped %config(noreplace) so operator edits survive upgrades.
  cssh also supports --sign-only: fetch/refresh the certificate without opening
  an ssh connection (silent by default; --verbose prints the cert path), so scp,
  rsync, sftp, and git reuse the pre-authenticated cert. The cache is principal-aware: cssh compares the
  cached cert's principals against the requested set and re-signs on a switch
  (principalA -> principalB), not only on expiry. First-time users need no
  setup: cssh generates a passphraseless ed25519 keypair when the key is missing
  (CSSH_AUTOGEN=0 to disable; a half-present key is left untouched, not clobbered).
- All-principals expansion: a /sign request may set all_principals: true to mint
  a cert for every principal in the user's first (alphabetical) group, instead
  of enumerating them. The API expands that group's finite allowed_principals
  and refuses a "*"-granting group (an unbounded set can't be enumerated). The
  cssh client exposes it as `cssh --sign-only --all-principals` (sign-only gated,
  mutually exclusive with --principals).
- Self-service certificates: an opt-in self_principal config block lets an
  authenticated user obtain a cert for their own short uid (jsmith@FOO.COM ->
  "jsmith") without group membership, constrained by a realm allowlist and a
  denylist that always includes "root". Granted two ways: explicitly via
  `cssh --self --sign-only`, and implicitly when a normal connect
  (`cssh jsmith@host` / `cssh host`) requests exactly the caller's own uid — the
  server verifies the requested principal equals the authenticated user. See
  docs/RUNBOOK.md and the config example.
- cssh hardened for bash AND native zsh: the optional --cacert is now passed
  via an explicit branch instead of the ${cacert:+...} idiom, which word-splits
  in bash but NOT in native zsh (curl would otherwise get "--cacert <path>" as a
  single mangled argument, breaking TLS to a private-CA API). Re-adds
  CERBERUS_CACERT support (dropped in an earlier revision), adds a --cacert
  per-call flag, a BSD/macOS `date -j` fallback for cert-expiry parsing, and an
  `id -un` fallback when $USER is unset.
- CA key generation moved to a RAM-backed tmpfs working dir (make encrypt-ca-key
  uses /dev/shm) so the plaintext CA key never touches durable storage on the
  default Linux path; falls back to the working dir + shred where /dev/shm is
  unavailable (docs/THREAT-MODEL.md SC-6).
- Realm stripping for static members: optional strip_realms config lets a listed
  realm's @REALM suffix be dropped before the members: match, so members can be
  enumerated by bare short name. Per-realm scoped; LDAP routing unaffected.
* Thu Jul 02 2026 Paul Kilar <pkilar@gmail.com> - 0.5.0-1
- Optional, opt-in cerberus-signer-eif subpackage: bundles a prebuilt
  Enclave Image File at /usr/share/cerberus/ssh-cert-signer.eif so a
  deployment can ship as a single artifact. Built ONLY when the RPM
  build is invoked with --define "eif_file <path>" (build-rpm.sh --eif);
  a default build is unchanged and still produces only cerberus-api and
  cerberus-signer. SECURITY: the EIF bakes in the KMS-encrypted CA key
  and the PCR0-pinned public key, so this package carries per-deployment
  CA key material and is per-architecture — distribute it only over an
  operator-controlled channel, never a shared or public repository.
- CA-key protection guardrails in ssh-cert-signer/Makefile: make
  encrypt-ca-key now REFUSES to overwrite existing ca_key/ca_key.pub/
  ca_key.enc (regenerating mints a different CA and would force
  re-distributing the public key to every SSH server); make clean no
  longer deletes CA key material; a new make clean-ca-key removes it
  explicitly for a deliberate rotation.
- Hardened encrypt-ca-key: a failed KMS encrypt no longer leaves a
  0-byte ca_key.enc and shreds the plaintext — the plaintext CA key is
  preserved on failure. Plaintext is securely deleted with shred (falling
  back to rm), and require-ca-files rejects an empty ca_key.enc.
* Wed Jul 01 2026 Paul Kilar <pkilar@gmail.com> - 0.4.0-1
- Host-mediated, attested KMS Decrypt: the enclave no longer has any
  network of its own and the standalone VSOCK KMS proxy is removed. The
  API host performs the attested kms:Decrypt on the enclave's behalf via
  a two-message BeginKeyLoad/CompleteKeyLoad handshake; the CA-key
  plaintext is never visible to the host and AWS credentials never enter
  the enclave. ACTION REQUIRED: the KMS key policy must require
  attestation for Decrypt (deny non-attested Decrypt) and grant the EC2
  instance role Decrypt; see docs/kms-attestation-policy.md.
- One-shot CA-key load gate: the CA identity is pinned on first load. A
  post-load swap to a different key is refused, a same-key reload is
  idempotent (the host re-drives the handshake on every restart).
- CA public-key pin baked into the EIF by default (CA_PUBLIC_KEY_PATH):
  a decrypted CA key whose public half does not match is refused.
- LDAP-backed RBAC (opt-in): Cerberus groups may resolve membership from
  LDAP, routed by Kerberos realm, with positive caching and fail-closed
  semantics for LDAP-backed groups.
- Configurable signer endpoint via CERBERUS_SIGNER_ENDPOINT
  (vsock://, tcp://, unix://).
- Structured slog events for key-load gate refusals; sentinel errors.
- Kerberos keytab path is now sourced only from keytab_path in
  config.yaml (the KERBEROS_KEYTAB_PATH env var is no longer read).
- STRIDE/DREAD threat model added (docs/THREAT-MODEL.md).
- Module paths renamed to canonical github.com/pkilar/cerberus/*.
- Go toolchain bumped to 1.26.4; AWS SDK and golang.org/x/crypto
  dependency refresh.

* Thu May 21 2026 Paul Kilar <pkilar@gmail.com> - 0.3.0-1
- Expose Nitro Enclave CPU and memory utilization as Prometheus metrics
  (sourced via NSM in-band describe-pcr; no host metrics).
- Switch ssh-cert-signer to github.com/pkilar/nitro-enclaves-sdk-go v1.1.0

* Thu May 21 2026 Paul Kilar <pkilar@gmail.com> - 0.2.0-1
- API rejects empty Principals; signer applies the same check as defense
  in depth.
- Config validation refuses zero or negative validity durations.
- Signer rejects SSH key inputs that carry authorized_keys-style prefix
  options or trailing data.
- Enclave-side ECDSA curve allowlist made explicit (P-256/P-384/P-521).

* Mon May 18 2026 Paul Kilar <pkilar@gmail.com> - 0.1.1-1
- Fix ARM64 install failure: drop the hardcoded ARCH=amd64 variable from
  /etc/sysconfig/cerberus-signer.

* Sun Mar 22 2026 Paul Kilar <pkilar@gmail.com> - 0.1.0-1
- Initial RPM packaging
- Separate subpackages for API and signer services
- Systemd integration with security hardening
- Enclave lifecycle management via run-enclave.sh wrapper
