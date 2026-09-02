%global goipath     cerberus

# build-rpm.sh passes --define "rpm_version <VERSION>". This fallback exists so a
# bare `rpmbuild -ba cerberus.spec`, with no --define, fails in an obvious place
# instead of a confusing one: without it rpmbuild only warns about an unexpanded
# macro, carries the literal "%%{rpm_version}" into Version:, and then dies much
# later in %%setup when the tarball's directory name does not match. 0.0.0 is
# unmistakably not a release.
%{!?rpm_version: %global rpm_version 0.0.0}

# Fedora requires a written reason whenever debuginfo generation is disabled.
# These binaries are linked with `-s -w` (see %build), so they carry neither a
# symbol table nor DWARF, and find-debuginfo would emit an empty -debuginfo
# subpackage. It would in fact fail outright: Go's internal linker emits no
# NT_GNU_BUILD_ID note, and find-debuginfo runs --strict-build-id.
# Producing usable debuginfo would mean dropping -s -w and forcing
# -linkmode=external (what Fedora's own %%gobuild macro does), which pulls in a
# C toolchain. Not worth it for these binaries.
%global debug_package %{nil}

Name:           cerberus
Version:        %{rpm_version}
Release:        1%{?dist}
Summary:        SSH Certificate Authority for AWS Nitro Enclaves

License:        MIT
URL:            https://github.com/pkilar/cerberus
Source0:        %{name}-%{version}.tar.gz
# sysusers.d fragments. These are not optional: %files entries carry
# %%attr(...,cerberus,...) / %%attr(...,cerberus-audit,...), and rpm's dependency
# generator turns those into Requires: user()/group(). Only a packaged sysusers.d
# file emits the matching Provides -- see the comment in cerberus.sysusers.
Source1:        cerberus.sysusers
Source2:        cerberus-vsock-watch.sysusers

BuildRequires:  golang >= 1.26
BuildRequires:  systemd-rpm-macros

# `noarch` belongs in this list even though the daemons are arch-specific: the
# cerberus-client subpackage is BuildArch: noarch, and without it here that
# subpackage cannot be built on any host outside the allowlist.
ExclusiveArch:  x86_64 aarch64 noarch

%description
Cerberus is an SSH Certificate Authority that runs inside an AWS Nitro Enclave.
The CA private key is KMS-encrypted and only decrypted inside the enclave,
ensuring the key never exists in plaintext on the host.

Supported distributions: Amazon Linux 2023, Fedora, RHEL 9+.
Amazon Linux 2 and RHEL 8 are not supported: both are end-of-life, and
neither can satisfy this spec's BuildRequires: systemd-rpm-macros, which is
not available in their default repositories.

# ---------------------------------------------------------------------------
# Subpackage: cerberus-api
# ---------------------------------------------------------------------------
%package api
Summary:        Cerberus SSH Certificate API service
Requires:       krb5-libs
Requires(pre):  shadow-utils
%{?systemd_requires}
%{?sysusers_requires_compat}

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
# Subpackage: cerberus-vsock-watch
#
# The detective control from docs/vsock-connect-detection.md: alerts on any
# AF_VSOCK connect() to the enclave from a process other than cerberus-api
# itself (e.g. a root-level process bypassing Casbin authorization entirely —
# see docs/THREAT-MODEL.md SIGN-1). Runs two independent detectors (an auditd
# rule + an eBPF tracepoint probe) side by side. It does NOT authorize or
# block signing requests; it only makes an out-of-band signing attempt
# observable. Requires audit (auditctl) for the auditd-based detector; on
# RHEL 10 that package alone isn't sufficient -- see the Requires block below.
# The eBPF detector needs no additional package (the object is prebuilt and
# embedded in the binary) but does need a 5.8+ kernel with BPF ring buffer
# support and CAP_BPF/CAP_PERFMON (granted via the unit's
# AmbientCapabilities, not requiring root).
# ---------------------------------------------------------------------------
%package vsock-watch
Summary:        Cerberus VSOCK-connect detective control (out-of-band signing detection)
Requires:       audit
# RHEL 10 split the classic audit userspace tooling: auditctl (needed by
# TamperWatch's AuditRulePresent, vsockwatch/tamper.go, to verify the auditd
# rule is still installed) ships in audit-rules there, not the base audit
# package -- confirmed via `dnf provides '*/auditctl'` on a RHEL 10 host.
# Gated on the rhel macro (>= 10) so Amazon Linux 2023, Fedora, and RHEL 9
# (which leave it undefined, or define it below 10) are unaffected -- audit
# alone is sufficient there, and audit-rules isn't guaranteed to exist as a
# distinct package on those distributions.
%if 0%{?rhel} >= 10
Requires:       audit-rules
%endif
Requires(pre):  shadow-utils
%{?systemd_requires}
%{?sysusers_requires_compat}

%description vsock-watch
Detects an AF_VSOCK connect() to the Cerberus enclave from any process other
than the legitimate cerberus-api — the signal that something on the host
bypassed Casbin authorization and is attempting to mint SSH certificates
directly against the enclave. Runs an auditd-based detector and an eBPF
tracepoint probe independently, ships alerts to a structured log and,
optionally, an external webhook, and pings an external heartbeat endpoint so
tampering with the detectors themselves is also observable. This is a
detective, not preventive, control — see docs/vsock-connect-detection.md.

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
%{_datadir}/cerberus/ssh-cert-signer.eif. CONDITIONAL and per-deployment: the EIF
bakes in the KMS-encrypted CA private key and the PCR0-pinned CA public key, so
this package carries CA key material and pins a deployment-specific PCR0. It is
per-architecture and must be distributed only over an operator-controlled
channel, never a shared or public repository. Built only when the RPM build is
invoked with --define "eif_file <path>" (note the space, not '='). build-rpm.sh
sets that automatically when the tree holds ca_key.enc + ca_key.pub, or from an
explicit --eif; --no-eif suppresses it.
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
# Fedora's Go macros set GOTOOLCHAIN=local so a distro build never downloads a
# toolchain. That is the right default for packages built in Fedora's own
# network-isolated buildsystem, but it is not how these packages are produced:
# they are built in an ephemeral container by packaging/build-in-container.sh,
# which already needs the network because the Go module dependencies are not
# vendored. go.mod requires Go 1.27 and no supported distribution ships it yet
# (Fedora stable, RHEL 9/10 and Amazon Linux 2023 are all on 1.26.7), so allow
# the toolchain to be fetched.
#
# This is safe for what is shipped: CGO_ENABLED=0 below makes the binaries
# statically linked, so the compiler version leaves no trace in the package --
# rpm generates no library dependencies from them at all. The fetched toolchain
# lives and dies inside the build container.
#
# The cost is that this spec can no longer be rebuilt in a network-isolated
# builder such as mock or Koji. That was already true for the unvendored module
# dependencies; this does not make it newly true, but it does mean vendoring
# alone would not restore it.
export GOTOOLCHAIN=auto
# Amazon Linux 2023's golang package additionally sets GOSUMDB=off, and a
# toolchain download is a module fetch that must be checksum-verified -- with the
# sum database disabled Go refuses it outright ("checksum database disabled by
# GOSUMDB=off"). Restore the upstream default. This strengthens the fetch rather
# than weakening it: the alternative would be disabling verification, not
# avoiding it.
export GOSUMDB=sum.golang.org
export CGO_ENABLED=0

# Build the API binary.
cd ssh-cert-api
go build -ldflags="-s -w -X github.com/pkilar/cerberus/version.Version=%{version}" -o ssh-cert-api ./cmd/ssh-cert-api
cd ..

# Build the signer binary.
cd ssh-cert-signer
go build -ldflags="-s -w -X github.com/pkilar/cerberus/version.Version=%{version}" -o ssh-cert-signer ./cmd/ssh-cert-signer
cd ..

# Build the vsock-watch detective control (root module — no cd needed). The
# embedded eBPF object (vsockwatch/ebpf/src/vsock_connect.bpf.o) is prebuilt
# and checked in rather than compiled here: it needs only clang -target bpf
# against stable UAPI headers (no kernel BTF/vmlinux.h — see
# vsockwatch/ebpf/src/vsock_connect.c's header comment), and eBPF bytecode is
# architecture-portable, so one object serves both x86_64 and aarch64. Run
# `make vsock-watch-bpf` to regenerate it from source if that file changes.
go build -ldflags="-s -w -X github.com/pkilar/cerberus/version.Version=%{version}" -o cerberus-vsock-watch ./cmd/cerberus-vsock-watch

%install
rm -rf %{buildroot}

# --- cerberus-api ---
install -D -m 0755 ssh-cert-api/ssh-cert-api \
    %{buildroot}%{_bindir}/ssh-cert-api

install -D -m 0644 packaging/rpm/cerberus-api.service \
    %{buildroot}%{_unitdir}/cerberus-api.service

install -D -m 0640 packaging/rpm/cerberus-api.sysconfig \
    %{buildroot}%{_sysconfdir}/sysconfig/cerberus-api

# The config template lives in %{_datadir}, not %{_sysconfdir}: nothing reads
# it, operators copy it to config.yaml. Shipping it as configuration froze it --
# once an admin touched it, upgrades stopped refreshing it and new options never
# surfaced. As read-only package data it is replaced on every upgrade, and 0644
# is unremarkable there (it carries no secrets and is public in the repo).
install -D -m 0644 ssh-cert-api/configs/config-example.yaml \
    %{buildroot}%{_datadir}/cerberus/config.yaml.example

# /etc/cerberus is where operators put the config.yaml they derive from that
# template, so the package still owns the directory even though it no longer
# ships a file into it.
install -d -m 0750 %{buildroot}%{_sysconfdir}/cerberus

install -D -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/cerberus.conf
install -D -m 0644 %{SOURCE2} %{buildroot}%{_sysusersdir}/cerberus-vsock-watch.conf

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

# --- cerberus-vsock-watch ---
install -D -m 0755 cerberus-vsock-watch \
    %{buildroot}%{_bindir}/cerberus-vsock-watch

install -D -m 0644 packaging/rpm/cerberus-vsock-watch.service \
    %{buildroot}%{_unitdir}/cerberus-vsock-watch.service

install -D -m 0640 packaging/rpm/cerberus-vsock-watch.sysconfig \
    %{buildroot}%{_sysconfdir}/sysconfig/cerberus-vsock-watch

install -D -m 0644 packaging/audit-rules/61-cerberus-vsock.rules \
    %{buildroot}%{_sysconfdir}/audit/rules.d/61-cerberus-vsock.rules

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
# Belt AND braces, because neither mechanism alone covers every supported target.
#
# The sysusers.d file (Source1) is what makes the package installable at all on
# rpm >= 6: %%files carries %%attr(...,cerberus,...), so rpm generates
# Requires: user(cerberus)/group(cerberus), and only a packaged sysusers.d emits
# the matching Provides. Without it dnf and rpm both refuse ("nothing provides
# user(cerberus)") -- confirmed on rpm 6.0.2.
#
# But shipping it is not sufficient. On RHEL 9 %%sysusers_create_compat expands to
# nothing and rpm 4.16 has no native sysusers handling, so nothing creates the
# account and every %%attr file lands root-owned ("warning: user cerberus does not
# exist - using root") -- verified by installing on Rocky 9. Amazon Linux 2023
# behaves the same way. So create the account explicitly as well. The %%{?...}
# guard also keeps the scriptlet valid where the macro is undefined outright.
#
# Both paths are idempotent: the getent guards make the useradd a no-op when
# sysusers already ran. Never invoked from %%postun, so the account survives erase.
%{?sysusers_create_compat:%sysusers_create_compat %{SOURCE1}}
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
# cerberus-vsock-watch scriptlets
# ---------------------------------------------------------------------------
%pre vsock-watch
# A DIFFERENT account than cerberus-api's own "cerberus" user: a compromise of the
# cerberus account alone must not also blind this watcher. See
# docs/vsock-connect-detection.md §4.3. Home is "/" rather than /etc/cerberus for
# the same reason -- that directory belongs to the other account.
#
# Ships a sysusers.d fragment (Source2) *and* creates the account explicitly, for
# the reasons spelled out in %%pre api above: the shipped file is what satisfies
# rpm >= 6's generated group(cerberus-audit) dependency, and the explicit creation
# is what actually makes the account exist on RHEL 9 and Amazon Linux 2023.
%{?sysusers_create_compat:%sysusers_create_compat %{SOURCE2}}
getent group cerberus-audit >/dev/null || groupadd -r cerberus-audit
getent passwd cerberus-audit >/dev/null || \
    useradd -r -g cerberus-audit -d / -s /sbin/nologin \
    -c "Cerberus VSOCK-watch detective control" cerberus-audit
exit 0

%post vsock-watch
%systemd_post cerberus-vsock-watch.service

%preun vsock-watch
%systemd_preun cerberus-vsock-watch.service

%postun vsock-watch
%systemd_postun_with_restart cerberus-vsock-watch.service

# ---------------------------------------------------------------------------
# File lists
# ---------------------------------------------------------------------------
%files api
%license LICENSE
%doc docs/RUNBOOK.md
%{_bindir}/ssh-cert-api
%{_unitdir}/cerberus-api.service
%config(noreplace) %attr(0640,root,cerberus) %{_sysconfdir}/sysconfig/cerberus-api
%dir %attr(0750,root,cerberus) %{_sysconfdir}/cerberus
%{_sysusersdir}/cerberus.conf
%dir %{_datadir}/cerberus
%{_datadir}/cerberus/config.yaml.example
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
%dir %{_libexecdir}/cerberus
%{_libexecdir}/cerberus/run-enclave.sh
%dir %{_datadir}/cerberus
%{_datadir}/cerberus/Dockerfile

%files vsock-watch
%license LICENSE
%doc docs/vsock-connect-detection.md
%{_bindir}/cerberus-vsock-watch
%{_unitdir}/cerberus-vsock-watch.service
%config(noreplace) %attr(0640,root,cerberus-audit) %{_sysconfdir}/sysconfig/cerberus-vsock-watch
%{_sysusersdir}/cerberus-vsock-watch.conf
%config(noreplace) %{_sysconfdir}/audit/rules.d/61-cerberus-vsock.rules

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
* Mon Aug 31 2026 Paul Kilar <pkilar@gmail.com> - 0.10.6-1
- Ship sysusers.d fragments so the packages install on rpm >= 6. Six %%files
  entries carry %%attr(...,cerberus,...) / %%attr(...,cerberus-audit,...), which
  rpm 6 turns into Requires: user()/group(); only a packaged sysusers.d file
  emits the matching Provides, so cerberus-api and cerberus-vsock-watch were
  uninstallable on current Fedora ("nothing provides user(cerberus)"). Older rpm
  (4.16, 4.20) does not generate the dependency, which is why this went
  unnoticed. The explicit account creation in %%pre is retained alongside the
  shipped file: on RHEL 9 %%sysusers_create_compat expands to nothing and rpm has
  no native sysusers handling, so the file alone would leave the account
  uncreated and every %%attr path root-owned.
- Committed Version/pkgver fields are now obvious placeholders rather than stale
  real-looking versions, so a bare rpmbuild fails visibly rather than carrying an
  unexpanded macro into %%setup.
- Repair the malformed 0.10.5 entry in the Debian changelog (missing trailer).
- Dependency updates: aws-sdk group bumped in ssh-cert-api and ssh-cert-signer.
* Mon Aug 17 2026 Paul Kilar <pkilar@gmail.com> - 0.10.5-1
- Ship the config template as %{_datadir}/cerberus/config.yaml.example instead
  of %%config(noreplace) %{_sysconfdir}/cerberus/config.yaml.example. Nothing
  reads the file -- operators copy it to config.yaml -- so marking it
  noreplace froze it: once an admin touched it, upgrades left it alone and
  newly added options never surfaced. As ordinary package data it is refreshed
  on every upgrade. Mode is now 0644; a restricted mode is anomalous under
  %{_datadir} and the template carries no secrets.
- cerberus-api still owns %{_sysconfdir}/cerberus (0750 root:cerberus). It was
  previously created only as a side effect of installing the template into it,
  and remains where the operator's config.yaml belongs.
* Thu Jul 23 2026 Paul Kilar <pkilar@gmail.com> - 0.10.4-1
- Reduce cerberus-vsock-watch alert noise on a cerberus-api.service
  restart: a third real restart chaos test on the same RHEL 10 host
  (verify-vsock-watch-hardware.sh) confirmed 0.10.3's Indeterminate
  downgrade was working correctly (the reported failure was actually a
  bug in the verification script, since fixed, that didn't distinguish
  Anomalous from Indeterminate alerts) -- but showed the Indeterminate
  alert still fires on essentially every restart, which is safe but
  noisy. Allowlist.Classify's single cgroup recheck is now a bounded
  retry loop (cgroupRevalidateAttempts/cgroupRevalidateInterval,
  default 10 attempts x 50ms) instead of one attempt, giving systemd's
  cgroup settling a real window to finish -- only on the rare mismatch
  path, not every event. The common case now resolves cleanly to
  Expected with no alert at all; the Indeterminate safety net (never
  Blockworthy) remains for whatever residual timing variance exceeds
  the retry budget. See docs/vsock-connect-detection.md §4.1.
* Thu Jul 23 2026 Paul Kilar <pkilar@gmail.com> - 0.10.3-1
- Fix a second round of a real false-positive in cerberus-vsock-watch,
  found via a second real cerberus-api.service restart chaos test on a
  real RHEL 10 host (verify-vsock-watch-hardware.sh): 0.10.2's uncached
  recheck reduced but did not fully close a cgroup-mismatch false
  positive, because a single immediate recheck can still race systemd's
  own cgroup settling during a restart. Allowlist.Classify now
  downgrades a cgroup mismatch that survives the recheck to
  Indeterminate (exe/uid already matched, so this isn't "any random
  process") rather than Anomalous -- it still alerts at critical
  severity, but is deliberately never Blockworthy, so --block cannot
  SIGKILL the legitimate, freshly-restarted ssh-cert-api over a
  cgroup-settling timing race. A genuine attacker satisfying the same
  narrow bar (matching exe and uid, wrong cgroup) is still loudly
  alerted on, just not auto-killed by this signal alone. See
  docs/vsock-connect-detection.md §4.1.
* Thu Jul 23 2026 Paul Kilar <pkilar@gmail.com> - 0.10.2-1
- Fix a real false-positive in cerberus-vsock-watch found via a live
  cerberus-api.service restart chaos test on a real RHEL 10 host
  (verify-vsock-watch-hardware.sh): Allowlist's cached expected cgroup
  inode can go stale across a restart that changes the unit's cgroup
  (systemd may rmdir+recreate an empty transient cgroup between stop and
  start), misclassifying the newly-restarted, perfectly legitimate
  ssh-cert-api as Anomalous for up to the 5s cache window -- and, with
  the opt-in --block reactive-kill enabled, killing it outright.
  Allowlist.Classify now does one uncached re-check (refreshUID/
  refreshCgroupID) before declaring a uid or cgroup mismatch Anomalous;
  a genuinely wrong uid/cgroup still mismatches on the fresh lookup, so
  this only closes the cache-timing false positive, not the actual
  security check. See docs/vsock-connect-detection.md §4.1.
* Thu Jul 23 2026 Paul Kilar <pkilar@gmail.com> - 0.10.1-1
- Fix cerberus-vsock-watch missing auditctl on RHEL 10: that release split
  the classic audit userspace tooling so auditctl (needed by TamperWatch's
  AuditRulePresent check, vsockwatch/tamper.go) ships in a separate
  audit-rules package rather than the base audit package. The vsock-watch
  subpackage now also Requires audit-rules when %{rhel} >= 10; Amazon Linux
  2023, Fedora, and RHEL 9 are unaffected (audit alone is still
  sufficient there). No functional change to any other subpackage.
* Wed Jul 22 2026 Paul Kilar <pkilar@gmail.com> - 0.10.0-1
- New cerberus-vsock-watch subpackage: a detective control for SIGN-1
  (docs/THREAT-MODEL.md) — a compromised host with root access can dial the
  enclave's VSOCK listener directly, bypassing ssh-cert-api's Casbin
  authorization entirely, and mint certificates for arbitrary principals.
  This does not close that gap (no host-side control fully can — see
  docs/vsock-connect-detection.md §7) but makes exploitation observable:
  two independent detectors (an auditd rule correlating SYSCALL/SOCKADDR
  records, and an eBPF probe on the syscalls:sys_enter_connect tracepoint)
  each classify every AF_VSOCK connect to the enclave against an allowlist
  of the known-good ssh-cert-api process (exe path, service-account uid,
  and — best-effort — cgroup), and ship a critical alert for anything else.
  Also watches for the auditd rule itself disappearing (a
  "detector tampering" meta-alert) and can ping an external heartbeat
  endpoint so a monitoring system outside this host notices if the watcher
  goes silent. Runs as its own cerberus-audit service account, distinct
  from cerberus-api's, so compromising the API service alone does not also
  blind the watcher. See docs/vsock-connect-detection.md.
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
