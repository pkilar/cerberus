%global goipath     cerberus
%global debug_package %{nil}

Name:           cerberus
Version:        %{rpm_version}
Release:        1%{?dist}
Summary:        SSH Certificate Authority for AWS Nitro Enclaves

License:        Proprietary
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

# Stage the EIF directory but leave it empty. The Enclave Image File
# bakes in the KMS-encrypted CA key (Dockerfile COPYs ca_key.enc), so the
# EIF is per-deployment and must NOT be shipped inside the generic RPM.
# Operators build the EIF separately and drop it into this directory
# (see docs/RUNBOOK.md, Post-Install Setup).
install -d -m 0755 %{buildroot}%{_datadir}/cerberus

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

# ---------------------------------------------------------------------------
# Changelog
# ---------------------------------------------------------------------------
%changelog
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

* Sat Mar 22 2026 Paul Kilar <pkilar@gmail.com> - 0.1.0-1
- Initial RPM packaging
- Separate subpackages for API and signer services
- Systemd integration with security hardening
- Enclave lifecycle management via run-enclave.sh wrapper
