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
over VSOCK and runs a KMS proxy for the enclave's outbound KMS calls.

# ---------------------------------------------------------------------------
# Subpackage: cerberus-signer
# ---------------------------------------------------------------------------
%package signer
Summary:        Cerberus SSH Certificate Signer (Nitro Enclave)
Requires:       aws-nitro-enclaves-cli
%{?systemd_requires}

%description signer
The SSH certificate signer for Cerberus. Packaged as a Nitro Enclave Image
File (EIF) that runs inside an AWS Nitro Enclave. Decrypts the CA private
key via KMS at startup and signs SSH certificates received over VSOCK.

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

# Directory for EIF files (populated post-install or via CI).
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
* Sat Mar 22 2026 Cerberus Maintainers <cerberus@example.com> - 0.1.0-1
- Initial RPM packaging
- Separate subpackages for API and signer services
- Systemd integration with security hardening
- Enclave lifecycle management via run-enclave.sh wrapper
