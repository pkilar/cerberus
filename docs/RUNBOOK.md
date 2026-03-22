# Cerberus SSH Certificate Authority — Operations Runbook

This runbook covers day-to-day operations, deployment, monitoring, and troubleshooting for the Cerberus SSH Certificate Authority.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Configuration](#configuration)
5. [Building](#building)
6. [RPM Packaging](#rpm-packaging)
7. [Deployment](#deployment)
8. [Running Locally](#running-locally)
9. [Health Checks & Monitoring](#health-checks--monitoring)
10. [Operational Procedures](#operational-procedures)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)
13. [Testing](#testing)
14. [CI/CD](#cicd)
15. [Appendix](#appendix)

---

## System Overview

Cerberus is an SSH Certificate Authority that runs inside an AWS Nitro Enclave. It consists of two services:

| Service             | Runs On       | Purpose                                                                     |
| ------------------- | ------------- | --------------------------------------------------------------------------- |
| **ssh-cert-api**    | EC2 host      | HTTPS API with Kerberos/SPNEGO authentication, authorization, and KMS proxy |
| **ssh-cert-signer** | Nitro Enclave | Decrypts CA private key via KMS, signs SSH certificates                     |

The CA private key **never exists in plaintext outside the enclave**. The enclave has no network access — all KMS calls are proxied through the host via VSOCK.

---

## Architecture

```
User (Kerberos) → HTTPS → [ssh-cert-api on EC2 host] → VSOCK:5000 → [ssh-cert-signer in Nitro Enclave]
                                                                              ↓
                                                                     KMS decrypt CA key
                                                                              ↓
User ← signed certificate ← [ssh-cert-api] ← VSOCK ← [ssh-cert-signer signs cert]
```

### VSOCK Channels

| Channel   | CID              | Port | Direction      | Purpose                                |
| --------- | ---------------- | ---- | -------------- | -------------------------------------- |
| Signing   | 16 (ENCLAVE_CID) | 5000 | Host → Enclave | Certificate signing requests           |
| KMS Proxy | 3 (INSTANCE_CID) | 8000 | Enclave → Host | KMS API calls (enclave has no network) |

### Message Protocol

Services communicate using JSON-encoded messages over VSOCK:

- **LoadKeySigner** — Sent at startup. Carries AWS credentials so the enclave can decrypt the CA key via KMS.
- **SignSshKey** — Carries a signing request (public key, principals, validity, permissions, attributes). Returns the signed certificate.

---

## Prerequisites

### EC2 Host Requirements

- **Nitro-capable EC2 instance** (e.g., `m5.xlarge`, `c5.xlarge`, or any `.metal` instance)
- **Supported OS**: Amazon Linux 2, Amazon Linux 2023, RHEL 8+, or Fedora
- **Nitro Enclaves enabled** on the instance (set during launch or via `modify-instance-attribute`)
- **nitro-cli** installed and configured
- **AWS IAM role** attached to the instance with KMS Decrypt permissions for the CA key
- **Kerberos keytab** for SPNEGO authentication
- **TLS certificate and key** for HTTPS

### KMS Key Policy

The EC2 instance role must have permission to call `kms:Decrypt` on the KMS key used to encrypt the CA private key. If using Nitro Enclave attestation, the KMS key policy should include a condition on the enclave's PCR values:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/INSTANCE-ROLE" },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<PCR0-value-from-manifest>"
    }
  }
}
```

### Software Dependencies

- Go 1.26+ (for building from source)
- Docker (for building EIF images)
- `nitro-cli` (for enclave management)
- `aws` CLI (for credential verification)
- `golangci-lint`, `gosec`, `govulncheck` (for development/testing)

---

## Configuration

### ssh-cert-api Environment Variables

| Variable               | Default               | Description                          |
| ---------------------- | --------------------- | ------------------------------------ |
| `CONFIG_PATH`          | `configs/config.yaml` | Path to authorization config file    |
| `KERBEROS_KEYTAB_PATH` | —                     | Path to Kerberos keytab file         |
| `AWS_REGION`           | `us-east-1`           | AWS region for KMS operations        |
| `ENCLAVE_VSOCK_PORT`   | `5000`                | VSOCK port for enclave communication |
| `DEBUG`                | `false`               | Enable debug-level logging           |

### ssh-cert-signer Environment Variables

| Variable           | Default           | Description                          |
| ------------------ | ----------------- | ------------------------------------ |
| `CA_KEY_FILE_PATH` | `/app/ca_key.enc` | Path to KMS-encrypted CA private key |
| `AWS_REGION`       | `us-east-1`       | AWS region for KMS operations        |
| `DEBUG`            | `false`           | Enable debug-level logging           |

### Authorization Config (config.yaml)

The API service uses a YAML configuration file to define authorization policies. Key fields:

```yaml
# Kerberos keytab for authenticating incoming requests
keytab_path: "/etc/krb5.keytab"

# Optional SPNEGO service principal (auto-detected from keytab if omitted)
service_principal: ""

# Listen address (default: ":8443")
listen: ":8443"

# TLS certificate and key paths (defaults: "cert.pem", "key.pem")
tls_cert: "/etc/cerberus/cert.pem"
tls_key: "/etc/cerberus/key.pem"

# Authorization groups
groups:
  backend-engineers:
    members:
      - "alice@REALM.COM"
      - "bob@REALM.COM"
    certificate_rules:
      validity: "8h"                         # Max certificate lifetime
      allowed_principals:                     # Principals the user may request (* = wildcard)
        - "root"
        - "ec2-user"
      permissions:                            # SSH certificate extensions
        permit-X11-forwarding: ""
        permit-agent-forwarding: ""
        permit-port-forwarding: ""
        permit-pty: ""
        permit-user-rc: ""
      static_attributes:                      # Custom key-value pairs embedded in cert
        team: "backend"
        access-level: "production"
      critical_options:                       # SSH critical options
        source-address: "10.20.30.0/24"
```

**Authorization flow**: The API matches the authenticated Kerberos principal against group membership, then enforces the **first matching** group's `certificate_rules`.

### Validation Constraints

| Constraint                 | Value                   |
| -------------------------- | ----------------------- |
| Max certificate validity   | 24 hours                |
| Max principals per request | 100                     |
| Clock skew tolerance       | 300 seconds (5 minutes) |
| Nonce size                 | 32 bytes                |
| API read/write timeout     | 10 seconds              |
| Enclave read/write timeout | 5 seconds               |
| VSOCK connection deadline  | 30 seconds              |

---

## Building

### Build Binaries

```bash
# Build both services (creates .amd64 and .arm64 binaries)
make build

# Build individual services
make -C ssh-cert-api build
make -C ssh-cert-signer build
```

### Build Enclave Image Files (EIF)

```bash
# Both architectures
make eif

# Architecture-specific
make eif-amd64
make eif-arm64
```

**Output files:**
- `ssh-cert-signer/ssh-cert-signer-amd64.eif`
- `ssh-cert-signer/ssh-cert-signer-arm64.eif`
- `ssh-cert-signer/pcr-manifest-amd64.json` — Contains PCR0, PCR1, PCR2 values
- `ssh-cert-signer/pcr-manifest-arm64.json`

> **Important**: After building a new EIF, update the KMS key policy with the new PCR values from the manifest if using attestation-based conditions.

### Clean Build Artifacts

```bash
make clean
```

---

## RPM Packaging

Cerberus provides RPM packaging for Amazon Linux 2, Amazon Linux 2023, RHEL, and Fedora. The spec produces two subpackages:

| Package           | Contents                                                                     |
| ----------------- | ---------------------------------------------------------------------------- |
| `cerberus-api`    | API binary, systemd unit, sysconfig, example config, `cerberus` user/group   |
| `cerberus-signer` | Signer binary, Dockerfile, systemd unit, sysconfig, enclave lifecycle script |

### Building RPMs

**Prerequisites:**

```bash
# Amazon Linux 2023 / Fedora / RHEL 8+
sudo dnf install rpm-build rpmdevtools golang make

# Amazon Linux 2 / RHEL 7
sudo yum install rpm-build rpmdevtools golang make
```

**Build locally:**

```bash
./packaging/rpm/build-rpm.sh
```

**Build in a clean mock chroot:**

```bash
./packaging/rpm/build-rpm.sh --mock
```

Output RPMs are placed in `rpmbuild/RPMS/<arch>/`.

### Installing

```bash
# Amazon Linux 2023 / Fedora / RHEL 8+
sudo dnf install rpmbuild/RPMS/x86_64/cerberus-api-*.rpm
sudo dnf install rpmbuild/RPMS/x86_64/cerberus-signer-*.rpm

# Amazon Linux 2 / RHEL 7
sudo yum install rpmbuild/RPMS/x86_64/cerberus-api-*.rpm
sudo yum install rpmbuild/RPMS/x86_64/cerberus-signer-*.rpm
```

### RPM File Locations

When installed via RPM, files are placed at standard FHS paths:

| File                | RPM Path                                          | Notes                    |
| ------------------- | ------------------------------------------------- | ------------------------ |
| API binary          | `/usr/bin/ssh-cert-api`                           | —                        |
| Signer binary       | `/usr/bin/ssh-cert-signer`                        | —                        |
| API systemd unit    | `/usr/lib/systemd/system/cerberus-api.service`    | —                        |
| Signer systemd unit | `/usr/lib/systemd/system/cerberus-signer.service` | —                        |
| API sysconfig       | `/etc/sysconfig/cerberus-api`                     | `%config(noreplace)`     |
| Signer sysconfig    | `/etc/sysconfig/cerberus-signer`                  | `%config(noreplace)`     |
| Example config      | `/etc/cerberus/config.yaml.example`               | Copy to `config.yaml`    |
| Enclave wrapper     | `/usr/libexec/cerberus/run-enclave.sh`            | Used by systemd          |
| Dockerfile          | `/usr/share/cerberus/Dockerfile`                  | For building EIFs        |
| EIF directory       | `/usr/share/cerberus/`                            | Place EIF files here     |
| Log directory       | `/var/log/cerberus/`                              | Owned by `cerberus` user |

### Post-Install Setup (RPM)

1. Copy and edit the configuration:
   ```bash
   sudo cp /etc/cerberus/config.yaml.example /etc/cerberus/config.yaml
   sudo vim /etc/cerberus/config.yaml
   ```
2. Place the Kerberos keytab:
   ```bash
   sudo cp krb5.keytab /etc/cerberus/krb5.keytab
   sudo chown root:cerberus /etc/cerberus/krb5.keytab
   sudo chmod 640 /etc/cerberus/krb5.keytab
   ```
3. Place TLS certificate and key (update paths in `config.yaml`).
4. Build or copy the EIF into `/usr/share/cerberus/`:
   ```bash
   sudo cp ssh-cert-signer-amd64.eif /usr/share/cerberus/
   ```
5. Start the services:
   ```bash
   sudo systemctl enable --now cerberus-signer
   sudo systemctl enable --now cerberus-api
   ```

### Managing Services (RPM Install)

```bash
# API service
sudo systemctl start cerberus-api
sudo systemctl stop cerberus-api
sudo systemctl restart cerberus-api
journalctl -u cerberus-api -f

# Signer enclave
sudo systemctl start cerberus-signer      # launches enclave
sudo systemctl stop cerberus-signer       # terminates enclave
sudo systemctl restart cerberus-signer    # terminate + relaunch
sudo /usr/libexec/cerberus/run-enclave.sh status
```

### Sysconfig Reference

Environment variables are managed via sysconfig files rather than inline in the systemd unit.

**`/etc/sysconfig/cerberus-api`**: `CONFIG_PATH`, `KERBEROS_KEYTAB_PATH`, `AWS_REGION`, `ENCLAVE_VSOCK_PORT`, `DEBUG`

**`/etc/sysconfig/cerberus-signer`**: `ARCH`, `EIF_PATH`, `ENCLAVE_CID`, `ENCLAVE_CPU_COUNT`, `ENCLAVE_MEMORY_MIB`, `ENCLAVE_DEBUG`

### Versioning

The RPM version is read from the `VERSION` file in the project root. Bump it before building a release:

```bash
echo "1.0.0" > VERSION
```

---

## Deployment

### Option A: RPM Install (Recommended)

See [RPM Packaging](#rpm-packaging) above. After installing the RPMs, follow the [Post-Install Setup](#post-install-setup-rpm) steps.

### Option B: Manual Deployment

#### Step 1: Prepare the EC2 Instance

1. Launch a Nitro-capable EC2 instance with Nitro Enclaves enabled.
2. Attach an IAM role with KMS Decrypt permissions.
3. Install `nitro-cli` and allocate enclave resources:
   ```bash
   # Amazon Linux 2
   sudo amazon-linux-extras install aws-nitro-enclaves-cli

   # Amazon Linux 2023 / RHEL / Fedora
   sudo dnf install aws-nitro-enclaves-cli

   # All distributions
   sudo systemctl enable nitro-enclaves-allocator
   sudo systemctl start nitro-enclaves-allocator
   ```
4. Configure enclave allocator (e.g., `/etc/nitro_enclaves/allocator.yaml`):
   ```yaml
   memory_mib: 1024
   cpu_count: 1
   ```

#### Step 2: Deploy the Signer (Enclave)

1. Copy the EIF file to the instance:
   ```bash
   scp ssh-cert-signer/ssh-cert-signer-amd64.eif ec2-user@host:/opt/cerberus/
   ```
2. Copy the encrypted CA key:
   ```bash
   scp ca_key.enc ec2-user@host:/opt/cerberus/
   ```
3. Launch the enclave:
   ```bash
   nitro-cli run-enclave \
     --cpu-count 1 \
     --memory 1024 \
     --eif-path /opt/cerberus/ssh-cert-signer-amd64.eif \
     --enclave-cid 16
   ```
4. Verify the enclave is running:
   ```bash
   nitro-cli describe-enclaves
   ```

#### Step 3: Deploy the API Service

1. Copy the binary and configuration:
   ```bash
   scp ssh-cert-api/ssh-cert-api.amd64 ec2-user@host:/opt/cerberus/ssh-cert-api
   scp ssh-cert-api/configs/config.yaml ec2-user@host:/opt/cerberus/config.yaml
   ```
2. Place TLS certificate and key:
   ```bash
   scp cert.pem key.pem ec2-user@host:/opt/cerberus/
   ```
3. Place the Kerberos keytab:
   ```bash
   scp krb5.keytab ec2-user@host:/etc/cerberus/krb5.keytab
   ```
4. Start the API service:
   ```bash
   CONFIG_PATH=/opt/cerberus/config.yaml \
   KERBEROS_KEYTAB_PATH=/etc/cerberus/krb5.keytab \
   AWS_REGION=us-east-1 \
   /opt/cerberus/ssh-cert-api
   ```

#### Step 4: Verify End-to-End

```bash
# Health check (no auth required)
curl -k https://localhost:8443/health
# Expected: {"status":"healthy"}

# Sign a key (requires Kerberos ticket)
kinit user@REALM.COM
curl -k --negotiate -u : \
  -X POST https://localhost:8443/sign \
  -H "Content-Type: application/json" \
  -d '{"ssh_key": "ssh-rsa AAAA...", "principals": ["ec2-user"]}'
```

#### Systemd Service (Manual Install)

If deploying manually (without RPM), create systemd units. See `packaging/rpm/cerberus-api.service` and `packaging/rpm/cerberus-signer.service` as templates, or install the RPMs which handle this automatically.

---

## Running Locally

For local development (without a Nitro Enclave):

```bash
# Generate self-signed TLS certs
make -C ssh-cert-api tls-certs

# Start the API service
make run-api
```

The API will start on `:8443` with auto-generated TLS certificates. Without an enclave, signing requests will fail, but health checks and auth flows can be tested.

### Debug Mode

Enable verbose logging by setting `DEBUG=true`:

```bash
DEBUG=true CONFIG_PATH=configs/config.yaml ./ssh-cert-api
```

### Running the Enclave in Debug Mode

On a Nitro-capable instance:

```bash
make run-enclave-debug              # AMD64 (default)
make run-enclave-debug ARCH=arm64   # ARM64
```

This launches the enclave with `--debug-mode --attach-console` for live log output.

---

## Health Checks & Monitoring

### Health Endpoint

```
GET /health
```

- **No authentication required**
- Returns HTTP 200 with `{"status": "healthy"}` when the API service is running
- Does **not** verify enclave connectivity (it only confirms the API process is alive)

### Monitoring Recommendations

| Check                    | Method                                          | Frequency |
| ------------------------ | ----------------------------------------------- | --------- |
| API process alive        | `GET /health` → HTTP 200                        | Every 30s |
| Enclave running          | `nitro-cli describe-enclaves` → State = RUNNING | Every 60s |
| End-to-end signing       | Test sign request with a service account        | Every 5m  |
| TLS certificate expiry   | Check cert NotAfter date                        | Daily     |
| Kerberos keytab validity | `klist -k /etc/krb5.keytab`                     | Daily     |
| KMS key accessibility    | `aws kms describe-key`                          | Every 5m  |
| Disk space               | Standard OS monitoring                          | Every 5m  |

### Key Log Messages

**Startup (API):**
```
Starting SSH Certificate API...
VSOCK proxy on port 8000
```

**Successful signing:**
```
Signing request from user: alice@REALM.COM
Successfully signed SSH key ID: alice@REALM.COM
```

**Failures:**
```
Signing failed: <error details>
```

**Debug mode** (`DEBUG=true`) adds verbose output including credential handling and VSOCK communication details. Credentials are automatically redacted (truncated to 4 chars + `***`).

---

## Operational Procedures

### Rotating the CA Key

1. Generate a new SSH CA key pair:
   ```bash
   ssh-keygen -t rsa -b 4096 -f ca_key -N ""
   ```
2. Encrypt the private key with KMS:
   ```bash
   aws kms encrypt \
     --key-id alias/cerberus-ca-key \
     --plaintext fileb://ca_key \
     --output text --query CiphertextBlob | base64 -d > ca_key.enc
   ```
3. Securely delete the plaintext key:
   ```bash
   shred -u ca_key
   ```
4. Deploy `ca_key.enc` to the enclave image or mount point.
5. Distribute the new `ca_key.pub` to all SSH servers that trust the CA.
6. Restart the enclave (the signer loads the key at startup).

### Rotating the TLS Certificate

1. Obtain a new TLS certificate and key.
2. Replace the files at the paths specified in `config.yaml` (`tls_cert`, `tls_key`).
3. Restart the API service:
   ```bash
   sudo systemctl restart cerberus-api
   ```

### Rotating the Kerberos Keytab

1. Generate a new keytab from your KDC/Active Directory.
2. Replace the keytab at the path specified in `config.yaml` (`keytab_path`).
3. Restart the API service:
   ```bash
   sudo systemctl restart cerberus-api
   ```

### Adding or Removing Users

1. Edit `config.yaml` to add/remove principals from the appropriate group's `members` list.
2. Restart the API service to pick up the changes:
   ```bash
   sudo systemctl restart cerberus-api
   ```

### Restarting the Enclave

```bash
# Terminate the running enclave
nitro-cli terminate-enclave --all

# Relaunch
nitro-cli run-enclave \
  --cpu-count 1 \
  --memory 1024 \
  --eif-path /opt/cerberus/ssh-cert-signer-amd64.eif \
  --enclave-cid 16
```

After restarting the enclave, the API service will automatically send a `LoadKeySigner` message on the next signing request to reinitialize the CA key.

### Updating the EIF (Enclave Image)

1. Build a new EIF:
   ```bash
   make eif-amd64
   ```
2. Note the new PCR values from `ssh-cert-signer/pcr-manifest-amd64.json`.
3. If using attestation-based KMS policy, update the KMS key policy with the new PCR values **before** deploying the new EIF.
4. Copy the new EIF to the instance.
5. Terminate and relaunch the enclave.

---

## Troubleshooting

### API Service Won't Start

| Symptom                                          | Likely Cause                   | Resolution                                                                                     |
| ------------------------------------------------ | ------------------------------ | ---------------------------------------------------------------------------------------------- |
| `listen tcp :8443: bind: address already in use` | Port conflict                  | Check `ss -tlnp \| grep 8443`, stop the conflicting process, or change `listen` in config.yaml |
| `failed to load keytab`                          | Keytab missing or unreadable   | Verify `keytab_path` in config.yaml, check file permissions (`chmod 600`)                      |
| `failed to load TLS certificate`                 | Cert/key missing or mismatched | Verify paths in config.yaml, regenerate if needed                                              |
| `failed to parse config`                         | YAML syntax error              | Validate YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"`          |

### Enclave Won't Launch

| Symptom                    | Likely Cause                           | Resolution                                                                             |
| -------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------- |
| `Insufficient resources`   | Not enough CPU/memory allocated        | Increase allocator settings in `/etc/nitro_enclaves/allocator.yaml`, restart allocator |
| `Enclave not supported`    | Instance type doesn't support enclaves | Use a Nitro-capable instance type (m5, c5, r5, etc.)                                   |
| `Failed to create enclave` | Enclave support not enabled            | Enable Nitro Enclaves on the instance (`aws ec2 modify-instance-attribute`)            |
| `CID already in use`       | Previous enclave still running         | Run `nitro-cli terminate-enclave --all`                                                |

### Signing Failures

| Error                                           | Likely Cause                         | Resolution                                                                                  |
| ----------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------- |
| `CA signer is not initialized`                  | Enclave hasn't loaded the CA key yet | Check enclave logs; verify KMS credentials are reachable                                    |
| `failed to decrypt key with KMS`                | KMS permissions or PCR mismatch      | Verify IAM role has `kms:Decrypt`; check PCR values in KMS key policy match the running EIF |
| `validity duration exceeds maximum allowed 24h` | Requested validity too long          | Reduce `validity` in config.yaml to ≤ 24h                                                   |
| `failed to parse public key`                    | Malformed SSH public key in request  | Verify the key is a valid SSH public key (e.g., `ssh-keygen -l -f key.pub`)                 |
| `Signing failed` (HTTP 500)                     | Generic signing error                | Check API logs for details; enclave may be unresponsive                                     |

### Authentication Failures

| Error                                | Likely Cause                                      | Resolution                                                             |
| ------------------------------------ | ------------------------------------------------- | ---------------------------------------------------------------------- |
| `Authentication required` (HTTP 401) | Missing or invalid Kerberos ticket                | Run `kinit user@REALM.COM`; verify the keytab is valid with `klist -k` |
| SPNEGO negotiation fails             | Service principal mismatch                        | Set `service_principal` in config.yaml to match the keytab's principal |
| `Clock skew too great`               | Time difference between client and server > 5 min | Sync clocks with NTP: `chronyc tracking` or `ntpdate pool.ntp.org`     |

### Authorization Failures

| Error                                                | Likely Cause                                        | Resolution                                                                               |
| ---------------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `Not authorized for requested principals` (HTTP 403) | User's group doesn't allow the requested principals | Check `allowed_principals` in the user's group config; `*` allows all                    |
| User gets wrong permissions                          | User matches the wrong group                        | Groups are matched in order — the **first match** wins. Reorder groups in config.yaml    |
| User not found in any group                          | Principal not listed in any `members` list          | Add the user's full Kerberos principal (e.g., `user@REALM.COM`) to the appropriate group |

### VSOCK / KMS Proxy Issues

| Symptom                        | Likely Cause                               | Resolution                                                                   |
| ------------------------------ | ------------------------------------------ | ---------------------------------------------------------------------------- |
| Signing requests timeout       | Enclave not running or VSOCK misconfigured | `nitro-cli describe-enclaves` — verify state is RUNNING and CID is 16        |
| KMS decrypt fails from enclave | KMS proxy not running on host              | Verify the API service is running (it runs the KMS proxy on port 8000)       |
| `connection refused` on VSOCK  | Wrong CID or port                          | Verify CID=16 and port=5000 match between host and enclave                   |
| KMS proxy TLS errors           | AWS endpoint unreachable                   | Check outbound HTTPS (443) to `kms.<region>.amazonaws.com` from the EC2 host |
| Intermittent VSOCK failures    | Resource exhaustion in enclave             | Check enclave memory allocation (1024 MB minimum recommended)                |

### Network & Connectivity

| Symptom                     | Likely Cause                         | Resolution                                                                   |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------------------- |
| Can't reach API from client | Security group blocks port 8443      | Add inbound rule for TCP 8443                                                |
| KMS calls fail              | No outbound internet or VPC endpoint | Set up a KMS VPC endpoint or ensure NAT gateway for outbound HTTPS           |
| TLS handshake failure       | Certificate doesn't match hostname   | Regenerate cert with correct SAN/CN, or use `-k` (insecure) for testing only |

### RPM Package Issues

| Symptom                                     | Likely Cause                             | Resolution                                                                                       |
| ------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `cerberus` user doesn't exist after install | `%pre` scriptlet failed                  | Run `sudo useradd -r -g cerberus -d /etc/cerberus -s /sbin/nologin cerberus`                     |
| Config overwritten on upgrade               | Config not marked `noreplace`            | Reinstall; configs use `%config(noreplace)` so this should not happen                            |
| Service won't start after RPM install       | Missing config.yaml                      | Copy `/etc/cerberus/config.yaml.example` to `/etc/cerberus/config.yaml` and edit it              |
| `run-enclave.sh: EIF file not found`        | EIF not placed in `/usr/share/cerberus/` | Build and copy the EIF: `sudo cp ssh-cert-signer-amd64.eif /usr/share/cerberus/`                 |
| Permission denied on keytab                 | Wrong ownership                          | `sudo chown root:cerberus /etc/cerberus/krb5.keytab && sudo chmod 640 /etc/cerberus/krb5.keytab` |

### Diagnostic Commands

```bash
# Check enclave status
nitro-cli describe-enclaves

# View enclave console output (debug mode only)
nitro-cli console --enclave-id <enclave-id>

# Check API service logs (systemd)
journalctl -u cerberus-api -f

# Verify KMS access from the host
aws kms describe-key --key-id alias/cerberus-ca-key

# Verify Kerberos keytab
klist -k /etc/cerberus/krb5.keytab

# Test health endpoint
curl -k https://localhost:8443/health

# Test VSOCK connectivity (if socat is available)
socat - VSOCK-CONNECT:16:5000

# Check listening ports
ss -tlnp | grep -E '8443|8000'

# Check AWS credentials on the instance
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Security Considerations

### CA Key Protection

- The CA private key is **KMS-encrypted at rest** and only decrypted inside the Nitro Enclave.
- The plaintext key **never leaves the enclave** — it exists only in enclave memory.
- Use **attestation-based KMS policies** (PCR conditions) so only the specific enclave image can decrypt the key.

### Network Security

- The enclave has **no network access** — all external calls go through the VSOCK KMS proxy on the host.
- The API listens on HTTPS only (TLS required).
- Restrict access to port 8443 via security groups to authorized networks.

### Authentication & Authorization

- All signing requests require **Kerberos/SPNEGO authentication**.
- Authorization is **group-based** with per-group certificate rules.
- Principals support **wildcard matching** — use carefully.
- The first matching group wins — order groups from most to least restrictive.

### Certificate Safety

- Maximum validity is capped at **24 hours** (hardcoded).
- Certificates include a **5-minute clock skew** tolerance (valid 5 minutes before issuance).
- Each certificate gets a **cryptographically random** serial and nonce.
- `critical_options` like `source-address` can restrict certificate use to specific networks.

### Credential Handling

- AWS credentials sent to the enclave are **redacted in logs** (truncated to 4 characters).
- Debug mode provides more verbose output but still redacts secrets.

### Audit Trail

- Every signing request is logged with the authenticated principal and key ID.
- Static attributes embedded in certificates (e.g., `team`, `access-level`) provide audit context.

---

## Testing

### Running Tests

```bash
# All tests
make test

# Individual components
./test_runner.sh api          # API service unit tests
./test_runner.sh signer       # Signer service unit tests
./test_runner.sh integration  # Integration tests (mock VSOCK)
./test_runner.sh security     # gosec + govulncheck
./test_runner.sh lint         # golangci-lint
./test_runner.sh coverage     # Coverage reports (HTML)
./test_runner.sh all          # Everything
```

### Running Specific Tests

```bash
cd ssh-cert-api && go test -v -run TestSpecificName ./internal/config
cd ssh-cert-signer && go test -v ./...
```

### Test Coverage

```bash
make test-coverage
# Reports generated at:
#   ssh-cert-api/coverage.html
#   ssh-cert-signer/coverage.html
#   integration-coverage.html
```

### Integration Tests

Integration tests (in the root module) use a mock TCP server to simulate VSOCK since VSOCK requires Nitro hardware. They create real RSA keys and validate full certificate signing flows.

```bash
# Run integration tests
go test -v ./...

# Skip integration tests (they're also skipped with -short)
go test -short -v ./...
```

### Multi-Module Note

This is **not** a Go workspace. There are three separate `go.mod` files:
- `/go.mod` — root (shared packages + integration tests)
- `/ssh-cert-api/go.mod` — API service
- `/ssh-cert-signer/go.mod` — Signer service

You must `cd` into the correct directory before running `go test`, `go build`, or `go mod tidy`.

---

## CI/CD

### GitHub Actions

The workflow at `.github/workflows/go.yml` runs on every push and pull request to `main`:

1. **Build**: Compiles all Go modules with `go build -v ./...`
2. **Test**: Runs all tests with `go test -v ./...`
3. **Go version**: 1.26

### Deployment Pipeline (Manual)

1. Merge to `main`
2. Build binaries and EIF: `make build && make eif-amd64`
3. Record PCR values from manifest
4. Update KMS key policy if PCR values changed
5. Deploy EIF and binary to the EC2 instance
6. Terminate old enclave, launch new one
7. Restart the API service
8. Verify with health check and test signing request

---

## Appendix

### API Request/Response Format

**POST /sign** — Sign an SSH public key

Request:
```json
{
  "ssh_key": "ssh-rsa AAAA...",
  "principals": ["ec2-user", "root"]
}
```

Response (success):
```json
{
  "signed_certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."
}
```

### SSH Certificate Fields

Certificates generated by Cerberus include:

| Field             | Value                                         |
| ----------------- | --------------------------------------------- |
| `CertType`        | `ssh.UserCert` (user certificate)             |
| `Serial`          | Cryptographically random 64-bit number        |
| `Nonce`           | 32-byte cryptographically random value        |
| `KeyId`           | Kerberos principal (e.g., `user@REALM.COM`)   |
| `ValidPrincipals` | Authorized login usernames                    |
| `ValidAfter`      | Current time − 300 seconds                    |
| `ValidBefore`     | Current time + validity duration              |
| `Extensions`      | Permissions + custom static attributes        |
| `CriticalOptions` | SSH critical options (e.g., `source-address`) |

### SSH Server Configuration

To trust certificates signed by Cerberus, add to `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/cerberus-ca.pub
```

Then place the CA public key at `/etc/ssh/cerberus-ca.pub` and reload sshd:

```bash
sudo systemctl reload sshd
```

### Client Usage

```bash
# Get a Kerberos ticket
kinit user@REALM.COM

# Request a signed certificate
curl -k --negotiate -u : \
  -X POST https://cerberus.example.com:8443/sign \
  -H "Content-Type: application/json" \
  -d "{\"ssh_key\": \"$(cat ~/.ssh/id_rsa.pub)\", \"principals\": [\"ec2-user\"]}" \
  -o ~/.ssh/id_rsa-cert.pub

# Verify the certificate
ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub

# SSH using the certificate (automatic if cert matches key)
ssh ec2-user@server.example.com
```

### File Locations Summary

**RPM install** (recommended):

| File             | Location                                        | Notes                |
| ---------------- | ----------------------------------------------- | -------------------- |
| API binary       | `/usr/bin/ssh-cert-api`                         | —                    |
| Signer binary    | `/usr/bin/ssh-cert-signer`                      | —                    |
| API config       | `/etc/cerberus/config.yaml`                     | Copy from `.example` |
| API sysconfig    | `/etc/sysconfig/cerberus-api`                   | Env vars             |
| Signer sysconfig | `/etc/sysconfig/cerberus-signer`                | Enclave params       |
| Kerberos keytab  | `/etc/cerberus/krb5.keytab`                     | —                    |
| Enclave wrapper  | `/usr/libexec/cerberus/run-enclave.sh`          | Used by systemd      |
| EIF image        | `/usr/share/cerberus/ssh-cert-signer-amd64.eif` | Place after build    |
| Log directory    | `/var/log/cerberus/`                            | Owned by `cerberus`  |

**Manual install**:

| File             | Location                                  | Notes          |
| ---------------- | ----------------------------------------- | -------------- |
| API binary       | `/opt/cerberus/ssh-cert-api`              | —              |
| API config       | `/opt/cerberus/config.yaml`               | —              |
| TLS cert         | `/opt/cerberus/cert.pem`                  | —              |
| TLS key          | `/opt/cerberus/key.pem`                   | —              |
| Kerberos keytab  | `/etc/cerberus/krb5.keytab`               | —              |
| EIF image        | `/opt/cerberus/ssh-cert-signer-amd64.eif` | —              |
| Encrypted CA key | `/app/ca_key.enc` (inside enclave)        | —              |
| PCR manifest     | `ssh-cert-signer/pcr-manifest-amd64.json` | Build artifact |

### Port Reference

| Port | Protocol | Service         | Purpose                            |
| ---- | -------- | --------------- | ---------------------------------- |
| 8443 | HTTPS    | ssh-cert-api    | Client-facing API                  |
| 5000 | VSOCK    | ssh-cert-signer | Signing channel (Host → Enclave)   |
| 8000 | VSOCK    | ssh-cert-api    | KMS proxy channel (Enclave → Host) |
