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
| **ssh-cert-api**    | EC2 host      | HTTPS API with Kerberos/SPNEGO authentication and authorization              |
| **ssh-cert-signer** | Nitro Enclave | Decrypts CA private key via KMS, signs SSH certificates                     |

The CA private key **never exists in plaintext outside the enclave**. The enclave has no network access — the host performs a host-mediated attested KMS Decrypt on behalf of the enclave at startup.

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

| Channel | CID              | Port | Direction      | Purpose                      |
| ------- | ---------------- | ---- | -------------- | ---------------------------- |
| Signing | 16 (ENCLAVE_CID) | 5000 | Host → Enclave | Key-load and signing traffic |

The host no longer listens on any VSOCK port. The old port-8000 KMS proxy channel has been removed.

### Message Protocol

Services communicate using JSON-encoded messages over VSOCK:

- **BeginKeyLoad** — Sent by the host at startup. In production (with `/dev/nsm`) the enclave generates an NSM attestation document (containing its ephemeral RSA public key) and returns it together with the KMS-encrypted CA-key ciphertext read from `CA_KEY_FILE_PATH`. In development (no `/dev/nsm`) the enclave decrypts the CA key directly and returns `Loaded=true`.
- **CompleteKeyLoad** — Sent by the host after it has called `kms:Decrypt` with the enclave's attestation document as `Recipient`. Carries the `CiphertextForRecipient` CMS envelope (CA-key plaintext encrypted to the enclave's attestation public key); the enclave decrypts it with its ephemeral private key and installs the CA signer. AWS credentials are **not** sent to the enclave — the host uses its EC2 instance role directly for the KMS call.
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

**Build host** (compiling binaries and producing EIF files):

- Go 1.26+
- Docker, including the `buildx` plugin (`docker buildx version` to verify)
- Python 3 (the EIF build pipes `nitro-cli build-enclave` JSON output through `python3` to write the PCR manifest)
- `aws-nitro-enclaves-cli` and `aws-nitro-enclaves-cli-devel` (the AWS Nitro Enclaves CLI)
- For cross-architecture EIF builds, QEMU `binfmt_misc` (`docker run --privileged --rm tonistiigi/binfmt --install all`)
- `aws` CLI (for credential verification and `kms encrypt` of the CA key)

**Runtime host** (where the enclave runs):

- `nitro-cli` (provided by `aws-nitro-enclaves-cli`)
- `nitro-enclaves-allocator.service` running
- Docker is **only** required on the runtime host if you intend to rebuild the EIF in place using the shipped `/usr/share/cerberus/Dockerfile` (see [Updating the EIF](#updating-the-eif-enclave-image)). The `cerberus-signer` RPM does **not** pull docker in as a dependency, so install it separately if needed.

**Development / CI:**

- `golangci-lint`, `gosec`, `govulncheck`

---

## Configuration

### ssh-cert-api Environment Variables

| Variable               | Default               | Description                                                                                               |
| ---------------------- | --------------------- | --------------------------------------------------------------------------------------------------------- |
| `CONFIG_PATH`          | `configs/config.yaml` | Path to authorization config file                                                                         |
| `AWS_REGION`           | `us-east-1`           | AWS region for the host's attested KMS `Decrypt` during CA-key load                                       |
| `CERBERUS_SIGNER_ENDPOINT` | —                 | Override the signer dial target as `scheme://addr` (e.g. `vsock://16:5000`, `tcp://127.0.0.1:5000`, `unix:///run/usbhsm.sock`). Unset → the compile-time VSOCK CID `16` / port `5000` in `constants/`. |
| `RATE_LIMIT_RPS`       | `5`                   | Per-principal `/sign` rate limit, requests per second                                                     |
| `RATE_LIMIT_BURST`     | `10`                  | Per-principal burst allowance                                                                             |
| `LOG_FORMAT`           | `text`                | `json` emits structured slog JSON for log aggregation; anything else emits human-readable text            |
| `DEBUG`                | `false`               | Enable debug-level logging                                                                                |

> The Kerberos **keytab path is not an environment variable** — it is set via the `keytab_path` field in `config.yaml`. The keytab must be mode `0600` or `0400`; group/world-readable keytabs refuse startup.

### ssh-cert-signer Environment Variables

| Variable              | Default                       | Description                                                                                                                                                                                                         |
| --------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CA_KEY_FILE_PATH`    | `/app/ca_key.enc`             | Path to KMS-encrypted CA private key (non-secret ciphertext baked into the EIF)                                                                                                                                    |
| `CA_PUBLIC_KEY_PATH`  | `/app/ca_key.pub` (set in the EIF) | Path to the CA public key, baked into the EIF alongside the ciphertext and covered by PCR0. The packaged `Dockerfile` COPYs `ca_key.pub` and sets this variable, so the pin is **active by default** in packaged builds: the enclave verifies the decrypted CA key's public half against it and refuses on mismatch (defense-in-depth on top of the KMS key policy). The enclave code itself still treats the pin as opt-in — an EIF built without `ca_key.pub` and without this variable logs `loadkey.ca_pubkey.unpinned` at WARN and proceeds. To opt out, remove the `ca_key.pub` COPY/ENV from the `Dockerfile`. |
| `AWS_REGION`          | `us-east-1`                   | AWS region for KMS operations (used by the **host** when it calls `kms:Decrypt` on behalf of the enclave)                                                                                                          |
| `REQUIRE_ATTESTATION` | `true` when `/dev/nsm` exists | If `true`, the signer generates an NSM attestation document for the host-mediated KMS Decrypt flow. Set to `false` only for local development without a Nitro device — never in production. Accepts `true/1/yes` or `false/0/no` (case-insensitive); when **unset** it auto-detects `/dev/nsm`. Any other value (a typo, or an explicitly empty string) is rejected at startup so a misconfiguration fails closed instead of silently disabling attestation. |
| `LOG_FORMAT`          | `text`                        | `json` emits structured slog JSON; anything else emits text                                                                                                                                                         |
| `DEBUG`               | `false`                       | Enable debug-level logging                                                                                                                                                                                          |

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

# Optional: realms whose @REALM suffix is stripped before the static members:
# match, so members can be listed by bare short name (alice) instead of the
# full alice@REALM.COM. Omit to keep exact uid@REALM matching. When enabled,
# write members: for the listed realms as bare names. See "Realm stripping".
# strip_realms:
#   - "REALM.COM"

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
        team@example.com: "backend"          # Namespace custom names per PROTOCOL.certkeys §4
        access-level@example.com: "production"
      critical_options:                       # SSH critical options
        source-address: "10.20.30.0/24"
```

**Authorization flow**: The API matches the authenticated Kerberos principal against group membership. When a user belongs to multiple groups, the API picks the **first group in alphabetical order by group name** whose `allowed_principals` cover **every** principal in the request. Principals are *not* combined across groups within a single request — pick the right group, or the request is rejected with `403`. Enforcement is in `ssh-cert-api/internal/authz/casbin.go`.

**All-principals expansion** (`all_principals: true`): a `/sign` request may set `all_principals: true` (mutually exclusive with `principals`) to mint a cert for **every** principal in the user's **first group** (alphabetically). The API expands that group's finite `allowed_principals`, deduped and capped at 100. If the selected group grants `allowed_principals: ["*"]` (any principal), the request is **refused with a 400** — an unbounded set cannot be enumerated into a certificate; the caller must request explicit principals instead. The `cssh` client exposes this as `cssh --sign-only --all-principals` (see `docs/cssh.md`).

**Self-service certificates**: with the top-level `self_principal:` block enabled, an authenticated user may obtain a cert for their **own short uid** — `jsmith@FOO.COM` → principal `jsmith` — without being enumerated in any group. Granted two ways, both of which issue a cert for *exactly* the authenticated uid:

- **Explicitly** — a `/sign` request with `self_principal: true` (mutually exclusive with `principals`/`all_principals`); the server derives the uid from the authenticated identity. This is what `cssh --self --sign-only` sends.
- **Implicitly** — a normal request whose `principals` are **exactly** the caller's own uid (e.g. `jsmith` requesting `["jsmith"]`) that no group covers is accepted via the self path. The "requested principal equals the authenticated uid" check *is* the verification. This is what makes a plain `cssh jsmith@host` (or `cssh host` when the login equals your uid) connect succeed without group membership. A request for any *other* principal is unaffected — it still needs a group.

It is constrained so it stays safe:

- **Realm allowlist** (`self_principal.realms`): only callers whose Kerberos realm is listed may self-issue. This blocks the cross-realm collision where `jsmith@FOO.COM` and `jsmith@BAR.COM` would both map onto local account `jsmith`. Single-realm shops list their one realm.
- **Denylist** (`self_principal.deny`): short uids that may never be self-issued. **`root` is always denied** — a hard floor the code adds that config cannot remove; add your shared/role accounts (`deploy`, `postgres`, …). Obtaining `root` requires a deliberate group with `allowed_principals: ["root"]`.
- **Cert parameters** come from `self_principal.certificate_rules` (validity, permissions, extensions); its `allowed_principals` is ignored (the principal is the uid).
- **The server is still the final gate.** A self-issued `jsmith` cert only opens accounts sshd authorizes for principal `jsmith` (by default the local account named `jsmith`, or an [AuthorizedPrincipalsFile](#authorizedprincipalsfile-advanced-1-to-1-mapping) mapping). In a fleet where accounts are provisioned per-human with matching names, the blast radius is exactly the user's own account. Pair it with `AuthorizedPrincipalsFile` for explicit identity→account mapping.

Config:

```yaml
self_principal:
  enabled: true
  realms: [EXAMPLE.COM]        # allowlist; a caller's realm must be listed
  deny: [deploy]               # 'root' is always denied regardless of this list
  certificate_rules:
    validity: "8h"
    permissions:
      permit-pty: ""
```

In the `cssh` client: `cssh --self --sign-only` explicitly fetches your own cert (the flag requires `--sign-only`), and a normal `cssh jsmith@host` / `cssh host` connect is accepted implicitly via the self path. See `docs/cssh.md`.

**Realm stripping** (`strip_realms:`): SPNEGO/GSSAPI authenticates users as `uid@REALM.COM`, so by default every static `members:` entry must be written in that fully-qualified form. Listing a realm under the top-level `strip_realms:` removes the `@REALM` suffix from an authenticated principal **before** the static `members:` match, letting you enumerate members by bare short name (`alice`) instead of `alice@REALM.COM`. It is opt-in and off by default; an empty or omitted list preserves exact `uid@REALM` matching.

- **Scoping is per-realm, deliberately.** Only principals whose realm is listed are stripped; identities in unlisted realms keep the full `uid@REALM` form. `alice@EXAMPLE.COM` and `alice@OTHER.COM` therefore never collapse onto the same `members:` entry unless you list **both** realms — do that only if that collision is intended.
- **When enabled, write `members:` for the listed realms as bare names.** With `strip_realms: ["REALM.COM"]`, the lookup key for `alice@REALM.COM` becomes `alice`, so the group must list `alice`, not `alice@REALM.COM` (the latter would no longer match). Members in *unlisted* realms are still listed in full form.
- **LDAP-backed groups are unaffected.** `strip_realms` touches only the static `members:` lookup. The LDAP resolver always receives the full `uid@REALM` string, so realm routing for `ldap_groups:` is unchanged.
- **Matching is case-sensitive.** Kerberos realms are conventionally uppercase; a lowercase entry strips nothing and is surfaced at startup as `slog.Warn("config.strip_realm.lowercase", "key", ...)`. A blank/whitespace entry is a hard startup failure.
- Audit logs (`auth.success`, `sign.request`) and the per-principal rate limiter always key on the full `uid@REALM`, regardless of this setting.

### OIDC / OAuth Bearer Authentication

Cerberus can accept **OIDC bearer tokens** (`Authorization: Bearer <JWT>`) as a second authentication method alongside Kerberos/SPNEGO — for users backed by a cloud IdP (Okta, Azure AD, Google, Keycloak, …) rather than a Kerberos ticket. It is opt-in via the top-level `oauth:` block; omit it (or set `enabled: false`) and the service behaves exactly as a Kerberos-only deployment. When enabled the API dispatches on the `Authorization` scheme — `Negotiate` → Kerberos, `Bearer` → OIDC — and an unauthenticated `/sign` is challenged with **both** `WWW-Authenticate: Negotiate` and `WWW-Authenticate: Bearer`.

Tokens are validated **entirely offline**: the issuer's JWKS is discovered at startup (`/.well-known/openid-configuration`) and cached (refreshed on key rotation); every request verifies the JWT signature, `iss`, `aud`, and `exp`/`nbf`/`iat` (with `leeway` clock-skew tolerance). The enclave is never involved — validation happens entirely on the host, which already has network.

**Identity vs authorization.** The token's `username_claim` plus the configured `realm` label form the `Username@Realm` identity used for the cert `KeyID`, audit logs, and per-principal rate limiting — the same contract a Kerberos principal has. **Authorization is separate**: it comes from the token's `groups_claim`, whose values are matched against per-group `oidc_groups:` bindings, exactly parallel to LDAP `ldap_groups:`. The groups claim never influences the cert identity, and the identity claims never grant access. OIDC requests are authorized **only** via `oidc_groups` — an OIDC identity never matches a static `members:` entry or an LDAP group even if its `realm` label collides with a Kerberos/LDAP realm (the namespaces are isolated in `candidateGroups`), so the label is a cosmetic identity tag for authz purposes.

| Key | Meaning | Default |
| --------------- | ------------------------------------------------------------------ | ------------- |
| `enabled` | Turn OIDC bearer auth on | `false` |
| `issuer` | OIDC issuer URL (discovery base); startup fails fast if unreachable | — (required) |
| `audiences` | Acceptable `aud` values; a token must carry at least one | — (required) |
| `username_claim` | Claim used as the short uid | `sub` |
| `groups_claim` | Claim (JSON array) matched against `oidc_groups:` | `groups` |
| `realm` | Synthetic realm label for the `Username@Realm` identity | — (required) |
| `algorithms` | Accepted JWS signing algorithms (asymmetric only) | `["RS256"]` |
| `leeway` | Clock-skew tolerance for `exp`/`nbf`/`iat` | `60s` |
| `http_timeout` | Timeout for discovery and JWKS fetches | `5s` |

```yaml
oauth:
  enabled: true
  issuer: "https://idp.example.com"
  audiences: ["cerberus"]
  username_claim: "preferred_username"
  groups_claim: "groups"
  realm: "OIDC"
  algorithms: ["RS256"]
  leeway: "60s"
  http_timeout: "5s"

groups:
  oidc-admins:
    oidc_groups: ["platform-eng"]        # matched against the token's groups claim
    certificate_rules:
      validity: "8h"
      allowed_principals: ["root"]
      permissions: { permit-pty: "" }
```

**Setup.**

1. Register this service with the IdP and note the audience/client identifier it mints into tokens; list it under `audiences`.
2. Choose `username_claim` (`sub` is stable but opaque; `preferred_username`/`email` are human-readable) and a `groups_claim` your IdP populates.
3. Pick a `realm` label **distinct from every Kerberos and LDAP realm and every `strip_realms` entry** — a collision would misroute OIDC identities into LDAP or strip their realm, and is warned at startup (`config.oauth.realm_collision`).
4. Map IdP groups to Cerberus groups with `oidc_groups:`. A group has exactly one membership source — `oidc_groups` cannot coexist with `members:` or `ldap_groups:`.

**Security notes.**

- **Algorithm-confusion is blocked two ways:** only asymmetric algorithms are accepted (`none` and any HMAC `HS*` are rejected at config load **and** at verification), so the issuer's public keys can never be abused as an HMAC secret.
- **Group authorization is namespace-isolated.** An OIDC request resolves membership *only* from `oidc_groups`, never static `members:` or LDAP, so a token's `username_claim` can never grant a Kerberos/LDAP group even if `realm` collides with a real realm.
- **`self_principal` + OIDC needs a trustworthy username claim.** If `self_principal` is enabled *and* the OIDC `realm` is listed in `self_principal.realms`, an OIDC user can self-issue a cert for their `username_claim` value. Use a claim the user cannot edit at the IdP and that is unique per person (`sub` is safest; `email`/`preferred_username` only if the IdP guarantees them). A mutable or non-unique claim would let one user self-issue for another's uid, and also conflates audit logs and rate-limit buckets.
- **Client tokens are cached on disk.** `cssh` can obtain a token via the OAuth 2.0 Device Authorization Grant (`cssh --oauth` / `CSSH_AUTH=oidc`), caching the access token and (when the IdP grants `offline_access`) a refresh token under `~/.cache/cerberus/oidc-token.json` (mode `0600`) with silent refresh; callers may also supply a token out-of-band. A leaked token — or the cached refresh token — is replayable until it expires or is revoked at the IdP, so treat the cache as a credential and keep `leeway` small (default 60s; > 2m is warned as `config.oauth.leeway_long`). See `docs/cssh.md`.
- **Network-restrict the bearer edge.** A token with an unknown key id triggers a JWKS refetch in the auth middleware *before* the per-principal rate limiter, so an unauthenticated flood of bogus-`kid` tokens can drive outbound IdP fetches (bounded by `http_timeout` and go-oidc's single-flight). Protect the edge with the same network ACL you use for `/health` and `/metrics`.
- **Startup couples to the IdP.** Like the LDAP initial-bind probe, the API refuses to start if issuer discovery fails.

**Troubleshooting.**

| Symptom | Cause / fix |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `401` with `WWW-Authenticate: Negotiate` + `Bearer` | Missing/invalid credential; expected for the first probe. Send a valid bearer token. |
| `token verification failed` in `auth.failed` | Bad signature, wrong `iss`, unknown `kid`, or a disallowed `alg`. Confirm `issuer` matches the token and the signing alg is in `algorithms`. |
| `token audience … not in the allowed set` | The token's `aud` isn't in `audiences`. Add this service's audience. |
| `token expired` / `token not yet valid` | Clock skew between IdP and host beyond `leeway`; sync NTP or raise `leeway` slightly. |
| `username claim "…" is empty or missing` | The `username_claim` isn't present in the token; pick a claim the IdP emits. |
| Authenticated user gets `403` | Their token's `groups_claim` values match no `oidc_groups:` binding. (A group using `oidc_groups` while `oauth.enabled` is false is a hard startup error, not a 403.) |
| Startup aborts: `Failed to initialize OIDC authenticator` | Issuer discovery failed — unreachable/misconfigured `issuer`, or `http_timeout` too low. |

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

### SSH Certificate Extensions and Critical Options

OpenSSH dispatches certificate extensions and critical options through a hardcoded table in `auth-options.c` (`cert_parse_options`). Anything outside that table that appears in an issued certificate is handled as follows:

- **Unknown extension** → sshd logs `Certificate extension "<name>" is not supported` at `LogLevel INFO` and **ignores** it. The cert still authenticates.
- **Unknown critical option** → sshd logs an `error` and **rejects** the certificate.

This is why `permissions:` in a group's `certificate_rules` should only contain names from the recognized extensions list, and `critical_options:` should only contain names from the recognized critical options list. `static_attributes:` is the place for custom metadata — those land in the cert's extensions list and are read by downstream tooling (e.g., `ssh-keygen -L -f cert.pub`), not by sshd's authorization logic.

#### Recognized by stock OpenSSH

| Type            | Name                      | Effect                                                                      |
| --------------- | ------------------------- | --------------------------------------------------------------------------- |
| Extension       | `permit-X11-forwarding`   | Allow `ssh -X` / `-Y`                                                       |
| Extension       | `permit-agent-forwarding` | Allow `ssh -A`                                                              |
| Extension       | `permit-port-forwarding`  | Allow `-L`, `-R`, `-D`                                                      |
| Extension       | `permit-pty`              | Allow PTY allocation (required for interactive shells)                      |
| Extension       | `permit-user-rc`          | Run user's `~/.ssh/rc` on connection                                        |
| Extension       | `no-touch-required`       | FIDO/U2F: skip the touch requirement                                        |
| Critical option | `force-command`           | Override the user's command with the value (e.g., restrict to `rsync` only) |
| Critical option | `source-address`          | Comma-separated CIDR list; cert is only valid from these addresses          |
| Critical option | `verify-required`         | FIDO/U2F: require user verification (PIN/biometric) in addition to presence |

Anything else — including names cerberus operators add via `static_attributes:` — falls through to the "not supported" branch. That's expected and harmless.

#### Custom extension naming

Per the SSH certificate spec ([PROTOCOL.certkeys §4, "Custom Extensions"](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys)), names that are not defined by OpenSSH **must** be namespaced as `name@domain` to avoid collisions with future standard extensions. Cerberus example configs use `name@example.com`; replace the domain with your organization's. Namespacing does **not** suppress the sshd warning — the dispatch table is still hardcoded — but it documents intent and prevents collisions if OpenSSH later adopts a standard extension with the same bare name.

At startup, `ssh-cert-api` walks every group's `static_attributes:` and emits one structured `slog.Warn("config.static_attribute.not_namespaced", "group", ..., "key", ...)` per bare key. This is non-fatal — the service still starts — so legacy deployments can migrate gradually, but the warning surfaces the migration debt in operator logs.

#### Acting on custom extensions server-side

Stock sshd cannot make authorization decisions based on a custom extension; the dispatch is hardcoded. If you need to gate logins on `team`, `access-level`, etc., use `AuthorizedPrincipalsCommand` in `sshd_config`:

```
AuthorizedPrincipalsCommand /usr/local/bin/check-cert-policy %u %k %t %f
AuthorizedPrincipalsCommandUser nobody
```

The script receives the certificate, runs `ssh-keygen -L -f -` against it, and writes the allowed principals (or nothing, to deny) on stdout.

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

**Prerequisite — the encrypted CA key must already exist at `ssh-cert-signer/ca_key.enc`.** The `Dockerfile` `COPY`s this file into the image, so the encrypted key is baked into the EIF. Without it, `docker buildx build` will fail with a `COPY` error. To create it:

```bash
make -C ssh-cert-signer encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:<region>:<account>:key/<key-id>
# or, if you already have ca_key.enc somewhere else:
cp /path/to/ca_key.enc ssh-cert-signer/
```

Then build:

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

> **Important**: Because `ca_key.enc` is baked into the EIF, any CA key rotation (or any code/binary change) produces a new PCR0. After building a new EIF, update the KMS key policy with the new PCR values from the manifest **before** deploying the new EIF if using attestation-based conditions — see [Updating the EIF](#updating-the-eif-enclave-image).

### Clean Build Artifacts

```bash
make clean
```

---

## RPM Packaging

Cerberus provides RPM packaging for Amazon Linux 2, Amazon Linux 2023, RHEL, and Fedora. The spec produces two subpackages by default, plus one optional package:

| Package               | Contents                                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `cerberus-api`        | API binary, systemd unit, sysconfig, example config, `cerberus` user/group                                                            |
| `cerberus-signer`     | Signer binary, Dockerfile, systemd unit, sysconfig, enclave lifecycle script                                                          |
| `cerberus-signer-eif` | **Optional, opt-in.** A prebuilt Enclave Image File. Built only with `--eif` (see below); carries CA key material — per-deployment, per-arch |

> By default the `cerberus-signer` RPM does **not** ship the Enclave Image File. The EIF bakes in the KMS-encrypted CA key (the `Dockerfile` `COPY`s `ca_key.enc` into the image) and pins a deployment-specific PCR0, so it is a per-deployment artifact rather than a redistributable one. The default flow is to build it with `make eif-<arch>` and drop it into `/usr/share/cerberus/` after installing the RPM (see [Post-Install Setup](#post-install-setup-rpm), step 4).
>
> If you prefer to ship a deployment as a single artifact, build the **optional** `cerberus-signer-eif` package (`build-rpm.sh --eif <path>`, below). It bundles one prebuilt EIF at `/usr/share/cerberus/ssh-cert-signer.eif`. Because that EIF carries the KMS-encrypted CA private key **and** the PCR0-pinned public key, this package is **per-deployment and per-architecture** — treat it as sensitive and distribute it **only over an operator-controlled channel, never a shared or public repository** (see the [Threat Model](THREAT-MODEL.md) note on the RPM channel).

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

**Also bundle the EIF (optional `cerberus-signer-eif` package):**

```bash
# Build the EIF first (see "Build Enclave Image Files (EIF)"), then:
./packaging/rpm/build-rpm.sh --eif ssh-cert-signer/ssh-cert-signer-amd64.eif
```

`--eif` is incompatible with `--mock` (the per-deployment EIF must be built on a trusted host, not a clean chroot), and the EIF's architecture must match the RPM build architecture. The resulting `cerberus-signer-eif` RPM carries CA key material — see the note under [RPM Packaging](#rpm-packaging).

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

| File                  | RPM Path                                          | Notes                                                    |
| --------------------- | ------------------------------------------------- | -------------------------------------------------------- |
| API binary            | `/usr/bin/ssh-cert-api`                           | —                                                        |
| Signer binary         | `/usr/bin/ssh-cert-signer`                        | —                                                        |
| API systemd unit      | `/usr/lib/systemd/system/cerberus-api.service`    | —                                                        |
| Signer systemd unit   | `/usr/lib/systemd/system/cerberus-signer.service` | —                                                        |
| API sysconfig         | `/etc/sysconfig/cerberus-api`                     | `%config(noreplace)`                                     |
| Signer sysconfig      | `/etc/sysconfig/cerberus-signer`                  | `%config(noreplace)`                                     |
| Example config        | `/etc/cerberus/config.yaml.example`               | Copy to `config.yaml`                                    |
| Enclave wrapper       | `/usr/libexec/cerberus/run-enclave.sh`            | Used by systemd                                          |
| Dockerfile            | `/usr/share/cerberus/Dockerfile`                  | For building EIFs                                        |
| EIF                   | `/usr/share/cerberus/ssh-cert-signer.eif`         | Operator copies post-install, **or** shipped by the optional `cerberus-signer-eif` package |
| Log directory         | `/var/log/cerberus/`                              | Owned by `cerberus` user                                 |

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
4. **Place the EIF** at `/usr/share/cerberus/ssh-cert-signer.eif`. *Skip this step if you installed the optional `cerberus-signer-eif` package — it already put the EIF there.* Otherwise build (or copy) the EIF, **renaming on copy** to `ssh-cert-signer.eif`. The RPM is per-architecture, so only one EIF arch is ever valid for a given host — the sysconfig points at a single arch-less path:
   ```bash
   # x86_64 host
   sudo cp ssh-cert-signer-amd64.eif /usr/share/cerberus/ssh-cert-signer.eif
   # aarch64 host
   sudo cp ssh-cert-signer-arm64.eif /usr/share/cerberus/ssh-cert-signer.eif
   ```
   By default the EIF is not bundled because it carries the KMS-encrypted CA key — see the note under [RPM Packaging](#rpm-packaging).
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

**`/etc/sysconfig/cerberus-api`**: `CONFIG_PATH`, `AWS_REGION`, `CERBERUS_SIGNER_ENDPOINT` (optional), `DEBUG` (the keytab path is set in `config.yaml` via `keytab_path`, not here)

**`/etc/sysconfig/cerberus-signer`**: `EIF_PATH`, `ENCLAVE_CID`, `ENCLAVE_CPU_COUNT`, `ENCLAVE_MEMORY_MIB`, `ENCLAVE_DEBUG` (the older `ARCH` variable was removed; `EIF_PATH` is now a single arch-less path — `/usr/share/cerberus/ssh-cert-signer.eif` — that operators populate post-install by renaming the per-arch build output)

### Versioning

The RPM version is read from the `VERSION` file in the project root. Bump it before building a release:

```bash
echo "1.0.0" > VERSION
```

### Arch Linux packages

The repo also ships Arch Linux packaging in [`packaging/arch/`](../packaging/arch/) — a `makepkg` split package mirroring the RPM: `cerberus-api`, `cerberus-signer`, `cerberus-client` (noarch), and the opt-in `cerberus-signer-eif`. Build it as a **regular user** (`makepkg` refuses to run as root), with `base-devel` and `go` installed:

```bash
./packaging/arch/build-arch.sh                                   # → ./archbuild/*.pkg.tar.zst
./packaging/arch/build-arch.sh --eif ssh-cert-signer/ssh-cert-signer-amd64.eif   # opt-in EIF package
sudo pacman -U ./archbuild/cerberus-client-*.pkg.tar.zst
```

`build-arch.sh` stages the same source-tarball snapshot as `build-rpm.sh` and pins `pkgver` from `VERSION`. The Arch packages follow Arch/systemd conventions: service env files live in `/etc/conf.d/` (not `/etc/sysconfig/`), the enclave wrapper is at `/usr/lib/cerberus/run-enclave.sh`, and the `cerberus` user plus `/var/log/cerberus` are created declaratively via `sysusers.d`/`tmpfiles.d` (pacman hooks) rather than a scriptlet. The opt-in `cerberus-signer-eif` package carries per-deployment CA key material — the same distribution caveat as the RPM applies. See [`packaging/arch/README.md`](../packaging/arch/README.md).

### Debian / Ubuntu packages

The repo also ships Debian packaging in [`packaging/debian/`](../packaging/debian/) — a `debhelper` multi-binary source package mirroring the RPM: `cerberus-api`, `cerberus-signer`, `cerberus-client` (`Architecture: all`), and the opt-in `cerberus-signer-eif` (built under the `pkg.cerberus.eif` build profile). Build it with `build-essential debhelper dpkg-dev fakeroot` installed and Go ≥ 1.26 on PATH (newer than the distro `golang-go`):

```bash
./packaging/debian/build-deb.sh                                    # → ./debbuild/*.deb
./packaging/debian/build-deb.sh --eif ssh-cert-signer/ssh-cert-signer-amd64.eif   # opt-in EIF package
sudo apt install ./debbuild/cerberus-client_*.deb
```

`build-deb.sh` stages the same source snapshot as `build-rpm.sh` and pins the `debian/changelog` version from `VERSION` (`3.0 (native)` format, so no orig tarball). The Debian packages follow Debian/systemd conventions: service env files live in `/etc/default/` (not `/etc/sysconfig/`), the enclave wrapper is `/usr/lib/cerberus/run-enclave.sh`, files under `/etc` are dpkg conffiles, and the `cerberus` user plus `/var/log/cerberus` are created via `sysusers.d`/`tmpfiles.d` (needs debhelper ≥ 13.6, i.e. Debian 12 / Ubuntu 22.04+). Units are installed **without** being enabled/started (they need site config and a Nitro host). The opt-in `cerberus-signer-eif` package carries per-deployment CA key material — same distribution caveat as the RPM. See [`packaging/debian/README.md`](../packaging/debian/README.md).

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

- **No authentication required.**
- Reflects the cached result of a background enclave probe — a `HealthMonitor` goroutine pings the signer every 5 seconds (2-second probe timeout) and the handler reads the most recent snapshot. The request path **never** opens a VSOCK connection.
- Returns HTTP 200 with `{"status": "healthy"}` when the most recent probe succeeded and the signer reports a loaded CA key.
- Returns HTTP 503 with a JSON body of `{"status": "unhealthy", "reason": "..."}` for these failure modes:
  - `"starting up"` — no probe has completed yet.
  - `"health check stale"` — the cached snapshot is older than 30 seconds (the monitor goroutine is likely stuck or the enclave is unreachable).
  - `"enclave unreachable"` — the last probe failed (VSOCK dial error, timeout, or signer side closed).
  - `"signer not loaded"` — the enclave is reachable but reports the CA key isn't loaded yet.
- The caching exists because the signer caps in-flight VSOCK connections at 32 (a shared semaphore covering `/sign` and health probes). Inline `/health` probing would let unauthenticated callers starve signing capacity, so **don't replace this with on-demand probing**.
- When LDAP RBAC is configured, the response body gains an `ldap` array with one entry per backend:
  ```json
  {
    "status": "healthy",
    "ldap": [
      { "name": "corp-ad", "healthy": true,  "last_checked": "2026-05-27T15:04:00Z" },
      { "name": "corp-openldap", "healthy": false, "last_checked": "...", "last_error": "ldap: connection refused" }
    ]
  }
  ```
  Per-backend status is **advisory** — the top-level `status` stays gated on the enclave staleness path so that a transient LDAP outage cannot stop static-only certificate issuance. Alert on `ldap[].healthy` separately (or scrape `cerberus_ldap_backend_up{backend="..."}` from `/metrics`).

### Metrics Endpoint

```
GET /metrics
```

- **No authentication required.** Standard Prometheus exposition format from `promhttp.Handler()`.
- Exposes `cerberus_sign_*` and `cerberus_enclave_errors_total` (request-path counters), plus the enclave-resource series populated by the background poller in `EnclaveMetricsCollector`:
  - `cerberus_enclave_cpu_seconds_total{mode="user|nice|system|idle|iowait|irq|softirq"}` - counter, seconds.
  - `cerberus_enclave_memory_bytes{type="total|available|free|buffers|cached"}` - gauge, bytes.
  - `cerberus_enclave_metrics_scrape_errors_total` - counter; increments on every failed VSOCK probe.
  - `cerberus_enclave_metrics_last_scrape_timestamp_seconds` - gauge; **0 until the first successful probe**, otherwise the Unix timestamp of the most recent success. use `time() - cerberus_enclave_metrics_last_scrape_timestamp_seconds > 60` as a staleness alert; this fires from process start until the first successful poll, which is the desired behavior.
  - **Network exposure**: like `/health`, this endpoint is unauthenticated by design so Prometheus can scrape without Kerberos. Unlike `/health`, the response now includes enclave-internal CPU and memory pressure data, which can be a useful side-channel signal to an attacker probing for OOM-triggering inputs or covert-channel timing. **Restrict `/metrics` to the Prometheus scraper subnet via security groups, ALB listener rules, or an in-service IP allow-list** - do not rely on obscurity.
  - Tune the poll cadence with `ENCLAVE_METRICS_INTERVAL` (Go duration, default `15s`, minimum `1s`). The poller probe-times-out at 2s per call; failed polls leave the previous snapshot in place, so dashboards see stale-but-monotonic counters until the enclave recovers.

### Monitoring Recommendations

| Check                    | Method                                                                                                                                                                                                       | Frequency |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- |
| API + enclave health     | `GET /health` → HTTP 200 (`status: healthy`); 503 includes a `reason` field — see [Health Endpoint](#health-endpoint)                                                                                        | Every 30s |
| Enclave resource metrics | `GET /metrics`; alert on `time() - cerberus_enclave_metrics_last_scrape_timestamp_seconds > 60` and on rate (`cerberus_enclave_metrics_scrape_errors_total`) > 0 - see [Metrics Endpoint](#metrics-endpoint) | Every 15s |
| Enclave process running  | `nitro-cli describe-enclaves` → State = RUNNING                                                                                                                                                              | Every 60s |
| End-to-end signing       | Test sign request with a service account                                                                                                                                                                     | Every 5m  |
| TLS certificate expiry   | Check cert NotAfter date                                                                                                                                                                                     | Daily     |
| Kerberos keytab validity | `klist -k /etc/krb5.keytab`                                                                                                                                                                                  | Daily     |
| KMS key accessibility    | `aws kms describe-key`                                                                                                                                                                                       | Every 5m  |
| Disk space               | Standard OS monitoring                                                                                                                                                                                       | Every 5m  |

### Key Log Messages

**Startup (API):**
```
Starting SSH Certificate API...
Loading CA key into enclave (host-mediated attested KMS decrypt)...
Enclave CA key loaded successfully
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

**Debug mode** (`DEBUG=true`) adds verbose output including VSOCK communication details. AWS credentials are not sent to the enclave; the host uses its EC2 instance role directly for the KMS call, so there is nothing to redact on the wire.

---

## Operational Procedures

### Rotating the CA Key

Because `ca_key.enc` (and `ca_key.pub`, the integrity pin) are baked into the EIF at Docker build time (the signer Dockerfile `COPY`s both into the image), CA-key rotation **always requires rebuilding the EIF**. This in turn changes PCR0, so attestation-based KMS policies must be updated before the new enclave can decrypt.

> **Before you begin — the CA key material is protected against accidental loss.** `make encrypt-ca-key` **refuses to run** if `ca_key`, `ca_key.pub`, or `ca_key.enc` already exist, and `make clean` never deletes them. Rotation is therefore a deliberate act: first remove the old material with `make -C ssh-cert-signer clean-ca-key` (or `rm -f ca_key ca_key.pub ca_key.enc`). Do this only when you truly intend to rotate — the new CA will not be trusted by any SSH server until you re-distribute the new `ca_key.pub` (step 7). The manual `ssh-keygen` in step 1 will also prompt before overwriting an existing `ca_key`; never overwrite a key you have not deliberately rotated.

> **Do the generate + encrypt on a trusted, single-tenant host, in a RAM-backed directory.** `/dev/shm` is tmpfs on Linux, so the plaintext CA key never touches durable storage — `shred` is not a guaranteed erase on SSD, copy-on-write, or journaled filesystems, so keeping the plaintext off disk entirely is the stronger control. `make -C ssh-cert-signer encrypt-ca-key KMS_KEY_ARN=...` does steps 1–3 below in one RAM-backed step (with a fallback where `/dev/shm` is unavailable).

1. Generate a new SSH CA key pair into a RAM-backed working directory:
   ```bash
   work=$(mktemp -d -p /dev/shm cerberus-ca.XXXXXX)
   ssh-keygen -t ed25519 -f "$work/ca_key" -N ""
   ```
2. Encrypt the private key with KMS, then move only the two safe artifacts (encrypted `ca_key.enc`, public `ca_key.pub`) into the current directory:
   ```bash
   aws kms encrypt \
     --key-id alias/cerberus-ca-key \
     --plaintext "fileb://$work/ca_key" \
     --output text --query CiphertextBlob | base64 -d > ca_key.enc
   cp "$work/ca_key.pub" ./ca_key.pub
   ```
3. Wipe the RAM-backed plaintext and working directory:
   ```bash
   shred -u "$work/ca_key" 2>/dev/null; rm -rf "$work"
   ```
4. Place the encrypted key **and the public key** into the build context and rebuild the EIF. The Dockerfile bakes `ca_key.pub` in as the `CA_PUBLIC_KEY_PATH` pin, so both files must be present (the `eif-*` targets refuse to build otherwise):
   ```bash
   cp ca_key.enc ca_key.pub ssh-cert-signer/
   make eif-amd64       # or eif-arm64
   ```
5. Update the KMS key policy with the new PCR0 from `ssh-cert-signer/pcr-manifest-<arch>.json` if you are using attestation-based conditions. Apply this **before** deploying the new EIF, or the new enclave will fail KMS Decrypt.
6. Copy the new EIF to the host (e.g. `/usr/share/cerberus/` for RPM installs, `/opt/cerberus/` for manual installs).
7. Distribute the new `ca_key.pub` to all SSH servers that trust the CA.
8. Restart the enclave (`sudo systemctl restart cerberus-signer` for RPM installs, or follow [Restarting the Enclave](#restarting-the-enclave)). The signer loads the key at startup.

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

### Managing LDAP RBAC

If a Cerberus group is LDAP-backed (`ldap_groups:` instead of `members:`), membership changes are made in the directory, not in `config.yaml`. The cache TTL configured per backend (default 60s, hard cap 10m) bounds how long a removed user can still authorize.

Operational notes:

- **Adding/removing users:** edit the LDAP group. No service restart required. The change takes effect within `cache_ttl` of the next authentication attempt for that user.
- **Adding a new LDAP backend or new Cerberus group binding:** edit `config.yaml` and restart `cerberus-api`. Backends are validated at startup; a misconfigured backend refuses to start the service (see [Troubleshooting](#authorization-failures)).
- **Rotating LDAP credentials:**
  - *Simple bind:* replace `/etc/cerberus/ldap.pw` (mode `0600`, owned by the service user) and `sudo systemctl restart cerberus-api`. The file is read once at startup; rotation requires a restart, the same model used by the Kerberos keytab.
  - *GSSAPI bind:* rotate the underlying keytab (see [Rotating the Kerberos Keytab](#rotating-the-kerberos-keytab)). GSSAPI bind reuses the API's keytab; the same restart picks up both.
  - *Anonymous bind:* no credentials to rotate.
- **Failure semantics:** LDAP-backed groups fail closed if the directory is unreachable — a `/sign` request from a user whose realm is covered by an unhealthy backend is denied (logged as `authz.ldap.error`). Static-only groups (`members:`) keep working through an LDAP outage. The top-level `/health` status does NOT flip red on LDAP failure (see [Health Endpoint](#health-endpoint)); alert on `ldap[].healthy` or the `cerberus_ldap_backend_up` gauge.
- **Disabling LDAP entirely:** delete the entire `ldap:` section from `config.yaml` and restart. Group definitions that still reference `ldap_groups:` will fail validation at startup, so either migrate them to `members:` or delete them at the same time.

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

After restarting the enclave, restart the API service as well (`sudo systemctl restart cerberus-api`). On startup the API performs the `BeginKeyLoad` / `CompleteKeyLoad` handshake: it reads `CA_KEY_FILE_PATH`, receives the enclave's NSM attestation document, calls `kms:Decrypt` with that document as `Recipient`, and sends the resulting `CiphertextForRecipient` to the enclave to install the CA signer. No manual intervention is required once both services are running.

### Updating the EIF (Enclave Image)

EIF builds can be done on any build host that has Go, Docker (with `buildx`), `nitro-cli`, and Python 3 installed — see [Software Dependencies](#software-dependencies). If you are rebuilding the EIF directly on the runtime EC2 instance using the shipped `/usr/share/cerberus/Dockerfile`, install Docker first (the `cerberus-signer` RPM does not require it): `sudo dnf install docker docker-buildx-plugin && sudo systemctl enable --now docker`.

1. Ensure `ssh-cert-signer/ca_key.enc` exists in the build context (see [Build Enclave Image Files (EIF)](#build-enclave-image-files-eif) for how to produce it).
2. Build a new EIF:
   ```bash
   make eif-amd64
   ```
3. Note the new PCR values from `ssh-cert-signer/pcr-manifest-amd64.json`.
4. If using attestation-based KMS policy, update the KMS key policy with the new PCR values **before** deploying the new EIF.
5. Copy the new EIF to the instance.
6. Terminate and relaunch the enclave (`sudo systemctl restart cerberus-signer` on RPM installs, or follow [Restarting the Enclave](#restarting-the-enclave)).

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
| `CA signer is not initialized`                  | Enclave hasn't loaded the CA key yet | Check enclave logs; verify the host can reach KMS (outbound TCP 443) and the instance role has `kms:Decrypt` with the attestation-conditioned key policy |
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

| Error                                                          | Likely Cause                                        | Resolution                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Not authorized for requested principals` (HTTP 403)           | User's group doesn't allow the requested principals | Check `allowed_principals` in the user's group config; `*` allows all                                                                                                                                                                                                                                               |
| User gets wrong permissions                                    | User matches the wrong group                        | Groups are evaluated in **alphabetical order by group name** — the first group whose `allowed_principals` cover the entire request wins. YAML map order is irrelevant. To change the winner, rename groups (e.g., prefix with `a-`) or tighten `allowed_principals` so only the intended group matches the request. |
| User not found in any group                                    | Principal not listed in any `members` list          | Add the user's full Kerberos principal (e.g., `user@REALM.COM`) to the appropriate group                                                                                                                                                                                                                            |
| HTTP 403 with `authz.ldap.error` in logs                       | LDAP backend unreachable or denied bind             | Check `cerberus_ldap_backend_up{backend="..."}` and the `ldap[]` array in `/health`. Fix the directory or credentials; if simple bind, verify `/etc/cerberus/ldap.pw` perms (`0600`) and contents. LDAP-backed groups fail closed by design — static groups (`members:`) are unaffected.                            |
| Service refuses to start with `ldap[...] initial probe failed` | Misconfigured LDAP backend at startup               | Verify `url:`, `bind:` credentials, and TLS settings. The service is intentionally strict here: a misconfigured directory should not silently degrade — restart only succeeds once every configured backend completes its initial bind.                                                                             |
| `realm "..." claimed by both backends`                         | Two LDAP backends list overlapping realms           | Make `realms:` disjoint across all `ldap:` entries. A Kerberos realm may map to at most one LDAP backend.                                                                                                                                                                                                           |

### VSOCK / KMS Issues

There is no longer a VSOCK KMS proxy. The host calls `kms:Decrypt` directly over its own network using the EC2 instance role; only the `CiphertextForRecipient` CMS envelope crosses VSOCK to the enclave.

| Symptom                                            | Likely Cause                                               | Resolution                                                                                                                                         |
| -------------------------------------------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Signing requests timeout                           | Enclave not running or VSOCK misconfigured                 | `nitro-cli describe-enclaves` — verify state is RUNNING and CID is 16                                                                             |
| `connection refused` on VSOCK                      | Wrong CID or port                                          | Verify CID=16 and port=5000 match between host and enclave                                                                                         |
| `Failed to load CA key into enclave` at API start  | Host KMS Decrypt failed                                    | Check outbound HTTPS (443) to `kms.<region>.amazonaws.com`; verify the instance role has `kms:Decrypt` with the PCR0-conditioned attestation policy |
| `KMS AccessDenied` in API logs                     | Instance role lacks `kms:Decrypt` or PCR mismatch         | Confirm the key policy requires `kms:RecipientAttestation:ImageSha384` matching the running EIF's PCR0 (see `pcr-manifest-<arch>.json`); confirm the instance role is the calling principal in the policy |
| `CA key does not match pinned public key`          | Baked `ca_key.pub` does not match the decrypted `ca_key.enc` | The EIF's `ca_key.pub` and `ca_key.enc` are from different keypairs. Rebuild the EIF with a matched pair from a single `make encrypt-ca-key` run (the `CA_PUBLIC_KEY_PATH` pin is baked into the EIF, not host sysconfig). |
| `loadkey.ca_pubkey.unpinned` WARN in enclave logs | EIF built without `ca_key.pub` / `CA_PUBLIC_KEY_PATH`     | The packaged `Dockerfile` bakes the pin by default, so this should not appear for a standard build. If it does, the EIF was built without `ca_key.pub` (pin disabled) — rebuild with the public key present to enable the pin, or treat as benign if you intentionally opted out. |
| Intermittent VSOCK failures                        | Resource exhaustion in enclave                             | Check enclave memory allocation (1024 MB minimum recommended)                                                                                      |

### Network & Connectivity

| Symptom                     | Likely Cause                         | Resolution                                                                   |
| --------------------------- | ------------------------------------ | ---------------------------------------------------------------------------- |
| Can't reach API from client | Security group blocks port 8443      | Add inbound rule for TCP 8443                                                |
| KMS calls fail              | No outbound internet or VPC endpoint | Set up a KMS VPC endpoint or ensure NAT gateway for outbound HTTPS           |
| TLS handshake failure       | Certificate doesn't match hostname   | Regenerate cert with correct SAN/CN, or use `-k` (insecure) for testing only |

### RPM Package Issues

| Symptom                                     | Likely Cause                                                                                                              | Resolution                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `cerberus` user doesn't exist after install | `%pre` scriptlet failed                                                                                                   | Run `sudo useradd -r -g cerberus -d /etc/cerberus -s /sbin/nologin cerberus`                                         |
| Config overwritten on upgrade               | Config not marked `noreplace`                                                                                             | Reinstall; configs use `%config(noreplace)` so this should not happen                                                |
| Service won't start after RPM install       | Missing config.yaml                                                                                                       | Copy `/etc/cerberus/config.yaml.example` to `/etc/cerberus/config.yaml` and edit it                                  |
| `run-enclave.sh: EIF file not found`        | EIF not placed at `/usr/share/cerberus/ssh-cert-signer.eif` (the default RPM does not ship it — it bakes in the encrypted CA key) | Copy and rename the matching arch's EIF: `sudo cp ssh-cert-signer-amd64.eif /usr/share/cerberus/ssh-cert-signer.eif` — or install the optional `cerberus-signer-eif` package |
| `refusing to generate a new CA key … already exists` | `make encrypt-ca-key` guards against clobbering existing CA key material (`ca_key`/`ca_key.pub`/`ca_key.enc`) | Intended for a deliberate rotation only. Remove the old material first: `make -C ssh-cert-signer clean-ca-key`, then re-run |
| Permission denied on keytab                 | Wrong ownership                                                                                                           | `sudo chown root:cerberus /etc/cerberus/krb5.keytab && sudo chmod 640 /etc/cerberus/krb5.keytab`                     |

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
ss -tlnp | grep 8443

# Check AWS credentials on the instance
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Security Considerations

### CA Key Protection

- The CA private key is **KMS-encrypted at rest** and only decrypted inside the Nitro Enclave.
- The plaintext key **never leaves the enclave** — it exists only in enclave memory.
- Use **attestation-based KMS policies** (PCR conditions) so only the specific enclave image can decrypt the key.
- **CRITICAL — KMS key policy requirement:** Because the host now holds `ca_key.enc` and calls `kms:Decrypt` itself, the KMS key policy **must** require a `kms:RecipientAttestation:ImageSha384` condition (PCR0) on every `Decrypt` action for the instance role. The policy must **not** grant the instance role any unconditioned `kms:Decrypt` — a compromised host that can call a plaintext Decrypt would read the CA private key. The calling principal (the instance IAM role) is unchanged from the previous design. See `docs/kms-attestation-policy.md` for the recommended policy template.
- **Protected against accidental loss/regeneration.** The public CA key must be trusted by every `sshd` (`TrustedUserCAKeys`), so regenerating the CA is expensive — do it only on suspected private-key compromise. The signer `Makefile` enforces this: `make encrypt-ca-key` **refuses** to overwrite an existing `ca_key`/`ca_key.pub`/`ca_key.enc`, and `make clean` never deletes them. Deliberate rotation requires an explicit `make -C ssh-cert-signer clean-ca-key` first (see [Rotating the CA Key](#rotating-the-ca-key)).
- **The optional `cerberus-signer-eif` RPM carries CA key material.** If you build it (`build-rpm.sh --eif`), that package embeds the KMS-encrypted CA key and the PCR0-pinned public key. It is per-deployment and per-architecture — distribute it only over an operator-controlled channel, never a shared or public repository.

### Network Security

- The enclave has **no network access** — it makes no external calls. The host performs the attested `kms:Decrypt` on the enclave's behalf using its own EC2 instance role; only the resulting CMS envelope (already encrypted to the enclave's attestation public key) crosses VSOCK.
- The API listens on HTTPS only (TLS required).
- Restrict access to port 8443 via security groups to authorized networks.
- **`/metrics` and `/health` are intentionally unauthenticated** so Prometheus and load balancers can reach them without Kerberos tickets. Both expose information about enclave state — `/metrics` in particular surfaces enclave CPU/memory pressure (see [Metrics Endpoint](#metrics-endpoint)). **Restrict these paths to known-good source ranges at the network layer** (security group, ALB listener rule, or in-service IP allow-list); the application does not enforce a source check.

### Authentication & Authorization

- All signing requests require **Kerberos/SPNEGO authentication**.
- Authorization is **group-based** with per-group certificate rules.
- Principals support **wildcard matching** — use carefully. A group with `allowed_principals: ["*"]` authorizes a user to request *any* principal, but the **issued certificate is always scoped to exactly the principals the user requested**, never the group's full `allowed_principals` list and never a literal `"*"`. Requesting `"*"` itself is rejected (it is meaningful only as a policy wildcard, not as a certificate principal).
- When a user is in multiple groups, the **first group alphabetically by name** whose `allowed_principals` cover the request wins. Reordering YAML keys won't change this — rename groups if you need a different winner.
- Per-principal rate limiting on `/sign` is on by default (`RATE_LIMIT_RPS=5`, `RATE_LIMIT_BURST=10`). Tune via env vars if needed.

### Certificate Safety

- Maximum validity is capped at **24 hours** (hardcoded).
- Certificates include a **5-minute clock skew** tolerance (valid 5 minutes before issuance).
- Each certificate gets a **cryptographically random** serial and nonce.
- `critical_options` like `source-address` can restrict certificate use to specific networks.

> **Enclave trust model:** the enclave validates structural properties of every signing request it receives over VSOCK (key algorithm and minimum strength, validity bound, principal count, empty/`"*"` principals, extension/critical-option key collisions) as defense-in-depth, but it does **not** re-run the host's authorization policy. The host API (`ssh-cert-api`) remains the authority for *which* principals, permissions, and critical options a given user may obtain. A compromise of the host process is therefore in scope for cert misuse (the CA key itself stays protected by the enclave + KMS PCR policy); protect the host accordingly.

### Credential Handling

- AWS credentials are **not sent to the enclave**. The host uses its EC2 instance role directly for the `kms:Decrypt` call; only the resulting `CiphertextForRecipient` CMS envelope (which is already encrypted to the enclave's ephemeral attestation public key) crosses VSOCK.
- Debug mode provides more verbose output about VSOCK message flow. There is no AWS secret material on the wire to redact.

### Audit Trail

- Every signing request is logged with the authenticated principal and key ID.
- Static attributes embedded in certificates (e.g., `team@example.com`, `access-level@example.com`) provide audit context. Namespace custom names per [SSH cert spec §4](#ssh-certificate-extensions-and-critical-options).

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

The workflow at `.github/workflows/go.yml` runs four jobs on every push and pull request to `main`. The first three use a per-module matrix (root, `ssh-cert-api`, `ssh-cert-signer`); the fourth iterates internally. Each job picks the toolchain from the target module's `go.mod` (currently 1.26):

1. **Build & test** (matrix per module)
   - `go build -v ./...`
   - `go mod tidy` drift check (fails if running `go mod tidy` would change `go.mod`/`go.sum`)
   - `go test -race -shuffle=on -count=1 ./...`
2. **golangci-lint** (matrix per module) — pinned `v2.12.2` with `.golangci.yml` (bodyclose, contextcheck, errorlint, misspell, nilerr, unconvert, plus `gofmt`/`goimports`)
3. **govulncheck** (matrix per module) — `golang.org/x/vuln/cmd/govulncheck@latest`
4. **gosec** (single job, iterates) — `github.com/securego/gosec/v2@latest` at `-severity=medium`, run sequentially on root, `ssh-cert-api`, and `ssh-cert-signer`

`gosec`, `golangci-lint`, and `govulncheck` are installed by the workflow (`go install`) rather than tracked as Go 1.24+ tool dependencies; this keeps them out of `go.sum` and shrinks the supply-chain surface of a signing service.

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
  "signed_key": "ssh-rsa-cert-v01@openssh.com AAAA..."
}
```

The field name is `signed_key` — defined by `messages.SigningResponse` (`messages/messages.go`) and validated by `messages/messages_test.go`. Don't rename in docs; this is the wire contract shared with stress clients and any future SDK.

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

#### AuthorizedPrincipalsFile (advanced 1-to-1 mapping)

By default, a Cerberus cert authenticates when the **local login name** you SSH to appears in the certificate's principals list — `ssh ec2-user@host` succeeds when the cert carries `ec2-user`. That keeps identity and account names in lock-step.

`AuthorizedPrincipalsFile` decouples them: for each local account (`%u`), sshd reads a file listing which **certificate principals** may assume that account. This lets you map a human identity principal (e.g. `alice`, or the realm-qualified `alice@EXAMPLE.COM` Cerberus signs) onto one or more local/role accounts (`deploy`, `ec2-user`) with an auditable, server-side allowlist — without the certificate having to carry the account name.

> When `AuthorizedPrincipalsFile` is set for an account, the implicit "login name must be a cert principal" rule **no longer applies** to that account: sshd accepts the login only if one of the cert's principals is listed in the file. List every allowed principal explicitly — including the account's own name, if you still want the default behavior for it.

**1. Point sshd at a per-account file** (`%u` expands to the target account name):

```
# /etc/ssh/sshd_config
TrustedUserCAKeys        /etc/ssh/cerberus-ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

**2. Create the mapping files.** The directory and files must be owned by root and not group/world-writable, or sshd's `StrictModes` ignores them:

```bash
sudo mkdir -p /etc/ssh/auth_principals
# Cert principals allowed to log in AS the local 'deploy' account:
printf '%s\n' alice bob carol@EXAMPLE.COM | sudo tee /etc/ssh/auth_principals/deploy
# ...and AS 'ec2-user':
printf '%s\n' alice | sudo tee /etc/ssh/auth_principals/ec2-user
sudo chmod 0755 /etc/ssh/auth_principals
sudo chmod 0644 /etc/ssh/auth_principals/*
sudo systemctl reload sshd
```

**3. Issue an identity-scoped cert and connect.** The cert carries the *human's* principal; the server decides which accounts it maps to:

```bash
cssh --principals alice --sign-only   # cert with principal "alice"
ssh deploy@server.example.com         # allowed: "alice" is listed in .../deploy
ssh ec2-user@server.example.com       # allowed: "alice" is listed in .../ec2-user
ssh root@server.example.com           # denied: no /etc/ssh/auth_principals/root
```

**Scope it to specific accounts.** Setting `AuthorizedPrincipalsFile` globally changes the rule for *every* account. To remap only some accounts and keep the default (principal == login name) everywhere else, put it in a `Match` block:

```
Match User deploy,ec2-user
    AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

**Static file vs. dynamic command.** `AuthorizedPrincipalsFile` is the static form. For decisions that depend on certificate *contents* — a custom `team` / `access-level` extension, time of day, an external lookup — use `AuthorizedPrincipalsCommand` instead (see [Acting on custom extensions server-side](#acting-on-custom-extensions-server-side)). Either way the mapping is an **additional** gate: the certificate must still be signed by the trusted CA, unexpired, and satisfy any `source-address` / critical options.

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

| File             | Location                                  | Notes                                                                                                                              |
| ---------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| API binary       | `/usr/bin/ssh-cert-api`                   | —                                                                                                                                  |
| Signer binary    | `/usr/bin/ssh-cert-signer`                | —                                                                                                                                  |
| API config       | `/etc/cerberus/config.yaml`               | Copy from `.example`                                                                                                               |
| API sysconfig    | `/etc/sysconfig/cerberus-api`             | Env vars                                                                                                                           |
| Signer sysconfig | `/etc/sysconfig/cerberus-signer`          | Enclave params                                                                                                                     |
| Kerberos keytab  | `/etc/cerberus/krb5.keytab`               | —                                                                                                                                  |
| Enclave wrapper  | `/usr/libexec/cerberus/run-enclave.sh`    | Used by systemd                                                                                                                    |
| EIF image        | `/usr/share/cerberus/ssh-cert-signer.eif` | Place after build; **rename on copy** — `EIF_PATH` is arch-less. The host RPM is per-arch, so only one EIF arch is valid per host. |
| Log directory    | `/var/log/cerberus/`                      | Owned by `cerberus`                                                                                                                |

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

| Port | Protocol | Service         | Purpose                          |
| ---- | -------- | --------------- | -------------------------------- |
| 8443 | HTTPS    | ssh-cert-api    | Client-facing API                |
| 5000 | VSOCK    | ssh-cert-signer | Key-load and signing (Host → Enclave) |
