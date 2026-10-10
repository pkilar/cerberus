# Threat model

This is a guide for automated scanning. The full threat model is `docs/THREAT-MODEL.md`: 82 numbered threats with IDs such as `SIGN-1`, trust boundaries, and the controls enforced in code versus by deployment. `AGENTS.md` describes the current key-load design.

## What this project does and where untrusted input enters

Cerberus is an SSH certificate authority. A user authenticates to an HTTPS gateway, `ssh-cert-api`, with Kerberos SPNEGO or an OIDC bearer token. The gateway checks the requested principals against a Casbin policy built from static members, LDAP groups or OIDC groups. It then sends a signing request over VSOCK to `ssh-cert-signer`, which runs inside an AWS Nitro Enclave, holds the CA private key, and returns a user certificate.

The CA key is stored KMS-encrypted. At startup the host calls `kms.Decrypt` with the enclave's attestation document. KMS encrypts the result to the enclave's ephemeral key, and the host relays that CMS envelope into the enclave. The host never sees the plaintext key.

Entry points, by attacker:

1. **Unauthenticated network client → `ssh-cert-api`.**
   - SPNEGO `Negotiate` and OIDC `Bearer` header parsing.
   - `GET /health` and `GET /metrics`.
   - The optional plain-HTTP observability listener, which must serve only `/health` and `/metrics`.
2. **Authenticated user → `POST /sign` and `GET /policy`.**
   - The `/sign` body is JSON, capped at 64 KiB. It carries:
     - principals, `all_principals` or `self_principal`
     - validity
     - extensions and permissions
     - the public key
   - The attacker's goal is a certificate for a principal they are not granted, a longer validity, or extra permissions.
3. **Compromised host (root on the parent EC2 instance) → enclave over VSOCK.**
   - The protocol is newline-delimited JSON (`messages/messages.go`) with five request types: `BeginKeyLoad`, `CompleteKeyLoad`, `SignSshKey`, `Ping` and `GetEnclaveMetrics`.
   - `CompleteKeyLoad` delivers CMS envelope bytes the attacker chooses.
   - The enclave does not authenticate its caller.
   - A compromised host can already obtain certificates for any principal. This is accepted by design (`SIGN-1`).
   - Even then, the enclave must keep the CA key and enforce the certificate invariants below.
4. **Client side.**
   - `packaging/profile.d/cssh.sh` is sourced into users' shells.
   - `cmd/cerberus-session` is a renewal bridge on a unix socket forwarded with `ssh -R`.
   - Attackers:
     - another local user on the client machine (temp files, the OIDC token cache, certificate files)
     - a malicious or compromised SSH server that can reach the forwarded socket
     - a malicious API response
5. **`cmd/cerberus-vsock-watch` (`vsockwatch/`).**
   - A host-side detective control that flags unexpected VSOCK connections to the enclave.
   - The attacker is a host process trying to reach the enclave without being detected.

Config files, environment variables, the keytab, CLI flags and the KMS key policy are set by the operator and are trusted.

## Invariants a finding would break

Certificate contents:
- A certificate's principals come only from the authorizer's granted set, never directly from the request body.
- One policy group must cover the whole request. Grants are never combined across groups.
- `*` and empty principals are never issued. A certificate has at most 100 principals.
- Validity is greater than 0 and at most 24 hours (`messages.MaxValidity`). Both the API and the enclave enforce this.
- Only user certificates are issued. Serials and nonces come from `crypto/rand`.
- The submitted public key must be a bare key: RSA of at least 2048 bits, ECDSA P-256, P-384 or P-521, or Ed25519.

CA key:
- The CA private key never leaves enclave memory.
- `CompleteKeyLoad` without a preceding `BeginKeyLoad` is refused.
- Once a key is loaded, a different key is refused.
- The `CA_PUBLIC_KEY_PATH` pin is checked.
- `REQUIRE_ATTESTATION` fails closed on an empty or unknown value.

Gateway:
- If LDAP fails, groups backed by LDAP deny the request.
- `/sign` and `/policy` are never served on the plain-HTTP listener.

## Components that matter most / least

- **Most:**
  - in `ssh-cert-signer/`: `internal/handlers/sign-public-key.go`, `internal/handlers/load-key-signer.go`, `internal/attestation/` and `cmd/ssh-cert-signer/main.go`
  - `messages/`
  - in `ssh-cert-api/internal/`: `api`, `auth`, `authz`, `config`, `keyload` and `enclave`
- **Medium:** `ssh-cert-api/internal/ldap`, `packaging/profile.d/cssh.sh`, `cmd/cerberus-session`, `vsockwatch/` and rate limiting.
- **Least:**
  - `cmd/cerberus-stress`, a load-testing tool
  - test files and mocks
  - packaging metadata and docs
  - the prebuilt `vsockwatch/ebpf/src/*.bpf.o` objects (review the `.c` sources beside them instead)
- **Dependencies:** bugs in dependencies are in scope only where Cerberus feeds them attacker-controlled input. Examples:
  - the CMS parser in `github.com/pkilar/nitro-enclaves-sdk-go`, reached through `CompleteKeyLoad`
  - gokrb5, reached through SPNEGO

## How to exercise it

The image holds the checkout at `/src`, with unstripped binaries in `/src/bin`. There are three Go modules (`/src`, `/src/ssh-cert-api` and `/src/ssh-cert-signer`) and no `go.work`, so run `go` commands from inside each module directory.

- **Tests:** `go test -race ./...` in each module. The root `integration_test.go` drives a TCP loopback mock of the enclave.
- **Fuzzing:**
  - `cd /src/ssh-cert-signer && go test -fuzz=FuzzDecryptCMSEnvelope ./internal/attestation/`
  - `cd /src/ssh-cert-api && go test -fuzz=FuzzPrincipalRulesUnmarshal ./internal/config/`
  - Nothing fuzzes the `/sign` JSON body, the signer's request dispatch, SPNEGO handling or `cerberus-session` yet. These are good places to add a harness.
- **Running the binaries:**
  - The signer listens only on VSOCK. Drive its handlers through Go tests, as the `*_test.go` files in `ssh-cert-signer/internal/handlers` do.
  - The API can reach a signer over TCP or a unix socket through `CERBERUS_SIGNER_ENDPOINT` (`ssh-cert-api/internal/enclave/endpoint.go`).
  - `internal/api` tests use `httptest` with fake authenticators.
  - The real binaries need a keytab, a config file and AWS KMS at startup, so they do not run end to end offline. Prefer tests.
- **Client tests:** `make test-cssh` and `bash tests/cssh_login_as_test.sh`. They stub `curl`, `klist` and `ssh`.

## How you rate severity

- **Critical:**
  - A user, or an unauthenticated client, obtains a certificate for a principal they are not authorized for. This covers authentication bypass, authorization bypass and principal or group confusion.
  - The CA private key leaks out of the enclave.
  - The enclave can be made to sign with, or load, a key the attacker chooses.
- **High:**
  - From the host, an enclave-side certificate invariant can be bypassed: a `*` or empty principal, validity over 24 hours, a non-user certificate, or permissions the request did not carry.
  - An unauthenticated remote client can crash or hang `ssh-cert-api`.
  - VSOCK input can crash or hang the enclave, which stops all signing.
  - Through `cssh.sh` or `cerberus-session`, another local user or a remote SSH server can steal or replace a certificate or OIDC token, or force a renewal.
- **Medium:**
  - Denial of service by an authenticated user, such as bypassing the rate limiter or exhausting resources.
  - Evading `vsockwatch` detection.
  - Information disclosure through `/health`, `/metrics`, `/policy` or the logs that does not include secrets or tokens.
- **Low:** problems that need a non-default, insecure setting, or hardening suggestions without a demonstrated attack.

## Anything to leave alone

- A compromised host can request certificates for any principal, because the enclave trusts the host's authorization decision (`SIGN-1`). Report this only if an enclave-side invariant above also breaks.
- Threats already listed in `docs/THREAT-MODEL.md` are known. Report one only with a concrete attack that goes beyond the residual risk documented there.
- Behaviours that are deliberate:
  - There is no certificate revocation. The 24-hour validity cap is the revocation strategy.
  - `/metrics` is unauthenticated and protected by network ACLs.
  - The LDAP options `insecure_skip_verify` and `ldap://` are operator choices that log warnings.
- Development mode, where the signer runs without `/dev/nsm` and decrypts without attestation, has no isolation guarantee. So does `DEBUG=true`.
- Zeroing key material in Go memory is best effort (`KMS-6`).
- The KMS key policy is set when the service is deployed (`docs/kms-attestation-policy.md`) and is not part of the code.
