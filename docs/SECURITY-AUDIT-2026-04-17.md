# Cerberus Security Audit — 2026-04-17

Defensive security audit across five domains (injection, crypto/secrets/attestation, web/TLS/DoS, authn/authz, concurrency/deps) using parallel sub-agent analysis. All findings below verified against source before publication; agent-inflated severities recalibrated.

## Threat model recap

- Internet → HTTPS → `ssh-cert-api` (EC2 host) → VSOCK → `ssh-cert-signer` (Nitro Enclave).
- The CA private key must never exist in plaintext outside the enclave — enforced via KMS + NSM attestation.
- KMS traffic is tunneled through a VSOCK-to-TCP proxy on the host; TLS is terminated inside the enclave by the AWS SDK. The host can see ciphertext but not plaintext, provided the enclave's TLS roots weren't tampered with at build time AND attestation enforcement binds decryption to the enclave's RSA key.

## Findings

### HIGH

#### H-1. Silent fallback to non-attested KMS Decrypt — `ssh-cert-signer/internal/handlers/load-key-signer.go:91-102`

`if attestProvider != nil && attestProvider.IsAvailable()` gates attestation. If `/dev/nsm` is unavailable at runtime (device misconfig, AZ incident, build mishap), the signer silently downgrades to plaintext `kms.Decrypt()` and `decryptOutput.Plaintext` is returned at L125. Plaintext then lives in enclave memory — still inside the enclave — but the security-model invariant ("CA key is decryptable only by an attested image") is silently broken, which also means operator cannot trust that a future host-side TLS MitM (compromised enclave image) would be blocked at the KMS boundary.

**Fix:** Add strict mode. Detect `/dev/nsm` existence at startup; if present but `IsAvailable()==false`, fail loudly. Or introduce `REQUIRE_ATTESTATION=true` env var (default true in production builds) and refuse to load the key without attestation.

#### H-2. No request body size limit on `/sign` — `ssh-cert-api/internal/api/server.go:93`

`json.NewDecoder(r.Body).Decode(&req)` with no `http.MaxBytesReader`. Authenticated client can POST an unbounded body to exhaust memory.

**Fix:** `r.Body = http.MaxBytesReader(w, r.Body, 64*1024)` before Decode. 64 KB is generous for an SSH pubkey + principals.

#### H-3. Missing `ReadHeaderTimeout` / `IdleTimeout` on `http.Server` — `ssh-cert-api/cmd/ssh-cert-api/main.go:95-100`

Only `ReadTimeout` and `WriteTimeout` set. Missing `ReadHeaderTimeout` leaves a Slowloris window during headers; missing `IdleTimeout` allows keep-alive connections to accumulate.

**Fix:** Add `ReadHeaderTimeout: 5*time.Second, IdleTimeout: 60*time.Second`.

#### H-4. Keytab file permissions not validated — `ssh-cert-api/internal/auth/kerberos.go:34`

`keytab.Load(keytabPath)` succeeds regardless of file mode. A world-readable keytab (common deploy error) hands the service's Kerberos key to any local user → forged SPNEGO tokens for any realm user.

**Fix:** `stat` the keytab and refuse to start if `mode & 0o077 != 0`.

### MEDIUM

#### M-1. Empty `Principals` slice authorizes successfully — `ssh-cert-api/internal/authz/casbin.go:104-123`

Inner loop over `requestedPrincipals` never runs when the slice is empty; `allAllowed` stays `true` and the first group matches. Impact is limited (SSH cert with zero `ValidPrincipals` cannot log in anywhere), but the caller still gets a well-signed cert with `CustomAttributes`/`CriticalOptions`/audit attributes — useful for audit-log pollution or state confusion.

**Fix:** Reject at handler entry: `if len(req.Principals) == 0 { 400 }`. Covered by a new regression test.

#### M-2. User-supplied principals not validated before reaching SSH cert — `ssh-cert-api/internal/api/server.go:111-141`

Principals flow into `ValidPrincipals` with no charset/length check. The Casbin matcher is exact-string, so NUL/newline smuggling can't bypass authz unless the group uses wildcard `*`. Groups with `allowed_principals: ["*"]` pass any string, including control characters, into the signed cert and into log output.

**Fix:** Validate each principal against `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$` before `Authorize()`. Cap principal count (e.g. ≤32).

#### M-3. No Kerberos realm allow-list — `ssh-cert-api/internal/auth/kerberos.go:33-58, 105-110`

Any realm for which the keytab has a valid service key is accepted. Low practical risk unless federated trust or multi-realm keytabs are configured, but defense-in-depth is cheap.

**Fix:** `allowed_realms: [EXAMPLE.COM]` in config; check `creds.Realm()` against it.

#### M-4. No `EncryptionContext` on KMS Decrypt — `ssh-cert-signer/internal/handlers/load-key-signer.go:86-88`

`DecryptInput` carries only `CiphertextBlob`. An attacker with host-side access to overwrite `/app/ca_key.enc` could substitute any other ciphertext encrypted under the same CMK. The attestation `Recipient` binds decryption to the enclave, not to the intended blob.

**Fix:** `EncryptionContext: {"service": "ssh-cert-signer", "purpose": "ca-key"}` matched at encrypt-time. Validate `decryptOutput.KeyId` matches the expected CMK ARN.

#### M-5. No explicit TLS hardening — `ssh-cert-api/cmd/ssh-cert-api/main.go:95`

No `TLSConfig` set on `http.Server`. Go's defaults are reasonable (TLS 1.2 min, modern ciphers since Go 1.18), but explicit hardening is audit-friendly.

**Fix:** `TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, PreferServerCipherSuites: true}`.

#### M-6. No SIGTERM/SIGINT handler; no graceful shutdown — `ssh-cert-api/cmd/ssh-cert-api/main.go:105`

`httpServer.ListenAndServeTLS(...)` blocks forever. In-flight signing requests are cut on process kill; enclave VSOCK calls may hang partners.

**Fix:** Add signal handler that calls `httpServer.Shutdown(ctx)` with a timeout and `enclaveClient.Close()`.

#### M-7. SPNEGO heuristic fallback parser — `ssh-cert-api/internal/auth/kerberos.go:87-122`

When standard SPNEGO parsing fails, the code byte-scans for `0x6e` (AP-REQ tag) and tries to parse from there. The AP-REQ still has to verify cryptographically against the keytab, so forgery is bounded — but a fragile parser around authn data is a smell and a maintenance burden.

**Fix:** Investigate which clients trip the standard parser. Prefer fixing client/server negotiation or removing the fallback.

### LOW

- **L-1.** `log.Printf("Base64 token: %s", token)` at `kerberos.go:71` — logs SPNEGO tokens at debug level. Ensure debug logging is off in production; token replay is time-bounded but still sensitive.
- **L-2.** `log.Printf` statements include user-controlled principals without `%q` quoting — control characters in a principal could forge log entries (`server.go:108, 113, 146`).
- **L-3.** No panic-recovery middleware on handlers; Go's default is safe but unstructured.
- **L-4.** Enclave client does not accept a `context.Context` — client-cancel isn't propagated; fine as long as VSOCK deadlines are set, which they are.
- **L-5.** `casbin_test.go` missing cases for empty principals, literal `*` request, realm mismatch, case sensitivity — regression risk for M-1/M-2 fixes.
- **L-6.** `messages.Credentials` not zeroed after use — Go GC timing only, negligible risk inside enclave.

### Dependency review

- `jcmturner/gokrb5/v8 v8.4.4` — current.
- `casbin/casbin/v2 v2.135.0` — current; `Enforce()` is concurrency-safe.
- `aws-sdk-go-v2 v1.36.5` — current.
- `mdlayher/vsock v1.2.1` — current.
- `edgebitio/nitro-enclaves-sdk-go` — pinned via `replace` to a 2022 commit. Audit this pin; if unmaintained, monitor for transitive aws-sdk CVEs.

Run `govulncheck ./...` in each module on every build.

## False positives dismissed

These were flagged by sub-agents at CRITICAL/HIGH but are NOT real issues after code inspection:

| Flagged | Reality |
|---|---|
| "Concurrent map writes in `casbin.go`" (DREAD 9.5) | `loadPolicies` is called only from `NewCasbinAuthorizer` during startup; maps are read-only during request handling. No race. |
| "Proxy double-close races" (DREAD 8.8) | `net.Conn.Close()` is idempotent; double-close returns an error but does not panic. The pattern is intentional to unblock the other `io.Copy` direction. |
| "Proxy stopped mid-request" (DREAD 8.2) | Intentional: the proxy is only needed during `LoadKeySigner()` at startup to decrypt the CA key. Subsequent signing requests do not need KMS. Stopping it after init reduces attack surface. |
| "PKCS#7 padding panic on empty input" (DREAD 6.5) | `removePKCS7Padding` checks `len(data) == 0` at the top of the function, before indexing. Safe. |
| "SSH cert serial zero check" | `rand.Int(rand.Reader, 2^64)` has ~2⁻⁶⁴ probability of returning zero. Practically impossible. |

## Priority remediation order

1. H-1 (attestation strict mode) — security model invariant.
2. H-2, H-3 (DoS hardening) — low-cost, high-value.
3. H-4 (keytab perms) — tiny code change.
4. M-1, M-2 (input validation) — one handler diff.
5. M-4 (EncryptionContext) — requires coordinated re-encrypt of existing CA blobs.
6. M-3, M-5, M-6 — defense in depth.

Once H-1–H-4 land, re-run this audit and add regression tests for the specific cases.
