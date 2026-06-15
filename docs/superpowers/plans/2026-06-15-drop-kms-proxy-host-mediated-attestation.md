# Drop the KMS Proxy via Host-Mediated Attested Decrypt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the host-side VSOCK→TCP KMS proxy by moving the KMS `Decrypt` call from the enclave to the host, keeping the response encrypted to the enclave's attestation key (`CiphertextForRecipient`) so the host never sees the plaintext CA key — and stop shipping AWS credentials into the enclave.

**Architecture:** Today the enclave makes an attested `kms.Decrypt` through a host byte-forwarding proxy, using AWS credentials the host forwards over VSOCK. New design: a two-message handshake. The host asks the enclave to `BeginKeyLoad`; the enclave mints an NSM attestation document and returns it together with the (KMS-encrypted, non-secret) CA-key ciphertext; the host performs the `Decrypt` with `Recipient` set to that document using its own instance-role credentials; the host returns the resulting `CiphertextForRecipient` (a CMS envelope only the enclave can open) via `CompleteKeyLoad`; the enclave decrypts it with its ephemeral private key and installs the CA signer. In development (no `/dev/nsm`) the signer has real network and decrypts directly itself — no proxy, no credentials on the wire.

**Tech Stack:** Go 1.26 (multi-module: root `cerberus`, `ssh-cert-api`, `ssh-cert-signer`), `aws-sdk-go-v2` (`service/kms`, `types.RecipientInfo`), `golang.org/x/crypto/ssh`, `github.com/pkilar/nitro-enclaves-sdk-go/crypto/cms`, `github.com/hf/nsm`, `github.com/mdlayher/vsock`.

---

## ⚠️ Migration Prerequisite (do this before deploying — not a code task)

The security of host-mediated decrypt rests entirely on the **KMS key policy denying any non-attested `Decrypt`**. Once the host holds the ciphertext blob and has `kms:Decrypt` (via the instance role), the *only* thing stopping a compromised host from issuing a plain `Decrypt` (no `Recipient`) and reading the plaintext CA key is the key policy.

Before rolling this out, confirm the CMK policy grants `Decrypt` to the parent instance role **only** under a `kms:RecipientAttestation:ImageSha384` (PCR0) condition, and that **no other statement** grants the instance role an unconditioned `Decrypt`. A request with no attestation document fails the condition and is denied (AWS: *"If the request doesn't include an attestation document, the role doesn't have permission to call the operation because this condition cannot be satisfied."*).

This is documented in Task 9 (`docs/kms-attestation-policy.md` update). The same property protects the *current* design against a host that reads `ca_key.enc` out of the EIF on disk, so a correctly-configured deployment already satisfies it — but it MUST be verified, because the new design makes the host the legitimate caller.

The IAM principal calling KMS is unchanged (the parent instance role in both designs — today the host forwards those same credentials to the enclave), so **the key policy needs no principal/condition changes**, only verification.

---

## File Structure

**New files**
- `ssh-cert-api/internal/keyload/keyload.go` — host orchestration of the Begin→KMS→Complete handshake; `KMSDecrypter` interface + AWS implementation. One responsibility: drive the CA-key load from the host side.
- `ssh-cert-api/internal/keyload/keyload_test.go` — unit tests for the orchestration with fakes.

**Modified files**
- `messages/messages.go` — add `BeginKeyLoad*`/`CompleteKeyLoad*` types and union fields; (Task 8) remove `LoadKeySigner*`; host `RedactedJSON` moves here.
- `messages/messages_test.go` — add Begin/Complete JSON round-trip + `RedactedJSON` tests; (Task 8) remove `Credentials` tests.
- `messages/credentials.go` — **deleted** in Task 8 (credentials no longer cross the wire).
- `ssh-cert-signer/internal/handlers/load-key-signer.go` — add `BeginKeyLoad`/`CompleteKeyLoad`/helpers; (Task 7) CA-pubkey pin; (Task 8) remove old `LoadKeySignerHandler` + VSOCK/credentials code.
- `ssh-cert-signer/internal/handlers/load-key-signer_test.go` — add tests for new entry points; (Task 8) remove old-handler tests.
- `ssh-cert-signer/cmd/ssh-cert-signer/main.go` — dispatch `BeginKeyLoad`/`CompleteKeyLoad`; (Task 8) remove `LoadKeySigner` dispatch.
- `ssh-cert-signer/cmd/ssh-cert-signer/main_test.go` — update ambiguous-variant test.
- `ssh-cert-api/internal/enclave/client.go` — add `BeginKeyLoad`/`CompleteKeyLoad` to the `Signer` interface + `vsockSigner`.
- `ssh-cert-api/internal/api/server_test.go` — add the two methods to `fakeSigner`.
- `ssh-cert-api/cmd/ssh-cert-api/main.go` — call `keyload.Run`; delete proxy wiring + `fetchAWSCredentials` + old `LoadKeySigner`.
- `ssh-cert-api/internal/proxy/` — **deleted** in Task 6 (`proxy.go` + `proxy_test.go`).
- `constants/constants.go` — (Task 8) remove now-unused `InstanceCID` + `InstanceListeningPort`.
- Docs (Task 9): `CLAUDE.md`, `docs/RUNBOOK.md`, `docs/kms-attestation-policy.md`, `ARCHITECTURE-EXECUTIVE.md`, `packaging/rpm/` notes.

**Sequencing principle:** the wire types are added *additively* first (old + new coexist), both ends are switched over, then the old path/types/proxy/credentials are removed last. Every task ends with all three modules building and tests green.

---

### Task 1: Wire protocol — add Begin/Complete message types

**Files:**
- Modify: `messages/messages.go:21-34` (unions) and after `:97` (new types)
- Test: `messages/messages_test.go`

- [ ] **Step 1: Write the failing test**

Add to `messages/messages_test.go`:

```go
func TestBeginKeyLoad_JSON(t *testing.T) {
	t.Parallel()
	req := Request{BeginKeyLoad: &BeginKeyLoadRequest{}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if decodedReq.BeginKeyLoad == nil {
		t.Fatal("expected BeginKeyLoad to be non-nil")
	}

	resp := Response{BeginKeyLoad: &BeginKeyLoadResponse{
		AttestationDocument: []byte("doc-bytes"),
		CiphertextBlob:      []byte("ciphertext"),
	}}
	rdata, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decodedResp Response
	if err := json.Unmarshal(rdata, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decodedResp.BeginKeyLoad == nil {
		t.Fatal("expected BeginKeyLoad response to be non-nil")
	}
	if string(decodedResp.BeginKeyLoad.AttestationDocument) != "doc-bytes" {
		t.Errorf("AttestationDocument round-trip mismatch: %q", decodedResp.BeginKeyLoad.AttestationDocument)
	}
	if string(decodedResp.BeginKeyLoad.CiphertextBlob) != "ciphertext" {
		t.Errorf("CiphertextBlob round-trip mismatch: %q", decodedResp.BeginKeyLoad.CiphertextBlob)
	}
	if decodedResp.BeginKeyLoad.Loaded {
		t.Error("Loaded should be false")
	}

	// Loaded-only (development) shape must omit the byte fields.
	loaded, err := json.Marshal(Response{BeginKeyLoad: &BeginKeyLoadResponse{Loaded: true}})
	if err != nil {
		t.Fatalf("marshal loaded: %v", err)
	}
	if strings.Contains(string(loaded), "attestationDocument") || strings.Contains(string(loaded), "ciphertextBlob") {
		t.Errorf("loaded response should omit empty byte fields, got %s", loaded)
	}
}

func TestCompleteKeyLoad_JSON(t *testing.T) {
	t.Parallel()
	req := Request{CompleteKeyLoad: &CompleteKeyLoadRequest{CiphertextForRecipient: []byte("cms-envelope")}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if decodedReq.CompleteKeyLoad == nil || string(decodedReq.CompleteKeyLoad.CiphertextForRecipient) != "cms-envelope" {
		t.Fatalf("CompleteKeyLoad round-trip mismatch: %+v", decodedReq.CompleteKeyLoad)
	}

	resp := Response{CompleteKeyLoad: &CompleteKeyLoadResponse{Success: true}}
	rdata, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decodedResp Response
	if err := json.Unmarshal(rdata, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decodedResp.CompleteKeyLoad == nil || !decodedResp.CompleteKeyLoad.Success {
		t.Fatalf("CompleteKeyLoad response round-trip mismatch: %+v", decodedResp.CompleteKeyLoad)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/pkilar/Devel/cerberus && go test ./messages/ -run 'TestBeginKeyLoad_JSON|TestCompleteKeyLoad_JSON'`
Expected: FAIL — `undefined: BeginKeyLoadRequest` (and friends).

- [ ] **Step 3: Add the new types and union fields**

In `messages/messages.go`, replace the `Request`/`Response` structs (`:21-34`) with:

```go
// These messages define the API between the ssh-cert-signer and ssh-cert-api.
// Only one of each field is expected to be set at any given time.
type Request struct {
	BeginKeyLoad      *BeginKeyLoadRequest      `json:"beginKeyLoad,omitempty"`
	CompleteKeyLoad   *CompleteKeyLoadRequest   `json:"completeKeyLoad,omitempty"`
	LoadKeySigner     *LoadKeySignerRequest     `json:"loadKeySigner,omitempty"`
	SignSshKey        *EnclaveSigningRequest    `json:"signSshKey,omitempty"`
	Ping              *PingRequest              `json:"ping,omitempty"`
	GetEnclaveMetrics *GetEnclaveMetricsRequest `json:"getEnclaveMetrics,omitempty"`
}

type Response struct {
	BeginKeyLoad    *BeginKeyLoadResponse    `json:"beginKeyLoad,omitempty"`
	CompleteKeyLoad *CompleteKeyLoadResponse `json:"completeKeyLoad,omitempty"`
	LoadKeySigner   *LoadKeySignerResponse   `json:"loadKeySigner,omitempty"`
	Error           *string                  `json:"error,omitempty"`
	SignSshKey      *SigningResponse         `json:"signSshKey,omitempty"`
	Pong            *PingResponse            `json:"pong,omitempty"`
	EnclaveMetrics  *EnclaveMetricsResponse  `json:"enclaveMetrics,omitempty"`
}
```

Then insert the new type definitions immediately after the `LoadKeySignerResponse` struct (after `messages/messages.go:97`):

```go
// BeginKeyLoadRequest asks the enclave to begin loading the CA key. The host
// sends this once at startup. The enclave's reply (BeginKeyLoadResponse) tells
// the host whether it must perform a host-mediated attested KMS Decrypt
// (production) or whether the enclave already loaded the key itself (dev).
type BeginKeyLoadRequest struct{}

// BeginKeyLoadResponse is the enclave's reply to BeginKeyLoadRequest.
//
// Production (attested enclave): AttestationDocument and CiphertextBlob are set
// and Loaded is false. The host calls KMS Decrypt with the attestation document
// as the Recipient and the ciphertext blob, then returns the result via
// CompleteKeyLoadRequest. Neither field is secret to the host — the blob is KMS
// ciphertext and the attestation document is a signed public artifact.
//
// Development (no /dev/nsm): Loaded is true and the other fields are empty — the
// enclave performed a direct (non-attested) KMS Decrypt over its own network and
// installed the CA signer. No CompleteKeyLoad follows.
type BeginKeyLoadResponse struct {
	AttestationDocument []byte `json:"attestationDocument,omitempty"`
	CiphertextBlob      []byte `json:"ciphertextBlob,omitempty"`
	Loaded              bool   `json:"loaded,omitempty"`
}

// CompleteKeyLoadRequest carries the KMS CiphertextForRecipient back to the
// enclave. It is a CMS envelope encrypting the CA-key plaintext to the enclave's
// attestation public key (RSAES_OAEP_SHA_256); only the originating enclave can
// open it, so this value is not secret to the host.
type CompleteKeyLoadRequest struct {
	CiphertextForRecipient []byte `json:"ciphertextForRecipient"`
}

// CompleteKeyLoadResponse reports whether the enclave decrypted the envelope and
// installed the CA signer.
type CompleteKeyLoadResponse struct {
	Success bool `json:"success,omitempty"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/pkilar/Devel/cerberus && go test ./messages/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add messages/messages.go messages/messages_test.go
git commit -m "messages: add BeginKeyLoad/CompleteKeyLoad wire types"
```

---

### Task 2: Enclave handlers — `BeginKeyLoad` + `CompleteKeyLoad`

**Files:**
- Modify: `ssh-cert-signer/internal/handlers/load-key-signer.go` (add new functions; leave old `LoadKeySignerHandler` in place for now)
- Test: `ssh-cert-signer/internal/handlers/load-key-signer_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `ssh-cert-signer/internal/handlers/load-key-signer_test.go`:

```go
func TestBeginKeyLoad_MissingFile_DevPath(t *testing.T) {
	// No NSM provider + attestation not required => dev path, which reads the
	// CA key file first and fails there before any KMS call.
	t.Setenv("REQUIRE_ATTESTATION", "false")
	t.Setenv("CA_KEY_FILE_PATH", "/nonexistent/path/to/key.enc")

	_, err := BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error when CA key file is missing")
	}
	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestBeginKeyLoad_AttestationRequiredButUnavailable(t *testing.T) {
	t.Setenv("REQUIRE_ATTESTATION", "true")

	_, err := BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error when attestation is required but provider is nil")
	}
	if !strings.Contains(err.Error(), "attestation is required") {
		t.Errorf("expected attestation-required error, got: %v", err)
	}
}

func TestBeginKeyLoad_DevPath_FailsAtKMS(t *testing.T) {
	// Dev path with a present-but-bogus key file reaches the direct KMS Decrypt,
	// which cannot succeed without AWS connectivity in CI.
	t.Setenv("REQUIRE_ATTESTATION", "false")
	tmpFile, err := os.CreateTemp(t.TempDir(), "test_key_*.enc")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString("fake encrypted content"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	_, err = BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error due to AWS/KMS failure in dev path")
	}
	if !strings.Contains(err.Error(), "failed to decrypt key with KMS") &&
		!strings.Contains(err.Error(), "failed to load AWS default config") {
		t.Errorf("expected AWS/KMS related error, got: %v", err)
	}
}

func TestCompleteKeyLoad_NoProvider(t *testing.T) {
	_, err := CompleteKeyLoad(t.Context(), nil, []byte("envelope"))
	if err == nil {
		t.Fatal("expected error when attestation provider is unavailable")
	}
	if !strings.Contains(err.Error(), "without an available attestation provider") {
		t.Errorf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-signer && go test ./internal/handlers/ -run 'TestBeginKeyLoad|TestCompleteKeyLoad'`
Expected: FAIL — `undefined: BeginKeyLoad` / `undefined: CompleteKeyLoad`.

- [ ] **Step 3: Add the new handler functions**

Insert the following into `ssh-cert-signer/internal/handlers/load-key-signer.go`, immediately **above** the existing `LoadKeySignerHandler` (`:43`). (Imports needed — `cmp`, `context`, `errors`, `fmt`, `log/slog`, `os`, `config`, `kms`, `ssh`, `logging`, `attestation` — are all already imported by the file.)

```go
// BeginKeyLoadResult is returned by BeginKeyLoad. Exactly one outcome is set:
//   - AttestationDocument + CiphertextBlob: production path. The caller (host)
//     must KMS-Decrypt CiphertextBlob with AttestationDocument as the Recipient
//     and feed the result to CompleteKeyLoad.
//   - Signer: development path (no NSM). The enclave decrypted the key itself
//     and the caller should install this signer directly.
type BeginKeyLoadResult struct {
	AttestationDocument []byte
	CiphertextBlob      []byte
	Signer              ssh.Signer
}

// BeginKeyLoad starts the CA-key load. In an attested enclave it reads the
// KMS-encrypted CA key and returns it together with a fresh NSM attestation
// document, leaving the actual KMS Decrypt to the host (host-mediated attested
// decrypt — the enclave has no network). Without an attestation provider it
// refuses unless attestation is not required, in which case it falls back to a
// direct KMS Decrypt over the process's own network (development only).
func BeginKeyLoad(ctx context.Context, attestProvider *attestation.Provider) (*BeginKeyLoadResult, error) {
	required, err := attestationRequired()
	if err != nil {
		return nil, err
	}

	if attestProvider != nil && attestProvider.IsAvailable() {
		encryptedKeyBytes, err := readEncryptedCAKey(ctx)
		if err != nil {
			return nil, err
		}
		attestDoc, err := attestProvider.GenerateAttestationDoc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate attestation document: %w", err)
		}
		slog.InfoContext(ctx, "loadkey.begin.attested",
			"ciphertext_bytes", len(encryptedKeyBytes), "attestation_bytes", len(attestDoc))
		return &BeginKeyLoadResult{
			AttestationDocument: attestDoc,
			CiphertextBlob:      encryptedKeyBytes,
		}, nil
	}

	if required {
		return nil, errors.New("attestation is required but unavailable; refusing to load CA key (set REQUIRE_ATTESTATION=false to override — not recommended in production)")
	}

	// Development fallback: no enclave isolation guarantee. The signer has real
	// network here, so it decrypts directly with its ambient credential chain.
	encryptedKeyBytes, err := readEncryptedCAKey(ctx)
	if err != nil {
		return nil, err
	}
	signer, err := decryptDirect(ctx, encryptedKeyBytes)
	if err != nil {
		return nil, err
	}
	slog.WarnContext(ctx, "loadkey.attestation.disabled",
		"detail", "CA key decrypted via non-attested KMS Decrypt; no enclave isolation guarantee")
	return &BeginKeyLoadResult{Signer: signer}, nil
}

// CompleteKeyLoad finishes a host-mediated attested load: it decrypts the CMS
// envelope (KMS CiphertextForRecipient) with the enclave's attestation private
// key and returns the parsed CA signer.
func CompleteKeyLoad(ctx context.Context, attestProvider *attestation.Provider, ciphertextForRecipient []byte) (ssh.Signer, error) {
	if attestProvider == nil || !attestProvider.IsAvailable() {
		return nil, errors.New("CompleteKeyLoad called without an available attestation provider")
	}
	if len(ciphertextForRecipient) == 0 {
		return nil, errors.New("CompleteKeyLoad called with empty CiphertextForRecipient")
	}
	plaintextKey, err := attestProvider.DecryptCMSEnvelope(ciphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CiphertextForRecipient: %w", err)
	}
	// Best-effort zero of the plaintext once parsing has copied it out.
	defer clear(plaintextKey)
	signer, err := parseCASigner(ctx, plaintextKey)
	if err != nil {
		return nil, err
	}
	slog.InfoContext(ctx, "loadkey.complete.attested")
	return signer, nil
}

// readEncryptedCAKey reads the KMS-encrypted CA key from CA_KEY_FILE_PATH.
func readEncryptedCAKey(ctx context.Context) ([]byte, error) {
	caKeyFilePath := cmp.Or(os.Getenv("CA_KEY_FILE_PATH"), "/app/ca_key.enc")
	// #nosec G304 -- caKeyFilePath comes from the CA_KEY_FILE_PATH env var set by
	// the operator (or a packaged systemd unit), not untrusted input.
	encryptedKeyBytes, err := os.ReadFile(caKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file '%s': %w", caKeyFilePath, err)
	}
	logging.DebugContext(ctx, "Successfully read encrypted key file (%d bytes)", len(encryptedKeyBytes))
	return encryptedKeyBytes, nil
}

// decryptDirect performs a non-attested KMS Decrypt over the process's own
// network using the ambient AWS credential chain. Only reached in development
// (no /dev/nsm and REQUIRE_ATTESTATION not true).
func decryptDirect(ctx context.Context, encryptedKeyBytes []byte) (ssh.Signer, error) {
	region := cmp.Or(os.Getenv("AWS_REGION"), "us-east-1")
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS default config: %w", err)
	}
	out, err := kms.NewFromConfig(cfg).Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: encryptedKeyBytes})
	if err != nil {
		slog.ErrorContext(ctx, "loadkey.kms_decrypt.failed", "error", err)
		return nil, fmt.Errorf("failed to decrypt key with KMS: %w", err)
	}
	defer clear(out.Plaintext)
	return parseCASigner(ctx, out.Plaintext)
}

// parseCASigner parses the decrypted PEM private key into an ssh.Signer.
// CA public-key pinning is layered on in Task 7.
func parseCASigner(ctx context.Context, plaintextKey []byte) (ssh.Signer, error) {
	logging.DebugContext(ctx, "Parsing decrypted CA private key (%d bytes)", len(plaintextKey))
	signer, err := ssh.ParsePrivateKey(plaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}
	return signer, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-signer && go test ./internal/handlers/`
Expected: PASS (all old + new tests).

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-signer/internal/handlers/load-key-signer.go ssh-cert-signer/internal/handlers/load-key-signer_test.go
git commit -m "signer/handlers: add BeginKeyLoad/CompleteKeyLoad (host-mediated attested decrypt)"
```

---

### Task 3: Enclave dispatch — handle Begin/Complete over VSOCK

**Files:**
- Modify: `ssh-cert-signer/cmd/ssh-cert-signer/main.go` (`processRequest` variant count + switch; add two handlers)

- [ ] **Step 1: Add the dispatch handlers**

Insert into `ssh-cert-signer/cmd/ssh-cert-signer/main.go` immediately **above** `handleLoadKeySigner` (`:273`):

```go
func handleBeginKeyLoad(ctx context.Context) messages.Response {
	res, err := handlers.BeginKeyLoad(ctx, attestProvider)
	if err != nil {
		return createErrorResponse(err)
	}
	if res.Signer != nil {
		// Development path: the enclave decrypted the key itself.
		caSigner.Store(&res.Signer)
		return messages.Response{BeginKeyLoad: &messages.BeginKeyLoadResponse{Loaded: true}}
	}
	return messages.Response{BeginKeyLoad: &messages.BeginKeyLoadResponse{
		AttestationDocument: res.AttestationDocument,
		CiphertextBlob:      res.CiphertextBlob,
	}}
}

func handleCompleteKeyLoad(ctx context.Context, req messages.CompleteKeyLoadRequest) messages.Response {
	signer, err := handlers.CompleteKeyLoad(ctx, attestProvider, req.CiphertextForRecipient)
	if err != nil {
		return createErrorResponse(err)
	}
	caSigner.Store(&signer)
	return messages.Response{CompleteKeyLoad: &messages.CompleteKeyLoadResponse{Success: true}}
}
```

- [ ] **Step 2: Wire them into the variant counter and switch**

In `processRequest`, extend the variant counter (after `messages/...:220-231`'s `nVariants` block) by adding two checks alongside the existing ones:

```go
	if req.BeginKeyLoad != nil {
		nVariants++
	}
	if req.CompleteKeyLoad != nil {
		nVariants++
	}
```

And add two cases at the top of the dispatch `switch` (`:236`), before `case req.LoadKeySigner != nil:`:

```go
	case req.BeginKeyLoad != nil:
		return handleBeginKeyLoad(ctx)
	case req.CompleteKeyLoad != nil:
		return handleCompleteKeyLoad(ctx, *req.CompleteKeyLoad)
```

- [ ] **Step 3: Run to verify it builds and existing tests pass**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-signer && go build ./... && go test ./cmd/...`
Expected: build OK; PASS.

- [ ] **Step 4: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-signer/cmd/ssh-cert-signer/main.go
git commit -m "signer: dispatch BeginKeyLoad/CompleteKeyLoad requests"
```

---

### Task 4: Host enclave client — Begin/Complete methods

**Files:**
- Modify: `ssh-cert-api/internal/enclave/client.go` (interface + `vsockSigner` methods)
- Modify: `ssh-cert-api/internal/api/server_test.go` (`fakeSigner` stubs)

- [ ] **Step 1: Extend the `Signer` interface**

In `ssh-cert-api/internal/enclave/client.go`, replace the `Signer` interface (`:25-30`) with:

```go
type Signer interface {
	SignPublicKey(ctx context.Context, req *messages.EnclaveSigningRequest) (string, error)
	Ping(ctx context.Context) (*messages.PingResponse, error)
	GetEnclaveMetrics(ctx context.Context) (*messages.EnclaveMetricsResponse, error)
	// BeginKeyLoad and CompleteKeyLoad drive the host-mediated CA-key load at
	// startup; see internal/keyload.
	BeginKeyLoad(ctx context.Context, req *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error)
	CompleteKeyLoad(ctx context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error)
	Close() error
}
```

- [ ] **Step 2: Implement the methods on `vsockSigner`**

Append to `ssh-cert-api/internal/enclave/client.go` (after `SignPublicKey`, end of file):

```go
// BeginKeyLoad asks the enclave to start loading the CA key. In production the
// reply carries an attestation document + the KMS-encrypted CA key for the host
// to decrypt; in development the enclave reports Loaded=true having decrypted
// the key itself.
func (vsockSigner) BeginKeyLoad(ctx context.Context, req *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, messages.Request{BeginKeyLoad: req}, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.BeginKeyLoad == nil {
		return nil, fmt.Errorf("no beginKeyLoad in response")
	}
	return response.BeginKeyLoad, nil
}

// CompleteKeyLoad returns the KMS CiphertextForRecipient to the enclave, which
// decrypts it inside and installs the CA signer.
func (vsockSigner) CompleteKeyLoad(ctx context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, messages.Request{CompleteKeyLoad: req}, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.CompleteKeyLoad == nil {
		return nil, fmt.Errorf("no completeKeyLoad in response")
	}
	return response.CompleteKeyLoad, nil
}
```

- [ ] **Step 3: Add stubs to `fakeSigner` so the api package still builds**

In `ssh-cert-api/internal/api/server_test.go`, immediately after `func (f *fakeSigner) Close() error { return nil }` (`:91`), add:

```go
func (f *fakeSigner) BeginKeyLoad(context.Context, *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	return nil, errors.New("fakeSigner.BeginKeyLoad not implemented")
}

func (f *fakeSigner) CompleteKeyLoad(context.Context, *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	return nil, errors.New("fakeSigner.CompleteKeyLoad not implemented")
}
```

(`errors` and `context` are already imported by `server_test.go`; if `goimports` reports `errors` unused-before-this it is already used by other fakes in the file.)

- [ ] **Step 4: Build + test the host module**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-api && go build ./... && go test ./internal/enclave/... ./internal/api/...`
Expected: build OK; PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-api/internal/enclave/client.go ssh-cert-api/internal/api/server_test.go
git commit -m "api/enclave: add BeginKeyLoad/CompleteKeyLoad client methods"
```

---

### Task 5: Host orchestration — `keyload` package

**Files:**
- Create: `ssh-cert-api/internal/keyload/keyload.go`
- Test: `ssh-cert-api/internal/keyload/keyload_test.go`

- [ ] **Step 1: Write the failing test**

Create `ssh-cert-api/internal/keyload/keyload_test.go`:

```go
package keyload

import (
	"context"
	"errors"
	"testing"

	"github.com/pkilar/cerberus/messages"
)

// fakeSigner implements just enough of enclave.Signer for keyload.Run. The
// unused interface methods are present so it satisfies enclave.Signer.
type fakeSigner struct {
	begin       *messages.BeginKeyLoadResponse
	beginErr    error
	complete    *messages.CompleteKeyLoadResponse
	completeErr error

	gotCiphertextForRecipient []byte
	completeCalled            bool
}

func (f *fakeSigner) SignPublicKey(context.Context, *messages.EnclaveSigningRequest) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeSigner) Ping(context.Context) (*messages.PingResponse, error) { return nil, errors.New("unused") }
func (f *fakeSigner) GetEnclaveMetrics(context.Context) (*messages.EnclaveMetricsResponse, error) {
	return nil, errors.New("unused")
}
func (f *fakeSigner) Close() error { return nil }
func (f *fakeSigner) BeginKeyLoad(context.Context, *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	return f.begin, f.beginErr
}
func (f *fakeSigner) CompleteKeyLoad(_ context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	f.completeCalled = true
	f.gotCiphertextForRecipient = req.CiphertextForRecipient
	return f.complete, f.completeErr
}

type fakeKMS struct {
	out         []byte
	err         error
	gotBlob     []byte
	gotDoc      []byte
	called      bool
}

func (k *fakeKMS) DecryptForEnclave(_ context.Context, blob, doc []byte) ([]byte, error) {
	k.called = true
	k.gotBlob = blob
	k.gotDoc = doc
	return k.out, k.err
}

func TestRun_DevPath_LoadedSkipsKMS(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{Loaded: true}}
	kms := &fakeKMS{}
	if err := Run(t.Context(), signer, kms); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if kms.called {
		t.Error("KMS must not be called on the dev (Loaded) path")
	}
	if signer.completeCalled {
		t.Error("CompleteKeyLoad must not be called on the dev path")
	}
}

func TestRun_AttestedPath_HappyPath(t *testing.T) {
	signer := &fakeSigner{
		begin:    &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")},
		complete: &messages.CompleteKeyLoadResponse{Success: true},
	}
	kms := &fakeKMS{out: []byte("cms-envelope")}
	if err := Run(t.Context(), signer, kms); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if string(kms.gotBlob) != "blob" || string(kms.gotDoc) != "doc" {
		t.Errorf("KMS received blob=%q doc=%q", kms.gotBlob, kms.gotDoc)
	}
	if string(signer.gotCiphertextForRecipient) != "cms-envelope" {
		t.Errorf("CompleteKeyLoad received %q", signer.gotCiphertextForRecipient)
	}
}

func TestRun_AttestedPath_MissingFields(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc")}} // no ciphertext
	if err := Run(t.Context(), signer, &fakeKMS{}); err == nil {
		t.Fatal("expected error when ciphertext blob is missing")
	}
}

func TestRun_KMSError(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")}}
	kms := &fakeKMS{err: errors.New("AccessDenied")}
	if err := Run(t.Context(), signer, kms); err == nil {
		t.Fatal("expected error when KMS decrypt fails")
	}
}

func TestRun_CompleteNotSuccessful(t *testing.T) {
	signer := &fakeSigner{
		begin:    &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")},
		complete: &messages.CompleteKeyLoadResponse{Success: false},
	}
	kms := &fakeKMS{out: []byte("cms-envelope")}
	if err := Run(t.Context(), signer, kms); err == nil {
		t.Fatal("expected error when enclave reports load did not succeed")
	}
}

func TestRun_BeginError(t *testing.T) {
	signer := &fakeSigner{beginErr: errors.New("vsock dial failed")}
	if err := Run(t.Context(), signer, &fakeKMS{}); err == nil {
		t.Fatal("expected error when BeginKeyLoad fails")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-api && go test ./internal/keyload/`
Expected: FAIL — package/`Run` not defined.

- [ ] **Step 3: Create the package**

Create `ssh-cert-api/internal/keyload/keyload.go`:

```go
// Package keyload drives the host-mediated CA-key load. The enclave has no
// network, so rather than proxy its KMS traffic, the host performs the KMS
// Decrypt itself with its own instance-role credentials and the enclave's
// attestation document. KMS encrypts the plaintext to the enclave's attestation
// public key (CiphertextForRecipient), so the host never sees the plaintext CA
// key — only the enclave can open the envelope.
package keyload

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
)

// KMSDecrypter performs an attested KMS Decrypt on behalf of the enclave: given
// the KMS ciphertext blob and the enclave's attestation document, it returns the
// CiphertextForRecipient (a CMS envelope only the enclave can open).
type KMSDecrypter interface {
	DecryptForEnclave(ctx context.Context, ciphertextBlob, attestationDocument []byte) ([]byte, error)
}

// Run executes the Begin→(KMS)→Complete handshake. On the development path
// (enclave without /dev/nsm) the enclave decrypts the key itself and reports
// Loaded=true, so no KMS call or CompleteKeyLoad is needed.
func Run(ctx context.Context, signer enclave.Signer, kmsDecrypter KMSDecrypter) error {
	begin, err := signer.BeginKeyLoad(ctx, &messages.BeginKeyLoadRequest{})
	if err != nil {
		return fmt.Errorf("begin key load: %w", err)
	}
	if begin.Loaded {
		// Development enclave decrypted the key itself; nothing more to do.
		return nil
	}
	if len(begin.AttestationDocument) == 0 || len(begin.CiphertextBlob) == 0 {
		return errors.New("enclave returned neither a loaded signer nor an attestation document + ciphertext")
	}

	ciphertextForRecipient, err := kmsDecrypter.DecryptForEnclave(ctx, begin.CiphertextBlob, begin.AttestationDocument)
	if err != nil {
		return fmt.Errorf("host-mediated KMS decrypt: %w", err)
	}

	complete, err := signer.CompleteKeyLoad(ctx, &messages.CompleteKeyLoadRequest{CiphertextForRecipient: ciphertextForRecipient})
	if err != nil {
		return fmt.Errorf("complete key load: %w", err)
	}
	if !complete.Success {
		return errors.New("enclave reported CA key load did not succeed")
	}
	return nil
}

// awsDecrypter is the production KMSDecrypter. It uses the host's own network and
// AWS credential chain (the EC2 instance role).
type awsDecrypter struct{ client *kms.Client }

// NewAWSDecrypter builds a KMSDecrypter backed by AWS KMS in the given region.
func NewAWSDecrypter(ctx context.Context, region string) (KMSDecrypter, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return awsDecrypter{client: kms.NewFromConfig(cfg)}, nil
}

func (d awsDecrypter) DecryptForEnclave(ctx context.Context, ciphertextBlob, attestationDocument []byte) ([]byte, error) {
	out, err := d.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertextBlob,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt failed: %w", err)
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, errors.New("KMS returned empty CiphertextForRecipient despite Recipient being set")
	}
	return out.CiphertextForRecipient, nil
}
```

- [ ] **Step 4: Run tests + tidy**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-api && go mod tidy && go test ./internal/keyload/`
Expected: PASS. (`go mod tidy` pulls `service/kms` + `service/kms/types` into `ssh-cert-api`'s `go.mod`/`go.sum`.)

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-api/internal/keyload/ ssh-cert-api/go.mod ssh-cert-api/go.sum
git commit -m "api/keyload: host-mediated attested KMS decrypt orchestration"
```

---

### Task 6: Host main — switch to `keyload.Run`, delete the proxy

**Files:**
- Modify: `ssh-cert-api/cmd/ssh-cert-api/main.go`
- Delete: `ssh-cert-api/internal/proxy/proxy.go`, `ssh-cert-api/internal/proxy/proxy_test.go`

- [ ] **Step 1: Replace the proxy + load block in `main`**

In `ssh-cert-api/cmd/ssh-cert-api/main.go`, replace the entire section `--- 3. Start VSOCK Proxy ... vsockProxy.Stop()` (`:80-111`) with:

```go
	// --- 3. Load the CA key into the enclave (host-mediated attested decrypt) ---
	// The enclave has no network. Rather than proxy its KMS traffic, the host
	// performs the KMS Decrypt itself using its own instance-role credentials and
	// the enclave's attestation document; KMS returns the plaintext encrypted to
	// the enclave's attestation public key, so the host never sees the plaintext
	// CA key. Bounded so a hung KMS call cannot wedge startup; 60s comfortably
	// covers attestation + KMS round trip + key parse.
	region := cmp.Or(os.Getenv("AWS_REGION"), "us-east-1")
	logging.Debug("Loading CA key into enclave (host-mediated attested KMS decrypt)...")
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 60*time.Second)
	kmsDecrypter, err := keyload.NewAWSDecrypter(loadCtx, region)
	if err != nil {
		loadCancel()
		log.Fatalf("Failed to initialize KMS client: %v", err)
	}
	if err := keyload.Run(loadCtx, enclaveClient, kmsDecrypter); err != nil {
		loadCancel()
		log.Fatalf("Failed to load CA key into enclave: %v", err)
	}
	loadCancel()
	logging.Debug("Enclave CA key loaded successfully")
```

- [ ] **Step 2: Delete the old `LoadKeySigner` and `fetchAWSCredentials` functions**

Remove the entire block from `// LoadKeySigner sends a load-key-signer request...` (`:278`) through the end of `fetchAWSCredentials` (`:339`) in `ssh-cert-api/cmd/ssh-cert-api/main.go`.

- [ ] **Step 3: Fix imports**

In `ssh-cert-api/cmd/ssh-cert-api/main.go`:
- Remove imports: `"github.com/pkilar/cerberus/constants"`, `"github.com/pkilar/cerberus/messages"`, `"github.com/pkilar/cerberus/ssh-cert-api/internal/proxy"`, `"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"`, `"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"`. (`awsconfig` alias is no longer used — remove `awsconfig "github.com/aws/aws-sdk-go-v2/config"` too.)
- Add import: `"github.com/pkilar/cerberus/ssh-cert-api/internal/keyload"`.

(`cmp`, `os`, `context`, `time`, `fmt`, `log`, `logging` remain in use elsewhere in the file.)

- [ ] **Step 4: Delete the proxy package**

```bash
cd /home/pkilar/Devel/cerberus
git rm ssh-cert-api/internal/proxy/proxy.go ssh-cert-api/internal/proxy/proxy_test.go
```

- [ ] **Step 5: Build, tidy, test the host module**

Run:
```bash
cd /home/pkilar/Devel/cerberus/ssh-cert-api && go build ./... && go mod tidy && go test ./...
```
Expected: build OK; `go mod tidy` drops `ec2rolecreds`/`imds` if otherwise unused; PASS.

- [ ] **Step 6: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-api/cmd/ssh-cert-api/main.go ssh-cert-api/internal/proxy ssh-cert-api/go.mod ssh-cert-api/go.sum
git commit -m "api: host-mediated CA-key load; remove VSOCK KMS proxy and credential forwarding"
```

---

### Task 7: Pin the CA public key (close the substitution gap)

Host-mediated decrypt lets a compromised host substitute the ciphertext it sends to KMS, causing the enclave to load an attacker-chosen CA. The current design avoids this because the enclave both reads *and* uses the PCR0-measured EIF blob without the host touching it. Restore parity: after decrypting, verify the resulting public key against a CA public key pinned in the (PCR0-measured) enclave image.

**Files:**
- Modify: `ssh-cert-signer/internal/handlers/load-key-signer.go` (`parseCASigner` + new `verifyPinnedCAPublicKey`; add `bytes` import)
- Test: `ssh-cert-signer/internal/handlers/load-key-signer_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `ssh-cert-signer/internal/handlers/load-key-signer_test.go` (add `crypto/rand`, `crypto/rsa`, `os`, `golang.org/x/crypto/ssh` to its imports if not present — `os` already is):

```go
func TestParseCASigner_PinMatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pemBytes := pemEncodeRSA(t, key)
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse signer: %v", err)
	}
	pinPath := writeTempFile(t, ssh.MarshalAuthorizedKey(signer.PublicKey()))
	t.Setenv("CA_PUBLIC_KEY_PATH", pinPath)

	if _, err := parseCASigner(t.Context(), pemBytes); err != nil {
		t.Fatalf("expected pin to match, got: %v", err)
	}
}

func TestParseCASigner_PinMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	otherSigner, err := ssh.ParsePrivateKey(pemEncodeRSA(t, other))
	if err != nil {
		t.Fatalf("parse other: %v", err)
	}
	pinPath := writeTempFile(t, ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	t.Setenv("CA_PUBLIC_KEY_PATH", pinPath)

	if _, err := parseCASigner(t.Context(), pemEncodeRSA(t, key)); err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

func TestParseCASigner_Unpinned(t *testing.T) {
	t.Setenv("CA_PUBLIC_KEY_PATH", "")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if _, err := parseCASigner(t.Context(), pemEncodeRSA(t, key)); err != nil {
		t.Fatalf("unpinned should warn and proceed, got: %v", err)
	}
}

// pemEncodeRSA returns the PKCS#1 PEM encoding of key.
func pemEncodeRSA(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ca_pub_*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	return f.Name()
}
```

Add these imports to the test file's import block: `"crypto/rand"`, `"crypto/rsa"`, `"crypto/x509"`, `"encoding/pem"`, `"golang.org/x/crypto/ssh"`.

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-signer && go test ./internal/handlers/ -run TestParseCASigner`
Expected: FAIL — pin not enforced (mismatch test fails because `parseCASigner` ignores the env var).

- [ ] **Step 3: Implement the pin check**

In `ssh-cert-signer/internal/handlers/load-key-signer.go`, add `"bytes"` to the import block, and replace `parseCASigner` (from Task 2) with:

```go
// parseCASigner parses the decrypted PEM private key into an ssh.Signer and, if
// CA_PUBLIC_KEY_PATH is set, verifies the resulting public key matches the
// pinned CA public key baked into the (PCR0-measured) enclave image. This closes
// the only integrity gap introduced by host-mediated decryption: a compromised
// host could otherwise feed the enclave a CiphertextForRecipient derived from a
// substituted ciphertext, causing it to load an attacker-chosen CA. With the
// pin, such a key fails to match and is refused.
func parseCASigner(ctx context.Context, plaintextKey []byte) (ssh.Signer, error) {
	logging.DebugContext(ctx, "Parsing decrypted CA private key (%d bytes)", len(plaintextKey))
	signer, err := ssh.ParsePrivateKey(plaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}
	if err := verifyPinnedCAPublicKey(ctx, signer); err != nil {
		return nil, err
	}
	return signer, nil
}

// verifyPinnedCAPublicKey enforces CA_PUBLIC_KEY_PATH when set. The pinned key is
// non-secret and is expected to be baked into the enclave image (and thus covered
// by PCR0), so a host cannot tamper with it.
func verifyPinnedCAPublicKey(ctx context.Context, signer ssh.Signer) error {
	path := os.Getenv("CA_PUBLIC_KEY_PATH")
	if path == "" {
		slog.WarnContext(ctx, "loadkey.ca_pubkey.unpinned",
			"detail", "CA_PUBLIC_KEY_PATH not set; loaded CA key is not verified against a pinned public key")
		return nil
	}
	// #nosec G304 -- path is operator-supplied configuration, not untrusted input.
	pinnedBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read pinned CA public key '%s': %w", path, err)
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey(pinnedBytes)
	if err != nil {
		return fmt.Errorf("failed to parse pinned CA public key '%s': %w", path, err)
	}
	if !bytes.Equal(pinned.Marshal(), signer.PublicKey().Marshal()) {
		return errors.New("decrypted CA key does not match pinned CA public key (CA_PUBLIC_KEY_PATH); refusing to load")
	}
	slog.InfoContext(ctx, "loadkey.ca_pubkey.verified")
	return nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd /home/pkilar/Devel/cerberus/ssh-cert-signer && go test ./internal/handlers/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add ssh-cert-signer/internal/handlers/load-key-signer.go ssh-cert-signer/internal/handlers/load-key-signer_test.go
git commit -m "signer/handlers: pin decrypted CA key against CA_PUBLIC_KEY_PATH"
```

---

### Task 8: Remove the legacy `LoadKeySigner` path, credentials, and dead constants

**Files:**
- Modify: `ssh-cert-signer/internal/handlers/load-key-signer.go` (delete `LoadKeySignerHandler` + VSOCK/credentials code + now-unused imports)
- Modify: `ssh-cert-signer/internal/handlers/load-key-signer_test.go` (delete old-handler tests)
- Modify: `ssh-cert-signer/cmd/ssh-cert-signer/main.go` (delete `handleLoadKeySigner` + dispatch case + variant count)
- Modify: `ssh-cert-signer/cmd/ssh-cert-signer/main_test.go` (`TestProcessRequest_RejectsAmbiguousVariants`)
- Modify: `messages/messages.go` (delete `LoadKeySigner*` types + union fields; add `RedactedJSON`)
- Delete: `messages/credentials.go`
- Modify: `messages/messages_test.go` (delete `Credentials` tests)
- Modify: `constants/constants.go` (delete `InstanceCID` + `InstanceListeningPort`)

- [ ] **Step 1: Delete the old handler and its imports**

In `ssh-cert-signer/internal/handlers/load-key-signer.go`, delete the entire `LoadKeySignerHandler` function (`:34-178`). Then update the import block to:

```go
import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/crypto/ssh"

	"github.com/pkilar/cerberus/logging"
	"github.com/pkilar/cerberus/ssh-cert-signer/internal/attestation"
)
```

(Removed: `net`, `net/http`, `credentials`, `kms/types`, `awshttp`, `mdlayher/vsock`, `constants`, `messages`. `attestationRequired` and its `strings`/`os`/`fmt`/`errors` usage stay.)

- [ ] **Step 2: Delete the old-handler tests**

In `ssh-cert-signer/internal/handlers/load-key-signer_test.go`, delete `TestLoadKeySignerHandler_MissingFile`, `TestLoadKeySignerHandler_EmptyFilePath`, `TestLoadKeySignerHandler_EmptyFile`, `TestLoadKeySignerHandler_AttestationRequiredButUnavailable`, and `TestLoadKeySignerHandler_EnvironmentVariables` (they exercise the removed function; the Task 2 `BeginKeyLoad*` tests cover the equivalent paths). Keep `TestAttestationRequired`. Remove the now-unused `"github.com/pkilar/cerberus/messages"` import if `goimports` flags it.

- [ ] **Step 3: Delete enclave dispatch for `LoadKeySigner`**

In `ssh-cert-signer/cmd/ssh-cert-signer/main.go`: delete `handleLoadKeySigner` (`:273-283`); remove the `case req.LoadKeySigner != nil:` switch arm; remove the `if req.LoadKeySigner != nil { nVariants++ }` block.

- [ ] **Step 4: Update the ambiguous-variant test**

In `ssh-cert-signer/cmd/ssh-cert-signer/main_test.go`, replace the `cases` slice and the belt-and-braces assertion in `TestProcessRequest_RejectsAmbiguousVariants` (`:402-441`) so it no longer references `LoadKeySignerRequest`:

```go
	cases := []messages.Request{
		{
			BeginKeyLoad: &messages.BeginKeyLoadRequest{},
			SignSshKey:   &messages.EnclaveSigningRequest{},
		},
		{
			CompleteKeyLoad: &messages.CompleteKeyLoadRequest{},
			Ping:            &messages.PingRequest{},
		},
		{
			SignSshKey: &messages.EnclaveSigningRequest{},
			Ping:       &messages.PingRequest{},
		},
		{
			BeginKeyLoad: &messages.BeginKeyLoadRequest{},
			SignSshKey:   &messages.EnclaveSigningRequest{},
			Ping:         &messages.PingRequest{},
		},
	}
```

And change the final assertion from `resp.LoadKeySigner != nil` to `resp.BeginKeyLoad != nil`:

```go
			if resp.BeginKeyLoad != nil || resp.SignSshKey != nil || resp.Pong != nil {
				t.Errorf("ambiguous request must not be dispatched; got resp=%+v", resp)
			}
```

- [ ] **Step 5: Remove `LoadKeySigner*` from messages and relocate `RedactedJSON`**

In `messages/messages.go`: delete the `LoadKeySigner *LoadKeySignerRequest` field from `Request`, the `LoadKeySigner *LoadKeySignerResponse` field from `Response`, and the `LoadKeySignerRequest`/`LoadKeySignerResponse` type definitions (`:87-97`). Append this to `messages/messages.go` (move `RedactedJSON` off `credentials.go`):

```go
// RedactedJSON marshals a Request for safe debug logging.
//
// MAINTAINER NOTE: No Request variant currently carries secret material —
// credentials are no longer sent over the wire (the host performs the KMS
// Decrypt and only enclave-decryptable ciphertext crosses VSOCK). If a future
// variant carries a secret, redact it here BEFORE marshalling, or debug logging
// of that request will leak it.
func RedactedJSON(r Request) string {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}
```

Update `messages/messages.go`'s import block to include `"encoding/json"` and `"fmt"` (keep `"time"`):

```go
import (
	"encoding/json"
	"fmt"
	"time"
)
```

- [ ] **Step 6: Delete `credentials.go` and its tests**

```bash
cd /home/pkilar/Devel/cerberus
git rm messages/credentials.go
```

In `messages/messages_test.go`, delete `TestCredentials_Redacted`, `TestCredentials_String_NoSecretLeak`, and `TestCredentials_JSON`. Remove `"strings"` from its imports only if no remaining test uses it — `TestBeginKeyLoad_JSON` (Task 1) uses `strings.Contains`, so keep `"strings"`.

- [ ] **Step 7: Remove dead constants**

In `constants/constants.go`, delete the `InstanceCID` and `InstanceListeningPort` declarations (`:7-11`) and update the package doc to drop the parent-instance proxy port. Resulting file:

```go
// Package constants defines the VSOCK CIDs and port numbers used for
// communication between the ssh-cert-api host service and the ssh-cert-signer
// enclave. These values are fixed by the deployment topology; changing them
// requires a coordinated update on both sides.
package constants

// Context identifier for the enclave. This value must match the value used with `nitro-cli run-enclave`.
const EnclaveCID = 16

// Port the enclave listens on.
// Port 5000 is used here; any unused port above 1024 is fine.
const EnclaveListeningPort = 5000
```

- [ ] **Step 8: Build, tidy, and run the full suite + lint across all modules**

Run:
```bash
cd /home/pkilar/Devel/cerberus
go build ./... && (cd ssh-cert-api && go build ./...) && (cd ssh-cert-signer && go build ./...)
go mod tidy && (cd ssh-cert-api && go mod tidy) && (cd ssh-cert-signer && go mod tidy)
go test -race ./... && (cd ssh-cert-api && go test -race ./...) && (cd ssh-cert-signer && go test -race ./...)
golangci-lint run ./... && (cd ssh-cert-api && golangci-lint run ./...) && (cd ssh-cert-signer && golangci-lint run ./...)
gosec ./... ; (cd ssh-cert-api && gosec ./...) ; (cd ssh-cert-signer && gosec ./...)
git status --porcelain go.mod go.sum ssh-cert-api/go.mod ssh-cert-api/go.sum ssh-cert-signer/go.mod ssh-cert-signer/go.sum
```
Expected: all build; `go mod tidy` leaves the `go.*` files unchanged (CI tidy-drift gate); all tests pass under `-race`; lint clean. The signer module should drop `mdlayher/vsock`'s use in this file and `kms/types`/`awshttp`/`credentials` if otherwise unused (tidy reflects it).

- [ ] **Step 9: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add -A
git commit -m "Remove legacy LoadKeySigner path, wire credentials, and KMS proxy constants"
```

---

### Task 9: Documentation and the KMS-policy migration note

**Files:**
- Modify: `CLAUDE.md`, `docs/RUNBOOK.md`, `docs/kms-attestation-policy.md`, `ARCHITECTURE-EXECUTIVE.md`, `packaging/rpm/` (sysconfig/README)

- [ ] **Step 1: Update `CLAUDE.md`**

- Replace the architecture diagram's `proxy: VSOCK :8000 ─── TCP ───→ kms…` element: the host now calls KMS directly with the enclave's attestation document; there is no proxy.
- Rewrite the "Attestation hot path" paragraph: the KMS `Decrypt` now runs **on the host** (`ssh-cert-api/internal/keyload`) with `Recipient` set to the enclave's NSM attestation document; KMS returns `CiphertextForRecipient` (CMS envelope) which the enclave opens with its ephemeral key. AWS credentials never enter the enclave.
- Update the "No network in the enclave" invariant: in production the enclave makes **no** KMS call; the host mediates it. The dev (no `/dev/nsm`) signer decrypts directly over its own network. The `proxy/` package is gone.
- Replace the `LoadKeySigner` wire description with the `BeginKeyLoad`/`CompleteKeyLoad` handshake; note credentials no longer cross VSOCK.
- Add the `CA_PUBLIC_KEY_PATH` pin (new `loadkey.ca_pubkey.verified` / `loadkey.ca_pubkey.unpinned` events) and the `loadkey.begin.attested` / `loadkey.complete.attested` events to the slog event list.

- [ ] **Step 2: Update `docs/kms-attestation-policy.md` (the migration prerequisite)**

Add a prominent section stating: the CMK policy MUST grant `Decrypt` to the parent instance role **only** under a `kms:RecipientAttestation:ImageSha384` (PCR0) condition, and MUST NOT contain any unconditioned `Decrypt` allow for that role — otherwise the host (now the legitimate caller, holding the ciphertext) could issue a plaintext `Decrypt`. Note the calling principal is unchanged (parent instance role in both designs), so existing correctly-scoped policies need verification, not edits. Document `CA_PUBLIC_KEY_PATH` as the recommended defense-in-depth pin baked into the EIF.

- [ ] **Step 3: Update `docs/RUNBOOK.md`**

- Remove proxy lifecycle/troubleshooting entries; add the host-mediated load flow and the two new failure modes: KMS `Decrypt` denied (check the attestation-conditioned policy + instance role) and CA pin mismatch (`CA_PUBLIC_KEY_PATH`).
- Document setting `CA_PUBLIC_KEY_PATH` (point at the baked-in `ca_key.pub`) and `AWS_REGION`.

- [ ] **Step 4: Update `ARCHITECTURE-EXECUTIVE.md` and packaging**

- `ARCHITECTURE-EXECUTIVE.md`: reflect "host performs the attested KMS decrypt; no proxy; credentials never enter the enclave."
- `packaging/rpm/`: if `run-enclave.sh`/sysconfig referenced the proxy port `8000` or instance CID, remove it; document baking `ca_key.pub` into the image and exporting `CA_PUBLIC_KEY_PATH`. (Grep first: `rg -n '8000|InstanceCID|vsock-proxy|CA_PUBLIC_KEY' packaging/ docs/ run-enclave.sh 2>/dev/null`.)

- [ ] **Step 5: Commit**

```bash
cd /home/pkilar/Devel/cerberus
git add CLAUDE.md docs/ ARCHITECTURE-EXECUTIVE.md packaging/
git commit -m "docs: host-mediated attested KMS decrypt; proxy removal; CA pubkey pin; KMS policy prerequisite"
```

---

## Self-Review

**Spec coverage**
- "Encrypt the CA-key response to the attestation public key" → already satisfied; preserved on the attested path (Task 2 `CompleteKeyLoad` → `DecryptCMSEnvelope`).
- "Drop the KMS proxy" → Tasks 5–6 (host performs the KMS call; `proxy/` deleted).
- Credentials off the wire → Tasks 6 (host stops forwarding) + 8 (`Credentials`/`credentials.go` removed).
- Dev path = signer-direct KMS → Task 2 (`decryptDirect`), reached when no `/dev/nsm`.
- Enclave returns the ciphertext → Task 2/3 (`BeginKeyLoadResponse.CiphertextBlob`).
- Integrity parity for substitution → Task 7 (`CA_PUBLIC_KEY_PATH` pin).
- Policy prerequisite → Task 9 + the callout at the top.

**Type consistency** — `BeginKeyLoadResponse{AttestationDocument, CiphertextBlob, Loaded}`, `CompleteKeyLoadRequest{CiphertextForRecipient}`, `CompleteKeyLoadResponse{Success}`, `BeginKeyLoadResult{AttestationDocument, CiphertextBlob, Signer}`, `KMSDecrypter.DecryptForEnclave(ctx, ciphertextBlob, attestationDocument)`, `keyload.Run(ctx, enclave.Signer, KMSDecrypter)` are used identically across Tasks 1–6.

**Green-at-each-task** — Tasks 1–5 are additive (old path intact). Task 6 switches the host and deletes the proxy (enclave still serves the legacy variant). Task 7 is internal. Task 8 removes the now-unused legacy surface and runs the full `-race` + lint + tidy gate.

**Out of scope (note for executor)** — `integration_test.go`'s mock only serves `SignSshKey` and never referenced the load types, so it needs no change. An optional end-to-end test could teach the mock to answer `BeginKeyLoad` with `Loaded:true`; the `keyload` unit tests already cover both branches, so this is not required.
