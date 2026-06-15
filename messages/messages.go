// Package messages defines the JSON wire protocol between ssh-cert-api (the
// host-side HTTPS gateway) and ssh-cert-signer (the Nitro Enclave signer).
// Every request/response crossing VSOCK is encoded as one of these types.
package messages

import "time"

// MaxPrincipals is the maximum number of SSH principals accepted in a single
// signing request. Enforced by the host (before authorization, to bound the
// per-request Casbin work) and the enclave (in input validation).
const MaxPrincipals = 100

// MaxValidity caps the lifetime of any issued certificate. The enclave
// rejects requests exceeding this, and config.Validate refuses configs whose
// per-group validity exceeds it — so a misconfigured group fails at startup
// instead of silently denying every signing request at runtime.
const MaxValidity = 24 * time.Hour

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

// PingRequest is a no-op request used by /health to verify the enclave is
// reachable and has a loaded CA signer.
type PingRequest struct{}

// GetEnclaveMetricsRequest asks the enclave to sample its own /proc/stat and
// /proc/meminfo. The host polls this on a slow cadence (default 15s, matched
// to the default Prometheus scrape interval) and exposes the values via the
// /metrics endpoint as cerberus_enclave_cpu_seconds_total{mode} and
// cerberus_enclave_memory_bytes{type}.
type GetEnclaveMetricsRequest struct{}

// EnclaveMetricsResponse carries one snapshot of enclave resource usage. CPU
// values are cumulative seconds since enclave boot (counter semantics — the
// host emits them as Prometheus counters and Grafana queries use rate());
// Memory values are byte counts at sample time (gauge semantics).
type EnclaveMetricsResponse struct {
	CPU    EnclaveCPUTimes    `json:"cpu"`
	Memory EnclaveMemoryStats `json:"memory"`
}

// EnclaveCPUTimes is the seven canonical /proc/stat aggregate-cpu modes,
// converted from jiffies to seconds inside the enclave so the host doesn't
// have to know the enclave's CLK_TCK.
type EnclaveCPUTimes struct {
	User    float64 `json:"user"`
	Nice    float64 `json:"nice"`
	System  float64 `json:"system"`
	Idle    float64 `json:"idle"`
	IOWait  float64 `json:"iowait"`
	IRQ     float64 `json:"irq"`
	SoftIRQ float64 `json:"softirq"`
}

// EnclaveMemoryStats is the subset of /proc/meminfo the host surfaces as
// Prometheus metrics. Bytes (not kB) so the wire format matches the unit
// node_exporter uses.
type EnclaveMemoryStats struct {
	TotalBytes     uint64 `json:"totalBytes"`
	AvailableBytes uint64 `json:"availableBytes"`
	FreeBytes      uint64 `json:"freeBytes"`
	BuffersBytes   uint64 `json:"buffersBytes"`
	CachedBytes    uint64 `json:"cachedBytes"`
}

// PingResponse is the enclave's reply to a PingRequest. SignerLoaded is
// false during the brief window between process start and LoadKeySigner
// completing; load balancers should treat that as unhealthy.
type PingResponse struct {
	SignerLoaded bool `json:"signerLoaded"`
}

// LoadKeySignerRequest carries the AWS credentials the enclave uses to decrypt
// the CA key via KMS. The encrypted key itself lives on the enclave filesystem
// (CA_KEY_FILE_PATH); it does not travel over the wire.
type LoadKeySignerRequest struct {
	Credentials Credentials `json:"credentials"`
}

type LoadKeySignerResponse struct {
	Success bool   `json:"success,omitempty"`
	Error   string `json:"error,omitempty"`
}

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

// SigningRequest is the structure for JSON requests coming from the web API.
type SigningRequest struct {
	SSHKey     string   `json:"ssh_key"`
	KeyID      string   `json:"key_id,omitempty"`
	Principals []string `json:"principals,omitempty"`
}

// SigningResponse is the structure for JSON response sent back by the web API and the Nitro Enclave.
type SigningResponse struct {
	SignedKey string `json:"signed_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

// EnclaveSigningRequest is the structure for JSON request being sent to the Nitro Enclave.
// The three map fields share a serialization policy: an empty or nil map is
// elided from the wire payload (omitempty) rather than encoded as "null", so a
// group with no permissions / static_attributes / critical_options produces
// the same compact shape. The signer treats a missing field as an empty map
// (maps.Copy from nil is a no-op) and the overlap check ranges nil safely.
type EnclaveSigningRequest struct {
	SSHKey           string            `json:"ssh_key"`
	KeyID            string            `json:"key_id"`
	Principals       []string          `json:"principals"`
	Validity         string            `json:"validity"`
	Permissions      map[string]string `json:"permissions,omitempty"`
	CustomAttributes map[string]string `json:"custom_attributes,omitempty"`
	CriticalOptions  map[string]string `json:"critical_options,omitempty"`
}
