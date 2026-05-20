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
	LoadKeySigner *LoadKeySignerRequest  `json:"loadKeySigner,omitempty"`
	SignSshKey    *EnclaveSigningRequest `json:"signSshKey,omitempty"`
	Ping          *PingRequest           `json:"ping,omitempty"`
}

type Response struct {
	LoadKeySigner *LoadKeySignerResponse `json:"loadKeySigner,omitempty"`
	Error         *string                `json:"error,omitempty"`
	SignSshKey    *SigningResponse       `json:"signSshKey,omitempty"`
	Pong          *PingResponse          `json:"pong,omitempty"`
}

// PingRequest is a no-op request used by /health to verify the enclave is
// reachable and has a loaded CA signer.
type PingRequest struct{}

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
type EnclaveSigningRequest struct {
	SSHKey           string            `json:"ssh_key"`
	KeyID            string            `json:"key_id"`
	Principals       []string          `json:"principals"`
	Validity         string            `json:"validity"`
	Permissions      map[string]string `json:"permissions"`
	CustomAttributes map[string]string `json:"custom_attributes"`
	CriticalOptions  map[string]string `json:"critical_options,omitempty"`
}
