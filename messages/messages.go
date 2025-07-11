package messages

// These messages define the API between the ssh-cert-signer and ssh-cert-api.
// Only one of each field is expected to be set at any given time.
type Request struct {
	LoadKeySigner *LoadKeySignerRequest  `json:"loadKeySigner,omitempty"`
	SignSshKey    *EnclaveSigningRequest `json:"signSshKey,omitempty"`
}

type Response struct {
	LoadKeySigner *LoadKeySignerResponse `json:"loadKeySigner,omitempty"`
	Error         *string                `json:"error,omitempty"`
	SignSshKey    *SigningResponse       `json:"signSshKey,omitempty"`
}

// Requests loading of KMS-encrypted CA certificate.
type LoadKeySignerRequest struct {
	EncryptedKey string      `json:"encryptedKey"`
	Credentials  Credentials `json:"credentials"`
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
