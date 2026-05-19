// Package attestation provides Nitro Enclave attestation for KMS Decrypt calls.
// When running inside a Nitro Enclave, it generates NSM attestation documents
// and decrypts the CMS envelopes returned by KMS. Outside an enclave, it
// gracefully degrades to a no-op so the signer can run without attestation
// during development.
package attestation

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"

	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Provider wraps NSM attestation document generation and CMS envelope decryption.
// If the NSM device is not available (outside an enclave), all operations
// gracefully return nil/false so callers can fall back to standard KMS Decrypt.
type Provider struct {
	session *nsm.Session
	rsaKey  *rsa.PrivateKey
}

// NewProvider creates an attestation Provider. It attempts to open the NSM
// device at /dev/nsm and generate an RSA-2048 keypair. If NSM is unavailable
// (not running inside an enclave), the provider is returned in a degraded state
// where IsAvailable() returns false.
func NewProvider() *Provider {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Printf("NSM device not available: %v (attestation disabled)", err)
		return &Provider{}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = sess.Close()
		log.Printf("Failed to generate RSA keypair for attestation: %v", err)
		return &Provider{}
	}

	return &Provider{session: sess, rsaKey: key}
}

// IsAvailable returns true if the provider has an active NSM session and
// can generate attestation documents.
func (p *Provider) IsAvailable() bool {
	return p != nil && p.session != nil && p.rsaKey != nil
}

// GenerateAttestationDoc requests an attestation document from the NSM device.
// The document includes the provider's RSA public key so that KMS can encrypt
// the response plaintext under it.
func (p *Provider) GenerateAttestationDoc() ([]byte, error) {
	if !p.IsAvailable() {
		return nil, errors.New("attestation not available")
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&p.rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
	}

	res, err := p.session.Send(&request.Attestation{
		PublicKey: pubKeyDER,
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation request failed: %w", err)
	}

	if res.Error != "" {
		return nil, fmt.Errorf("NSM returned error: %s", res.Error)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM did not return an attestation document")
	}

	return res.Attestation.Document, nil
}

// DecryptCMSEnvelope decrypts a CMS EnvelopedData structure (RFC 5652) as
// returned by KMS in the CiphertextForRecipient field. The envelope uses
// RSA-OAEP-SHA256 key transport and AES-256-CBC content encryption.
//
// KMS emits BER (with indefinite-length wrappers and occasionally a
// constructed encrypted-content OCTET STRING), which Go's encoding/asn1
// rejects. We delegate to the edgebit Nitro SDK's cms package, which performs
// a BER→DER pass and concatenates constructed OCTET STRINGs before
// unmarshaling — the same path AWS's reference implementations take.
//
// The gate is narrower than IsAvailable on purpose: decryption needs only
// the RSA key, not the NSM session. Callers that require end-to-end
// attestation (i.e. attestation doc generation) check IsAvailable separately.
func (p *Provider) DecryptCMSEnvelope(data []byte) (plaintext []byte, err error) {
	if p == nil || p.rsaKey == nil {
		return nil, errors.New("attestation RSA key not available")
	}

	// Trust-boundary defense: the upstream BER parser has at least one
	// known panic on adversarial input (off-by-one bound check in
	// readObject's multi-byte-tag loop). Since the input here is the KMS
	// response body proxied via VSOCK from the parent instance, a
	// compromised host could inject crafted bytes. Convert any panic into
	// an error so the enclave fails closed instead of crashing — and log
	// it, because a panic here is a strong signal of a hostile host and
	// operators need to see it (the raw bytes are intentionally not
	// logged; input_len is the signal-to-noise floor).
	defer func() {
		if r := recover(); r != nil {
			slog.Error("attestation.cms.parser_panic",
				"panic", fmt.Sprintf("%v", r),
				"input_len", len(data))
			err = fmt.Errorf("CMS envelope parser panicked on input: %v", r)
		}
	}()

	plaintext, err = cms.DecryptEnvelopedKey(p.rsaKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt CMS envelope: %w", err)
	}
	return plaintext, nil
}

// Close releases the NSM session.
func (p *Provider) Close() {
	if p != nil && p.session != nil {
		_ = p.session.Close()
	}
}
