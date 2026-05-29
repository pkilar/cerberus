package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"strings"
	"time"

	"github.com/pkilar/cerberus/messages"

	"golang.org/x/crypto/ssh"
)

const (
	// Clock skew allowance in seconds
	clockSkewSeconds = 300 // 5 minutes
	// Nonce size in bytes
	nonceSize = 32
	// Minimum RSA key size accepted in submitted public keys. Anything below
	// 2048 is too weak to certify even for a short-lived cert.
	minRSAKeyBits = 2048
)

// SignPublicKey contains the core logic for signing the SSH key.
func SignPublicKey(ctx context.Context, caSigner ssh.Signer, req messages.EnclaveSigningRequest) (*messages.SigningResponse, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("operation cancelled: %w", ctx.Err())
	default:
	}

	// Validate inputs; this also parses the validity duration (once).
	validityDuration, err := validateSigningRequest(req)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if caSigner == nil {
		return nil, fmt.Errorf("CA signer is not initialized. Call LoadKeySigner first")
	}

	publicKey, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	// The input must be a bare authorized_keys-style key blob. Prefix options
	// (e.g. `cert-authority,no-pty ssh-rsa ...`) and trailing bytes are silently
	// dropped by ParseAuthorizedKey today; refuse them so the input string the
	// caller sent is faithfully what we sign.
	if len(options) > 0 {
		return nil, fmt.Errorf("public key must not carry SSH options")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("public key must not carry trailing data")
	}

	if err := validatePublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("rejected public key: %w", err)
	}

	// Reject zero/negative durations: a 0 or negative duration produces a cert
	// with ValidBefore <= ValidAfter (after the clock-skew back-date), which
	// sshd rejects. Fail loudly here instead of issuing a useless cert.
	if validityDuration <= 0 {
		return nil, fmt.Errorf("validity duration must be positive (got %v)", validityDuration)
	}

	// Security check: limit validity duration
	if validityDuration > messages.MaxValidity {
		return nil, fmt.Errorf("validity duration %v exceeds maximum allowed %v", validityDuration, messages.MaxValidity)
	}

	// Generate cryptographically secure nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate secure nonce: %w", err)
	}

	// Generate cryptographically secure serial number
	serialMax := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure serial number: %w", err)
	}

	// Cert permissions. Extensions hold SSH-protocol permissions (permit-pty,
	// permit-port-forwarding, ...) and any audit/custom attributes — the SSH
	// cert format keeps them in the same map. CriticalOptions are separate
	// and carry stronger enforcement semantics. validateSigningRequest has
	// already rejected any key collision between Permissions and
	// CustomAttributes, so the merge below is unambiguous.
	permissions := ssh.Permissions{
		Extensions:      make(map[string]string),
		CriticalOptions: make(map[string]string),
	}
	maps.Copy(permissions.Extensions, req.Permissions)
	maps.Copy(permissions.Extensions, req.CustomAttributes)
	maps.Copy(permissions.CriticalOptions, req.CriticalOptions)

	now := time.Now()
	cert := &ssh.Certificate{
		Nonce:           nonce,
		Key:             publicKey,
		Serial:          serial.Uint64(),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		// Unix() is monotonically positive since the epoch; the uint64 cast
		// cannot overflow until year 2262, and ssh.Certificate requires uint64.
		ValidAfter:  uint64(now.Unix()) - clockSkewSeconds,    //#nosec G115
		ValidBefore: uint64(now.Add(validityDuration).Unix()), //#nosec G115
		Permissions: permissions,
	}

	// Check for context cancellation before signing
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("operation cancelled before signing: %w", ctx.Err())
	default:
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("cryptographic signing failed: %w", err)
	}

	slog.Info("sign.cert_issued",
		"key_id", req.KeyID,
		"serial", cert.Serial,
		"valid_after", cert.ValidAfter,
		"valid_before", cert.ValidBefore,
		"principals", req.Principals,
	)

	signedKeyBytes := ssh.MarshalAuthorizedKey(cert)

	return &messages.SigningResponse{
		SignedKey: strings.TrimSpace(string(signedKeyBytes)),
	}, nil
}

// validateSigningRequest performs comprehensive input validation and returns
// the parsed validity duration so the caller does not re-parse it. The
// positive/maximum bounds on the duration are enforced by the caller against
// the returned value.
func validateSigningRequest(req messages.EnclaveSigningRequest) (time.Duration, error) {
	if strings.TrimSpace(req.SSHKey) == "" {
		return 0, fmt.Errorf("SSH key cannot be empty")
	}

	if strings.TrimSpace(req.KeyID) == "" {
		return 0, fmt.Errorf("KeyID cannot be empty")
	}

	if strings.TrimSpace(req.Validity) == "" {
		return 0, fmt.Errorf("validity duration cannot be empty")
	}

	// Parse the validity duration once, here; the caller uses the returned
	// value rather than parsing the string a second time.
	validity, err := time.ParseDuration(req.Validity)
	if err != nil {
		return 0, fmt.Errorf("invalid validity duration format: %w", err)
	}

	// Refuse an empty principals slice. The host API rejects this too; this
	// is the enclave-side belt-and-braces for any future host that forgets.
	if len(req.Principals) == 0 {
		return 0, fmt.Errorf("principals cannot be empty")
	}

	// Limit number of principals for security
	if len(req.Principals) > messages.MaxPrincipals {
		return 0, fmt.Errorf("too many principals: %d (maximum: %d)", len(req.Principals), messages.MaxPrincipals)
	}

	// Validate principals are not empty strings
	for i, principal := range req.Principals {
		if strings.TrimSpace(principal) == "" {
			return 0, fmt.Errorf("principal at index %d cannot be empty", i)
		}
	}

	// Reject overlapping keys between Permissions and CustomAttributes. Both
	// merge into the cert's Extensions map, so a collision would silently
	// override one with the other depending on iteration order — refuse the
	// request rather than letting that ambiguity reach the signed cert.
	for k := range req.CustomAttributes {
		if _, exists := req.Permissions[k]; exists {
			return 0, fmt.Errorf("key %q present in both permissions and custom_attributes", k)
		}
	}

	return validity, nil
}

// validatePublicKey restricts the algorithms and key sizes the signer will
// issue certificates for. Even when the host has authorized the request, the
// enclave refuses to certify keys it considers too weak to be useful for
// short-lived auth.
func validatePublicKey(publicKey ssh.PublicKey) error {
	cpk, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("unsupported public key wrapper: %T", publicKey)
	}
	switch k := cpk.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		// No upper bound is enforced here: ssh.ParseAuthorizedKey (called
		// above, inside the enclave) already rejects RSA moduli larger than
		// 8192 bits ("ssh: rsa modulus too large"), so an oversized key never
		// reaches this switch. 8192-bit RSA is strong, not pathological, so we
		// only enforce the lower bound here.
		if k.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("RSA key too small: %d bits (minimum %d)", k.N.BitLen(), minRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		// Explicit curve allowlist. ssh.ParseAuthorizedKey currently only
		// emits NIST-P256/P384/P521, but enumerating them here keeps the
		// signer's contract local instead of depending on a transitive
		// parser invariant that may widen in a future x/crypto release.
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			// OK
		default:
			return fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		// Ed25519 is fixed-strength; nothing more to check.
	default:
		return fmt.Errorf("unsupported public key type: %T", k)
	}
	return nil
}
