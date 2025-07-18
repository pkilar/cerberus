package handlers

import (
	"cerberus/messages"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"maps"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// Maximum validity duration for certificates (24 hours)
	maxValidityDuration = 24 * time.Hour
	// Maximum number of principals allowed
	maxPrincipals = 100
	// Clock skew allowance in seconds
	clockSkewSeconds = 300 // 5 minutes
	// Nonce size in bytes
	nonceSize = 32
)

// SignPublicKey contains the core logic for signing the SSH key.
func SignPublicKey(ctx context.Context, caSigner ssh.Signer, req messages.EnclaveSigningRequest) (*messages.SigningResponse, error) {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("operation cancelled: %w", ctx.Err())
	default:
	}

	// Validate inputs
	if err := validateSigningRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if caSigner == nil {
		return nil, fmt.Errorf("CA signer is not initialized. Call LoadKeySigner first")
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	validityDuration, err := time.ParseDuration(req.Validity)
	if err != nil {
		return nil, fmt.Errorf("invalid validity duration string '%s': %w", req.Validity, err)
	}

	// Security check: limit validity duration
	if validityDuration > maxValidityDuration {
		return nil, fmt.Errorf("validity duration %v exceeds maximum allowed %v", validityDuration, maxValidityDuration)
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

	// Build permissions correctly - fix critical bug
	permissions := ssh.Permissions{
		Extensions:      make(map[string]string),
		CriticalOptions: make(map[string]string),
	}

	// Copy permissions to extensions
	if req.Permissions != nil {
		maps.Copy(permissions.Extensions, req.Permissions)
	}

	// Copy custom attributes to extensions
	if req.CustomAttributes != nil {
		maps.Copy(permissions.Extensions, req.CustomAttributes)
	}

	// Copy critical options
	if req.CriticalOptions != nil {
		maps.Copy(permissions.CriticalOptions, req.CriticalOptions)
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Nonce:           nonce,
		Key:             publicKey,
		Serial:          serial.Uint64(),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(now.Unix()) - clockSkewSeconds,
		ValidBefore:     uint64(now.Add(validityDuration).Unix()),
		Permissions:     permissions,
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

	log.Printf("Successfully signed certificate for KeyID: %s, Serial: %d, ValidAfter: %d, ValidBefore: %d",
		req.KeyID, cert.Serial, cert.ValidAfter, cert.ValidBefore)

	signedKeyBytes := ssh.MarshalAuthorizedKey(cert)

	return &messages.SigningResponse{
		SignedKey: strings.TrimSpace(string(signedKeyBytes)),
	}, nil
}

// validateSigningRequest performs comprehensive input validation
func validateSigningRequest(req messages.EnclaveSigningRequest) error {
	if strings.TrimSpace(req.SSHKey) == "" {
		return fmt.Errorf("SSH key cannot be empty")
	}

	if strings.TrimSpace(req.KeyID) == "" {
		return fmt.Errorf("KeyID cannot be empty")
	}

	if strings.TrimSpace(req.Validity) == "" {
		return fmt.Errorf("validity duration cannot be empty")
	}

	// Validate validity duration format
	if _, err := time.ParseDuration(req.Validity); err != nil {
		return fmt.Errorf("invalid validity duration format: %w", err)
	}

	// Limit number of principals for security
	if len(req.Principals) > maxPrincipals {
		return fmt.Errorf("too many principals: %d (maximum: %d)", len(req.Principals), maxPrincipals)
	}

	// Validate principals are not empty strings
	for i, principal := range req.Principals {
		if strings.TrimSpace(principal) == "" {
			return fmt.Errorf("principal at index %d cannot be empty", i)
		}
	}

	return nil
}
