package handlers

import (
	"cerberus/messages"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"maps"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SignPublicKey contains the core logic for signing the SSH key.
func SignPublicKey(ctx context.Context, caSigner ssh.Signer, req messages.EnclaveSigningRequest) (*messages.SigningResponse, error) {
	if caSigner == nil {
		return nil, fmt.Errorf("CA signer is not initialized. Call LoadKeySigner first")
	}

	r := &messages.SigningResponse{}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	validityDuration, err := time.ParseDuration(req.Validity)
	if err != nil {
		return nil, fmt.Errorf("invalid validity duration string '%s': %w", req.Validity, err)
	}

	permissions := ssh.Permissions{
		Extensions:      make(map[string]string),
		CriticalOptions: make(map[string]string),
	}
	maps.Copy(permissions.Extensions, req.Permissions)
	maps.Copy(permissions.Extensions, req.CustomAttributes)
	maps.Copy(permissions.CriticalOptions, req.CriticalOptions)

	cert := &ssh.Certificate{
		Nonce:           []byte{},
		Key:             publicKey,
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(time.Now().Unix()) - 60, // Allow for 60s clock skew
		ValidBefore:     uint64(time.Now().Add(validityDuration).Unix()),
		Permissions:     permissions,
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("cryptographic signing failed: %w", err)
	}
	log.Printf("Successfully signed certificate for KeyID: %s", req.KeyID)

	signedKeyBytes := ssh.MarshalAuthorizedKey(cert)
	r.SignedKey = strings.TrimSpace(string(signedKeyBytes))
	return r, nil
}
