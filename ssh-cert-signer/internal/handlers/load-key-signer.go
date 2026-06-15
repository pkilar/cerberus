// Package handlers implements the enclave-side request handlers: BeginKeyLoad
// and CompleteKeyLoad drive the host-mediated CA-key load on startup (with
// Nitro attestation when available), and SignPublicKey produces an SSH
// certificate for a validated request. The CA private key lives in this
// process's memory and never leaves the enclave.
package handlers

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

// BeginKeyLoadResult is returned by BeginKeyLoad. Exactly one outcome is set:
//   - AttestationDocument + CiphertextBlob: production path. The host must call
//     KMS Decrypt with the attestation document as the Recipient, then return
//     the CiphertextForRecipient to the enclave via CompleteKeyLoad.
//   - Signer non-nil: development path (no /dev/nsm). The enclave already
//     decrypted the key itself. No CompleteKeyLoad follows.
type BeginKeyLoadResult struct {
	AttestationDocument []byte
	CiphertextBlob      []byte
	Signer              ssh.Signer
}

// BeginKeyLoad starts the host-mediated CA-key load sequence. In production the
// enclave generates an attestation document and returns the KMS-encrypted CA key
// blob to the host; the host performs the KMS Decrypt and sends the resulting
// CiphertextForRecipient back via CompleteKeyLoad. In development (no /dev/nsm
// and REQUIRE_ATTESTATION not true) the enclave decrypts the key over its own
// network (development only).
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
			"ciphertext_bytes", len(encryptedKeyBytes),
			"attestation_doc_bytes", len(attestDoc))
		return &BeginKeyLoadResult{
			AttestationDocument: attestDoc,
			CiphertextBlob:      encryptedKeyBytes,
		}, nil
	}

	if required {
		return nil, errors.New("attestation is required but unavailable; refusing to load CA key without an available attestation provider (set REQUIRE_ATTESTATION=false to override — not recommended in production)")
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

// CompleteKeyLoad finishes the host-mediated key load by decrypting the CMS
// envelope that KMS returned as CiphertextForRecipient. Only reached in the
// production attested path; requires a live attestation provider.
func CompleteKeyLoad(ctx context.Context, attestProvider *attestation.Provider, ciphertextForRecipient []byte) (ssh.Signer, error) {
	if attestProvider == nil || !attestProvider.IsAvailable() {
		return nil, errors.New("cannot complete key load without an available attestation provider")
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
	// #nosec G304,G703 -- caKeyFilePath comes from the CA_KEY_FILE_PATH env var set
	// by the operator (or a packaged systemd unit), not untrusted input.
	encryptedKeyBytes, err := os.ReadFile(caKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file '%s': %w", caKeyFilePath, err)
	}
	logging.DebugContext(ctx, "Read encrypted CA key file (%d bytes)", len(encryptedKeyBytes))
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
	// #nosec G304,G703 -- path is operator-supplied configuration, not untrusted input.
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

// attestationRequired reports whether KMS Decrypt must use a Recipient attestation
// document. Defaults to true when /dev/nsm is present (i.e. running inside a Nitro
// Enclave). REQUIRE_ATTESTATION=true|false overrides the auto-detection.
func attestationRequired() (bool, error) {
	// Case-insensitive so REQUIRE_ATTESTATION=True / =TRUE / =Yes are honored.
	// Misreading these as "fall through to auto-detect" silently disables a
	// security-critical setting on hosts without /dev/nsm.
	raw, set := os.LookupEnv("REQUIRE_ATTESTATION")
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	case "":
		if set {
			// Explicitly set to empty: treat as a misconfiguration rather than
			// silently auto-detecting, so a blanked-out value fails closed.
			return false, fmt.Errorf("REQUIRE_ATTESTATION is set but empty; use true/false (or unset it to auto-detect /dev/nsm)")
		}
		// Unset: auto-detect by probing for the NSM device.
		_, err := os.Stat("/dev/nsm")
		return err == nil, nil
	default:
		// An unrecognized value (e.g. a typo) must NOT silently fall through to
		// auto-detection — that could disable attestation on a host without
		// /dev/nsm. Fail closed so the misconfiguration is caught at startup.
		return false, fmt.Errorf("REQUIRE_ATTESTATION has unrecognized value %q; use true/false (or unset it to auto-detect /dev/nsm)", raw)
	}
}
