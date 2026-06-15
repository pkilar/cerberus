// Package handlers implements the enclave-side request handlers:
// LoadKeySignerHandler decrypts the KMS-encrypted CA key on startup (with
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
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"

	"github.com/pkilar/cerberus/constants"
	"github.com/pkilar/cerberus/logging"
	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-signer/internal/attestation"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
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
	// #nosec G304 -- caKeyFilePath comes from the CA_KEY_FILE_PATH env var set by
	// the operator (or a packaged systemd unit), not untrusted input.
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

// LoadKeySignerHandler loads an encrypted CA key from a file and decrypts it with KMS.
// If attestProvider is non-nil and available, an NSM attestation document is attached
// to the KMS Decrypt call for full enclave attestation. Pass nil to skip attestation
// (development mode or testing).
//
// When running inside a Nitro Enclave (detected via /dev/nsm) or when
// REQUIRE_ATTESTATION=true, the handler refuses to decrypt without a working
// attestation provider. This prevents silent downgrade to plaintext KMS Decrypt
// if the NSM device becomes unavailable.
func LoadKeySignerHandler(ctx context.Context, req messages.LoadKeySignerRequest, attestProvider *attestation.Provider) (ssh.Signer, error) {
	required, err := attestationRequired()
	if err != nil {
		return nil, err
	}
	if required {
		if attestProvider == nil || !attestProvider.IsAvailable() {
			return nil, errors.New("attestation is required but unavailable; refusing to load CA key (set REQUIRE_ATTESTATION=false to override — not recommended in production)")
		}
	}

	// Set default region to us-east-1 if not specified
	region := cmp.Or(os.Getenv("AWS_REGION"), "us-east-1")

	// Create custom HTTP client that routes through VSOCK proxy
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			logging.DebugContext(ctx, "KMS SDK attempting to connect to: %s (network: %s)", addr, network)
			logging.DebugContext(ctx, "Intercepting connection via vsock (cid=%d, port=%d)", constants.InstanceCID, constants.InstanceListeningPort)
			conn, err := vsock.Dial(constants.InstanceCID, constants.InstanceListeningPort, nil)
			if err != nil {
				slog.ErrorContext(ctx, "loadkey.vsock_dial_failed", "error", err)
				return nil, err
			}
			logging.DebugContext(ctx, "VSOCK connection established successfully")
			return conn, nil
		}
	})

	// The AWS SDK must use the credentials from the parent instance.
	credentialProvider := credentials.NewStaticCredentialsProvider(req.Credentials.AccessKeyId, req.Credentials.SecretAccessKey, req.Credentials.Token)

	// Drop our reference to the credential material once the provider has copied
	// it. req is passed by value, so this clears the only copy this function
	// holds; the static provider retains its own, which is unavoidable for the
	// KMS call below. Go strings are immutable so this does not wipe the backing
	// bytes, but releasing the reference lets the GC reclaim them and shrinks the
	// window in which a heap scan finds the secret in this struct — the same
	// best-effort defense-in-depth applied to the plaintext key buffers later.
	req.Credentials = messages.Credentials{}

	logging.DebugContext(ctx, "Loading AWS configuration...")
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithHTTPClient(httpClient),
		config.WithCredentialsProvider(credentialProvider))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS default config: %w", err)
	}

	caKeyFilePath := cmp.Or(os.Getenv("CA_KEY_FILE_PATH"), "/app/ca_key.enc")

	// Read the encrypted CA key from file
	logging.DebugContext(ctx, "Reading encrypted CA key from file: %s", caKeyFilePath)
	// #nosec G304,G703 -- caKeyFilePath comes from the CA_KEY_FILE_PATH env
	// var set by the operator (or a packaged systemd unit), not untrusted input.
	encryptedKeyBytes, err := os.ReadFile(caKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file '%s': %w", caKeyFilePath, err)
	}
	logging.DebugContext(ctx, "Successfully read encrypted key file (%d bytes)", len(encryptedKeyBytes))

	kmsClient := kms.NewFromConfig(cfg)
	logging.DebugContext(ctx, "Created KMS client for region: %s", region)
	logging.DebugContext(ctx, "All HTTP requests will go through VSOCK proxy to parent instance")

	// Build KMS Decrypt input
	logging.DebugContext(ctx, "Decrypting CA key with KMS...")
	logging.DebugContext(ctx, "Encrypted key size: %d bytes", len(encryptedKeyBytes))
	decryptInput := &kms.DecryptInput{
		CiphertextBlob: encryptedKeyBytes,
	}

	// If running inside an enclave, attach attestation document
	if attestProvider != nil && attestProvider.IsAvailable() {
		logging.DebugContext(ctx, "Generating NSM attestation document...")
		attestDoc, err := attestProvider.GenerateAttestationDoc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate attestation document: %w", err)
		}
		decryptInput.Recipient = &types.RecipientInfo{
			AttestationDocument:    attestDoc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		}
		logging.DebugContext(ctx, "Attestation document attached to KMS Decrypt request (%d bytes)", len(attestDoc))
	}

	decryptOutput, err := kmsClient.Decrypt(ctx, decryptInput)
	if err != nil {
		slog.ErrorContext(ctx, "loadkey.kms_decrypt.failed", "error", err)
		return nil, fmt.Errorf("failed to decrypt key with KMS: %w", err)
	}

	// Extract plaintext — different path depending on whether attestation was used
	var plaintextKey []byte
	if decryptInput.Recipient != nil {
		// Attested path: plaintext is re-encrypted in a CMS envelope
		if len(decryptOutput.CiphertextForRecipient) == 0 {
			return nil, fmt.Errorf("KMS returned empty CiphertextForRecipient despite Recipient being set")
		}
		logging.DebugContext(ctx, "Decrypting CMS envelope from CiphertextForRecipient (%d bytes)...", len(decryptOutput.CiphertextForRecipient))
		plaintextKey, err = attestProvider.DecryptCMSEnvelope(decryptOutput.CiphertextForRecipient)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CiphertextForRecipient: %w", err)
		}
		slog.InfoContext(ctx, "loadkey.kms_decrypt.attested")
	} else {
		// Non-attested path: plaintext is directly available. This is a
		// security-relevant downgrade (no enclave isolation guarantee), so it
		// is surfaced at WARN with a stable event name an aggregator can alert
		// on — never run production this way.
		plaintextKey = decryptOutput.Plaintext
		slog.WarnContext(ctx, "loadkey.attestation.disabled",
			"detail", "CA key decrypted via non-attested KMS Decrypt; no enclave isolation guarantee")
	}

	// Best-effort zero of the plaintext key buffer once parsing has consumed
	// it. ssh.ParsePrivateKey is documented to copy into independent big.Int
	// allocations rather than retain the input slice, so clearing here doesn't
	// disturb the returned Signer. We also zero the SDK's response buffers for
	// the same defense-in-depth reason; the SDK may retain references inside,
	// but anything we can clear shrinks the heap-scan attack surface.
	defer func() {
		clear(plaintextKey)
		clear(decryptOutput.Plaintext)
		clear(decryptOutput.CiphertextForRecipient)
	}()

	// Parse the decrypted private key
	signer, err := ssh.ParsePrivateKey(plaintextKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}

	return signer, nil
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
