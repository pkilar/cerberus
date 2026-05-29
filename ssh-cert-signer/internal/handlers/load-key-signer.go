// Package handlers implements the enclave-side request handlers:
// LoadKeySignerHandler decrypts the KMS-encrypted CA key on startup (with
// Nitro attestation when available), and SignPublicKey produces an SSH
// certificate for a validated request. The CA private key lives in this
// process's memory and never leaves the enclave.
package handlers

import (
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
	if attestationRequired() {
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
func attestationRequired() bool {
	// Case-insensitive so REQUIRE_ATTESTATION=True / =TRUE / =Yes are honored.
	// Misreading these as "fall through to auto-detect" silently disables a
	// security-critical setting on hosts without /dev/nsm.
	switch strings.ToLower(os.Getenv("REQUIRE_ATTESTATION")) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	_, err := os.Stat("/dev/nsm")
	return err == nil
}
