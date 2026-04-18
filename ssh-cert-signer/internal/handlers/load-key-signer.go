// Package handlers implements the enclave-side request handlers:
// LoadKeySignerHandler decrypts the KMS-encrypted CA key on startup (with
// Nitro attestation when available), and SignPublicKey produces an SSH
// certificate for a validated request. The CA private key lives in this
// process's memory and never leaves the enclave.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"
	"ssh-cert-signer/internal/attestation"

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
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
		logging.Debug("AWS_REGION not set, defaulting to us-east-1")
	}

	// Create custom HTTP client that routes through VSOCK proxy
	httpClient := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			logging.Debug("KMS SDK attempting to connect to: %s (network: %s)", addr, network)
			logging.Debug("Intercepting connection via vsock (cid=%d, port=%d)", constants.INSTANCE_CID, constants.INSTANCE_LISTENING_PORT)
			conn, err := vsock.Dial(constants.INSTANCE_CID, constants.INSTANCE_LISTENING_PORT, nil)
			if err != nil {
				log.Printf("VSOCK dial failed: %v", err)
				return nil, err
			}
			logging.Debug("VSOCK connection established successfully")
			return conn, nil
		}
	})

	// The AWS SDK must use the credentials from the parent instance.
	credentialProvider := credentials.NewStaticCredentialsProvider(req.Credentials.AccessKeyId, req.Credentials.SecretAccessKey, req.Credentials.Token)

	logging.Debug("Loading AWS configuration...")
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithHTTPClient(httpClient),
		config.WithCredentialsProvider(credentialProvider))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS default config: %w", err)
	}

	caKeyFilePath := os.Getenv("CA_KEY_FILE_PATH")
	if caKeyFilePath == "" {
		caKeyFilePath = "/app/ca_key.enc"
		logging.Debug("CA_KEY_FILE_PATH not set, defaulting to %s", caKeyFilePath)
	}

	// Read the encrypted CA key from file
	logging.Debug("Reading encrypted CA key from file: %s", caKeyFilePath)
	// #nosec G304,G703 -- caKeyFilePath comes from the CA_KEY_FILE_PATH env
	// var set by the operator (or a packaged systemd unit), not untrusted input.
	encryptedKeyBytes, err := os.ReadFile(caKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file '%s': %w", caKeyFilePath, err)
	}
	logging.Debug("Successfully read encrypted key file (%d bytes)", len(encryptedKeyBytes))

	kmsClient := kms.NewFromConfig(cfg)
	logging.Debug("Created KMS client for region: %s", region)
	logging.Debug("All HTTP requests will go through VSOCK proxy to parent instance")

	// Build KMS Decrypt input
	logging.Debug("Decrypting CA key with KMS...")
	logging.Debug("Encrypted key size: %d bytes", len(encryptedKeyBytes))
	decryptInput := &kms.DecryptInput{
		CiphertextBlob: encryptedKeyBytes,
	}

	// If running inside an enclave, attach attestation document
	if attestProvider != nil && attestProvider.IsAvailable() {
		logging.Debug("Generating NSM attestation document...")
		attestDoc, err := attestProvider.GenerateAttestationDoc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate attestation document: %w", err)
		}
		decryptInput.Recipient = &types.RecipientInfo{
			AttestationDocument:    attestDoc,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		}
		logging.Debug("Attestation document attached to KMS Decrypt request (%d bytes)", len(attestDoc))
	}

	decryptOutput, err := kmsClient.Decrypt(ctx, decryptInput)
	if err != nil {
		log.Printf("KMS decrypt error details: %v", err)
		return nil, fmt.Errorf("failed to decrypt key with KMS: %w", err)
	}

	// Extract plaintext — different path depending on whether attestation was used
	var plaintextKey []byte
	if decryptInput.Recipient != nil {
		// Attested path: plaintext is re-encrypted in a CMS envelope
		if len(decryptOutput.CiphertextForRecipient) == 0 {
			return nil, fmt.Errorf("KMS returned empty CiphertextForRecipient despite Recipient being set")
		}
		logging.Debug("Decrypting CMS envelope from CiphertextForRecipient (%d bytes)...", len(decryptOutput.CiphertextForRecipient))
		plaintextKey, err = attestProvider.DecryptCMSEnvelope(decryptOutput.CiphertextForRecipient)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt CiphertextForRecipient: %w", err)
		}
		log.Println("Successfully decrypted CA key with KMS (attested)")
	} else {
		// Non-attested path: plaintext is directly available
		plaintextKey = decryptOutput.Plaintext
		log.Println("Successfully decrypted CA key with KMS (non-attested)")
	}

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
	switch os.Getenv("REQUIRE_ATTESTATION") {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	_, err := os.Stat("/dev/nsm")
	return err == nil
}
