package handlers

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// LoadKeySignerHandler loads an encrypted CA key form a file and decrypts it with KMS.
func LoadKeySignerHandler(ctx context.Context, req messages.LoadKeySignerRequest) (ssh.Signer, error) {
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

	// The AWS SDK must use the credentials from the parent intance.
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
	encryptedKeyBytes, err := os.ReadFile(caKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key file '%s': %w", caKeyFilePath, err)
	}
	logging.Debug("Successfully read encrypted key file (%d bytes)", len(encryptedKeyBytes))

	kmsClient := kms.NewFromConfig(cfg)
	logging.Debug("Created KMS client for region: %s", region)
	logging.Debug("All HTTP requests will go through VSOCK proxy to parent instance")

	// Decrypt the key using KMS
	logging.Debug("Decrypting CA key with KMS...")
	logging.Debug("Encrypted key size: %d bytes", len(encryptedKeyBytes))
	decryptOutput, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: encryptedKeyBytes,
	})
	if err != nil {
		log.Printf("KMS decrypt error details: %v", err)
		return nil, fmt.Errorf("failed to decrypt key with KMS: %w", err)
	}
	log.Println("Successfully decrypted CA key with KMS")

	// Parse the decrypted private key
	signer, err := ssh.ParsePrivateKey(decryptOutput.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decrypted private key: %w", err)
	}

	return signer, nil
}
