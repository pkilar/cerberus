package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"
	"ssh-cert-api/internal/api"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"
	"ssh-cert-api/internal/proxy"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

func main() {
	log.Println("Starting SSH Certificate API...")

	// --- 1. Load Configuration ---
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.yaml" // Default for local development
		logging.Debug("CONFIG_PATH not set, using default: %s", configPath)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	logging.Debug("Configuration loaded successfully.")

	// --- 2. Initialize Dependencies ---
	kerberosAuthenticator, err := auth.NewKerberosAuthenticator(cfg.KeytabPath, cfg.ServicePrincipal)
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos authenticator: %v", err)
	}
	enclaveClient, err := enclave.NewClient()
	if err != nil {
		log.Fatalf("Failed to initialize enclave client: %v", err)
	}
	defer enclaveClient.Close()

	// --- 3. Start VSOCK Proxy for AWS Services ---
	// This proxy allows the enclave to communicate with AWS services
	// Get the current AWS region for KMS endpoint
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
		logging.Debug("AWS_REGION not set, defaulting to %s for KMS proxy", region)
	}

	kmsEndpoint := fmt.Sprintf("kms.%s.amazonaws.com:443", region)
	vsockProxy := proxy.New(constants.INSTANCE_LISTENING_PORT, kmsEndpoint)

	ctx := context.Background()
	err = vsockProxy.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start VSOCK proxy: %v", err)
	}
	logging.Debug("Started VSOCK proxy on port %d forwarding to %s", constants.INSTANCE_LISTENING_PORT, kmsEndpoint)

	// Initialize the enclave with AWS credentials
	logging.Debug("Initializing enclave with AWS credentials...")
	err = LoadKeySigner()
	if err != nil {
		log.Fatalf("Failed to initialize enclave: %v", err)
	}
	logging.Debug("Enclave initialized successfully")
	vsockProxy.Stop()

	// --- 4. Setup API Server ---
	server, err := api.NewServer(cfg, kerberosAuthenticator, enclaveClient)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	// --- 5. Define the HTTP server with authentication middleware ---
	httpServer := &http.Server{
		Addr:         cfg.Listen,
		Handler:      server.Router(), // The router now includes the middleware
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// --- 6. Start Server ---
	log.Printf("Server listening on https://%s", cfg.Listen)

	err = httpServer.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey)
	if err != nil {
		log.Fatalf("Failed to start HTTPS server: %v. Ensure %s and %s are present.", err, cfg.TlsCert, cfg.TlsKey)
	}
}

// LoadKeySigner sends a load-key-signer request to the enclave
func LoadKeySigner() error {
	logging.Debug("Fetching AWS credentials from metadata service...")
	credentials, err := fetchAWSCredentials()
	if err != nil {
		return fmt.Errorf("failed to fetch AWS credentials: %w", err)
	}
	logging.Debug("Successfully fetched AWS credentials")

	// Create the LoadKeySigner request
	request := messages.Request{
		LoadKeySigner: &messages.LoadKeySignerRequest{
			EncryptedKey: "", // Empty for now - the enclave will load from file
			Credentials:  *credentials,
		},
	}

	var response messages.Response
	err = enclave.CommunicateWithEnclave(constants.ENCLAVE_CID, request, &response)
	if err != nil {
		return fmt.Errorf("error communicating with enclave: %w", err)
	}

	if response.Error != nil {
		return fmt.Errorf("enclave error: %s", *response.Error)
	}

	logging.Debug("Successfully loaded key signer in enclave")
	return nil
}

// fetchAWSCredentials retrieves AWS credentials from the EC2 instance metadata service
func fetchAWSCredentials() (*messages.Credentials, error) {
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	metadataClient := imds.NewFromConfig(cfg)

	roleNameResp, err := metadataClient.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "iam/security-credentials/",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM role name: %w", err)
	}
	defer roleNameResp.Content.Close()

	roleNameBytes, err := io.ReadAll(roleNameResp.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to read IAM role name: %w", err)
	}
	roleName := strings.TrimSpace(string(roleNameBytes))

	credentialsResp, err := metadataClient.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "iam/security-credentials/" + roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM credentials: %w", err)
	}
	defer credentialsResp.Content.Close()

	credentialsBytes, err := io.ReadAll(credentialsResp.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to read IAM credentials: %w", err)
	}

	var creds messages.Credentials
	if err := json.Unmarshal(credentialsBytes, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials JSON: %w", err)
	}

	return &creds, nil
}
