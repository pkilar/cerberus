// Command ssh-cert-api is the host-side HTTPS gateway. It authenticates users
// via Kerberos SPNEGO, enforces per-group authorization via Casbin, rate-limits
// per principal, and forwards approved signing requests over VSOCK to the
// ssh-cert-signer running in a Nitro Enclave.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"
	"ssh-cert-api/internal/api"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/authz"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"
	"ssh-cert-api/internal/proxy"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"golang.org/x/sync/errgroup"
)

const shutdownGrace = 10 * time.Second

func main() {
	log.Println("Starting SSH Certificate API...")

	// --- 1. Load Configuration ---
	configPath := cmp.Or(os.Getenv("CONFIG_PATH"), "configs/config.yaml")
	logging.Debug("Using config path: %s", configPath)
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
	defer func() { _ = enclaveClient.Close() }()

	// --- 3. Start VSOCK Proxy for AWS Services ---
	// This proxy allows the enclave to communicate with AWS services
	// Get the current AWS region for KMS endpoint
	region := cmp.Or(os.Getenv("AWS_REGION"), "us-east-1")
	kmsEndpoint := fmt.Sprintf("kms.%s.amazonaws.com:443", region)
	vsockProxy := proxy.New(constants.InstanceListeningPort, kmsEndpoint)

	ctx := context.Background()
	err = vsockProxy.Start(ctx)
	if err != nil {
		log.Fatalf("Failed to start VSOCK proxy: %v", err)
	}
	logging.Debug("Started VSOCK proxy on port %d forwarding to %s", constants.InstanceListeningPort, kmsEndpoint)

	// Initialize the enclave with AWS credentials
	logging.Debug("Initializing enclave with AWS credentials...")
	err = LoadKeySigner()
	if err != nil {
		log.Fatalf("Failed to initialize enclave: %v", err)
	}
	logging.Debug("Enclave initialized successfully")

	// The KMS proxy exists only so the enclave can decrypt the CA key on
	// startup. Once LoadKeySigner returns, the plaintext key lives in the
	// enclave's memory and KMS is never needed again — tearing the proxy
	// down removes the host→AWS network path. If you add code that
	// requires the enclave to call AWS at runtime, leave the proxy running.
	vsockProxy.Stop()

	// --- 4. Initialize Authorizer ---
	authorizer, err := authz.NewCasbinAuthorizer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize authorizer: %v", err)
	}

	// --- 5. Setup API Server ---
	server, err := api.NewServer(cfg, kerberosAuthenticator, authorizer, enclaveClient)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	// --- 5. Define the HTTP server with authentication middleware ---
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Router(), // The router now includes the middleware
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// --- 6. Start Server with graceful shutdown ---
	log.Printf("Server listening on https://%s", cfg.Listen)

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	g, gctx := errgroup.WithContext(rootCtx)

	g.Go(func() error {
		if err := httpServer.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("https server: %w (ensure %s and %s are present)", err, cfg.TlsCert, cfg.TlsKey)
		}
		return nil
	})

	g.Go(func() error {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		select {
		case sig := <-sigChan:
			log.Printf("Received %s — draining connections (deadline %s)", sig, shutdownGrace)
		case <-gctx.Done():
			// Server goroutine errored; propagate by returning nil here.
			return nil
		}

		// Intentionally detach from gctx here: a grace-timeout for
		// draining must not be cut short by the parent's cancellation.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx) //nolint:contextcheck // graceful shutdown ctx is independent by design

	})

	if err := g.Wait(); err != nil {
		log.Fatalf("Server error: %v", err)
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
	err = enclave.CommunicateWithEnclave(constants.EnclaveCID, request, &response)
	if err != nil {
		return fmt.Errorf("error communicating with enclave: %w", err)
	}

	if response.Error != nil {
		return fmt.Errorf("enclave error: %s", *response.Error)
	}

	logging.Debug("Successfully loaded key signer in enclave")
	return nil
}

// fetchAWSCredentials retrieves AWS credentials from the EC2 instance metadata
// service. It defers the IMDSv2 token dance, role discovery, and JSON decodeing
// to the  SDK's ec2rolecreds provider rather than hand-rolling the IMDS calls.
func fetchAWSCredentials() (*messages.Credentials, error) {
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	provider := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = imdsClient
	})

	creds, err := provider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve EC2 role credentials: %w", err)
	}

	return &messages.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		Token:           creds.SessionToken,
	}, nil
}
