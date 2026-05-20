// Command ssh-cert-api is the host-side HTTPS gateway. It authenticates users
// via Kerberos SPNEGO, enforces per-group authorization via Casbin, rate-limits
// per principal, and forwards approved signing requests over VSOCK to the
// ssh-cert-signer running in a Nitro Enclave.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
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
	enclaveClient := enclave.New()
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

	// Initialize the enclave with AWS credentials. Use a bounded context so a
	// hung KMS Decrypt during startup doesn't block the service indefinitely;
	// 60s comfortably covers attestation + KMS round-trip + key parse.
	logging.Debug("Initializing enclave with AWS credentials...")
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 60*time.Second)
	err = LoadKeySigner(loadCtx)
	loadCancel()
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

	// --- 4b. Start background enclave health monitor ---
	// /health reads from the cached snapshot this populates, so flooding the
	// unauthenticated /health endpoint can't consume signer capacity needed
	// by /sign — only the monitor's background tick hits VSOCK.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	healthMonitor := api.NewHealthMonitor(enclaveClient)
	healthMonitor.Start(rootCtx)

	// --- 5. Setup API Server ---
	server, err := api.NewServer(cfg, kerberosAuthenticator, authorizer, enclaveClient, healthMonitor)
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
		// Pin the TLS policy explicitly rather than relying on Go's defaults.
		// TLS 1.2 minimum keeps older Kerberos-aware HTTP clients working; the
		// cipher list is restricted to AEAD constructions (TLS 1.3 has its
		// own AEAD-only set and ignores this field).
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	// --- 6. Start Server with graceful shutdown ---
	log.Printf("Server listening on https://%s", cfg.Listen)

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

// LoadKeySigner sends a load-key-signer request to the enclave. The supplied
// ctx bounds the entire fetch-credentials + VSOCK round trip; on cancellation
// the VSOCK client tears its connection down promptly.
func LoadKeySigner(ctx context.Context) error {
	logging.Debug("Fetching AWS credentials from metadata service...")
	credentials, err := fetchAWSCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch AWS credentials: %w", err)
	}
	logging.Debug("Successfully fetched AWS credentials")

	// Create the LoadKeySigner request. The encrypted key itself is read by
	// the enclave from CA_KEY_FILE_PATH; it does not travel over the wire.
	request := messages.Request{
		LoadKeySigner: &messages.LoadKeySignerRequest{
			Credentials: *credentials,
		},
	}

	var response messages.Response
	if err := enclave.CommunicateWithEnclave(ctx, constants.EnclaveCID, request, &response); err != nil {
		return fmt.Errorf("error communicating with enclave: %w", err)
	}

	if response.Error != nil {
		return fmt.Errorf("enclave error: %s", *response.Error)
	}

	logging.Debug("Successfully loaded key signer in enclave")
	return nil
}

// fetchAWSCredentials retrieves AWS credentials from the EC2 instance metadata
// service. It defers the IMDSv2 token dance, role discovery, and JSON decoding
// to the SDK's ec2rolecreds provider rather than hand-rolling the IMDS calls.
// Caps the call at 10s within the caller's broader budget so a hung metadata
// service can't eat the parent LoadKeySigner budget.
func fetchAWSCredentials(ctx context.Context) (*messages.Credentials, error) {
	imdsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cfg, err := awsconfig.LoadDefaultConfig(imdsCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	provider := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = imdsClient
	})

	creds, err := provider.Retrieve(imdsCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve EC2 role credentials: %w", err)
	}

	return &messages.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		Token:           creds.SessionToken,
	}, nil
}
