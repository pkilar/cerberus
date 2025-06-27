package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"
)

// EnclaveSigningRequest is the structure for JSON requests coming from the web API.
type EnclaveSigningRequest struct {
	SSHKey           string            `json:"ssh_key"`
	KeyID            string            `json:"key_id"`
	Principals       []string          `json:"principals"`
	Validity         string            `json:"validity"`
	Permissions      map[string]string `json:"permissions"`
	CustomAttributes map[string]string `json:"custom_attributes"`
}

// EnclaveSigningResponse is the structure for JSON responses sent back to the web API.
type EnclaveSigningResponse struct {
	SignedKey string `json:"signed_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

// main is the entry point for the enclave application.
func main() {
	log.Println("Starting Enclave Signing Service...")

	// 1. Fetch the CA Private Key from AWS Parameter Store.
	// The parameter name is passed via an environment variable.
	caKeyParamName := os.Getenv("CA_KEY_PARAMETER_NAME")
	if caKeyParamName == "" {
		log.Fatalf("FATAL: CA_KEY_PARAMETER_NAME environment variable not set.")
	}

	caSigner, err := loadSignerFromParameterStore(context.Background(), caKeyParamName)
	if err != nil {
		log.Fatalf("FATAL: Could not load CA key from Parameter Store: %v", err)
	}
	log.Println("CA private key loaded and parsed successfully.")

	// 2. Listen for connections on a VSOCK port.
	// The parent EC2 instance will connect to this listener.
	// Port 5000 is used here; any unused port above 1024 is fine.
	const vsockPort = 5000
	listener, err := vsock.Listen(vsockPort, nil)
	if err != nil {
		log.Fatalf("FATAL: failed to listen on vsock port %d: %v", vsockPort, err)
	}
	defer listener.Close()
	log.Printf("Listening on vsock port %d...", vsockPort)

	// 3. Accept and handle connections in a loop.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ERROR: failed to accept connection: %v", err)
			continue
		}
		// Handle each connection in a new goroutine to allow concurrent processing.
		go handleConnection(conn, caSigner)
	}
}

// handleConnection reads a request, signs it, and writes a response.
func handleConnection(conn net.Conn, caSigner ssh.Signer) {
	defer conn.Close()
	log.Println("Accepted new connection from parent instance.")

	// Set a deadline for reading to prevent hanging connections.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Decode the JSON request from the connection.
	var req EnclaveSigningRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("ERROR: failed to decode request: %v", err)
		writeResponse(conn, EnclaveSigningResponse{Error: "Invalid request format"})
		return
	}

	// Sign the public key using the details from the request.
	signedCert, err := signPublicKey(req, caSigner)
	if err != nil {
		log.Printf("ERROR: failed to sign key for KeyID '%s': %v", req.KeyID, err)
		writeResponse(conn, EnclaveSigningResponse{Error: err.Error()})
		return
	}

	// Write the successful response back to the parent instance.
	log.Printf("Successfully signed certificate for KeyID: %s", req.KeyID)
	writeResponse(conn, EnclaveSigningResponse{SignedKey: signedCert})
}

// signPublicKey contains the core logic for creating and signing the certificate.
func signPublicKey(req EnclaveSigningRequest, caSigner ssh.Signer) (string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	validityDuration, err := time.ParseDuration(req.Validity)
	if err != nil {
		return "", fmt.Errorf("invalid validity duration string '%s': %w", req.Validity, err)
	}

	permissions := ssh.Permissions{
		Extensions: make(map[string]string),
	}
	for k, v := range req.Permissions {
		permissions.Extensions[k] = v
	}
	for k, v := range req.CustomAttributes {
		permissions.Extensions[k] = v
	}

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
		return "", fmt.Errorf("cryptographic signing failed: %w", err)
	}

	signedKeyBytes := ssh.MarshalAuthorizedKey(cert)
	return string(signedKeyBytes), nil
}

// loadSignerFromParameterStore fetches a key from AWS SSM Parameter Store and creates an ssh.Signer.
func loadSignerFromParameterStore(ctx context.Context, paramName string) (ssh.Signer, error) {
	// The AWS SDK, when run inside a Nitro Enclave, automatically uses the IAM role
	// of the parent EC2 instance for credentials.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS default config: %w", err)
	}

	ssmClient := ssm.NewFromConfig(cfg)
	
	// The WithDecryption field expects a *bool, not a bool.
	// We create a helper variable to get a pointer to true.
	withDecryption := true
	paramOutput, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           &paramName,
		WithDecryption: &withDecryption,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get parameter '%s' from SSM: %w", paramName, err)
	}

	privateKeyBytes := []byte(*paramOutput.Parameter.Value)
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from SSM parameter: %w", err)
	}

	return signer, nil
}

// writeResponse sends a JSON response back over the VSOCK connection.
func writeResponse(conn net.Conn, resp EnclaveSigningResponse) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Printf("ERROR: failed to write response: %v", err)
	}
}
