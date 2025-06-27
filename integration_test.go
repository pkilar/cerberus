// integration_test.go
// Integration tests for Cerberus SSH Certificate Authority
// These tests verify the complete workflow from API to enclave signing

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"ssh-cert-api/config"
	"ssh-cert-api/pkg/api"
	"ssh-cert-api/pkg/auth"
	"ssh-cert-api/pkg/enclave"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"
)

// MockVSockServer simulates the enclave signing service for integration testing
type MockVSockServer struct {
	listener net.Listener
	signer   ssh.Signer
	port     uint32
	running  bool
}

func NewMockVSockServer(port uint32) (*MockVSockServer, error) {
	// Create a test SSH signer
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test key: %v", err)
	}
	
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}

	return &MockVSockServer{
		signer: signer,
		port:   port,
	}, nil
}

func (s *MockVSockServer) Start() error {
	// Note: This would normally use vsock.Listen, but for testing we'll use TCP
	// In a real integration test environment, this would need VSOCK support
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	
	s.listener = listener
	s.running = true
	
	go s.acceptConnections()
	return nil
}

func (s *MockVSockServer) Stop() error {
	s.running = false
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *MockVSockServer) acceptConnections() {
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				fmt.Printf("Accept error: %v\n", err)
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *MockVSockServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	var req EnclaveSigningRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		s.writeResponse(conn, EnclaveSigningResponse{Error: "Invalid request format"})
		return
	}
	
	signedCert, err := s.signPublicKey(req)
	if err != nil {
		s.writeResponse(conn, EnclaveSigningResponse{Error: err.Error()})
		return
	}
	
	s.writeResponse(conn, EnclaveSigningResponse{SignedKey: signedCert})
}

func (s *MockVSockServer) signPublicKey(req EnclaveSigningRequest) (string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	validityDuration, err := time.ParseDuration(req.Validity)
	if err != nil {
		return "", fmt.Errorf("invalid validity duration: %w", err)
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
		Key:             publicKey,
		Serial:          uint64(time.Now().UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(time.Now().Unix()) - 60,
		ValidBefore:     uint64(time.Now().Add(validityDuration).Unix()),
		Permissions:     permissions,
	}

	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	return string(ssh.MarshalAuthorizedKey(cert)), nil
}

func (s *MockVSockServer) writeResponse(conn net.Conn, resp EnclaveSigningResponse) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	json.NewEncoder(conn).Encode(resp)
}

// Data structures for integration tests (duplicated from signer for isolation)
type EnclaveSigningRequest struct {
	SSHKey           string            `json:"ssh_key"`
	KeyID            string            `json:"key_id"`
	Principals       []string          `json:"principals"`
	Validity         string            `json:"validity"`
	Permissions      map[string]string `json:"permissions"`
	CustomAttributes map[string]string `json:"custom_attributes"`
}

type EnclaveSigningResponse struct {
	SignedKey string `json:"signed_key,omitempty"`
	Error     string `json:"error,omitempty"`
}

// MockKerberosAuthenticator for integration testing
type MockKerberosAuthenticator struct {
	Users map[string]string // Maps auth headers to user principals
}

func (m *MockKerberosAuthenticator) Authenticate(r *http.Request, kt *keytab.Keytab) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("no authorization header")
	}
	
	if user, exists := m.Users[authHeader]; exists {
		return user, nil
	}
	
	return "", fmt.Errorf("authentication failed")
}

// MockEnclaveClient that connects to our mock VSOCK server
type MockEnclaveClient struct {
	port uint32
}

func (m *MockEnclaveClient) SignPublicKey(req *enclave.EnclaveSigningRequest) (string, error) {
	// Convert to our local request format
	localReq := EnclaveSigningRequest{
		SSHKey:           req.SSHKey,
		KeyID:            req.KeyID,
		Principals:       req.Principals,
		Validity:         req.Validity,
		Permissions:      req.Permissions,
		CustomAttributes: req.CustomAttributes,
	}
	
	// Connect to mock server (using TCP instead of VSOCK for testing)
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", m.port))
	if err != nil {
		return "", fmt.Errorf("failed to connect to mock enclave: %v", err)
	}
	defer conn.Close()
	
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	
	if err := json.NewEncoder(conn).Encode(localReq); err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	
	var resp EnclaveSigningResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}
	
	if resp.Error != "" {
		return "", fmt.Errorf("enclave error: %s", resp.Error)
	}
	
	return resp.SignedKey, nil
}

func (m *MockEnclaveClient) Close() {}

func TestIntegration_EndToEndSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start mock enclave server
	mockServer, err := NewMockVSockServer(15000)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	
	if err := mockServer.Start(); err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer mockServer.Stop()
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create test configuration
	cfg := &config.Config{
		Groups: map[string]config.Group{
			"admin": {
				Members: []string{"admin@example.com"},
				CertificateRules: config.CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"admin", "root"},
					Permissions: map[string]string{
						"permit-pty": "",
					},
					StaticAttributes: map[string]string{
						"environment": "test",
					},
				},
			},
		},
	}

	// Create mock authenticator
	mockAuth := &MockKerberosAuthenticator{
		Users: map[string]string{
			"Bearer admin-token": "admin@example.com",
		},
	}

	// Create mock enclave client
	mockEnclave := &MockEnclaveClient{port: 15000}

	// Create API server
	server, err := api.NewServer(cfg, (*auth.KerberosAuthenticator)(mockAuth), (*enclave.Client)(mockEnclave))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create test public key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	
	testPublicKey := string(ssh.MarshalAuthorizedKey(publicKey))

	// Create signing request
	signingReq := api.SigningRequest{
		SSHKey:     testPublicKey,
		Principals: []string{"admin"},
	}

	reqBody, err := json.Marshal(signingReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Create HTTP request
	req := httptest.NewRequest("POST", "/sign", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Handle request
	router := server.Router()
	router.ServeHTTP(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
		t.Logf("Response body: %s", w.Body.String())
		return
	}

	var response api.SigningResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.SignedKey == "" {
		t.Error("expected signed key in response")
		return
	}

	// Verify the signed certificate
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
	if err != nil {
		t.Fatalf("failed to parse signed certificate: %v", err)
	}

	cert, ok := certKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("expected SSH certificate")
	}

	// Verify certificate properties
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "admin" {
		t.Errorf("expected principals [admin], got %v", cert.ValidPrincipals)
	}

	if cert.Permissions.Extensions["permit-pty"] != "" {
		t.Error("expected permit-pty permission")
	}

	if cert.Permissions.Extensions["environment"] != "test" {
		t.Error("expected environment=test attribute")
	}

	// Verify certificate is currently valid
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now || cert.ValidBefore < now {
		t.Error("certificate should be valid now")
	}
}

func TestIntegration_AuthorizationFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Start mock enclave server
	mockServer, err := NewMockVSockServer(15001)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	
	if err := mockServer.Start(); err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer mockServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create test configuration
	cfg := &config.Config{
		Groups: map[string]config.Group{
			"users": {
				Members: []string{"user@example.com"},
				CertificateRules: config.CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"user"},
					Permissions: map[string]string{
						"permit-pty": "",
					},
				},
			},
		},
	}

	mockAuth := &MockKerberosAuthenticator{
		Users: map[string]string{
			"Bearer user-token": "user@example.com",
		},
	}

	mockEnclave := &MockEnclaveClient{port: 15001}

	server, err := api.NewServer(cfg, (*auth.KerberosAuthenticator)(mockAuth), (*enclave.Client)(mockEnclave))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create test public key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	
	testPublicKey := string(ssh.MarshalAuthorizedKey(publicKey))

	// Request unauthorized principal
	signingReq := api.SigningRequest{
		SSHKey:     testPublicKey,
		Principals: []string{"admin"}, // User is not allowed 'admin' principal
	}

	reqBody, err := json.Marshal(signingReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/sign", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer user-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	router := server.Router()
	router.ServeHTTP(w, req)

	// Should return 403 Forbidden
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	var response api.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if response.Error == "" {
		t.Error("expected error message in response")
	}
}

func TestIntegration_EnclaveConnectionFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Don't start the mock server - simulate connection failure

	cfg := &config.Config{
		Groups: map[string]config.Group{
			"admin": {
				Members: []string{"admin@example.com"},
				CertificateRules: config.CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"admin"},
					Permissions: map[string]string{
						"permit-pty": "",
					},
				},
			},
		},
	}

	mockAuth := &MockKerberosAuthenticator{
		Users: map[string]string{
			"Bearer admin-token": "admin@example.com",
		},
	}

	// Point to non-existent port
	mockEnclave := &MockEnclaveClient{port: 99999}

	server, err := api.NewServer(cfg, (*auth.KerberosAuthenticator)(mockAuth), (*enclave.Client)(mockEnclave))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Create test request
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	
	testPublicKey := string(ssh.MarshalAuthorizedKey(publicKey))

	signingReq := api.SigningRequest{
		SSHKey:     testPublicKey,
		Principals: []string{"admin"},
	}

	reqBody, err := json.Marshal(signingReq)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest("POST", "/sign", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	router := server.Router()
	router.ServeHTTP(w, req)

	// Should return 500 Internal Server Error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}

	var response api.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if response.Error == "" {
		t.Error("expected error message in response")
	}
}

// Benchmark integration test
func BenchmarkIntegration_EndToEndSigning(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// Setup similar to TestIntegration_EndToEndSigning but simplified
	mockServer, err := NewMockVSockServer(15002)
	if err != nil {
		b.Fatalf("failed to create mock server: %v", err)
	}
	
	if err := mockServer.Start(); err != nil {
		b.Fatalf("failed to start mock server: %v", err)
	}
	defer mockServer.Stop()

	time.Sleep(100 * time.Millisecond)

	cfg := &config.Config{
		Groups: map[string]config.Group{
			"admin": {
				Members: []string{"admin@example.com"},
				CertificateRules: config.CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"admin"},
					Permissions: map[string]string{
						"permit-pty": "",
					},
				},
			},
		},
	}

	mockAuth := &MockKerberosAuthenticator{
		Users: map[string]string{
			"Bearer admin-token": "admin@example.com",
		},
	}

	mockEnclave := &MockEnclaveClient{port: 15002}

	server, err := api.NewServer(cfg, (*auth.KerberosAuthenticator)(mockAuth), (*enclave.Client)(mockEnclave))
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}

	// Pre-generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to generate test key: %v", err)
	}
	
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		b.Fatalf("failed to create public key: %v", err)
	}
	
	testPublicKey := string(ssh.MarshalAuthorizedKey(publicKey))

	signingReq := api.SigningRequest{
		SSHKey:     testPublicKey,
		Principals: []string{"admin"},
	}

	reqBody, err := json.Marshal(signingReq)
	if err != nil {
		b.Fatalf("failed to marshal request: %v", err)
	}

	router := server.Router()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/sign", bytes.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer admin-token")
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			b.Fatalf("request failed with status %d", w.Code)
		}
	}
}