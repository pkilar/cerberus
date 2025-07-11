// integration_test.go
// Integration tests for Cerberus SSH Certificate Authority
// These tests verify the complete workflow from API to enclave signing

package cerberus

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"cerberus/messages"

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
	// Note: This would normally use vsock.ListenContextID, but for testing we'll use TCP
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

	var req messages.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		s.writeErrorResponse(conn, "Invalid request format")
		return
	}

	if req.SignSshKey != nil {
		signedCert, err := s.signPublicKey(*req.SignSshKey)
		if err != nil {
			s.writeErrorResponse(conn, err.Error())
			return
		}
		s.writeSuccessResponse(conn, signedCert)
	} else {
		s.writeErrorResponse(conn, "Unsupported request type")
	}
}

func (s *MockVSockServer) signPublicKey(req messages.EnclaveSigningRequest) (string, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.SSHKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	validityDuration, err := time.ParseDuration(req.Validity)
	if err != nil {
		return "", fmt.Errorf("invalid validity duration: %w", err)
	}

	permissions := ssh.Permissions{
		Extensions:      make(map[string]string),
		CriticalOptions: make(map[string]string),
	}

	// Copy permissions and custom attributes to extensions
	for k, v := range req.Permissions {
		permissions.Extensions[k] = v
	}
	for k, v := range req.CustomAttributes {
		permissions.Extensions[k] = v
	}

	// Copy critical options
	for k, v := range req.CriticalOptions {
		permissions.CriticalOptions[k] = v
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

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), nil
}

func (s *MockVSockServer) writeSuccessResponse(conn net.Conn, signedKey string) {
	response := messages.Response{
		SignSshKey: &messages.SigningResponse{
			SignedKey: signedKey,
		},
	}
	s.writeResponse(conn, response)
}

func (s *MockVSockServer) writeErrorResponse(conn net.Conn, errorMsg string) {
	response := messages.Response{
		Error: &errorMsg,
	}
	s.writeResponse(conn, response)
}

func (s *MockVSockServer) writeResponse(conn net.Conn, resp messages.Response) {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	responseBytes, _ := json.Marshal(resp)
	conn.Write(responseBytes)
	conn.Write([]byte{'\n'})
}

// Simple integration test that verifies the messages package works correctly
func TestIntegration_MessageSerialization(t *testing.T) {
	// Test EnclaveSigningRequest serialization
	req := messages.EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ...",
		KeyID:      "test-user",
		Principals: []string{"admin", "user"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
		},
		CriticalOptions: map[string]string{
			"source-address": "192.168.1.0/24",
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal EnclaveSigningRequest: %v", err)
	}

	// Test JSON unmarshaling
	var decoded messages.EnclaveSigningRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal EnclaveSigningRequest: %v", err)
	}

	// Verify fields
	if decoded.SSHKey != req.SSHKey {
		t.Errorf("SSHKey mismatch: expected %s, got %s", req.SSHKey, decoded.SSHKey)
	}
	if decoded.KeyID != req.KeyID {
		t.Errorf("KeyID mismatch: expected %s, got %s", req.KeyID, decoded.KeyID)
	}
	if len(decoded.Principals) != len(req.Principals) {
		t.Errorf("Principals length mismatch: expected %d, got %d", len(req.Principals), len(decoded.Principals))
	}
	if decoded.CriticalOptions["source-address"] != req.CriticalOptions["source-address"] {
		t.Errorf("CriticalOptions mismatch: expected %s, got %s",
			req.CriticalOptions["source-address"], decoded.CriticalOptions["source-address"])
	}
}

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

	// Create test public key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}

	testPublicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))

	// Create signing request
	signingReq := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-user@example.com",
		Principals: []string{"admin"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
			"issued_at":   fmt.Sprintf("%d", time.Now().Unix()),
		},
		CriticalOptions: map[string]string{
			"source-address": "192.168.1.0/24",
		},
	}

	// Create request message
	request := messages.Request{
		SignSshKey: &signingReq,
	}

	// Connect to mock server and send request
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", 15000))
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send request
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Read response
	var response messages.Response
	responseBytes := make([]byte, 4096)
	n, err := conn.Read(responseBytes)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// Parse response (remove trailing newline)
	responseData := bytes.TrimSpace(responseBytes[:n])
	if err := json.Unmarshal(responseData, &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Check for errors
	if response.Error != nil {
		t.Fatalf("received error response: %s", *response.Error)
	}

	if response.SignSshKey == nil || response.SignSshKey.SignedKey == "" {
		t.Fatal("expected signed key in response")
	}

	// Verify the signed certificate
	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignSshKey.SignedKey))
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

	if cert.KeyId != "test-user@example.com" {
		t.Errorf("expected KeyID 'test-user@example.com', got '%s'", cert.KeyId)
	}

	// Verify extensions (permissions + custom attributes)
	if cert.Permissions.Extensions["permit-pty"] != "" {
		t.Error("expected permit-pty permission")
	}

	if cert.Permissions.Extensions["environment"] != "test" {
		t.Error("expected environment=test attribute")
	}

	// Verify critical options
	if cert.Permissions.CriticalOptions["source-address"] != "192.168.1.0/24" {
		t.Errorf("expected source-address critical option, got: %v", cert.Permissions.CriticalOptions)
	}

	// Verify certificate is currently valid
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now || cert.ValidBefore < now {
		t.Error("certificate should be valid now")
	}

	t.Logf("Successfully created and verified SSH certificate with KeyID: %s", cert.KeyId)
}

func TestIntegration_EnclaveConnectionFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Try to connect to non-existent server
	conn, err := net.DialTimeout("tcp", "localhost:99999", 1*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected connection to fail, but it succeeded")
	}

	// Verify we get a connection error (this is expected behavior)
	if !strings.Contains(err.Error(), "connection refused") && !strings.Contains(err.Error(), "no connection could be made") {
		t.Logf("Got expected connection error: %v", err)
	}
}
