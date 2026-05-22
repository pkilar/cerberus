// integration_test.go
// Integration tests for Cerberus SSH Certificate Authority
// These tests verify the complete workflow from API to enclave signing

package cerberus

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkilar/cerberus/messages"

	"golang.org/x/crypto/ssh"
)

// MockVSockServer simulates the enclave signing service for integration testing
type MockVSockServer struct {
	listener net.Listener
	signer   ssh.Signer
	addr     string
}

func NewMockVSockServer() (*MockVSockServer, error) {
	// Create a test SSH signer
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &MockVSockServer{signer: signer}, nil
}

func (s *MockVSockServer) Start() error {
	// Real builds use vsock.Listen; the mock uses TCP on an ephemeral port to
	// avoid clashing with anything else on the host or in CI.
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.listener = listener
	s.addr = listener.Addr().String()

	go s.acceptConnections()
	return nil
}

// Addr returns the loopback address the mock is listening on, including the
// dynamically-assigned port. Only valid after Start.
func (s *MockVSockServer) Addr() string { return s.addr }

func (s *MockVSockServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *MockVSockServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Clean Stop closed the listener — normal termination.
				return
			}
			// Match production behavior: don't exit on transient errors,
			// just back off briefly. Tests have no logger here, but
			// returning on any error would hide regressions where the
			// listener spuriously errors mid-test.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *MockVSockServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Mirror the production enclave's framing: bufio.Scanner with a 256 KiB
	// cap, newline-delimited JSON. Using json.NewDecoder.Decode would silently
	// accept oversize requests and miss regressions in the wire-protocol cap.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)
	if !scanner.Scan() {
		s.writeErrorResponse(conn, "Invalid request format")
		return
	}
	var req messages.Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
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

	maps.Copy(permissions.Extensions, req.Permissions)
	maps.Copy(permissions.Extensions, req.CustomAttributes)
	maps.Copy(permissions.CriticalOptions, req.CriticalOptions)

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
			"environment@example.com": "test",
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

// startMockEnclave starts a MockVSockServer scoped to the test lifetime. Stop
// is registered as a t.Cleanup so callers don't have to track it themselves.
func startMockEnclave(t *testing.T) *MockVSockServer {
	t.Helper()
	server, err := NewMockVSockServer()
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	t.Cleanup(func() { _ = server.Stop() })
	return server
}

// verifyCertMatches asserts that the issued certificate carries the principals,
// permissions, custom attributes, and critical options from the original
// signing request, and that the validity window covers "now".
func verifyCertMatches(t *testing.T, cert *ssh.Certificate, want messages.EnclaveSigningRequest) {
	t.Helper()

	if cert.KeyId != want.KeyID {
		t.Errorf("KeyId: want %q, got %q", want.KeyID, cert.KeyId)
	}
	if !slices.Equal(cert.ValidPrincipals, want.Principals) {
		t.Errorf("ValidPrincipals: want %v, got %v", want.Principals, cert.ValidPrincipals)
	}

	// Production behavior collapses Permissions + CustomAttributes into
	// the SSH cert's Extensions map; CriticalOptions stays separate.
	for k, v := range want.Permissions {
		if got := cert.Permissions.Extensions[k]; got != v {
			t.Errorf("Extensions[%q]: want %q, got %q", k, v, got)
		}
	}
	for k, v := range want.CustomAttributes {
		if got := cert.Permissions.Extensions[k]; got != v {
			t.Errorf("Extensions[%q]: want %q, got %q", k, v, got)
		}
	}
	for k, v := range want.CriticalOptions {
		if got := cert.Permissions.CriticalOptions[k]; got != v {
			t.Errorf("CriticalOptions[%q]: want %q, got %q", k, v, got)
		}
	}

	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now || cert.ValidBefore < now {
		t.Errorf("certificate not valid now: ValidAfter=%d, ValidBefore=%d, now=%d",
			cert.ValidAfter, cert.ValidBefore, now)
	}
}

func TestIntegration_EndToEndSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := startMockEnclave(t)

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

	signingReq := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-user@example.com",
		Principals: []string{"admin"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment@example.com": "test",
		},
		CriticalOptions: map[string]string{
			"source-address": "192.168.1.0/24",
		},
	}

	// Connect to mock server and send request
	conn, err := net.Dial("tcp", mockServer.Addr())
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(messages.Request{SignSshKey: &signingReq}); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Mirror the production host client: bufio.NewReader.ReadBytes('\n').
	// A single conn.Read works on localhost (TCP coalesces) but would short-
	// read on any path with MTU-sensitive framing — exactly the regression we
	// want this test to catch.
	var response messages.Response
	responseBytes, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(responseBytes), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response.Error != nil {
		t.Fatalf("received error response: %s", *response.Error)
	}
	if response.SignSshKey == nil || response.SignSshKey.SignedKey == "" {
		t.Fatal("expected signed key in response")
	}

	certKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignSshKey.SignedKey))
	if err != nil {
		t.Fatalf("failed to parse signed certificate: %v", err)
	}
	cert, ok := certKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("expected SSH certificate")
	}

	verifyCertMatches(t, cert, signingReq)

	t.Logf("Successfully created and verified SSH certificate with KeyID: %s", cert.KeyId)
}

// TestIntegration_ConcurrentSigning drives N goroutines each through a
// full signing round-trip against the mock enclave. The mock spawns a
// per-connection goroutine so this also exercises that path. Combined
// with `go test -race`, this catches regressions in JSON framing,
// connection lifecycle, or shared state under load.
func TestIntegration_ConcurrentSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	addr := startMockEnclave(t).Addr()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := range N {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: dial: %w", idx, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))

			req := messages.Request{
				SignSshKey: &messages.EnclaveSigningRequest{
					SSHKey:     pubStr,
					KeyID:      fmt.Sprintf("concurrent-user-%d", idx),
					Principals: []string{"admin"},
					Validity:   "1h",
				},
			}
			if err := json.NewEncoder(conn).Encode(req); err != nil {
				errs <- fmt.Errorf("goroutine %d: encode: %w", idx, err)
				return
			}

			// Mirror the production host client: bufio.NewReader.ReadBytes('\n').
			// A single conn.Read works on localhost (TCP coalesces) but would
			// short-read on any path with MTU-sensitive framing.
			responseBytes, err := bufio.NewReader(conn).ReadBytes('\n')
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: read: %w", idx, err)
				return
			}
			var resp messages.Response
			if err := json.Unmarshal(bytes.TrimSpace(responseBytes), &resp); err != nil {
				errs <- fmt.Errorf("goroutine %d: unmarshal: %w", idx, err)
				return
			}
			if resp.Error != nil {
				errs <- fmt.Errorf("goroutine %d: enclave error: %s", idx, *resp.Error)
				return
			}
			if resp.SignSshKey == nil || resp.SignSshKey.SignedKey == "" {
				errs <- fmt.Errorf("goroutine %d: empty signed key", idx)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestIntegration_MalformedRequest verifies the mock enclave returns a
// structured error response on garbled input rather than hanging or closing
// silently. This mirrors the enclave's actual handler behaviour.
func TestIntegration_MalformedRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := startMockEnclave(t)

	conn, err := net.Dial("tcp", mockServer.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("this is definitely not JSON\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Same newline-delimited framing as the rest of the test suite — see the
	// comment in TestIntegration_EndToEndSigning for why bufio.NewReader.ReadBytes
	// is preferred over a single conn.Read.
	responseBytes, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var resp messages.Response
	if err := json.Unmarshal(bytes.TrimSpace(responseBytes), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil || *resp.Error == "" {
		t.Errorf("expected error response, got: %+v", resp)
	}
}
