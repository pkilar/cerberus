package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Mock connection for testing
type MockConn struct {
	readData   []byte
	writeData  []byte
	readIndex  int
	closed     bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func (m *MockConn) Read(b []byte) (n, error) {
	if m.readIndex >= len(m.readData) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *MockConn) Write(b []byte) (n, error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *MockConn) Close() error {
	m.closed = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr                { return nil }
func (m *MockConn) RemoteAddr() net.Addr               { return nil }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { m.readDeadline = t; return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { m.writeDeadline = t; return nil }

// Helper function to create a test SSH signer
func createTestSigner(t *testing.T) ssh.Signer {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	
	return signer
}

// Helper function to create a test public key
func createTestPublicKey(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	
	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create public key: %v", err)
	}
	
	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func TestSignPublicKey(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	tests := []struct {
		name        string
		request     EnclaveSigningRequest
		expectError bool
	}{
		{
			name: "valid request",
			request: EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-1",
				Principals: []string{"user1", "user2"},
				Validity:   "1h",
				Permissions: map[string]string{
					"permit-pty": "",
				},
				CustomAttributes: map[string]string{
					"environment": "test",
				},
			},
			expectError: false,
		},
		{
			name: "invalid public key",
			request: EnclaveSigningRequest{
				SSHKey:     "invalid-key-format",
				KeyID:      "test-key-2",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
		},
		{
			name: "invalid validity duration",
			request: EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-3",
				Principals: []string{"user1"},
				Validity:   "invalid-duration",
			},
			expectError: true,
		},
		{
			name: "empty principals",
			request: EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-4",
				Principals: []string{},
				Validity:   "1h",
			},
			expectError: false, // Empty principals should be allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedKey, err := signPublicKey(tt.request, signer)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if signedKey != "" {
					t.Error("expected empty signed key on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if signedKey == "" {
					t.Error("expected signed key but got empty string")
				}
				
				// Verify the signed key format
				if !strings.Contains(signedKey, "ssh-rsa-cert-v01@openssh.com") {
					t.Error("signed key should contain certificate type identifier")
				}
				
				// Try to parse the signed certificate
				publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKey))
				if err != nil {
					t.Errorf("failed to parse signed certificate: %v", err)
				}
				
				cert, ok := publicKey.(*ssh.Certificate)
				if !ok {
					t.Error("expected SSH certificate")
				} else {
					// Verify certificate fields
					if cert.KeyId != tt.request.KeyID {
						t.Errorf("expected KeyId %s, got %s", tt.request.KeyID, cert.KeyId)
					}
					
					if len(cert.ValidPrincipals) != len(tt.request.Principals) {
						t.Errorf("expected %d principals, got %d", len(tt.request.Principals), len(cert.ValidPrincipals))
					}
					
					for i, principal := range tt.request.Principals {
						if i < len(cert.ValidPrincipals) && cert.ValidPrincipals[i] != principal {
							t.Errorf("expected principal %s, got %s", principal, cert.ValidPrincipals[i])
						}
					}
					
					// Verify permissions and custom attributes are in extensions
					for k, v := range tt.request.Permissions {
						if cert.Permissions.Extensions[k] != v {
							t.Errorf("expected permission %s=%s, got %s", k, v, cert.Permissions.Extensions[k])
						}
					}
					
					for k, v := range tt.request.CustomAttributes {
						if cert.Permissions.Extensions[k] != v {
							t.Errorf("expected attribute %s=%s, got %s", k, v, cert.Permissions.Extensions[k])
						}
					}
				}
			}
		})
	}
}

func TestHandleConnection(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	tests := []struct {
		name         string
		request      EnclaveSigningRequest
		expectError  bool
		invalidJSON  bool
	}{
		{
			name: "successful signing",
			request: EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: false,
		},
		{
			name: "invalid public key",
			request: EnclaveSigningRequest{
				SSHKey:     "invalid-key",
				KeyID:      "test-key",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
		},
		{
			name:        "invalid JSON",
			invalidJSON: true,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestData []byte
			var err error
			
			if tt.invalidJSON {
				requestData = []byte("invalid json")
			} else {
				requestData, err = json.Marshal(tt.request)
				if err != nil {
					t.Fatalf("failed to marshal request: %v", err)
				}
			}

			conn := &MockConn{
				readData: requestData,
			}

			handleConnection(conn, signer)

			if !conn.closed {
				t.Error("connection should be closed after handling")
			}

			// Parse the response
			var response EnclaveSigningResponse
			err = json.Unmarshal(conn.writeData, &response)
			if err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if tt.expectError {
				if response.Error == "" {
					t.Error("expected error in response")
				}
				if response.SignedKey != "" {
					t.Error("expected empty signed key on error")
				}
			} else {
				if response.Error != "" {
					t.Errorf("unexpected error in response: %s", response.Error)
				}
				if response.SignedKey == "" {
					t.Error("expected signed key in response")
				}
			}
		})
	}
}

func TestWriteResponse(t *testing.T) {
	tests := []struct {
		name     string
		response EnclaveSigningResponse
	}{
		{
			name: "success response",
			response: EnclaveSigningResponse{
				SignedKey: "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAB...",
			},
		},
		{
			name: "error response",
			response: EnclaveSigningResponse{
				Error: "signing failed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &MockConn{}
			
			writeResponse(conn, tt.response)

			// Parse the written data
			var decoded EnclaveSigningResponse
			err := json.Unmarshal(conn.writeData, &decoded)
			if err != nil {
				t.Fatalf("failed to decode written response: %v", err)
			}

			if decoded.SignedKey != tt.response.SignedKey {
				t.Errorf("expected SignedKey %s, got %s", tt.response.SignedKey, decoded.SignedKey)
			}
			if decoded.Error != tt.response.Error {
				t.Errorf("expected Error %s, got %s", tt.response.Error, decoded.Error)
			}
		})
	}
}

func TestEnclaveSigningRequest_JSON(t *testing.T) {
	req := EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "test-key-id",
		Principals: []string{"user1", "user2"},
		Validity:   "24h",
		Permissions: map[string]string{
			"permit-pty":     "",
			"permit-user-rc": "",
		},
		CustomAttributes: map[string]string{
			"environment":     "production",
			"requesting_user": "admin@example.com",
		},
	}

	// Test marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Test unmarshaling
	var decoded EnclaveSigningRequest
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	// Verify all fields
	if decoded.SSHKey != req.SSHKey {
		t.Errorf("expected SSHKey %s, got %s", req.SSHKey, decoded.SSHKey)
	}
	if decoded.KeyID != req.KeyID {
		t.Errorf("expected KeyID %s, got %s", req.KeyID, decoded.KeyID)
	}
	if len(decoded.Principals) != len(req.Principals) {
		t.Errorf("expected %d principals, got %d", len(req.Principals), len(decoded.Principals))
	}
	if decoded.Validity != req.Validity {
		t.Errorf("expected Validity %s, got %s", req.Validity, decoded.Validity)
	}
	
	// Check maps
	for k, v := range req.Permissions {
		if decoded.Permissions[k] != v {
			t.Errorf("expected permission %s=%s, got %s", k, v, decoded.Permissions[k])
		}
	}
	for k, v := range req.CustomAttributes {
		if decoded.CustomAttributes[k] != v {
			t.Errorf("expected attribute %s=%s, got %s", k, v, decoded.CustomAttributes[k])
		}
	}
}

func TestCertificateFields(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)
	
	req := EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-cert-fields",
		Principals: []string{"testuser", "admin"},
		Validity:   "2h",
		Permissions: map[string]string{
			"permit-pty":           "",
			"permit-port-forwarding": "",
		},
		CustomAttributes: map[string]string{
			"department": "engineering",
			"project":    "cerberus",
		},
	}

	signedKey, err := signPublicKey(req, signer)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	// Parse certificate
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signedKey))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := publicKey.(*ssh.Certificate)

	// Test certificate type
	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert type, got %d", cert.CertType)
	}

	// Test validity period
	now := time.Now().Unix()
	if cert.ValidAfter > uint64(now) {
		t.Error("certificate should be valid now (considering clock skew)")
	}
	
	expectedValidBefore := time.Now().Add(2 * time.Hour).Unix()
	// Allow some variance for test execution time
	if cert.ValidBefore < uint64(expectedValidBefore-60) || cert.ValidBefore > uint64(expectedValidBefore+60) {
		t.Errorf("certificate validity period incorrect, expected around %d, got %d", expectedValidBefore, cert.ValidBefore)
	}

	// Test serial number is set
	if cert.Serial == 0 {
		t.Error("certificate serial should be non-zero")
	}
}

// Benchmark tests
func BenchmarkSignPublicKey(b *testing.B) {
	signer := createTestSigner(b.(*testing.T))
	testPublicKey := createTestPublicKey(b.(*testing.T))
	
	req := EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "benchmark-key",
		Principals: []string{"user"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := signPublicKey(req, signer)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkJSONMarshalUnmarshal(b *testing.B) {
	req := EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "benchmark-key",
		Principals: []string{"user1", "user2"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(req)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}
		
		var decoded EnclaveSigningRequest
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}

// Test error cases for loadSignerFromParameterStore
func TestLoadSignerFromParameterStore_ErrorCases(t *testing.T) {
	t.Skip("Requires AWS credentials and SSM access - run manually for integration testing")
	
	// This test would check various error conditions:
	// - Parameter not found
	// - Access denied
	// - Invalid private key format
	// - Network connectivity issues
	
	tests := []struct {
		name      string
		paramName string
		expectErr bool
	}{
		{
			name:      "nonexistent parameter",
			paramName: "/nonexistent/parameter",
			expectErr: true,
		},
		{
			name:      "empty parameter name",
			paramName: "",
			expectErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadSignerFromParameterStore(context.Background(), tt.paramName)
			if tt.expectErr && err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}