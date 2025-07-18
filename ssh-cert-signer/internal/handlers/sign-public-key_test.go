package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"cerberus/messages"

	"golang.org/x/crypto/ssh"
)

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
		signer      ssh.Signer
		request     messages.EnclaveSigningRequest
		expectError bool
		errorMsg    string
	}{
		{
			name:   "valid request",
			signer: signer,
			request: messages.EnclaveSigningRequest{
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
			name:   "nil signer",
			signer: nil,
			request: messages.EnclaveSigningRequest{
				SSHKey:   testPublicKey,
				KeyID:    "test-key-nil-signer",
				Validity: "1h",
			},
			expectError: true,
			errorMsg:    "CA signer is not initialized",
		},
		{
			name:   "invalid public key",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     "invalid-key-format",
				KeyID:      "test-key-2",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
			errorMsg:    "failed to parse public key",
		},
		{
			name:   "invalid validity duration",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-3",
				Principals: []string{"user1"},
				Validity:   "invalid-duration",
			},
			expectError: true,
			errorMsg:    "invalid validity duration format",
		},
		{
			name:   "empty principals",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-4",
				Principals: []string{},
				Validity:   "1h",
			},
			expectError: false, // Empty principals should be allowed
		},
		{
			name:   "empty SSH key",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:   "",
				KeyID:    "test-key-5",
				Validity: "1h",
			},
			expectError: true,
			errorMsg:    "SSH key cannot be empty",
		},
		{
			name:   "empty KeyID",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:   testPublicKey,
				KeyID:    "",
				Validity: "1h",
			},
			expectError: true,
			errorMsg:    "KeyID cannot be empty",
		},
		{
			name:   "empty validity",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey: testPublicKey,
				KeyID:  "test-key-6",
			},
			expectError: true,
			errorMsg:    "validity duration cannot be empty",
		},
		{
			name:   "excessive validity duration",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:   testPublicKey,
				KeyID:    "test-key-7",
				Validity: "48h", // Exceeds 24h limit
			},
			expectError: true,
			errorMsg:    "validity duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := SignPublicKey(context.Background(), tt.signer, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMsg, err)
				}
				if response != nil {
					t.Error("expected nil response on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if response == nil || response.SignedKey == "" {
					t.Error("expected signed key but got empty response")
				}

				if response != nil && response.SignedKey != "" {
					// Verify the signed key format
					if !strings.Contains(response.SignedKey, "ssh-rsa-cert-v01@openssh.com") {
						t.Error("signed key should contain certificate type identifier")
					}

					// Try to parse the signed certificate
					publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
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
			}
		})
	}
}

func TestSignPublicKey_CertificateFields(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-cert-fields",
		Principals: []string{"testuser", "admin"},
		Validity:   "2h",
		Permissions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		},
		CustomAttributes: map[string]string{
			"department": "engineering",
			"project":    "cerberus",
		},
	}

	response, err := SignPublicKey(context.Background(), signer, req)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if response == nil || response.SignedKey == "" {
		t.Fatal("expected signed key in response")
	}

	// Parse certificate
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := publicKey.(*ssh.Certificate)

	// Test certificate type
	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert type, got %d", cert.CertType)
	}

	// Test serial number is set
	if cert.Serial == 0 {
		t.Error("certificate serial should be non-zero")
	}

	// Test that validity is set correctly (allowing for some clock skew)
	if cert.ValidAfter == 0 {
		t.Error("certificate ValidAfter should be set")
	}

	if cert.ValidBefore == 0 {
		t.Error("certificate ValidBefore should be set")
	}

	if cert.ValidBefore <= cert.ValidAfter {
		t.Error("certificate ValidBefore should be after ValidAfter")
	}
}

// Benchmark the signing performance
func BenchmarkSignPublicKey(b *testing.B) {
	signer := createTestSignerForBenchmark(b)
	testPublicKey := createTestPublicKeyForBenchmark(b)

	req := messages.EnclaveSigningRequest{
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
		_, err := SignPublicKey(context.Background(), signer, req)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

// Helper function for benchmarks
func createTestSignerForBenchmark(b *testing.B) ssh.Signer {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to generate test key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	return signer
}

func createTestPublicKeyForBenchmark(b *testing.B) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to generate test key: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		b.Fatalf("failed to create public key: %v", err)
	}

	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func TestSignPublicKey_CriticalOptions(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-critical-options",
		Principals: []string{"testuser"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"department": "security",
		},
		CriticalOptions: map[string]string{
			"force-command":  "/bin/restricted-shell",
			"source-address": "192.168.1.0/24,10.0.0.1/32",
		},
	}

	response, err := SignPublicKey(context.Background(), signer, req)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if response == nil || response.SignedKey == "" {
		t.Fatal("expected signed key in response")
	}

	// Parse certificate
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := publicKey.(*ssh.Certificate)

	// Test that critical options are present
	if len(cert.Permissions.CriticalOptions) != 2 {
		t.Errorf("expected 2 critical options, got %d", len(cert.Permissions.CriticalOptions))
	}

	// Test specific critical options
	if cert.Permissions.CriticalOptions["force-command"] != "/bin/restricted-shell" {
		t.Errorf("expected force-command '/bin/restricted-shell', got '%s'", cert.Permissions.CriticalOptions["force-command"])
	}

	if cert.Permissions.CriticalOptions["source-address"] != "192.168.1.0/24,10.0.0.1/32" {
		t.Errorf("expected source-address '192.168.1.0/24,10.0.0.1/32', got '%s'", cert.Permissions.CriticalOptions["source-address"])
	}

	// Test that extensions are still present
	if len(cert.Permissions.Extensions) < 2 {
		t.Errorf("expected at least 2 extensions (permissions + custom attributes), got %d", len(cert.Permissions.Extensions))
	}

	// Test specific extension
	if cert.Permissions.Extensions["department"] != "security" {
		t.Errorf("expected department 'security', got '%s'", cert.Permissions.Extensions["department"])
	}

	// Test that permit-pty permission is present
	if _, exists := cert.Permissions.Extensions["permit-pty"]; !exists {
		t.Error("expected permit-pty permission to be present")
	}
}
