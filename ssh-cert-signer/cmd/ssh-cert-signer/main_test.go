package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cerberus/messages"
	"ssh-cert-signer/internal/handlers"

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

// Helper function for benchmarks that need a signer
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

// Helper function for benchmarks that need a public key
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

func TestSignPublicKey(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	tests := []struct {
		name        string
		request     messages.EnclaveSigningRequest
		expectError bool
	}{
		{
			name: "valid request",
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
			name: "invalid public key",
			request: messages.EnclaveSigningRequest{
				SSHKey:     "invalid-key-format",
				KeyID:      "test-key-2",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
		},
		{
			name: "invalid validity duration",
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-3",
				Principals: []string{"user1"},
				Validity:   "invalid-duration",
			},
			expectError: true,
		},
		{
			name: "empty principals",
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-4",
				Principals: []string{},
				Validity:   "1h",
			},
			expectError: true, // Empty principals are now refused at the enclave
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := handlers.SignPublicKey(t.Context(), signer, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
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

func TestResponseSerialization(t *testing.T) {
	tests := []struct {
		name     string
		response messages.Response
	}{
		{
			name: "success response",
			response: messages.Response{
				SignSshKey: &messages.SigningResponse{
					SignedKey: "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAB...",
				},
			},
		},
		{
			name: "error response",
			response: messages.Response{
				Error: stringPtr("signing failed"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("failed to marshal response: %v", err)
			}

			// Test JSON deserialization
			var decoded messages.Response
			err = json.Unmarshal(data, &decoded)
			if err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Verify fields
			if tt.response.SignSshKey != nil {
				if decoded.SignSshKey == nil {
					t.Error("expected SignSshKey but got nil")
				} else if decoded.SignSshKey.SignedKey != tt.response.SignSshKey.SignedKey {
					t.Errorf("expected SignedKey %s, got %s", tt.response.SignSshKey.SignedKey, decoded.SignSshKey.SignedKey)
				}
			}

			if tt.response.Error != nil {
				if decoded.Error == nil {
					t.Error("expected Error but got nil")
				} else if *decoded.Error != *tt.response.Error {
					t.Errorf("expected Error %s, got %s", *tt.response.Error, *decoded.Error)
				}
			}
		})
	}
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

func TestSshSigningRequest_JSON(t *testing.T) {
	req := messages.EnclaveSigningRequest{
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
	var decoded messages.EnclaveSigningRequest
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

	response, err := handlers.SignPublicKey(t.Context(), signer, req)
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

	for b.Loop() {
		_, err := handlers.SignPublicKey(b.Context(), signer, req)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkJSONMarshalUnmarshal(b *testing.B) {
	req := messages.EnclaveSigningRequest{
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

	for b.Loop() {
		data, err := json.Marshal(req)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}

		var decoded messages.EnclaveSigningRequest
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}

// TestCASignerAtomicSwapUnderLoad exercises the atomic.Pointer[ssh.Signer]
// swap that backs the load-key-then-sign hot path. N readers continuously
// load the pointer and run a full sign while a writer replaces it. With
// -race, a regression that downgrades the primitive (e.g. to a bare pointer
// + mutex held incorrectly, or a non-atomic *ssh.Signer field) surfaces as
// a data race. Nil loads or sign errors fail the test.
func TestCASignerAtomicSwapUnderLoad(t *testing.T) {
	signer1 := createTestSigner(t)
	signer2 := createTestSigner(t)
	caSigner.Store(&signer1)
	t.Cleanup(func() {
		var zero *ssh.Signer
		caSigner.Store(zero)
	})

	pub := createTestPublicKey(t)
	const readers = 8
	stop := make(chan struct{})
	errs := make(chan error, readers)
	var wg sync.WaitGroup

	for range readers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				sp := caSigner.Load()
				if sp == nil {
					errs <- fmt.Errorf("caSigner.Load returned nil during swap")
					return
				}
				_, err := handlers.SignPublicKey(t.Context(), *sp, messages.EnclaveSigningRequest{
					SSHKey:     pub,
					KeyID:      "swap-load",
					Principals: []string{"u1"},
					Validity:   "1h",
				})
				if err != nil {
					errs <- fmt.Errorf("SignPublicKey under swap: %w", err)
					return
				}
			}
		})
	}

	// Hammer the swap. The 2 ms pacing gives readers many chances per
	// iteration to observe both halves of the swap.
	for i := range 50 {
		time.Sleep(2 * time.Millisecond)
		if i%2 == 0 {
			caSigner.Store(&signer2)
		} else {
			caSigner.Store(&signer1)
		}
	}

	close(stop)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// Test for the nil signer case in SignPublicKey handler
func TestSignPublicKey_NilSigner(t *testing.T) {
	testPublicKey := createTestPublicKey(t)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-key",
		Principals: []string{"user1"},
		Validity:   "1h",
	}

	// Test with nil signer
	_, err := handlers.SignPublicKey(t.Context(), nil, req)
	if err == nil {
		t.Error("expected error with nil signer")
	}
	if !strings.Contains(err.Error(), "CA signer is not initialized") {
		t.Errorf("expected 'CA signer is not initialized' error, got: %v", err)
	}
}
