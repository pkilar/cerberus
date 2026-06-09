package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/pkilar/cerberus/messages"

	"golang.org/x/crypto/ssh"
)

// Test-key caches: RSA-2048 generation costs ~50–200ms per call. Without
// caching, this package's table tests would run a dozen+ generations for
// the same conceptual "a test CA key" and "a test user pubkey", trading
// real CI time for no extra coverage. sync.OnceValue gives us "generated
// once per process, deterministically reused".
var (
	cachedCAKey   = sync.OnceValue(func() *rsa.PrivateKey { return mustGenRSA(2048) })
	cachedUserKey = sync.OnceValue(func() *rsa.PrivateKey { return mustGenRSA(2048) })
)

func mustGenRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err) // process-local fixture; failure here means rand.Reader is broken
	}
	return k
}

// createTestSigner returns the cached test CA signer.
func createTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(cachedCAKey())
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

// createTestPublicKey returns the cached test user public key in
// authorized_keys format.
func createTestPublicKey(t *testing.T) string {
	t.Helper()
	publicKey, err := ssh.NewPublicKey(&cachedUserKey().PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func TestSignPublicKey(t *testing.T) {
	t.Parallel()
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
				SSHKey:     testPublicKey,
				KeyID:      "test-key-nil-signer",
				Principals: []string{"user1"},
				Validity:   "1h",
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
			expectError: true,
			errorMsg:    "principals cannot be empty",
		},
		{
			// Defense-in-depth: even if a compromised host forwards a literal
			// "*" principal, the enclave refuses it — "*" is a policy wildcard,
			// not a usable certificate principal.
			name:   "wildcard principal rejected",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-wildcard",
				Principals: []string{"*"},
				Validity:   "1h",
			},
			expectError: true,
			errorMsg:    "wildcard",
		},
		{
			// PR #35: zero validity would produce a cert "valid" only inside
			// the 300s clock-skew window. Refuse instead.
			name:   "zero validity",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-zero-validity",
				Principals: []string{"user1"},
				Validity:   "0s",
			},
			expectError: true,
			errorMsg:    "validity duration must be positive",
		},
		{
			// PR #35: negative validity produces ValidBefore < ValidAfter.
			name:   "negative validity",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-neg-validity",
				Principals: []string{"user1"},
				Validity:   "-1h",
			},
			expectError: true,
			errorMsg:    "validity duration must be positive",
		},
		{
			// PR #35: SSH key with prefix options must be refused. The
			// authorized_keys parser accepts options silently; we don't.
			name:   "ssh key with prefix options",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     "cert-authority,no-pty " + testPublicKey,
				KeyID:      "test-key-options",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
			errorMsg:    "must not carry SSH options",
		},
		{
			// PR #35: SSH key with trailing data must be refused.
			name:   "ssh key with trailing data",
			signer: signer,
			request: messages.EnclaveSigningRequest{
				SSHKey:     strings.TrimSpace(testPublicKey) + "\nsecond-key-fragment\n",
				KeyID:      "test-key-trailing",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
			errorMsg:    "trailing data",
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
				SSHKey:     testPublicKey,
				KeyID:      "test-key-7",
				Principals: []string{"user1"},
				Validity:   "48h", // Exceeds 24h limit
			},
			expectError: true,
			errorMsg:    "validity duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			response, err := SignPublicKey(t.Context(), tt.signer, tt.request)

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
	t.Parallel()
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

	response, err := SignPublicKey(t.Context(), signer, req)
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

	for b.Loop() {
		_, err := SignPublicKey(b.Context(), signer, req)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

// Benchmark variants reuse the same cached keys; setup time should not be
// charged to the measured iterations.
func createTestSignerForBenchmark(b *testing.B) ssh.Signer {
	b.Helper()
	signer, err := ssh.NewSignerFromKey(cachedCAKey())
	if err != nil {
		b.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

func createTestPublicKeyForBenchmark(b *testing.B) string {
	b.Helper()
	publicKey, err := ssh.NewPublicKey(&cachedUserKey().PublicKey)
	if err != nil {
		b.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func TestSignPublicKey_CriticalOptions(t *testing.T) {
	t.Parallel()
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

	response, err := SignPublicKey(t.Context(), signer, req)
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

// sshAuthorizedKey marshals a crypto public key (RSA/ECDSA *.PublicKey or an
// ed25519.PublicKey) into authorized_keys form for use as a signing input.
func sshAuthorizedKey(t *testing.T, pub any) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func rsaAuthorizedKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	return sshAuthorizedKey(t, &k.PublicKey)
}

func ecdsaAuthorizedKey(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return sshAuthorizedKey(t, &k.PublicKey)
}

func ed25519AuthorizedKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return sshAuthorizedKey(t, pub)
}

// TestSignPublicKey_KeyAlgorithmAllowlist exercises validatePublicKey's
// security contract directly: weak RSA is refused, while RSA-2048+, the ECDSA
// NIST-curve allowlist, and Ed25519 are accepted. Without this a regression
// dropping the BitLen check or widening the type switch would weaken the CA
// with no functional symptom.
func TestSignPublicKey_KeyAlgorithmAllowlist(t *testing.T) {
	t.Parallel()
	signer := createTestSigner(t)

	tests := []struct {
		name    string
		sshKey  string
		wantErr string // empty == expect success
	}{
		{"rsa-1024 rejected", rsaAuthorizedKey(t, 1024), "RSA key too small"},
		{"rsa-2048 accepted", rsaAuthorizedKey(t, 2048), ""},
		{"ecdsa-p256 accepted", ecdsaAuthorizedKey(t, elliptic.P256()), ""},
		{"ecdsa-p384 accepted", ecdsaAuthorizedKey(t, elliptic.P384()), ""},
		{"ed25519 accepted", ed25519AuthorizedKey(t), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp, err := SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
				SSHKey: tt.sshKey, KeyID: "algo-test", Principals: []string{"u1"}, Validity: "1h",
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got err=%v, want containing %q", err, tt.wantErr)
				}
				if resp != nil {
					t.Error("expected nil response on rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil || resp.SignedKey == "" {
				t.Fatal("expected a signed certificate")
			}
		})
	}
}

// TestSignPublicKey_RejectsCertificateAsKey verifies that feeding a previously
// issued certificate back in as the public key is refused (it is not an
// ssh.CryptoPublicKey), rather than re-certified.
func TestSignPublicKey_RejectsCertificateAsKey(t *testing.T) {
	t.Parallel()
	signer := createTestSigner(t)
	seed, err := SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
		SSHKey: createTestPublicKey(t), KeyID: "seed", Principals: []string{"u1"}, Validity: "1h",
	})
	if err != nil {
		t.Fatalf("seed sign: %v", err)
	}
	_, err = SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
		SSHKey: seed.SignedKey, KeyID: "recert", Principals: []string{"u1"}, Validity: "1h",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported public key wrapper") {
		t.Fatalf("got err=%v, want 'unsupported public key wrapper'", err)
	}
}

// TestSignPublicKey_SignatureVerifiesAgainstCA asserts the core CA guarantee:
// the emitted certificate carries a valid signature made by our CA key — not
// merely a structurally well-formed cert. Field assertions elsewhere do not
// cover the cryptographic binding.
func TestSignPublicKey_SignatureVerifiesAgainstCA(t *testing.T) {
	t.Parallel()
	signer := createTestSigner(t)
	resp, err := SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
		SSHKey: createTestPublicKey(t), KeyID: "verify", Principals: []string{"testuser"}, Validity: "1h",
	})
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.SignedKey))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected *ssh.Certificate, got %T", pub)
	}

	if cert.Signature == nil {
		t.Fatal("certificate has no signature")
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), signer.PublicKey().Marshal()) {
		t.Error("certificate SignatureKey does not match the CA signer")
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), signer.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("testuser", cert); err != nil {
		t.Errorf("CheckCert (signature + validity + principal) failed: %v", err)
	}
}

// TestSignPublicKey_RejectsPermissionAttributeCollision verifies the
// ambiguity-rejection guard: the same key in both Permissions and
// CustomAttributes (which both merge into Extensions) must be refused, not
// silently overwritten by map iteration order.
func TestSignPublicKey_RejectsPermissionAttributeCollision(t *testing.T) {
	t.Parallel()
	signer := createTestSigner(t)
	_, err := SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
		SSHKey:           createTestPublicKey(t),
		KeyID:            "collide",
		Principals:       []string{"u1"},
		Validity:         "1h",
		Permissions:      map[string]string{"x@cerberus": ""},
		CustomAttributes: map[string]string{"x@cerberus": "v"},
	})
	if err == nil || !strings.Contains(err.Error(), "present in both permissions and custom_attributes") {
		t.Fatalf("got err=%v, want collision rejection", err)
	}
}

// TestSignPublicKey_TooManyPrincipals verifies the enclave's own MaxPrincipals
// cap (the host enforces it too; this is the enclave-side belt-and-braces).
func TestSignPublicKey_TooManyPrincipals(t *testing.T) {
	t.Parallel()
	signer := createTestSigner(t)
	principals := make([]string, messages.MaxPrincipals+1)
	for i := range principals {
		principals[i] = fmt.Sprintf("p%d", i)
	}
	_, err := SignPublicKey(t.Context(), signer, messages.EnclaveSigningRequest{
		SSHKey: createTestPublicKey(t), KeyID: "too-many", Principals: principals, Validity: "1h",
	})
	if err == nil || !strings.Contains(err.Error(), "too many principals") {
		t.Fatalf("got err=%v, want 'too many principals'", err)
	}
}
