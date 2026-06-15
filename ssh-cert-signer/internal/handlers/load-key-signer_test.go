package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/pkilar/cerberus/messages"
)

func TestLoadKeySignerHandler_MissingFile(t *testing.T) {
	t.Setenv("CA_KEY_FILE_PATH", "/nonexistent/path/to/key.enc")

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	_, err := LoadKeySignerHandler(t.Context(), req, nil)
	if err == nil {
		t.Error("expected error when file doesn't exist")
	}

	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestLoadKeySignerHandler_EmptyFilePath(t *testing.T) {
	// Test with default file path (should not exist)
	t.Setenv("CA_KEY_FILE_PATH", "")

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	_, err := LoadKeySignerHandler(t.Context(), req, nil)
	if err == nil {
		t.Error("expected error when default file doesn't exist")
	}

	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestLoadKeySignerHandler_EmptyFile(t *testing.T) {
	// Create a temporary empty file
	tmpFile, err := os.CreateTemp(t.TempDir(), "test_key_*.enc")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	// This should fail at the KMS decryption step since we can't connect to AWS in tests
	_, err = LoadKeySignerHandler(t.Context(), req, nil)
	if err == nil {
		t.Error("expected error when trying to decrypt empty file")
	}

	// Should fail either at KMS connection or decryption step
	if !strings.Contains(err.Error(), "failed to decrypt key with KMS") &&
		!strings.Contains(err.Error(), "failed to load AWS default config") {
		t.Errorf("expected AWS/KMS related error, got: %v", err)
	}
}

func TestAttestationRequired(t *testing.T) {
	tests := []struct {
		envValue string
		want     bool
	}{
		{"true", true},
		{"1", true},
		{"yes", true},
		{"TRUE", true},
		{" true ", true},
		{"false", false},
		{"0", false},
		{"no", false},
	}

	for _, tt := range tests {
		t.Run("REQUIRE_ATTESTATION="+tt.envValue, func(t *testing.T) {
			t.Setenv("REQUIRE_ATTESTATION", tt.envValue)
			got, err := attestationRequired()
			if err != nil {
				t.Fatalf("attestationRequired() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("attestationRequired() = %v, want %v", got, tt.want)
			}
		})
	}

	// An unrecognized value must fail closed rather than silently auto-detect:
	// a typo on a host without /dev/nsm would otherwise disable attestation.
	t.Run("REQUIRE_ATTESTATION=garbage fails closed", func(t *testing.T) {
		t.Setenv("REQUIRE_ATTESTATION", "garbage")
		if _, err := attestationRequired(); err == nil {
			t.Error("expected error for unrecognized REQUIRE_ATTESTATION value, got nil")
		}
	})

	// An explicitly empty value is treated as a misconfiguration, not unset.
	t.Run("REQUIRE_ATTESTATION=empty fails closed", func(t *testing.T) {
		t.Setenv("REQUIRE_ATTESTATION", "")
		if _, err := attestationRequired(); err == nil {
			t.Error("expected error for empty REQUIRE_ATTESTATION value, got nil")
		}
	})

	// When unset entirely, fall through to /dev/nsm detection.
	t.Run("REQUIRE_ATTESTATION unset auto-detects", func(t *testing.T) {
		os.Unsetenv("REQUIRE_ATTESTATION")
		_, nsmErr := os.Stat("/dev/nsm")
		wantAuto := nsmErr == nil
		got, err := attestationRequired()
		if err != nil {
			t.Fatalf("attestationRequired() unexpected error: %v", err)
		}
		if got != wantAuto {
			t.Errorf("attestationRequired() = %v, want %v (auto-detect)", got, wantAuto)
		}
	})
}

func TestLoadKeySignerHandler_AttestationRequiredButUnavailable(t *testing.T) {
	t.Setenv("REQUIRE_ATTESTATION", "true")

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	_, err := LoadKeySignerHandler(t.Context(), req, nil)
	if err == nil {
		t.Fatal("expected error when attestation is required but provider is nil")
	}
	if !strings.Contains(err.Error(), "attestation is required") {
		t.Errorf("expected attestation-required error, got: %v", err)
	}
}

// Test the environment variable handling
func TestLoadKeySignerHandler_EnvironmentVariables(t *testing.T) {
	testRegion := "us-west-2"
	t.Setenv("AWS_REGION", testRegion)

	// Create a temporary file with some content (not a real encrypted key)
	tmpFile, err := os.CreateTemp(t.TempDir(), "test_key_*.enc")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString("fake encrypted content"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}

	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	// This will fail at AWS connection, but we can verify the region was set
	_, err = LoadKeySignerHandler(t.Context(), req, nil)
	if err == nil {
		t.Error("expected error due to AWS connection failure")
	}

	// The error should be related to AWS connection or KMS operation
	if !strings.Contains(err.Error(), "failed to decrypt key with KMS") &&
		!strings.Contains(err.Error(), "failed to load AWS default config") {
		t.Errorf("expected AWS/KMS related error, got: %v", err)
	}
}

func TestBeginKeyLoad_MissingFile_DevPath(t *testing.T) {
	// No NSM provider + attestation not required => dev path, which reads the
	// CA key file first and fails there before any KMS call.
	t.Setenv("REQUIRE_ATTESTATION", "false")
	t.Setenv("CA_KEY_FILE_PATH", "/nonexistent/path/to/key.enc")

	_, err := BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error when CA key file is missing")
	}
	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestBeginKeyLoad_AttestationRequiredButUnavailable(t *testing.T) {
	t.Setenv("REQUIRE_ATTESTATION", "true")

	_, err := BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error when attestation is required but provider is nil")
	}
	if !strings.Contains(err.Error(), "attestation is required") {
		t.Errorf("expected attestation-required error, got: %v", err)
	}
}

func TestBeginKeyLoad_DevPath_FailsAtKMS(t *testing.T) {
	t.Setenv("REQUIRE_ATTESTATION", "false")

	// Create a temporary file with some content (not a real encrypted key)
	tmpFile, err := os.CreateTemp(t.TempDir(), "test_key_*.enc")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString("fake encrypted content"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	_, err = BeginKeyLoad(t.Context(), nil)
	if err == nil {
		t.Fatal("expected error due to AWS/KMS failure in dev path")
	}
	if !strings.Contains(err.Error(), "failed to decrypt key with KMS") &&
		!strings.Contains(err.Error(), "failed to load AWS default config") {
		t.Errorf("expected AWS/KMS related error, got: %v", err)
	}
}

func TestCompleteKeyLoad_NoProvider(t *testing.T) {
	_, err := CompleteKeyLoad(t.Context(), nil, []byte("envelope"))
	if err == nil {
		t.Fatal("expected error when attestation provider is unavailable")
	}
	if !strings.Contains(err.Error(), "without an available attestation provider") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseCASigner_PinMatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pemBytes := pemEncodeRSA(t, key)
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse signer: %v", err)
	}
	pinPath := writeTempFile(t, ssh.MarshalAuthorizedKey(signer.PublicKey()))
	t.Setenv("CA_PUBLIC_KEY_PATH", pinPath)

	if _, err := parseCASigner(t.Context(), pemBytes); err != nil {
		t.Fatalf("expected pin to match, got: %v", err)
	}
}

func TestParseCASigner_PinMismatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	otherSigner, err := ssh.ParsePrivateKey(pemEncodeRSA(t, other))
	if err != nil {
		t.Fatalf("parse other: %v", err)
	}
	pinPath := writeTempFile(t, ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))
	t.Setenv("CA_PUBLIC_KEY_PATH", pinPath)

	if _, err := parseCASigner(t.Context(), pemEncodeRSA(t, key)); err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
}

func TestParseCASigner_Unpinned(t *testing.T) {
	t.Setenv("CA_PUBLIC_KEY_PATH", "")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if _, err := parseCASigner(t.Context(), pemEncodeRSA(t, key)); err != nil {
		t.Fatalf("unpinned should warn and proceed, got: %v", err)
	}
}

// pemEncodeRSA returns the PKCS#1 PEM encoding of key.
func pemEncodeRSA(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ca_pub_*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}
	return f.Name()
}
