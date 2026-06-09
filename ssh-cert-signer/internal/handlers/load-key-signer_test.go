package handlers

import (
	"os"
	"strings"
	"testing"

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
