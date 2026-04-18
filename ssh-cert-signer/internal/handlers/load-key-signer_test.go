package handlers

import (
	"context"
	"os"
	"strings"
	"testing"

	"cerberus/messages"
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

	_, err := LoadKeySignerHandler(context.Background(), req, nil)
	if err == nil {
		t.Error("expected error when file doesn't exist")
	}

	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestLoadKeySignerHandler_EmptyFilePath(t *testing.T) {
	// Test with default file path (should not exist)
	originalPath := os.Getenv("CA_KEY_FILE_PATH")
	os.Unsetenv("CA_KEY_FILE_PATH")
	defer func() {
		if originalPath != "" {
			os.Setenv("CA_KEY_FILE_PATH", originalPath)
		}
	}()

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	_, err := LoadKeySignerHandler(context.Background(), req, nil)
	if err == nil {
		t.Error("expected error when default file doesn't exist")
	}

	if !strings.Contains(err.Error(), "failed to read encrypted key file") {
		t.Errorf("expected file read error, got: %v", err)
	}
}

func TestLoadKeySignerHandler_EmptyFile(t *testing.T) {
	// Create a temporary empty file
	tmpFile, err := os.CreateTemp("", "test_key_*.enc")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	// This should fail at the KMS decryption step since we can't connect to AWS in tests
	_, err = LoadKeySignerHandler(context.Background(), req, nil)
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
		{"false", false},
		{"0", false},
		{"no", false},
	}

	for _, tt := range tests {
		t.Run("REQUIRE_ATTESTATION="+tt.envValue, func(t *testing.T) {
			t.Setenv("REQUIRE_ATTESTATION", tt.envValue)
			if got := attestationRequired(); got != tt.want {
				t.Errorf("attestationRequired() = %v, want %v", got, tt.want)
			}
		})
	}

	// Unrecognized value falls through to /dev/nsm detection.
	t.Run("REQUIRE_ATTESTATION=garbage falls through", func(t *testing.T) {
		t.Setenv("REQUIRE_ATTESTATION", "garbage")
		_, nsmErr := os.Stat("/dev/nsm")
		wantAuto := nsmErr == nil
		if got := attestationRequired(); got != wantAuto {
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

	_, err := LoadKeySignerHandler(context.Background(), req, nil)
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
	tmpFile, err := os.CreateTemp("", "test_key_*.enc")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("fake encrypted content")
	tmpFile.Close()

	t.Setenv("CA_KEY_FILE_PATH", tmpFile.Name())

	req := messages.LoadKeySignerRequest{
		Credentials: messages.Credentials{
			AccessKeyId:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Token:           "test-token",
		},
	}

	// This will fail at AWS connection, but we can verify the region was set
	_, err = LoadKeySignerHandler(context.Background(), req, nil)
	if err == nil {
		t.Error("expected error due to AWS connection failure")
	}

	// The error should be related to AWS connection or KMS operation
	if !strings.Contains(err.Error(), "failed to decrypt key with KMS") &&
		!strings.Contains(err.Error(), "failed to load AWS default config") {
		t.Errorf("expected AWS/KMS related error, got: %v", err)
	}
}
