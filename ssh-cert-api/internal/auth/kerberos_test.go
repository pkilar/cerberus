package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckKeytabPermissions(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr string // substring expected in error, "" means no error
	}{
		{"owner-read-write 0600", 0o600, ""},
		{"owner-read-only 0400", 0o400, ""},
		{"group-readable 0640", 0o640, "insecure permissions"},
		{"world-readable 0604", 0o604, "insecure permissions"},
		{"world-readable 0644", 0o644, "insecure permissions"},
		{"group-writable 0620", 0o620, "insecure permissions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.keytab")
			if err := os.WriteFile(path, []byte("stub"), tt.mode); err != nil {
				t.Fatalf("failed to create keytab: %v", err)
			}
			// os.WriteFile applies the umask, so force the mode explicitly.
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatalf("failed to chmod keytab: %v", err)
			}

			err := checkKeytabPermissions(path)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("expected no error for mode %#o, got: %v", tt.mode, err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("expected error containing %q for mode %#o, got nil", tt.wantErr, tt.mode)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestCheckKeytabPermissions_MissingFile(t *testing.T) {
	err := checkKeytabPermissions(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "failed to stat keytab") {
		t.Errorf("expected stat error, got: %v", err)
	}
}
