package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckSecretFilePerms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		role    string
		mode    os.FileMode
		wantErr string
	}{
		{"keytab owner-only 0600", "keytab", 0o600, ""},
		{"keytab read-only 0400", "keytab", 0o400, ""},
		{"ldap pw owner-only 0600", "ldap password file", 0o600, ""},
		{"keytab group-readable 0640", "keytab", 0o640, "insecure permissions"},
		{"ldap pw world-readable 0644", "ldap password file", 0o644, "insecure permissions"},
		{"keytab group-writable 0620", "keytab", 0o620, "insecure permissions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("stub"), tt.mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			err := CheckSecretFilePerms(path, tt.role)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("expected no error for mode %#o, got: %v", tt.mode, err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("expected error containing %q for mode %#o, got nil", tt.wantErr, tt.mode)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.role):
				t.Errorf("expected error to include role %q, got: %v", tt.role, err)
			}
		})
	}
}

func TestCheckSecretFilePerms_MissingFile(t *testing.T) {
	t.Parallel()
	err := CheckSecretFilePerms(filepath.Join(t.TempDir(), "missing"), "ldap password file")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "failed to stat ldap password file") {
		t.Errorf("expected role in stat error, got: %v", err)
	}
}
