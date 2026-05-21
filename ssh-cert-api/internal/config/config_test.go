package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		yamlContent string
		expectError bool
		errSubstr   string
	}{
		{
			name: "valid config",
			yamlContent: `
keytab_path: "/etc/keytab/test.keytab"
groups:
  admin:
    members:
      - admin@example.com
      - root@example.com
    certificate_rules:
      validity: "24h"
      allowed_principals:
        - admin
        - root
      permissions:
        permit-pty: ""
        permit-user-rc: ""
      static_attributes:
        environment: "production"
  users:
    members:
      - user1@example.com
      - user2@example.com
    certificate_rules:
      validity: "1h"
      allowed_principals:
        - user1
        - user2
      permissions:
        permit-pty: ""
`,
			expectError: false,
		},
		{
			name: "invalid YAML",
			yamlContent: `
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      validity: "24h"
      allowed_principals:
        - admin
      permissions:
        permit-pty: ""
      invalid_indent:
    bad_yaml
`,
			expectError: true,
		},
		{
			name: "empty groups",
			yamlContent: `
groups: {}
`,
			expectError: true,
		},
		{
			name: "group with no members",
			yamlContent: `
keytab_path: "/etc/keytab/test.keytab"
groups:
  admin:
    members: []
    certificate_rules:
      validity: "24h"
      allowed_principals:
        - admin
`,
			expectError: true,
			errSubstr:   "has no members",
		},
		{
			name: "group with no validity",
			yamlContent: `
keytab_path: "/etc/keytab/test.keytab"
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      allowed_principals:
        - admin
`,
			expectError: true,
			errSubstr:   "no validity period defined",
		},
		{
			name: "invalid validity duration",
			yamlContent: `
keytab_path: "/etc/keytab/test.keytab"
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      validity: "invalid-duration"
      allowed_principals:
        - admin
`,
			expectError: true,
			errSubstr:   "invalid validity duration",
		},
		{
			name: "no allowed principals",
			yamlContent: `
keytab_path: "/etc/keytab/test.keytab"
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      validity: "24h"
      allowed_principals: []
`,
			expectError: true,
			errSubstr:   "no allowed_principals",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tempDir, "test-config.yaml")
			err := os.WriteFile(testFile, []byte(tt.yamlContent), 0644)
			if err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			// Load config
			cfg, err := LoadConfig(testFile)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if cfg != nil {
					t.Error("expected nil config on error")
				}
				if tt.errSubstr != "" && err != nil && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got: %v", tt.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("expected config but got nil")
				}
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/file.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errSubstr   string
	}{
		{
			name: "valid config",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "24h",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty groups",
			config: Config{
				Groups: map[string]Group{},
			},
			expectError: true,
		},
		{
			name: "group with no members",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{},
						CertificateRules: CertificateRules{
							Validity:          "24h",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "has no members",
		},
		{
			name: "group with empty validity",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "no validity period defined",
		},
		{
			name: "group with invalid validity duration",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "invalid",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "invalid validity duration",
		},
		{
			name: "group with no allowed principals",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "24h",
							AllowedPrincipals: []string{},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "no allowed_principals",
		},
		{
			// PR #35 added the d <= 0 guard. 0s would otherwise produce a cert
			// "valid" only inside the 300s clock-skew window.
			name: "zero validity",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "0s",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "must be positive",
		},
		{
			// Negative validity would produce ValidBefore < ValidAfter which
			// sshd refuses. Catch at startup, not at the user's terminal.
			name: "negative validity",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "-1h",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
			errSubstr:   "must be positive",
		},
		{
			name: "validity exceeds 24h max",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "25h",
							AllowedPrincipals: []string{"admin"},
						},
					},
				},
			},
			expectError: true,
		},
		{
			// Regression test: a non-empty value on a flag-style extension
			// (permit-pty: "yes") produces a wire-format payload that sshd
			// rejects as `Certificate option "permit-pty" corrupt (extra data)`.
			// Validate must catch this at config load.
			name: "flag extension with non-empty value",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "1h",
							AllowedPrincipals: []string{"admin"},
							Permissions: map[string]string{
								"permit-pty": "yes",
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "flag extension under critical_options with non-empty value",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "1h",
							AllowedPrincipals: []string{"admin"},
							CriticalOptions: map[string]string{
								"verify-required": "true",
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			// All flag extensions empty plus a non-flag critical option with
			// a payload (force-command) is the correct shape and must pass.
			name: "all flag extensions empty + force-command with payload",
			config: Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"admin": {
						Members: []string{"admin@example.com"},
						CertificateRules: CertificateRules{
							Validity:          "1h",
							AllowedPrincipals: []string{"admin"},
							Permissions: map[string]string{
								"permit-X11-forwarding":   "",
								"permit-agent-forwarding": "",
								"permit-port-forwarding":  "",
								"permit-pty":              "",
								"permit-user-rc":          "",
							},
							CriticalOptions: map[string]string{
								"force-command":  "/usr/bin/restricted-shell",
								"source-address": "10.0.0.0/8",
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("expected error containing %q, got: %v", tt.errSubstr, err)
			}
		})
	}
}

func TestValidate_ValidityDurationParsing(t *testing.T) {
	validDurations := []string{
		"1h",
		"24h",
		"1h30m",
		"30m",
		"3600s",
		"1h0m0s",
	}

	for _, duration := range validDurations {
		t.Run(duration, func(t *testing.T) {
			config := Config{
				KeytabPath: "/etc/keytab/test.keytab",
				Groups: map[string]Group{
					"test": {
						Members: []string{"test@example.com"},
						CertificateRules: CertificateRules{
							Validity:          duration,
							AllowedPrincipals: []string{"test"},
						},
					},
				},
			}

			err := config.Validate()
			if err != nil {
				t.Errorf("expected valid duration %s to pass validation, got error: %v", duration, err)
			}

			// Also test that the duration can actually be parsed
			_, parseErr := time.ParseDuration(duration)
			if parseErr != nil {
				t.Errorf("duration %s should be parseable: %v", duration, parseErr)
			}
		})
	}
}

func TestConfigStructure(t *testing.T) {
	// Test that the config structure matches expected YAML structure
	config := Config{
		KeytabPath: "/etc/keytab/test.keytab",
		Groups: map[string]Group{
			"admin": {
				Members: []string{"admin@example.com", "root@example.com"},
				CertificateRules: CertificateRules{
					Validity:          "24h",
					AllowedPrincipals: []string{"admin", "root"},
					Permissions: map[string]string{
						"permit-pty":     "",
						"permit-user-rc": "",
					},
					StaticAttributes: map[string]string{
						"environment": "production",
						"purpose":     "administrative",
					},
				},
			},
			"users": {
				Members: []string{"user1@example.com", "user2@example.com"},
				CertificateRules: CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"user1", "user2"},
					Permissions: map[string]string{
						"permit-pty": "",
					},
					StaticAttributes: map[string]string{
						"environment": "production",
					},
				},
			},
		},
	}

	// Validate the structure
	err := config.Validate()
	if err != nil {
		t.Errorf("valid config structure failed validation: %v", err)
	}

	// Test access to nested fields
	adminGroup := config.Groups["admin"]
	if len(adminGroup.Members) != 2 {
		t.Errorf("expected 2 admin members, got %d", len(adminGroup.Members))
	}

	if adminGroup.CertificateRules.Validity != "24h" {
		t.Errorf("expected validity 24h, got %s", adminGroup.CertificateRules.Validity)
	}

	if len(adminGroup.CertificateRules.AllowedPrincipals) != 2 {
		t.Errorf("expected 2 allowed principals, got %d", len(adminGroup.CertificateRules.AllowedPrincipals))
	}

	if adminGroup.CertificateRules.Permissions["permit-pty"] != "" {
		t.Errorf("expected empty permit-pty permission")
	}

	if adminGroup.CertificateRules.StaticAttributes["environment"] != "production" {
		t.Errorf("expected environment production, got %s", adminGroup.CertificateRules.StaticAttributes["environment"])
	}
}

func TestConfigValidation_MultipleGroups(t *testing.T) {
	config := Config{
		KeytabPath: "/etc/keytab/test.keytab",
		Groups: map[string]Group{
			"admin": {
				Members: []string{"admin@example.com"},
				CertificateRules: CertificateRules{
					Validity:          "24h",
					AllowedPrincipals: []string{"admin"},
				},
			},
			"users": {
				Members: []string{"user@example.com"},
				CertificateRules: CertificateRules{
					Validity:          "1h",
					AllowedPrincipals: []string{"user"},
				},
			},
			"invalid": {
				Members: []string{"test@example.com"},
				CertificateRules: CertificateRules{
					Validity:          "invalid-duration",
					AllowedPrincipals: []string{"test"},
				},
			},
		},
	}

	err := config.Validate()
	if err == nil {
		t.Error("expected validation to fail due to invalid group")
	}

	// Error should mention the specific group that failed
	if err.Error() != "invalid validity duration for group 'invalid': time: invalid duration \"invalid-duration\"" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestWarnings_StaticAttributesNamespacing(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []StaticAttributeWarning
	}{
		{
			name: "no groups",
			cfg:  Config{},
			want: nil,
		},
		{
			name: "all namespaced",
			cfg: Config{
				Groups: map[string]Group{
					"admin": {
						CertificateRules: CertificateRules{
							StaticAttributes: map[string]string{
								"team@example.com":         "platform",
								"access-level@example.com": "prod",
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			name: "mixed namespaced and bare across multiple groups",
			cfg: Config{
				Groups: map[string]Group{
					"users": {
						CertificateRules: CertificateRules{
							StaticAttributes: map[string]string{
								"tier@example.com": "gold",
								"region":           "us-east-1",
							},
						},
					},
					"admin": {
						CertificateRules: CertificateRules{
							StaticAttributes: map[string]string{
								"team":         "platform",
								"access-level": "prod",
							},
						},
					},
					"clean": {
						CertificateRules: CertificateRules{
							StaticAttributes: map[string]string{
								"env@example.com": "production",
							},
						},
					},
				},
			},
			// Sorted by (group, key).
			want: []StaticAttributeWarning{
				{Group: "admin", Key: "access-level"},
				{Group: "admin", Key: "team"},
				{Group: "users", Key: "region"},
			},
		},
		{
			name: "no static_attributes field set",
			cfg: Config{
				Groups: map[string]Group{
					"empty": {CertificateRules: CertificateRules{}},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.Warnings()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Warnings() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
