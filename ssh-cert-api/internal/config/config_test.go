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
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
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
			t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	mkBare := func(group, key string) Warning {
		return Warning{
			Kind:   WarnStaticAttributeNotNamespaced,
			Group:  group,
			Key:    key,
			Detail: "rename to " + key + "@<domain> per PROTOCOL.certkeys §4",
		}
	}
	tests := []struct {
		name string
		cfg  Config
		want []Warning
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
			// Sorted by (kind, backend, group, key); kind and backend are
			// equal here so it reduces to (group, key).
			want: []Warning{
				mkBare("admin", "access-level"),
				mkBare("admin", "team"),
				mkBare("users", "region"),
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
			t.Parallel()
			got := tt.cfg.Warnings()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Warnings() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// validLDAPConfig returns a Config that passes Validate with one LDAP backend
// and one LDAP-backed group. Each test mutates a clone before calling Validate.
func validLDAPConfig() Config {
	return Config{
		KeytabPath: "/etc/keytab",
		LDAP: []LDAPBackend{{
			Name:       "corp",
			Realms:     []string{"REALM.EXAMPLE.COM"},
			URL:        "ldaps://ad.corp.example:636",
			UserBaseDN: "DC=corp,DC=example",
			UserFilter: "(sAMAccountName=%s)",
			Bind: LDAPBind{
				Method:       LDAPBindSimple,
				DN:           "CN=svc,DC=corp,DC=example",
				PasswordFile: "/etc/cerberus/ldap.pw",
			},
		}},
		Groups: map[string]Group{
			"ssh-admins": {
				LDAPGroups: []string{"CN=ssh-admins,DC=corp,DC=example"},
				CertificateRules: CertificateRules{
					Validity:          "8h",
					AllowedPrincipals: []string{"root"},
				},
			},
		},
	}
}

func TestValidate_LDAP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{
			name:    "baseline valid",
			mutate:  func(c *Config) {},
			wantErr: "",
		},
		{
			name: "missing backend name",
			mutate: func(c *Config) {
				c.LDAP[0].Name = ""
			},
			wantErr: "name is required",
		},
		{
			name: "duplicate backend names",
			mutate: func(c *Config) {
				dup := c.LDAP[0]
				dup.Realms = []string{"OTHER.EXAMPLE.COM"}
				c.LDAP = append(c.LDAP, dup)
			},
			wantErr: "duplicate backend name",
		},
		{
			name: "empty realms",
			mutate: func(c *Config) {
				c.LDAP[0].Realms = nil
			},
			wantErr: "realms must be non-empty",
		},
		{
			name: "overlapping realms across backends",
			mutate: func(c *Config) {
				dup := c.LDAP[0]
				dup.Name = "second"
				c.LDAP = append(c.LDAP, dup)
			},
			wantErr: "is claimed by both backends",
		},
		{
			name: "missing url",
			mutate: func(c *Config) {
				c.LDAP[0].URL = ""
			},
			wantErr: "url is required",
		},
		{
			name: "missing user_base_dn",
			mutate: func(c *Config) {
				c.LDAP[0].UserBaseDN = ""
			},
			wantErr: "user_base_dn is required",
		},
		{
			name: "user_filter missing %s",
			mutate: func(c *Config) {
				c.LDAP[0].UserFilter = "(uid=fixed)"
			},
			wantErr: "user_filter must contain exactly one",
		},
		{
			name: "user_filter has two %s",
			mutate: func(c *Config) {
				c.LDAP[0].UserFilter = "(|(uid=%s)(sAMAccountName=%s))"
			},
			wantErr: "user_filter must contain exactly one",
		},
		{
			// "%%s" passes a naive strings.Count("%s")==1 check but fmt reads
			// "%%" as a literal percent, dropping the substitution entirely.
			name: "user_filter escaped %%s is rejected",
			mutate: func(c *Config) {
				c.LDAP[0].UserFilter = "(uid=%%s)"
			},
			wantErr: "user_filter must contain exactly one",
		},
		{
			name: "realms with whitespace-only entry",
			mutate: func(c *Config) {
				c.LDAP[0].Realms = []string{"  "}
			},
			wantErr: "must not contain empty or whitespace entries",
		},
		{
			name: "simple bind missing dn",
			mutate: func(c *Config) {
				c.LDAP[0].Bind.DN = ""
			},
			wantErr: "simple bind requires dn",
		},
		{
			name: "simple bind missing password_file",
			mutate: func(c *Config) {
				c.LDAP[0].Bind.PasswordFile = ""
			},
			wantErr: "simple bind requires password_file",
		},
		{
			name: "gssapi bind missing client_principal",
			mutate: func(c *Config) {
				c.LDAP[0].Bind = LDAPBind{Method: LDAPBindGSSAPI}
			},
			wantErr: "gssapi bind requires client_principal",
		},
		{
			name: "gssapi client_principal not user@REALM",
			mutate: func(c *Config) {
				c.LDAP[0].Bind = LDAPBind{
					Method:          LDAPBindGSSAPI,
					ClientPrincipal: "svc-account",
				}
			},
			wantErr: "must be in user@REALM form",
		},
		{
			name: "anonymous bind ok",
			mutate: func(c *Config) {
				c.LDAP[0].Bind = LDAPBind{Method: LDAPBindAnonymous}
			},
			wantErr: "",
		},
		{
			name: "unknown bind method",
			mutate: func(c *Config) {
				c.LDAP[0].Bind.Method = "kerberos5"
			},
			wantErr: "unknown bind method",
		},
		{
			name: "cache_ttl too long",
			mutate: func(c *Config) {
				c.LDAP[0].CacheTTL = 20 * time.Minute
			},
			wantErr: "cache_ttl",
		},
		{
			name: "negative cache_ttl",
			mutate: func(c *Config) {
				c.LDAP[0].CacheTTL = -1 * time.Second
			},
			wantErr: "cache_ttl must not be negative",
		},
		{
			name: "timeout too long",
			mutate: func(c *Config) {
				c.LDAP[0].Timeout = 60 * time.Second
			},
			wantErr: "timeout",
		},
		{
			name: "group has both members and ldap_groups",
			mutate: func(c *Config) {
				g := c.Groups["ssh-admins"]
				g.Members = []string{"bob@REALM.EXAMPLE.COM"}
				c.Groups["ssh-admins"] = g
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "group references ldap_groups but no backends",
			mutate: func(c *Config) {
				c.LDAP = nil
			},
			wantErr: "no ldap: backends are configured",
		},
		{
			name: "group has neither members nor ldap_groups",
			mutate: func(c *Config) {
				g := c.Groups["ssh-admins"]
				g.LDAPGroups = nil
				c.Groups["ssh-admins"] = g
			},
			wantErr: "no members and no ldap_groups",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLDAPConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("expected no error, got: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("expected error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestWarnings_LDAP(t *testing.T) {
	t.Parallel()
	mkWarn := func(kind, backend, key, detail string) Warning {
		return Warning{Kind: kind, Backend: backend, Key: key, Detail: detail}
	}
	tests := []struct {
		name   string
		mutate func(c *Config)
		want   []Warning
	}{
		{
			name:   "no warnings on baseline",
			mutate: func(c *Config) {},
			want:   nil,
		},
		{
			name: "insecure_skip_verify true",
			mutate: func(c *Config) {
				c.LDAP[0].TLS.InsecureSkipVerify = true
			},
			want: []Warning{
				mkWarn(WarnLDAPInsecureSkipVerify, "corp", "",
					"tls.insecure_skip_verify=true disables server certificate validation"),
			},
		},
		{
			name: "plaintext ldap on non-loopback",
			mutate: func(c *Config) {
				c.LDAP[0].URL = "ldap://ad.corp.example:389"
			},
			want: []Warning{
				mkWarn(WarnLDAPPlaintextURL, "corp", "",
					"url uses plaintext ldap:// against a non-loopback host; prefer ldaps://"),
			},
		},
		{
			name: "plaintext ldap on loopback is silent",
			mutate: func(c *Config) {
				c.LDAP[0].URL = "ldap://127.0.0.1:3893"
			},
			want: nil,
		},
		{
			name: "anonymous bind non-loopback",
			mutate: func(c *Config) {
				c.LDAP[0].Bind = LDAPBind{Method: LDAPBindAnonymous}
			},
			want: []Warning{
				mkWarn(WarnLDAPAnonymousNonLoopback, "corp", "",
					"anonymous bind is used against a non-loopback host; consider simple or gssapi bind"),
			},
		},
		{
			name: "anonymous bind on loopback is silent",
			mutate: func(c *Config) {
				c.LDAP[0].URL = "ldap://localhost:3893"
				c.LDAP[0].Bind = LDAPBind{Method: LDAPBindAnonymous}
			},
			want: nil,
		},
		{
			name: "long cache_ttl",
			mutate: func(c *Config) {
				c.LDAP[0].CacheTTL = 8 * time.Minute
			},
			want: []Warning{
				mkWarn(WarnLDAPCacheTTLLong, "corp", "",
					"cache_ttl=8m0s exceeds 5m; LDAP-removed users remain authorized until expiry"),
			},
		},
		{
			name: "lowercase realm",
			mutate: func(c *Config) {
				c.LDAP[0].Realms = []string{"realm.example.com"}
			},
			want: []Warning{
				mkWarn(WarnLDAPRealmLowercase, "corp", "realm.example.com",
					"Kerberos realms are conventionally uppercase; matching is case-sensitive"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLDAPConfig()
			tt.mutate(&cfg)
			cfg.applyDefaults()
			got := cfg.Warnings()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Warnings() =\n  %+v\nwant:\n  %+v", got, tt.want)
			}
		})
	}
}

func TestApplyDefaults_LDAP(t *testing.T) {
	t.Parallel()
	cfg := validLDAPConfig()
	cfg.applyDefaults()
	if cfg.LDAP[0].Timeout != 5*time.Second {
		t.Errorf("timeout default = %v, want 5s", cfg.LDAP[0].Timeout)
	}
	if cfg.LDAP[0].CacheTTL != 60*time.Second {
		t.Errorf("cache_ttl default = %v, want 60s", cfg.LDAP[0].CacheTTL)
	}
	if cfg.LDAP[0].GroupMembershipAttr != "memberOf" {
		t.Errorf("group_membership_attr default = %q, want memberOf", cfg.LDAP[0].GroupMembershipAttr)
	}
}

func TestApplyDefaults_LDAPKrb5ConfOnlyForGSSAPI(t *testing.T) {
	t.Parallel()
	cfg := validLDAPConfig()
	cfg.applyDefaults()
	if cfg.LDAP[0].Bind.Krb5ConfPath != "" {
		t.Errorf("krb5_conf_path should stay empty for simple bind, got %q", cfg.LDAP[0].Bind.Krb5ConfPath)
	}
	cfg.LDAP[0].Bind = LDAPBind{Method: LDAPBindGSSAPI, ClientPrincipal: "svc@REALM"}
	cfg.applyDefaults()
	if cfg.LDAP[0].Bind.Krb5ConfPath != "/etc/krb5.conf" {
		t.Errorf("krb5_conf_path default for gssapi = %q, want /etc/krb5.conf", cfg.LDAP[0].Bind.Krb5ConfPath)
	}
}

func TestEnclaveMetricsInterval_Defaults(t *testing.T) {
	// Cannot t.Parallel here: we mutate a process-global env var.
	t.Setenv("ENCLAVE_METRICS_INTERVAL", "")

	c := &Config{}
	c.applyDefaults()
	if c.EnclaveMetricsInterval != 15*time.Second {
		t.Errorf("default = %v, want 15s", c.EnclaveMetricsInterval)
	}
}

func TestEnclaveMetricsInterval_EnvOverride(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		yaml     time.Duration
		want     time.Duration
	}{
		{name: "env wins over yaml", envValue: "30s", yaml: 10 * time.Second, want: 30 * time.Second},
		{name: "yaml used when env empty", envValue: "", yaml: 10 * time.Second, want: 10 * time.Second},
		{name: "default when both empty", envValue: "", yaml: 0, want: 15 * time.Second},
		{name: "invalid env falls back to yaml", envValue: "not-a-duration", yaml: 10 * time.Second, want: 10 * time.Second},
		{name: "negative env falls back to default", envValue: "-5s", yaml: 0, want: 15 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENCLAVE_METRICS_INTERVAL", tt.envValue)
			c := &Config{EnclaveMetricsInterval: tt.yaml}
			c.applyDefaults()
			if c.EnclaveMetricsInterval != tt.want {
				t.Errorf("got %v, want %v", c.EnclaveMetricsInterval, tt.want)
			}
		})
	}
}

func TestEnclaveMetricsInterval_Validate(t *testing.T) {
	t.Parallel()
	base := func(d time.Duration) Config {
		return Config{
			KeytabPath:             "/tmp/k",
			EnclaveMetricsInterval: d,
			Groups: map[string]Group{
				"g": {
					Members: []string{"u@example.com"},
					CertificateRules: CertificateRules{
						Validity:          "1h",
						AllowedPrincipals: []string{"u"},
					},
				},
			},
		}
	}
	tests := []struct {
		name      string
		interval  time.Duration
		wantError bool
		errSubstr string
	}{
		{name: "zero is OK (defaults will fill)", interval: 0, wantError: false},
		{name: "5 seconds is OK", interval: 5 * time.Second, wantError: false},
		{name: "1 hour is OK", interval: time.Hour, wantError: false},
		{name: "negative rejected", interval: -1 * time.Second, wantError: true, errSubstr: "must not be negative"},
		{name: "sub-second rejected", interval: 100 * time.Millisecond, wantError: true, errSubstr: "minimum is 1s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := base(tt.interval)
			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantError && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("error %v does not contain %q", err, tt.errSubstr)
			}
		})
	}
}

func TestValidateListen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		addr      string
		wantError bool
		errSubstr string
	}{
		{name: "empty allowed (defaults handle it)", addr: "", wantError: false},
		{name: "all-interfaces shorthand", addr: ":8443", wantError: false},
		{name: "explicit ipv4 host:port", addr: "0.0.0.0:8443", wantError: false},
		{name: "loopback host:port", addr: "127.0.0.1:8443", wantError: false},
		{name: "ipv6 bracketed", addr: "[::1]:8443", wantError: false},
		{name: "host without port", addr: "0.0.0.0", wantError: true, errSubstr: "missing port"},
		{name: "host without port (loopback)", addr: "127.0.0.1", wantError: true, errSubstr: "missing port"},
		{name: "non-numeric port", addr: "0.0.0.0:https", wantError: true, errSubstr: "non-numeric port"},
		{name: "port zero", addr: ":0", wantError: true, errSubstr: "pick a fixed port"},
		{name: "port too high", addr: ":70000", wantError: true, errSubstr: "out of range"},
		{name: "port negative", addr: ":-1", wantError: true, errSubstr: "out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateListen(tt.addr)
			if tt.wantError && err == nil {
				t.Fatalf("expected error for %q, got nil", tt.addr)
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.addr, err)
			}
			if tt.wantError && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("expected error containing %q, got: %v", tt.errSubstr, err)
			}
		})
	}
}
