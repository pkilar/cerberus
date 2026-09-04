package config

import (
	"os"
	"path/filepath"
	"testing"
)

// observabilityConfig returns the smallest Config that passes Validate, with
// the plain-HTTP observability listener enabled.
func observabilityConfig() Config {
	return Config{
		KeytabPath: "/etc/keytab",
		Listen:     ":8443",
		Groups: map[string]Group{
			"ssh-admins": {
				Members: []string{"alice@EXAMPLE.COM"},
				CertificateRules: CertificateRules{
					Validity:          "8h",
					AllowedPrincipals: PlainPrincipals("root"),
				},
			},
		},
		ObservabilityHTTP: ObservabilityHTTPConfig{Enabled: true},
	}
}

func TestApplyDefaults_ObservabilityHTTP(t *testing.T) {
	t.Parallel()
	cfg := observabilityConfig()
	cfg.applyDefaults()
	if got, want := cfg.ObservabilityHTTP.Bind, "127.0.0.1"; got != want {
		t.Errorf("bind default = %q, want %q — enabling the listener must not publish metrics to the network", got, want)
	}
	if got, want := cfg.ObservabilityHTTP.Port, 9109; got != want {
		t.Errorf("port default = %d, want %d", got, want)
	}
	if got, want := cfg.ObservabilityHTTP.Addr(), "127.0.0.1:9109"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

func TestApplyDefaults_ObservabilityHTTPDisabledIsUntouched(t *testing.T) {
	t.Parallel()
	cfg := observabilityConfig()
	cfg.ObservabilityHTTP.Enabled = false
	cfg.applyDefaults()
	if cfg.ObservabilityHTTP.Bind != "" || cfg.ObservabilityHTTP.Port != 0 {
		t.Errorf("disabled block was populated: bind=%q port=%d; defaults must not imply the listener runs",
			cfg.ObservabilityHTTP.Bind, cfg.ObservabilityHTTP.Port)
	}
}

func TestApplyDefaults_ObservabilityHTTPExplicitValuesWin(t *testing.T) {
	t.Parallel()
	cfg := observabilityConfig()
	cfg.ObservabilityHTTP.Bind = "0.0.0.0"
	cfg.ObservabilityHTTP.Port = 19109
	cfg.applyDefaults()
	if got, want := cfg.ObservabilityHTTP.Addr(), "0.0.0.0:19109"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

func TestValidate_ObservabilityHTTP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:   "defaults are valid",
			mutate: func(c *Config) { c.applyDefaults() },
		},
		{
			name:   "explicit all-interfaces bind is valid",
			mutate: func(c *Config) { c.ObservabilityHTTP.Bind = "0.0.0.0"; c.ObservabilityHTTP.Port = 9109 },
		},
		{
			name:    "port above range",
			mutate:  func(c *Config) { c.ObservabilityHTTP.Port = 70000 },
			wantErr: true,
		},
		{
			name:    "port zero cannot be scraped or firewalled",
			mutate:  func(c *Config) { c.ObservabilityHTTP.Port = 0 },
			wantErr: true,
		},
		{
			name:    "hostname bind is rejected",
			mutate:  func(c *Config) { c.ObservabilityHTTP.Bind = "metrics.internal"; c.ObservabilityHTTP.Port = 9109 },
			wantErr: true,
		},
		{
			name:    "port collides with listen",
			mutate:  func(c *Config) { c.Listen = ":9109"; c.ObservabilityHTTP.Port = 9109 },
			wantErr: true,
		},
		{
			// A stale port left behind in a disabled block is inert, so it
			// must not fail startup.
			name: "disabled block is not validated",
			mutate: func(c *Config) {
				c.ObservabilityHTTP = ObservabilityHTTPConfig{Enabled: false, Port: 70000, Bind: "not-an-ip"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := observabilityConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestWarnings_ObservabilityHTTPExposed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		bind     string
		enabled  bool
		wantWarn bool
	}{
		{name: "loopback default does not warn", bind: "127.0.0.1", enabled: true},
		{name: "ipv6 loopback does not warn", bind: "::1", enabled: true},
		{name: "all interfaces warns", bind: "0.0.0.0", enabled: true, wantWarn: true},
		{name: "specific external address warns", bind: "10.0.0.7", enabled: true, wantWarn: true},
		// An empty bind renders as ":9109", which net.Listen reads as all
		// interfaces — the exposure the warning exists to flag.
		{name: "empty bind warns", bind: "", enabled: true, wantWarn: true},
		{name: "disabled never warns", bind: "0.0.0.0", enabled: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := observabilityConfig()
			cfg.ObservabilityHTTP.Enabled = tt.enabled
			cfg.ObservabilityHTTP.Bind = tt.bind
			cfg.ObservabilityHTTP.Port = 9109

			var found bool
			for _, w := range cfg.Warnings() {
				if w.Kind == WarnObservabilityHTTPExposed {
					found = true
				}
			}
			if found != tt.wantWarn {
				t.Errorf("%s warning present = %v, want %v", WarnObservabilityHTTPExposed, found, tt.wantWarn)
			}
		})
	}
}

// LoadConfig is the only path that exercises the yaml struct tags. Every other
// test here builds a Config directly, so a typo in `yaml:"observability_http"`
// (or in a member tag) would silently ignore the whole block and leave the
// listener disabled with no error anywhere.
func TestLoadConfig_ObservabilityHTTP(t *testing.T) {
	t.Parallel()
	const yamlContent = `
keytab_path: "/etc/keytab/test.keytab"
listen: ":8443"
observability_http:
  enabled: true
  bind: "0.0.0.0"
  port: 19109
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      validity: "24h"
      allowed_principals:
        - admin
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.ObservabilityHTTP.Enabled {
		t.Fatal("observability_http.enabled did not survive YAML parsing; check the struct tag")
	}
	if got, want := cfg.ObservabilityHTTP.Addr(), "0.0.0.0:19109"; got != want {
		t.Errorf("Addr() = %q, want %q; bind/port tags may be wrong", got, want)
	}
}

// The defaults must also survive a YAML round trip: a block with only
// `enabled: true` has to come back as 127.0.0.1:9109.
func TestLoadConfig_ObservabilityHTTPDefaults(t *testing.T) {
	t.Parallel()
	const yamlContent = `
keytab_path: "/etc/keytab/test.keytab"
observability_http:
  enabled: true
groups:
  admin:
    members:
      - admin@example.com
    certificate_rules:
      validity: "24h"
      allowed_principals:
        - admin
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := cfg.ObservabilityHTTP.Addr(), "127.0.0.1:9109"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

// TestLoadConfig_ShippedExample already covers that the example loads. This
// asserts the one property specific to this feature: copying the shipped
// example must never open a cleartext port by accident.
func TestLoadConfig_ShippedExampleKeepsListenerOff(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(filepath.Join("..", "..", "configs", "config-example.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ObservabilityHTTP.Enabled {
		t.Error("configs/config-example.yaml ships with observability_http enabled; it must default to off")
	}
}
