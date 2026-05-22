// Package config loads and validates the YAML configuration at startup.
// A running service never reloads config; the struct is effectively
// immutable after LoadConfig returns.
package config

import (
	"cmp"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkilar/cerberus/messages"

	"gopkg.in/yaml.v3"
)

// Config is the top-level structure for the entire config.yaml file.
type Config struct {
	Groups                 map[string]Group `yaml:"groups"`
	KeytabPath             string           `yaml:"keytab_path"`
	ServicePrincipal       string           `yaml:"service_principal"`
	Listen                 string           `yaml:"listen"`
	TlsCert                string           `yaml:"tls_cert"`
	TlsKey                 string           `yaml:"tls_key"`
	EnclaveMetricsInterval time.Duration    `yaml:"enclave_metrics_interval"`
}

// Group defines a set of members and the certificate rules that apply to them.
type Group struct {
	Members          []string         `yaml:"members"`
	CertificateRules CertificateRules `yaml:"certificate_rules"`
}

// CertificateRules specifies the parameters for a signed SSH certificate.
type CertificateRules struct {
	Validity          string            `yaml:"validity"`
	AllowedPrincipals []string          `yaml:"allowed_principals"`
	Permissions       map[string]string `yaml:"permissions"`
	StaticAttributes  map[string]string `yaml:"static_attributes"`
	CriticalOptions   map[string]string `yaml:"critical_options"`
}

// flagOnlyExtensions are SSH cert extensions and critical options whose
// presence enables the feature and whose data field must be a zero-length
// string per OpenSSH's PROTOCOL.certkeys. Any non-empty value gets serialized
// as "extra data" by the SSH wire format, and sshd rejects the certificate at
// connect time with errors like:
//
//	error: Certificate option "permit-pty" corrupt (extra data)
//	error: Invalid certificate options
//
// Catching this at config load turns a silent per-connection failure (hours
// or days after a deploy, often only visible to the user trying to ssh in)
// into a loud startup failure with a pointer to the offending group and key.
var flagOnlyExtensions = map[string]struct{}{
	"permit-X11-forwarding":   {},
	"permit-agent-forwarding": {},
	"permit-port-forwarding":  {},
	"permit-pty":              {},
	"permit-user-rc":          {},
	"no-touch-required":       {},
	"verify-required":         {},
}

// LoadConfig reads the YAML file from the given path and unmarshals it.
func LoadConfig(path string) (*Config, error) {
	// #nosec G304 -- path comes from the CONFIG_PATH env var set by the
	// operator (or a packaged systemd unit), not from untrusted input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Fill in defaults before validating; Validate is read-only so callers
	// who construct a Config directly (tests) can rely on it not mutating.
	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// applyDefaults sets fields that have a sensible fallback when omitted from
// the YAML. Defaults are operational (Listen address, TLS file paths); fields
// that must be supplied (keytab path, groups) are not defaulted.
func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TlsCert == "" {
		c.TlsCert = "cert.pem"
	}
	if c.TlsKey == "" {
		c.TlsKey = "key.pem"
	}
	// Env override takes precedence over YAML so operators can re-tune the
	// poller without redeploying config. Invalid values silently fall back to
	// the YAML/zero value, matching the rate-limit override pattern in
	// ratelimit.go.
	if v := os.Getenv("ENCLAVE_METRICS_INTERVAL"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			c.EnclaveMetricsInterval = parsed
		}
	}
	if c.EnclaveMetricsInterval == 0 {
		c.EnclaveMetricsInterval = 15 * time.Second
	}
}

// Validate checks the configuration for logical errors. It does not mutate
// the receiver — call applyDefaults first if you want defaults filled in.
func (c *Config) Validate() error {
	if len(c.Groups) == 0 {
		return fmt.Errorf("no groups defined in the configuration")
	}

	if c.KeytabPath == "" {
		return fmt.Errorf("keytab_path must be specified in the configuration")
	}

	// EnclaveMetricsInterval == 0 is allowed here: applyDefaults fills it
	// before LoadConfig reaches Validate, and tests that bypass applyDefaults
	// have skipped this field deliberately. Reject only absurd values that
	// would produce VSOCK pressure or never-firing tickers.
	if c.EnclaveMetricsInterval < 0 {
		return fmt.Errorf("enclave_metrics_interval must not be negative, got %v", c.EnclaveMetricsInterval)
	}
	if c.EnclaveMetricsInterval > 0 && c.EnclaveMetricsInterval < time.Second {
		return fmt.Errorf("enclave_metrics_interval %v is too short; minimum is 1s", c.EnclaveMetricsInterval)
	}

	if err := validateListen(c.Listen); err != nil {
		return err
	}

	for name, group := range c.Groups {
		if len(group.Members) == 0 {
			return fmt.Errorf("group '%s' has no members", name)
		}

		rules := group.CertificateRules
		if rules.Validity == "" {
			return fmt.Errorf("group '%s' has no validity period defined", name)
		}

		// Try parsing the duration to catch errors early.
		d, err := time.ParseDuration(rules.Validity)
		if err != nil {
			return fmt.Errorf("invalid validity duration for group '%s': %w", name, err)
		}
		// Reject zero/negative validity: a 0s value would produce a cert
		// "valid" only inside the signer's 300s clock-skew window; a negative
		// value would produce ValidBefore < ValidAfter which sshd refuses.
		// Catch the operator typo here rather than at the user's terminal.
		if d <= 0 {
			return fmt.Errorf("group '%s' validity %v must be positive", name, d)
		}
		// The enclave enforces the same cap; catching it here turns a silent
		// per-request rejection at runtime into a loud startup failure.
		if d > messages.MaxValidity {
			return fmt.Errorf("group '%s' validity %v exceeds maximum allowed %v", name, d, messages.MaxValidity)
		}

		if len(rules.AllowedPrincipals) == 0 {
			return fmt.Errorf("group '%s' has no allowed_principals", name)
		}

		if err := validateFlagExtensions(name, "permissions", rules.Permissions); err != nil {
			return err
		}
		if err := validateFlagExtensions(name, "critical_options", rules.CriticalOptions); err != nil {
			return err
		}
	}
	return nil
}

// validateListen rejects malformed listen addresses at config-load time so
// they don't surface as opaque bind errors several seconds into startup.
// Accepts ":port" (all interfaces), "host:port", and "[ipv6]:port"; rejects
// host-only forms like "0.0.0.0" that net.Listen would refuse with "missing
// port in address". An empty string is accepted because applyDefaults fills
// it in before LoadConfig calls Validate; tests that construct Config
// directly inherit the same lenience.
func validateListen(addr string) error {
	if addr == "" {
		return nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen %q is not a valid host:port: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("listen %q is missing a port", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("listen %q has non-numeric port %q", addr, port)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("listen %q port %d out of range 1..65535", addr, p)
	}
	return nil
}

// validateFlagExtensions rejects non-empty values on extensions/options that
// the SSH cert format requires to be empty. Unknown keys pass through — the
// signer treats them as opaque, which lets operators add OpenSSH extensions
// (e.g. force-command, source-address) without this code knowing about them.
func validateFlagExtensions(group, field string, m map[string]string) error {
	for k, v := range m {
		if _, isFlag := flagOnlyExtensions[k]; isFlag && v != "" {
			return fmt.Errorf("group %q: %s key %q must have empty value (got %q): "+
				"flag-style SSH cert extensions carry no data and sshd rejects non-empty payloads as corrupt",
				group, field, k, v)
		}
	}
	return nil
}

// StaticAttributeWarning identifies one static_attributes key that does not
// follow the `name@domain` namespacing convention from PROTOCOL.certkeys §4.
type StaticAttributeWarning struct {
	Group string
	Key   string
}

// Warnings returns non-fatal configuration issues discovered after Validate
// has passed. Currently it surfaces static_attributes keys that lack the
// `name@domain` namespace — unnamespaced names collide if OpenSSH later
// standardises an extension with the same bare name. Reported as a warning
// rather than a hard error so operators can migrate existing deployments
// gradually. Results are sorted by (group, key) for stable output.
func (c *Config) Warnings() []StaticAttributeWarning {
	var warns []StaticAttributeWarning
	for name, group := range c.Groups {
		for k := range group.CertificateRules.StaticAttributes {
			if !strings.Contains(k, "@") {
				warns = append(warns, StaticAttributeWarning{Group: name, Key: k})
			}
		}
	}
	slices.SortFunc(warns, func(a, b StaticAttributeWarning) int {
		if g := cmp.Compare(a.Group, b.Group); g != 0 {
			return g
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return warns
}
