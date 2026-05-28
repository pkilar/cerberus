// Package config loads and validates the YAML configuration at startup.
// A running service never reloads config; the struct is effectively
// immutable after LoadConfig returns.
package config

import (
	"cmp"
	"fmt"
	"net"
	"net/url"
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
	LDAP                   []LDAPBackend    `yaml:"ldap"`
}

// Group defines a set of members and the certificate rules that apply to them.
// Members and LDAPGroups are mutually exclusive: a group is either statically
// enumerated (members) or LDAP-backed (ldap_groups), never both. Enforced by
// Validate so operators wanting hybrid behavior must split into two groups.
type Group struct {
	Members          []string         `yaml:"members"`
	LDAPGroups       []string         `yaml:"ldap_groups"`
	CertificateRules CertificateRules `yaml:"certificate_rules"`
}

// LDAP bind methods. simple uses dn+password_file; gssapi reuses the API's
// keytab via gokrb5; anonymous binds with no credentials.
const (
	LDAPBindSimple    = "simple"
	LDAPBindGSSAPI    = "gssapi"
	LDAPBindAnonymous = "anonymous"
)

// LDAPBackend describes one directory service the authorizer can consult.
// Each backend declares the Kerberos realms it serves; a user authenticating
// from REALM-A is routed to whichever backend's realms include REALM-A. A
// realm may appear in at most one backend (overlap is a config error).
type LDAPBackend struct {
	Name                string        `yaml:"name"`
	Realms              []string      `yaml:"realms"`
	URL                 string        `yaml:"url"`
	Bind                LDAPBind      `yaml:"bind"`
	UserBaseDN          string        `yaml:"user_base_dn"`
	UserFilter          string        `yaml:"user_filter"`
	GroupMembershipAttr string        `yaml:"group_membership_attr"`
	TLS                 LDAPTLS       `yaml:"tls"`
	Timeout             time.Duration `yaml:"timeout"`
	CacheTTL            time.Duration `yaml:"cache_ttl"`
}

// LDAPBind describes how the API authenticates to the directory. For
// method=simple the DN and password_file are required; for gssapi the keytab
// already configured on the API is reused and ClientPrincipal selects the
// initiator identity within it; for anonymous no credentials are sent.
type LDAPBind struct {
	Method          string `yaml:"method"`
	DN              string `yaml:"dn"`
	PasswordFile    string `yaml:"password_file"`
	ClientPrincipal string `yaml:"client_principal"`
	Krb5ConfPath    string `yaml:"krb5_conf_path"`
}

// LDAPTLS configures TLS for ldaps:// dials. InsecureSkipVerify is honored
// but emits a startup warning; production deployments should always pin a CA.
type LDAPTLS struct {
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// ldapCacheTTLMax caps the cache TTL hard, bounding the worst-case window
// during which an LDAP-removed user could still be authorized. Operators who
// want a longer window can re-issue certs less frequently instead.
const ldapCacheTTLMax = 10 * time.Minute

// ldapTimeoutMax bounds the per-query timeout. A pathological value here can
// stall the entire /sign hot path through the enclave's 32-concurrent cap.
const ldapTimeoutMax = 30 * time.Second

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
	for i := range c.LDAP {
		b := &c.LDAP[i]
		if b.Timeout == 0 {
			b.Timeout = 5 * time.Second
		}
		if b.CacheTTL == 0 {
			b.CacheTTL = 60 * time.Second
		}
		if b.GroupMembershipAttr == "" {
			b.GroupMembershipAttr = "memberOf"
		}
		if b.Bind.Krb5ConfPath == "" && b.Bind.Method == LDAPBindGSSAPI {
			b.Bind.Krb5ConfPath = "/etc/krb5.conf"
		}
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

	// LDAP blocks are validated before groups so we can reject groups that
	// reference ldap_groups without any backend, and detect overlapping
	// realm coverage early.
	if err := c.validateLDAP(); err != nil {
		return err
	}

	for name, group := range c.Groups {
		hasStatic := len(group.Members) > 0
		hasLDAP := len(group.LDAPGroups) > 0
		if hasStatic && hasLDAP {
			return fmt.Errorf("group '%s': members and ldap_groups are mutually exclusive — split into two groups", name)
		}
		if !hasStatic && !hasLDAP {
			return fmt.Errorf("group '%s' has no members and no ldap_groups", name)
		}
		if hasLDAP && len(c.LDAP) == 0 {
			return fmt.Errorf("group '%s' references ldap_groups but no ldap: backends are configured", name)
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

// validateLDAP checks each LDAP backend in isolation, then rejects realm
// overlap between backends. Per-backend rules are intentionally strict: a
// misconfigured directory service is operator error, not runtime degradation.
// Group-level coordination (members vs ldap_groups exclusivity, references to
// missing backends) is enforced separately in the Validate group loop.
func (c *Config) validateLDAP() error {
	realmToBackend := map[string]string{}
	names := map[string]struct{}{}
	for i := range c.LDAP {
		b := &c.LDAP[i]
		if b.Name == "" {
			return fmt.Errorf("ldap[%d]: name is required", i)
		}
		if _, dup := names[b.Name]; dup {
			return fmt.Errorf("ldap[%d]: duplicate backend name %q", i, b.Name)
		}
		names[b.Name] = struct{}{}

		if len(b.Realms) == 0 {
			return fmt.Errorf("ldap[%s]: realms must be non-empty", b.Name)
		}
		for _, r := range b.Realms {
			if existing, dup := realmToBackend[r]; dup {
				return fmt.Errorf("ldap realm %q is claimed by both backends %q and %q", r, existing, b.Name)
			}
			realmToBackend[r] = b.Name
		}

		if b.URL == "" {
			return fmt.Errorf("ldap[%s]: url is required", b.Name)
		}
		if _, err := url.Parse(b.URL); err != nil {
			return fmt.Errorf("ldap[%s]: invalid url %q: %w", b.Name, b.URL, err)
		}
		if b.UserBaseDN == "" {
			return fmt.Errorf("ldap[%s]: user_base_dn is required", b.Name)
		}
		if strings.Count(b.UserFilter, "%s") != 1 {
			return fmt.Errorf("ldap[%s]: user_filter must contain exactly one %%s placeholder, got %q", b.Name, b.UserFilter)
		}

		switch b.Bind.Method {
		case LDAPBindSimple:
			if b.Bind.DN == "" {
				return fmt.Errorf("ldap[%s]: simple bind requires dn", b.Name)
			}
			if b.Bind.PasswordFile == "" {
				return fmt.Errorf("ldap[%s]: simple bind requires password_file", b.Name)
			}
		case LDAPBindGSSAPI:
			if b.Bind.ClientPrincipal == "" {
				return fmt.Errorf("ldap[%s]: gssapi bind requires client_principal (username@REALM in the API's keytab)", b.Name)
			}
			if !strings.Contains(b.Bind.ClientPrincipal, "@") {
				return fmt.Errorf("ldap[%s]: gssapi client_principal %q must be in user@REALM form", b.Name, b.Bind.ClientPrincipal)
			}
		case LDAPBindAnonymous:
			// no extra fields
		default:
			return fmt.Errorf("ldap[%s]: unknown bind method %q (must be simple, gssapi, or anonymous)", b.Name, b.Bind.Method)
		}

		if b.CacheTTL < 0 {
			return fmt.Errorf("ldap[%s]: cache_ttl must not be negative, got %v", b.Name, b.CacheTTL)
		}
		if b.CacheTTL > ldapCacheTTLMax {
			return fmt.Errorf("ldap[%s]: cache_ttl %v exceeds maximum %v", b.Name, b.CacheTTL, ldapCacheTTLMax)
		}
		if b.Timeout < 0 {
			return fmt.Errorf("ldap[%s]: timeout must not be negative, got %v", b.Name, b.Timeout)
		}
		if b.Timeout > ldapTimeoutMax {
			return fmt.Errorf("ldap[%s]: timeout %v exceeds maximum %v", b.Name, b.Timeout, ldapTimeoutMax)
		}
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

// Warning kinds. The string value is used directly as the slog event name at
// startup so log aggregators can key on it; the prefix follows the
// <area>.<event>[.<sub>] convention shared with the rest of the service.
const (
	WarnStaticAttributeNotNamespaced = "config.static_attribute.not_namespaced"
	WarnLDAPInsecureSkipVerify       = "config.ldap.insecure_skip_verify"
	WarnLDAPPlaintextURL             = "config.ldap.plaintext_url"
	WarnLDAPAnonymousNonLoopback     = "config.ldap.anonymous_non_loopback"
	WarnLDAPCacheTTLLong             = "config.ldap.cache_ttl_long"
	WarnLDAPRealmLowercase           = "config.ldap.realm_lowercase"
)

// Warning is one non-fatal configuration issue surfaced at startup. Kind is
// stable across releases (log-aggregator queries depend on it); Backend,
// Group, and Key are populated only when relevant to the warning kind, and
// Detail carries a human-readable explanation for direct operator viewing.
type Warning struct {
	Kind    string
	Backend string
	Group   string
	Key     string
	Detail  string
}

// Warnings returns non-fatal configuration issues discovered after Validate
// has passed:
//   - static_attributes keys that lack the `name@domain` namespace
//     (unnamespaced names collide if OpenSSH later standardises an extension
//     with the same bare name);
//   - LDAP backends that disable certificate verification, use plaintext
//     ldap:// against a non-loopback host, allow anonymous bind against a
//     non-loopback host, set cache_ttl greater than 5 minutes, or list realms
//     in lower case.
//
// All issues are reported as warnings rather than hard errors so operators
// can migrate existing deployments gradually. Results are sorted by
// (Kind, Backend, Group, Key) for stable output.
func (c *Config) Warnings() []Warning {
	var warns []Warning
	for name, group := range c.Groups {
		for k := range group.CertificateRules.StaticAttributes {
			if !strings.Contains(k, "@") {
				warns = append(warns, Warning{
					Kind:   WarnStaticAttributeNotNamespaced,
					Group:  name,
					Key:    k,
					Detail: "rename to " + k + "@<domain> per PROTOCOL.certkeys §4",
				})
			}
		}
	}
	for i := range c.LDAP {
		b := &c.LDAP[i]
		if b.TLS.InsecureSkipVerify {
			warns = append(warns, Warning{
				Kind:    WarnLDAPInsecureSkipVerify,
				Backend: b.Name,
				Detail:  "tls.insecure_skip_verify=true disables server certificate validation",
			})
		}
		if isPlaintextLDAPNonLoopback(b.URL) {
			warns = append(warns, Warning{
				Kind:    WarnLDAPPlaintextURL,
				Backend: b.Name,
				Detail:  "url uses plaintext ldap:// against a non-loopback host; prefer ldaps://",
			})
		}
		if b.Bind.Method == LDAPBindAnonymous && !isLoopbackURL(b.URL) {
			warns = append(warns, Warning{
				Kind:    WarnLDAPAnonymousNonLoopback,
				Backend: b.Name,
				Detail:  "anonymous bind is used against a non-loopback host; consider simple or gssapi bind",
			})
		}
		if b.CacheTTL > 5*time.Minute {
			warns = append(warns, Warning{
				Kind:    WarnLDAPCacheTTLLong,
				Backend: b.Name,
				Detail:  fmt.Sprintf("cache_ttl=%v exceeds 5m; LDAP-removed users remain authorized until expiry", b.CacheTTL),
			})
		}
		for _, r := range b.Realms {
			if r != strings.ToUpper(r) {
				warns = append(warns, Warning{
					Kind:    WarnLDAPRealmLowercase,
					Backend: b.Name,
					Key:     r,
					Detail:  "Kerberos realms are conventionally uppercase; matching is case-sensitive",
				})
			}
		}
	}
	slices.SortFunc(warns, func(a, b Warning) int {
		if g := cmp.Compare(a.Kind, b.Kind); g != 0 {
			return g
		}
		if g := cmp.Compare(a.Backend, b.Backend); g != 0 {
			return g
		}
		if g := cmp.Compare(a.Group, b.Group); g != 0 {
			return g
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return warns
}

// isPlaintextLDAPNonLoopback returns true if rawURL is a parseable ldap://
// (not ldaps://) URL whose host is not 127.0.0.0/8, ::1, or "localhost".
// Returns false for any other input (malformed URLs fail earlier in
// validateLDAP, so we don't double-warn here).
func isPlaintextLDAPNonLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "ldap" {
		return false
	}
	return !isLoopbackHost(u.Hostname())
}

// isLoopbackURL returns true when the URL's host resolves to a loopback
// literal. Used to suppress anonymous-bind warnings for local-only
// development directories.
func isLoopbackURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

func isLoopbackHost(host string) bool {
	switch host {
	case "", "localhost":
		return host == "localhost"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
