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

	// StripRealms lists Kerberos realms whose @REALM suffix is removed from an
	// authenticated principal before it is matched against static `members:`.
	// This lets operators enumerate members by bare short name (alice) instead
	// of alice@EXAMPLE.COM for the listed realms. Only principals whose realm
	// appears here are stripped; identities in unlisted realms keep their full
	// user@REALM form, so two realms never collapse onto the same members key
	// unless the operator explicitly lists both. Matching is case-sensitive
	// (Kerberos realms are conventionally uppercase). Empty disables stripping
	// entirely, preserving exact user@REALM matching. Realm routing for
	// LDAP-backed groups is unaffected — the resolver always sees the full
	// user@REALM string.
	StripRealms []string `yaml:"strip_realms"`

	// SelfPrincipal enables self-service certificates for a user's own identity
	// (the short uid of the authenticated Kerberos principal). Disabled unless
	// Enabled is true. See SelfPrincipalConfig.
	SelfPrincipal SelfPrincipalConfig `yaml:"self_principal"`

	// OAuth enables OIDC bearer-token authentication as a second method
	// alongside Kerberos/SPNEGO. Disabled unless Enabled is true; when disabled
	// the service behaves exactly as it did before OIDC support existed. See
	// OAuthConfig.
	OAuth OAuthConfig `yaml:"oauth"`
}

// SelfPrincipalConfig controls the self-service issuance path: an authenticated
// user may obtain a certificate for their own short uid (jsmith@FOO.COM ->
// "jsmith") without being enumerated in any group. It is opt-in and constrained
// so it stays safe:
//   - Realms is an allowlist: only callers whose Kerberos realm is listed may
//     self-issue. This blocks the cross-realm collision where jsmith@FOO.COM and
//     jsmith@BAR.COM would both collapse onto local account "jsmith".
//   - Deny lists short uids that may never be self-issued. The effective set
//     always includes "root" (a hard floor the authorizer adds), so root can
//     never be obtained via this path regardless of config.
//   - CertificateRules supplies the validity/permissions/extensions for the
//     issued cert; its AllowedPrincipals is ignored (the principal is the uid).
//
// The issued cert only opens accounts sshd authorizes for that principal
// (default: the account named after the uid, or an AuthorizedPrincipalsFile
// mapping), so the server remains the final gate.
type SelfPrincipalConfig struct {
	Enabled          bool             `yaml:"enabled"`
	Realms           []string         `yaml:"realms"`
	Deny             []string         `yaml:"deny"`
	CertificateRules CertificateRules `yaml:"certificate_rules"`
}

// OAuthConfig enables OIDC bearer-token authentication as a second method
// alongside Kerberos/SPNEGO. It is opt-in (Enabled) and, when off, the service
// behaves exactly as it did before OIDC support existed. When on, a request may
// present `Authorization: Bearer <JWT>`; the token is validated offline against
// the issuer's JWKS (signature, iss, aud, exp/nbf/iat with Leeway) and mapped to
// an identity and a set of groups:
//   - UsernameClaim selects the claim used as the short uid; together with Realm
//     it forms the Username@Realm identity used for the cert KeyID, audit logs,
//     and per-principal rate limiting — exactly parallel to a Kerberos principal.
//   - GroupsClaim selects the claim (a JSON array of strings) whose values are
//     matched against per-group `oidc_groups:` bindings for authorization —
//     parallel to LDAP `ldap_groups:`. The groups claim never influences the
//     cert identity.
//   - Realm is a synthetic label (e.g. "OIDC"); it must not collide with a
//     Kerberos/LDAP realm or a strip_realms entry, or OIDC identities would be
//     misrouted to LDAP or have their realm stripped (surfaced as a warning).
//   - Algorithms restricts the accepted JWS signing algorithms to an asymmetric
//     allowlist; `none` and any HMAC (HS*) algorithm are rejected at config load
//     and again at verification time, defeating algorithm-confusion attacks.
type OAuthConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Issuer        string        `yaml:"issuer"`
	Audiences     []string      `yaml:"audiences"`
	UsernameClaim string        `yaml:"username_claim"`
	GroupsClaim   string        `yaml:"groups_claim"`
	Realm         string        `yaml:"realm"`
	Algorithms    []string      `yaml:"algorithms"`
	Leeway        time.Duration `yaml:"leeway"`
	HTTPTimeout   time.Duration `yaml:"http_timeout"`
}

// Group defines a set of members and the certificate rules that apply to them.
// Membership has exactly one source: static `members:`, LDAP `ldap_groups:`, or
// OIDC `oidc_groups:` — never more than one. Enforced by Validate, so operators
// wanting hybrid behavior must split into separate groups (the
// first-alphabetical rule still applies across them).
type Group struct {
	Members          []string         `yaml:"members"`
	LDAPGroups       []string         `yaml:"ldap_groups"`
	OIDCGroups       []string         `yaml:"oidc_groups"`
	CertificateRules CertificateRules `yaml:"certificate_rules"`
}

// LDAP bind methods. simple uses dn+password_file; gssapi reuses the API's
// keytab via gokrb5; anonymous binds with no credentials.
const (
	LDAPBindSimple    = "simple"
	LDAPBindGSSAPI    = "gssapi"
	LDAPBindAnonymous = "anonymous"
)

// LDAP TLS modes for the SRV discovery path. The url path selects TLS from the
// url scheme instead (ldaps:// vs ldap://).
const (
	LDAPTLSModeLDAPS    = "ldaps"
	LDAPTLSModeStartTLS = "starttls"
	LDAPTLSModeNone     = "none"
)

// LDAPBackend describes one directory service the authorizer can consult.
// Each backend declares the Kerberos realms it serves; a user authenticating
// from REALM-A is routed to whichever backend's realms include REALM-A. A
// realm may appear in at most one backend (overlap is a config error).
type LDAPBackend struct {
	Name                string        `yaml:"name"`
	Realms              []string      `yaml:"realms"`
	URL                 string        `yaml:"url"`      // one-of with SRV
	SRV                 *LDAPSRV      `yaml:"srv"`      // one-of with URL
	TLSMode             string        `yaml:"tls_mode"` // SRV path only: ldaps | starttls | none
	Bind                LDAPBind      `yaml:"bind"`
	UserBaseDN          string        `yaml:"user_base_dn"`
	UserFilter          string        `yaml:"user_filter"`
	GroupMembershipAttr string        `yaml:"group_membership_attr"`
	TLS                 LDAPTLS       `yaml:"tls"`
	Timeout             time.Duration `yaml:"timeout"`
	CacheTTL            time.Duration `yaml:"cache_ttl"`
}

// LDAPSRV configures RFC 2782 DNS SRV discovery for a backend. The queried
// record name is "_<Service>._<Proto>.<Domain>". Discovered targets carry
// their own host+port; TLSMode on the parent LDAPBackend selects encryption.
type LDAPSRV struct {
	Domain   string        `yaml:"domain"`    // required, e.g. corp.example.com or dc._msdcs.corp.example.com
	Service  string        `yaml:"service"`   // default "ldap"
	Proto    string        `yaml:"proto"`     // default "tcp"
	CacheTTL time.Duration `yaml:"cache_ttl"` // SRV-record cache; default 30s, hard cap ldapCacheTTLMax (10m)
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

// oauthLeewayMax bounds the clock-skew tolerance applied to a token's
// exp/nbf/iat. A large leeway widens the window in which an expired or
// not-yet-valid token is accepted, so cap it hard.
const oauthLeewayMax = 5 * time.Minute

// oauthHTTPTimeoutMax bounds the HTTP timeout for issuer discovery and JWKS
// fetches. Discovery is a startup call and JWKS fetches happen off the hot
// path (cached), but a pathological value should still be rejected.
const oauthHTTPTimeoutMax = 30 * time.Second

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
	if c.OAuth.Enabled {
		if c.OAuth.UsernameClaim == "" {
			c.OAuth.UsernameClaim = "sub"
		}
		if c.OAuth.GroupsClaim == "" {
			c.OAuth.GroupsClaim = "groups"
		}
		if len(c.OAuth.Algorithms) == 0 {
			c.OAuth.Algorithms = []string{"RS256"}
		}
		if c.OAuth.Leeway == 0 {
			c.OAuth.Leeway = 60 * time.Second
		}
		if c.OAuth.HTTPTimeout == 0 {
			c.OAuth.HTTPTimeout = 5 * time.Second
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

	// A blank strip_realms entry would strip the empty realm — i.e. match every
	// principal that has no realm — which is both meaningless (auth rejects
	// realm-less credentials) and a footgun. Reject it as operator error.
	for i, realm := range c.StripRealms {
		if strings.TrimSpace(realm) == "" {
			return fmt.Errorf("strip_realms[%d] must not be empty or whitespace", i)
		}
	}

	if err := c.validateSelfPrincipal(); err != nil {
		return err
	}

	if err := c.validateOAuth(); err != nil {
		return err
	}

	for name, group := range c.Groups {
		hasStatic := len(group.Members) > 0
		hasLDAP := len(group.LDAPGroups) > 0
		hasOIDC := len(group.OIDCGroups) > 0
		sources := 0
		for _, has := range []bool{hasStatic, hasLDAP, hasOIDC} {
			if has {
				sources++
			}
		}
		if sources == 0 {
			return fmt.Errorf("group '%s' has no members, ldap_groups, or oidc_groups", name)
		}
		if sources > 1 {
			return fmt.Errorf("group '%s': members, ldap_groups, and oidc_groups are mutually exclusive — split into separate groups", name)
		}
		if hasLDAP && len(c.LDAP) == 0 {
			return fmt.Errorf("group '%s' references ldap_groups but no ldap: backends are configured", name)
		}
		if hasOIDC && !c.OAuth.Enabled {
			return fmt.Errorf("group '%s' references oidc_groups but oauth is not enabled", name)
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
	// Port 0 is syntactically valid in Go ("pick an ephemeral port") but
	// disallowed in production config: operators need to know which port
	// to scrape, route to, and open in security groups. If you need
	// ephemeral ports for an integration test, construct Config{} directly
	// and skip Validate.
	if p == 0 {
		return fmt.Errorf("listen %q uses port 0; pick a fixed port so operators can locate the service", addr)
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
			if strings.TrimSpace(r) == "" {
				return fmt.Errorf("ldap[%s]: realms must not contain empty or whitespace entries", b.Name)
			}
			if existing, dup := realmToBackend[r]; dup {
				return fmt.Errorf("ldap realm %q is claimed by both backends %q and %q", r, existing, b.Name)
			}
			realmToBackend[r] = b.Name
		}

		switch {
		case b.URL != "" && b.SRV != nil:
			return fmt.Errorf("ldap[%s]: set either url or srv, not both", b.Name)
		case b.URL == "" && b.SRV == nil:
			return fmt.Errorf("ldap[%s]: one of url or srv is required", b.Name)
		case b.URL != "":
			if _, err := url.Parse(b.URL); err != nil {
				return fmt.Errorf("ldap[%s]: invalid url %q: %w", b.Name, b.URL, err)
			}
			if b.TLSMode != "" {
				return fmt.Errorf("ldap[%s]: tls_mode is only valid with srv (the url scheme already selects TLS)", b.Name)
			}
		default: // b.SRV != nil
			if err := validateLDAPSRV(b); err != nil {
				return err
			}
		}
		if b.UserBaseDN == "" {
			return fmt.Errorf("ldap[%s]: user_base_dn is required", b.Name)
		}
		// user_filter must be exactly one %s substitution. strings.Count(...,
		// "%s") == 1 is insufficient: "(uid=%%s)" contains the substring "%s"
		// but fmt reads "%%" as a literal percent and drops the substitution,
		// leaving the escaped UID unused — a silently broken filter. Model
		// fmt's parsing by trial-formatting a sentinel and rejecting any
		// template fmt cannot fill cleanly. The ldap package's SafeUserFilter
		// (ldap.ValidFilterTemplate) applies the identical check at runtime;
		// this rejects it at startup. (Kept inline rather than calling the ldap
		// helper to avoid a config<->ldap import cycle — ldap imports config.)
		const filterProbe = "cerberusFilterProbe"
		if out := fmt.Sprintf(b.UserFilter, filterProbe); !strings.Contains(out, filterProbe) || strings.Contains(out, "%!") {
			return fmt.Errorf("ldap[%s]: user_filter must contain exactly one %%s placeholder and no other format directive, got %q", b.Name, b.UserFilter)
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

// validateLDAPSRV checks an srv-discovery backend: a bare, whitespace-free
// domain (the resolver adds the _service._proto prefix), label-safe
// service/proto overrides, a bounded cache_ttl, and a required, known tls_mode.
func validateLDAPSRV(b *LDAPBackend) error {
	d := strings.TrimSpace(b.SRV.Domain)
	if d == "" {
		return fmt.Errorf("ldap[%s]: srv.domain is required", b.Name)
	}
	if d != b.SRV.Domain || strings.ContainsAny(d, " \t\r\n") {
		return fmt.Errorf("ldap[%s]: srv.domain %q must not contain whitespace", b.Name, b.SRV.Domain)
	}
	if strings.Contains(d, "://") {
		return fmt.Errorf("ldap[%s]: srv.domain %q must be a bare domain, not a URL", b.Name, b.SRV.Domain)
	}
	if strings.HasPrefix(d, "_") {
		return fmt.Errorf("ldap[%s]: srv.domain %q must not start with '_'; the _service._proto prefix is added automatically", b.Name, b.SRV.Domain)
	}
	if b.SRV.Service != "" && !isDNSLabel(b.SRV.Service) {
		return fmt.Errorf("ldap[%s]: srv.service %q must be a single DNS label", b.Name, b.SRV.Service)
	}
	if b.SRV.Proto != "" && !isDNSLabel(b.SRV.Proto) {
		return fmt.Errorf("ldap[%s]: srv.proto %q must be a single DNS label", b.Name, b.SRV.Proto)
	}
	if b.SRV.CacheTTL < 0 {
		return fmt.Errorf("ldap[%s]: srv.cache_ttl must not be negative, got %v", b.Name, b.SRV.CacheTTL)
	}
	if b.SRV.CacheTTL > ldapCacheTTLMax {
		return fmt.Errorf("ldap[%s]: srv.cache_ttl %v exceeds maximum %v", b.Name, b.SRV.CacheTTL, ldapCacheTTLMax)
	}
	switch b.TLSMode {
	case LDAPTLSModeLDAPS, LDAPTLSModeStartTLS, LDAPTLSModeNone:
		return nil
	case "":
		return fmt.Errorf("ldap[%s]: tls_mode is required with srv (one of ldaps, starttls, none)", b.Name)
	default:
		return fmt.Errorf("ldap[%s]: invalid tls_mode %q (must be ldaps, starttls, or none)", b.Name, b.TLSMode)
	}
}

// isDNSLabel reports whether s is a non-empty RFC 1035 label ([A-Za-z0-9-], not
// starting or ending with '-'). The leading underscore of an SRV service/proto
// token is added by the resolver and is therefore not part of the label.
func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
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

// validateSelfPrincipal checks the self-service issuance block. A disabled block
// is not validated (a stale/incomplete config must not break startup). When
// enabled it requires a non-empty realm allowlist and a usable validity, and
// applies the same flag-extension rules as groups. AllowedPrincipals under
// self_principal.certificate_rules is intentionally ignored (the principal is
// the caller's uid), so it is not validated here.
func (c *Config) validateSelfPrincipal() error {
	sp := &c.SelfPrincipal
	if !sp.Enabled {
		return nil
	}
	if len(sp.Realms) == 0 {
		return fmt.Errorf("self_principal is enabled but has no realms; list the Kerberos realms allowed to self-issue")
	}
	for i, r := range sp.Realms {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("self_principal.realms[%d] must not be empty or whitespace", i)
		}
	}
	for i, d := range sp.Deny {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("self_principal.deny[%d] must not be empty or whitespace", i)
		}
	}
	rules := sp.CertificateRules
	if rules.Validity == "" {
		return fmt.Errorf("self_principal.certificate_rules has no validity period defined")
	}
	d, err := time.ParseDuration(rules.Validity)
	if err != nil {
		return fmt.Errorf("invalid self_principal validity duration: %w", err)
	}
	if d <= 0 {
		return fmt.Errorf("self_principal validity %v must be positive", d)
	}
	if d > messages.MaxValidity {
		return fmt.Errorf("self_principal validity %v exceeds maximum allowed %v", d, messages.MaxValidity)
	}
	if err := validateFlagExtensions("self_principal", "permissions", rules.Permissions); err != nil {
		return err
	}
	if err := validateFlagExtensions("self_principal", "critical_options", rules.CriticalOptions); err != nil {
		return err
	}
	return nil
}

// oauthAllowedAlgorithms is the asymmetric JWS signing-algorithm allowlist for
// OIDC token validation. Restricting verification to these — and rejecting
// `none` and every HMAC HS* algorithm — is the config-load half of the
// algorithm-confusion defense: the verifier's keyset holds only the issuer's
// RSA/EC public keys, so an attacker cannot present an HS256 token signed with
// the public-key bytes as the shared secret. The verifier enforces the same
// allowlist again at request time.
var oauthAllowedAlgorithms = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
}

// validateOAuth checks the OIDC bearer-auth block. A disabled block is not
// validated (a stale/incomplete config must not break startup). When enabled it
// requires an absolute issuer URL, at least one audience, a synthetic realm
// label, and an asymmetric-only algorithm allowlist; it bounds the leeway and
// HTTP timeout. UsernameClaim/GroupsClaim are not required here because
// applyDefaults fills them ("sub"/"groups") before LoadConfig reaches Validate.
func (c *Config) validateOAuth() error {
	o := &c.OAuth
	if !o.Enabled {
		return nil
	}
	if o.Issuer == "" {
		return fmt.Errorf("oauth is enabled but has no issuer")
	}
	u, err := url.Parse(o.Issuer)
	if err != nil {
		return fmt.Errorf("oauth issuer %q is not a valid URL: %w", o.Issuer, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("oauth issuer %q must be an absolute URL (e.g. https://idp.example.com)", o.Issuer)
	}
	if len(o.Audiences) == 0 {
		return fmt.Errorf("oauth is enabled but has no audiences; list the token audience(s) that identify this service")
	}
	for i, a := range o.Audiences {
		if strings.TrimSpace(a) == "" {
			return fmt.Errorf("oauth.audiences[%d] must not be empty or whitespace", i)
		}
	}
	if strings.TrimSpace(o.Realm) == "" {
		return fmt.Errorf("oauth is enabled but has no realm; set a synthetic realm label for OIDC identities")
	}
	if strings.Contains(o.Realm, "@") {
		return fmt.Errorf("oauth.realm %q must not contain '@'", o.Realm)
	}
	if len(o.Algorithms) == 0 {
		return fmt.Errorf("oauth is enabled but has no algorithms; list the JWS signing algorithms to accept")
	}
	for _, alg := range o.Algorithms {
		if _, ok := oauthAllowedAlgorithms[alg]; !ok {
			return fmt.Errorf("oauth.algorithms entry %q is not an allowed asymmetric algorithm "+
				"(permitted: RS256/384/512, ES256/384/512, PS256/384/512; none and HS* are rejected to prevent algorithm confusion)", alg)
		}
	}
	if o.Leeway < 0 {
		return fmt.Errorf("oauth.leeway must not be negative, got %v", o.Leeway)
	}
	if o.Leeway > oauthLeewayMax {
		return fmt.Errorf("oauth.leeway %v exceeds maximum %v", o.Leeway, oauthLeewayMax)
	}
	if o.HTTPTimeout < 0 {
		return fmt.Errorf("oauth.http_timeout must not be negative, got %v", o.HTTPTimeout)
	}
	if o.HTTPTimeout > oauthHTTPTimeoutMax {
		return fmt.Errorf("oauth.http_timeout %v exceeds maximum %v", o.HTTPTimeout, oauthHTTPTimeoutMax)
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
	WarnStripRealmLowercase          = "config.strip_realm.lowercase"
	WarnSelfPrincipalRealmLowercase  = "config.self_principal.realm_lowercase"
	WarnOAuthIssuerNotHTTPS          = "config.oauth.issuer_not_https"
	WarnOAuthRealmCollision          = "config.oauth.realm_collision"
	WarnOAuthLeewayLong              = "config.oauth.leeway_long"
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
	// strip_realms matching is case-sensitive against the realm the KDC returns
	// (conventionally uppercase). A lowercase entry silently strips nothing.
	for _, r := range c.StripRealms {
		if r != strings.ToUpper(r) {
			warns = append(warns, Warning{
				Kind:   WarnStripRealmLowercase,
				Key:    r,
				Detail: "Kerberos realms are conventionally uppercase; strip_realms matching is case-sensitive",
			})
		}
	}
	// self_principal.realms matching is likewise case-sensitive; a lowercase
	// entry allowlists nothing.
	if c.SelfPrincipal.Enabled {
		for _, r := range c.SelfPrincipal.Realms {
			if r != strings.ToUpper(r) {
				warns = append(warns, Warning{
					Kind:   WarnSelfPrincipalRealmLowercase,
					Key:    r,
					Detail: "Kerberos realms are conventionally uppercase; self_principal.realms matching is case-sensitive",
				})
			}
		}
	}
	// OIDC bearer-auth warnings.
	if c.OAuth.Enabled {
		if u, err := url.Parse(c.OAuth.Issuer); err == nil && u.Scheme != "https" {
			warns = append(warns, Warning{
				Kind:   WarnOAuthIssuerNotHTTPS,
				Detail: fmt.Sprintf("oauth.issuer %q is not https://; discovery and JWKS are fetched over an unauthenticated channel", c.OAuth.Issuer),
			})
		}
		// A realm label that collides with an LDAP backend realm or a strip_realms
		// entry would misroute OIDC identities into LDAP or strip their synthetic
		// realm, breaking the identity contract described on OAuthConfig.
		collides := slices.Contains(c.StripRealms, c.OAuth.Realm)
		for i := range c.LDAP {
			if slices.Contains(c.LDAP[i].Realms, c.OAuth.Realm) {
				collides = true
				break
			}
		}
		if collides {
			warns = append(warns, Warning{
				Kind:   WarnOAuthRealmCollision,
				Key:    c.OAuth.Realm,
				Detail: "oauth.realm collides with an LDAP backend realm or a strip_realms entry; pick a label unique to OIDC",
			})
		}
		if c.OAuth.Leeway > 2*time.Minute {
			warns = append(warns, Warning{
				Kind:   WarnOAuthLeewayLong,
				Detail: fmt.Sprintf("oauth.leeway=%v exceeds 2m; widens the window in which expired or not-yet-valid tokens are accepted", c.OAuth.Leeway),
			})
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
