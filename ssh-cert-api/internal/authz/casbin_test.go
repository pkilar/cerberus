package authz

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

func newTestConfig(groups map[string]config.Group) *config.Config {
	return &config.Config{
		Groups:     groups,
		KeytabPath: "/etc/krb5.keytab",
	}
}

func TestAuthorize_BasicAllow(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root", "ec2-user"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed, got denied")
	}
	if result.GroupName != "engineers" {
		t.Fatalf("expected group 'engineers', got %q", result.GroupName)
	}

	// Multiple allowed principals
	result, err = a.Authorize(t.Context(), "alice@REALM.COM", []string{"root", "ec2-user"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed for multiple principals")
	}
}

func TestAuthorize_BasicDeny(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"ec2-user"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied for unlisted principal")
	}
}

func TestAuthorize_UnknownUser(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "unknown@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied for unknown user")
	}
}

func TestAuthorize_WildcardPrincipal(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"superadmins": {
			Members: []string{"admin@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "4h",
				AllowedPrincipals: []string{"*"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// Wildcard should allow any SSH principal
	for _, principal := range []string{"root", "ec2-user", "anything", "deploy"} {
		result, err := a.Authorize(t.Context(), "admin@REALM.COM", []string{principal})
		if err != nil {
			t.Fatalf("Authorize(%s): %v", principal, err)
		}
		if !result.Allowed {
			t.Fatalf("expected allowed for wildcard principal %q", principal)
		}
	}

	// A wildcard group must also cover a multi-principal request in one shot
	// (every requested principal matched by "*" within the single group).
	result, err := a.Authorize(t.Context(), "admin@REALM.COM", []string{"root", "deploy", "ec2-user"})
	if err != nil {
		t.Fatalf("Authorize multi-principal: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed for multi-principal request against wildcard group")
	}
	if result.GroupName != "superadmins" {
		t.Fatalf("expected group 'superadmins', got %q", result.GroupName)
	}
}

func TestAuthorize_MultiGroup(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root", "ec2-user"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
		"analysts": {
			Members: []string{"charlie@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"analyst"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// Alice can sign for root but not analyst
	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("alice should be allowed for root")
	}

	result, err = a.Authorize(t.Context(), "alice@REALM.COM", []string{"analyst"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("alice should be denied for analyst")
	}

	// Charlie can sign for analyst but not root
	result, err = a.Authorize(t.Context(), "charlie@REALM.COM", []string{"analyst"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("charlie should be allowed for analyst")
	}
	if result.GroupName != "analysts" {
		t.Fatalf("expected group 'analysts', got %q", result.GroupName)
	}
}

func TestAuthorize_DeterministicOrder(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"zebra-team": {
			Members: []string{"bob@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "24h",
				AllowedPrincipals: []string{"root"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
		"alpha-team": {
			Members: []string{"bob@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"root"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	// Run multiple times to verify determinism
	for i := range 10 {
		a, err := NewCasbinAuthorizer(cfg, nil)
		if err != nil {
			t.Fatalf("NewCasbinAuthorizer (iteration %d): %v", i, err)
		}

		result, err := a.Authorize(t.Context(), "bob@REALM.COM", []string{"root"})
		if err != nil {
			t.Fatalf("Authorize (iteration %d): %v", i, err)
		}
		if !result.Allowed {
			t.Fatalf("iteration %d: expected allowed", i)
		}
		// "alpha-team" sorts before "zebra-team"
		if result.GroupName != "alpha-team" {
			t.Fatalf("iteration %d: expected group 'alpha-team' (alphabetically first), got %q", i, result.GroupName)
		}
		if result.CertificateRules.Validity != "1h" {
			t.Fatalf("iteration %d: expected validity '1h', got %q", i, result.CertificateRules.Validity)
		}
	}
}

func TestAuthorize_MultiGroupDisjointPrincipals(t *testing.T) {
	// Regression test: a user in multiple groups with different principals must
	// NOT get cross-group authorization. The returned CertificateRules must
	// come from the same group that authorized the principal.
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"alpha-admins": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"root"},
				Permissions:       map[string]string{"permit-pty": ""},
				CriticalOptions:   map[string]string{"source-address": "10.0.0.0/8"},
			},
		},
		"beta-devs": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "24h",
				AllowedPrincipals: []string{"deploy"},
				Permissions: map[string]string{
					"permit-pty":              "",
					"permit-port-forwarding":  "",
					"permit-agent-forwarding": "",
				},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// alice requests "root" — should be allowed via alpha-admins with alpha-admins' rules
	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize(root): %v", err)
	}
	if !result.Allowed {
		t.Fatal("alice should be allowed for root via alpha-admins")
	}
	if result.GroupName != "alpha-admins" {
		t.Fatalf("expected group 'alpha-admins', got %q", result.GroupName)
	}
	if result.CertificateRules.Validity != "1h" {
		t.Fatalf("expected validity '1h' from alpha-admins, got %q", result.CertificateRules.Validity)
	}

	// alice requests "deploy" — should be allowed via beta-devs with beta-devs' rules
	result, err = a.Authorize(t.Context(), "alice@REALM.COM", []string{"deploy"})
	if err != nil {
		t.Fatalf("Authorize(deploy): %v", err)
	}
	if !result.Allowed {
		t.Fatal("alice should be allowed for deploy via beta-devs")
	}
	if result.GroupName != "beta-devs" {
		t.Fatalf("expected group 'beta-devs', got %q", result.GroupName)
	}
	if result.CertificateRules.Validity != "24h" {
		t.Fatalf("expected validity '24h' from beta-devs, got %q", result.CertificateRules.Validity)
	}

	// alice requests both "root" and "deploy" — no single group allows both, must be denied
	result, err = a.Authorize(t.Context(), "alice@REALM.COM", []string{"root", "deploy"})
	if err != nil {
		t.Fatalf("Authorize(root,deploy): %v", err)
	}
	if result.Allowed {
		t.Fatal("alice should be denied when requesting principals from different groups")
	}
}

func TestAuthorize_PartialDeny(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"ec2-user"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// One allowed + one disallowed = denied
	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"ec2-user", "root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied when requesting mix of allowed and disallowed principals")
	}
}

func TestAuthorize_EmptyPrincipals(t *testing.T) {
	// Defense in depth: with no principals to check, the per-principal Casbin
	// loop trivially allows. Refuse instead — the HTTP layer (api/server.go)
	// refuses too, but Authorize must hold the line for any future caller
	// that bypasses the handler.
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
				Permissions:       map[string]string{"permit-pty": ""},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("Authorize must refuse empty requested principals")
	}

	// Same for an unknown user with an empty slice — must still refuse.
	result, err = a.Authorize(t.Context(), "nobody@REALM.COM", []string{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("Authorize must refuse empty requested principals regardless of user")
	}
}

func TestAuthorize_CertificateRulesReturned(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root", "ec2-user"},
				Permissions: map[string]string{
					"permit-pty":              "",
					"permit-agent-forwarding": "",
				},
				StaticAttributes: map[string]string{
					"team@example.com":         "backend",
					"access-level@example.com": "production",
				},
				CriticalOptions: map[string]string{
					"source-address": "10.0.0.0/8",
				},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed")
	}

	rules := result.CertificateRules
	if rules.Validity != "8h" {
		t.Fatalf("expected validity '8h', got %q", rules.Validity)
	}
	if len(rules.AllowedPrincipals) != 2 {
		t.Fatalf("expected 2 allowed principals, got %d", len(rules.AllowedPrincipals))
	}
	if len(rules.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(rules.Permissions))
	}
	if rules.StaticAttributes["team@example.com"] != "backend" {
		t.Fatalf("expected static attribute team@example.com=backend, got %q", rules.StaticAttributes["team@example.com"])
	}
	if rules.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("expected critical option source-address=10.0.0.0/8, got %q", rules.CriticalOptions["source-address"])
	}
}

// --- LDAP-backed authorization tests ---

// fakeLDAPResolver is a deterministic stand-in for an LDAPResolver in
// authorizer tests. Calls counts invocations so tests can verify the
// resolver is reached (or not) for a given principal.
type fakeLDAPResolver struct {
	dns       []string
	ok        bool
	err       error
	calls     int
	resultsBy map[string][]string // optional per-principal override
}

func (f *fakeLDAPResolver) GroupsForPrincipal(_ context.Context, principal string) ([]string, bool, error) {
	f.calls++
	if f.err != nil {
		return nil, false, f.err
	}
	if dns, ok := f.resultsBy[principal]; ok {
		return dns, true, nil
	}
	return f.dns, f.ok, nil
}

func TestAuthorize_LDAPGrantsMembership(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			LDAPGroups: []string{"CN=ssh-admins,OU=Groups,DC=corp,DC=example"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	resolver := &fakeLDAPResolver{
		// LDAP returns the DN with different casing than configured; the
		// authorizer must match it case-insensitively.
		dns: []string{"cn=ssh-admins,ou=Groups,dc=corp,dc=example"},
		ok:  true,
	}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@CORP.EXAMPLE", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed via LDAP")
	}
	if result.GroupName != "ssh-admins" {
		t.Errorf("got group %q, want ssh-admins", result.GroupName)
	}
	if result.Source != "ldap" {
		t.Errorf("got source %q, want ldap", result.Source)
	}
	if resolver.calls != 1 {
		t.Errorf("resolver called %d times, want 1", resolver.calls)
	}
}

func TestAuthorize_LDAPNoMatch(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			LDAPGroups: []string{"CN=ssh-admins,DC=corp,DC=example"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	resolver := &fakeLDAPResolver{
		dns: []string{"CN=marketing,DC=corp,DC=example"}, // not bound to any Cerberus group
		ok:  true,
	}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "bob@CORP.EXAMPLE", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied; user is in no bound LDAP group")
	}
}

func TestAuthorize_LDAPErrorFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		// A static group also accepts this user — proves LDAP error takes
		// precedence and does NOT fall through to static membership.
		"legacy-static": {
			Members: []string{"alice@CORP.EXAMPLE"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
		"ssh-admins": {
			LDAPGroups: []string{"CN=ssh-admins,DC=corp,DC=example"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	resolver := &fakeLDAPResolver{err: errors.New("ldap down")}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@CORP.EXAMPLE", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("LDAP error must fail closed, even when a static group would otherwise allow")
	}
}

func TestAuthorize_LDAPNoBackendForRealmFallsThrough(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"legacy-static": {
			Members: []string{"alice@OTHER.EXAMPLE"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	// ok=false signals "no backend for this realm"; the authorizer must
	// fall through to static groups (and NOT fail closed).
	resolver := &fakeLDAPResolver{ok: false}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@OTHER.EXAMPLE", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected static-group allow when LDAP has no backend for the realm")
	}
	if result.Source != "static" {
		t.Errorf("source = %q, want static", result.Source)
	}
}

// TestAuthorize_LDAPPrecedenceConfigStable verifies that when a user matches
// multiple LDAP-bound Cerberus groups, the alphabetically-first group's
// certificate rules apply regardless of the order LDAP returns DNs in. This
// is the invariant called out in CLAUDE.md ("group precedence is
// config-name-stable, not LDAP-state-stable").
func TestAuthorize_LDAPPrecedenceConfigStable(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"alpha-team": {
			LDAPGroups: []string{"CN=alpha,DC=corp"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"root"},
			},
		},
		"beta-team": {
			LDAPGroups: []string{"CN=beta,DC=corp"},
			CertificateRules: config.CertificateRules{
				Validity:          "24h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	// Two orderings of the same membership set: the alphabetically-first
	// Cerberus group ("alpha-team") must win in both.
	orderings := [][]string{
		{"CN=alpha,DC=corp", "CN=beta,DC=corp"},
		{"CN=beta,DC=corp", "CN=alpha,DC=corp"},
	}
	// Run multiple times to drown out map-iteration randomness.
	for i := range 10 {
		for _, dns := range orderings {
			resolver := &fakeLDAPResolver{dns: dns, ok: true}
			a, err := NewCasbinAuthorizer(cfg, resolver)
			if err != nil {
				t.Fatalf("NewCasbinAuthorizer iter=%d: %v", i, err)
			}
			result, err := a.Authorize(t.Context(), "alice@CORP", []string{"root"})
			if err != nil {
				t.Fatalf("Authorize iter=%d: %v", i, err)
			}
			if !result.Allowed || result.GroupName != "alpha-team" {
				t.Fatalf("iter=%d dns=%v: got allow=%v group=%q, want allow=true group=alpha-team",
					i, dns, result.Allowed, result.GroupName)
			}
		}
	}
}

// TestAuthorize_LDAPResolverMalformedPrincipal verifies that an LDAP error
// for a malformed user@REALM still fails closed cleanly.
func TestLDAPResolver_MalformedPrincipal(t *testing.T) {
	t.Parallel()
	r := NewLDAPResolver(nil, map[string]string{"REALM": "corp"})
	_, ok, err := r.GroupsForPrincipal(t.Context(), "no-at-sign")
	if ok || err == nil {
		t.Errorf("expected (false, error) for malformed principal, got ok=%v err=%v", ok, err)
	}
}

// stripRealmConfig builds a static-only config with a single group and the
// given strip_realms list, so the strip-realm tests share one setup.
func stripRealmConfig(members, stripRealms []string) *config.Config {
	cfg := newTestConfig(map[string]config.Group{
		"engineers": {
			Members: members,
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	cfg.StripRealms = stripRealms
	return cfg
}

// TestAuthorize_StripRealmMatchesBareMember verifies that a principal whose
// realm is listed in strip_realms matches a bare short-name members: entry.
func TestAuthorize_StripRealmMatchesBareMember(t *testing.T) {
	t.Parallel()
	cfg := stripRealmConfig([]string{"alice"}, []string{"EXAMPLE.COM"})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@EXAMPLE.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed: alice@EXAMPLE.COM should match bare member 'alice'")
	}
	if result.GroupName != "engineers" {
		t.Errorf("got group %q, want engineers", result.GroupName)
	}
}

// TestAuthorize_StripRealmUnlistedRealmKeepsFullForm verifies that a principal
// in a realm NOT listed in strip_realms is not stripped: it does not match a
// bare member, but still matches a fully-qualified one. This is the guard
// against cross-realm collision.
func TestAuthorize_StripRealmUnlistedRealmKeepsFullForm(t *testing.T) {
	t.Parallel()

	// Bare member 'alice' must NOT match alice@OTHER.COM when OTHER.COM is not
	// stripped.
	bare := stripRealmConfig([]string{"alice"}, []string{"EXAMPLE.COM"})
	a, err := NewCasbinAuthorizer(bare, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@OTHER.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied: alice@OTHER.COM must not collapse onto bare 'alice' for an unlisted realm")
	}

	// A fully-qualified member for the unlisted realm still matches unchanged.
	full := stripRealmConfig([]string{"bob@OTHER.COM"}, []string{"EXAMPLE.COM"})
	a2, err := NewCasbinAuthorizer(full, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err = a2.Authorize(t.Context(), "bob@OTHER.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed: bob@OTHER.COM should still match its fully-qualified member")
	}
}

// TestAuthorize_StripRealmDisabledExactMatch verifies that with no strip_realms
// configured, a bare member does not match a full user@REALM principal —
// behavior is byte-for-byte the pre-feature exact match.
func TestAuthorize_StripRealmDisabledExactMatch(t *testing.T) {
	t.Parallel()
	cfg := stripRealmConfig([]string{"alice"}, nil)
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@EXAMPLE.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied: with stripping disabled, bare 'alice' must not match alice@EXAMPLE.COM")
	}
}

// TestAuthorize_StripRealmResolverGetsFullPrincipal verifies that realm
// stripping does not affect LDAP routing: the resolver still receives the full
// user@REALM string even when that realm is listed in strip_realms. resultsBy
// is keyed on the full principal, so a match proves the unstripped form reached
// the resolver.
func TestAuthorize_StripRealmResolverGetsFullPrincipal(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			LDAPGroups: []string{"CN=ssh-admins,DC=corp,DC=example"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	cfg.StripRealms = []string{"CORP.EXAMPLE"}
	resolver := &fakeLDAPResolver{
		resultsBy: map[string][]string{
			// Keyed on the FULL principal; if stripping leaked into the resolver
			// input the key would be "alice" and this lookup would miss.
			"alice@CORP.EXAMPLE": {"CN=ssh-admins,DC=corp,DC=example"},
		},
	}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	result, err := a.Authorize(t.Context(), "alice@CORP.EXAMPLE", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed via LDAP: resolver must receive the full user@REALM despite strip_realms")
	}
	if result.Source != "ldap" {
		t.Errorf("got source %q, want ldap", result.Source)
	}
}

// TestAuthorizeAll_FirstAlphabeticalGroup verifies AuthorizeAll selects the
// first group (alphabetically) the user belongs to and returns its rules — the
// group whose full allowed_principals the caller will expand.
func TestAuthorizeAll_FirstAlphabeticalGroup(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"zebra": {
			Members:          []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: []string{"zoo"}},
		},
		"admins": {
			Members:          []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: []string{"root", "ec2-user"}},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, err := a.AuthorizeAll(t.Context(), "alice@REALM.COM")
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	if !res.Allowed {
		t.Fatal("expected allowed")
	}
	if res.GroupName != "admins" { // 'admins' sorts before 'zebra'
		t.Errorf("got group %q, want first-alphabetical 'admins'", res.GroupName)
	}
	if !slices.Equal(res.CertificateRules.AllowedPrincipals, []string{"root", "ec2-user"}) {
		t.Errorf("got allowed_principals %v, want the admins group's", res.CertificateRules.AllowedPrincipals)
	}
}

// TestAuthorizeAll_NoGroupDenied verifies a user in no group is denied.
func TestAuthorizeAll_NoGroupDenied(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"admins": {
			Members:          []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: []string{"root"}},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, err := a.AuthorizeAll(t.Context(), "stranger@REALM.COM")
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected denied for a user in no group")
	}
}

// TestAuthorizeAll_LDAPFailsClosed verifies AuthorizeAll inherits the same
// fail-closed semantics as Authorize: an LDAP resolver error denies rather than
// silently falling through.
func TestAuthorizeAll_LDAPFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			LDAPGroups:       []string{"CN=ssh-admins,DC=corp,DC=example"},
			CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: []string{"root"}},
		},
	})
	resolver := &fakeLDAPResolver{err: errors.New("ldap down")}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, err := a.AuthorizeAll(t.Context(), "alice@CORP.EXAMPLE")
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected fail-closed denial on LDAP error")
	}
}

// selfCfg builds a config with a self_principal block for AuthorizeSelf tests.
func selfCfg(enabled bool, realms, deny []string) *config.Config {
	cfg := newTestConfig(map[string]config.Group{
		"admins": {
			Members:          []string{"x@X"},
			CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: []string{"root"}},
		},
	})
	cfg.SelfPrincipal = config.SelfPrincipalConfig{
		Enabled:          enabled,
		Realms:           realms,
		Deny:             deny,
		CertificateRules: config.CertificateRules{Validity: "8h", Permissions: map[string]string{"permit-pty": ""}},
	}
	return cfg
}

func TestAuthorizeSelf_Allowed(t *testing.T) {
	t.Parallel()
	a, err := NewCasbinAuthorizer(selfCfg(true, []string{"FOO.COM"}, nil), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, err := a.AuthorizeSelf(t.Context(), "jsmith@FOO.COM")
	if err != nil {
		t.Fatalf("AuthorizeSelf: %v", err)
	}
	if !res.Allowed {
		t.Fatal("expected allowed for realm-allowlisted, non-denied uid")
	}
	if res.Source != "self" || res.GroupName != "self" {
		t.Errorf("got source=%q group=%q, want both 'self'", res.Source, res.GroupName)
	}
	if res.CertificateRules == nil || res.CertificateRules.Validity != "8h" {
		t.Errorf("expected self certificate_rules (validity 8h), got %+v", res.CertificateRules)
	}
}

func TestAuthorizeSelf_Disabled(t *testing.T) {
	t.Parallel()
	a, err := NewCasbinAuthorizer(selfCfg(false, []string{"FOO.COM"}, nil), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, _ := a.AuthorizeSelf(t.Context(), "jsmith@FOO.COM")
	if res.Allowed {
		t.Fatal("expected denied when self_principal is disabled")
	}
}

func TestAuthorizeSelf_RealmNotAllowlisted(t *testing.T) {
	t.Parallel()
	a, err := NewCasbinAuthorizer(selfCfg(true, []string{"FOO.COM"}, nil), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, _ := a.AuthorizeSelf(t.Context(), "jsmith@BAR.COM")
	if res.Allowed {
		t.Fatal("expected denied for a realm not in the allowlist")
	}
}

func TestAuthorizeSelf_DenylistedUid(t *testing.T) {
	t.Parallel()
	a, err := NewCasbinAuthorizer(selfCfg(true, []string{"FOO.COM"}, []string{"deploy"}), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, _ := a.AuthorizeSelf(t.Context(), "deploy@FOO.COM")
	if res.Allowed {
		t.Fatal("expected denied for a uid on the denylist")
	}
}

func TestAuthorizeSelf_RootAllowedByDefault(t *testing.T) {
	t.Parallel()
	// deny is empty: "root" is self-issuable like any other uid, since
	// self_principal is how Cerberus replaces static root SSH keys.
	a, err := NewCasbinAuthorizer(selfCfg(true, []string{"FOO.COM"}, nil), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, err := a.AuthorizeSelf(t.Context(), "root@FOO.COM")
	if err != nil {
		t.Fatalf("AuthorizeSelf: %v", err)
	}
	if !res.Allowed {
		t.Fatal("expected 'root' to be self-issuable by default (no hardcoded floor)")
	}
}

func TestAuthorizeSelf_RootDeniedWhenExplicitlyOnDenylist(t *testing.T) {
	t.Parallel()
	// An operator who still wants to block self-issued root certs can opt
	// back in by listing "root" in self_principal.deny.
	a, err := NewCasbinAuthorizer(selfCfg(true, []string{"FOO.COM"}, []string{"root"}), nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	res, _ := a.AuthorizeSelf(t.Context(), "root@FOO.COM")
	if res.Allowed {
		t.Fatal("expected 'root' to be denied when explicitly listed in self_principal.deny")
	}
}

// TestAuthorizeSelf_DenylistOnlyGatesRequesterUID verifies self_principal.deny
// is keyed on the REQUESTING caller's own uid, not on any principal name
// appearing in a request. jsmith is a member of a group that grants "root"
// (among others); even though "root" sits on self_principal.deny, that only
// blocks a caller whose own uid is "root" from self-issuing — it must have no
// effect on jsmith's ordinary group-granted Authorize() request for
// ["jsmith", "root"].
func TestAuthorizeSelf_DenylistOnlyGatesRequesterUID(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"admins": {
			Members: []string{"jsmith@FOO.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"jsmith", "root"},
			},
		},
	})
	cfg.SelfPrincipal = config.SelfPrincipalConfig{
		Enabled:          true,
		Realms:           []string{"FOO.COM"},
		Deny:             []string{"root"},
		CertificateRules: config.CertificateRules{Validity: "8h"},
	}
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// jsmith's own self-issuance is unaffected (their uid is "jsmith", not
	// on the denylist).
	selfRes, err := a.AuthorizeSelf(t.Context(), "jsmith@FOO.COM")
	if err != nil {
		t.Fatalf("AuthorizeSelf: %v", err)
	}
	if !selfRes.Allowed {
		t.Fatal("expected jsmith's self-issuance to be allowed")
	}

	// jsmith requesting a cert covering both "jsmith" and "root" is decided
	// entirely by group membership (Casbin), never by self_principal.deny.
	result, err := a.Authorize(t.Context(), "jsmith@FOO.COM", []string{"jsmith", "root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected jsmith to be granted [jsmith, root] via the admins group despite 'root' being on self_principal.deny")
	}
	if result.GroupName != "admins" {
		t.Errorf("GroupName = %q, want %q", result.GroupName, "admins")
	}

	// A caller whose own uid IS "root" is still blocked from self-issuing,
	// confirming the denylist entry still does its job for its actual target.
	rootSelfRes, err := a.AuthorizeSelf(t.Context(), "root@FOO.COM")
	if err != nil {
		t.Fatalf("AuthorizeSelf(root): %v", err)
	}
	if rootSelfRes.Allowed {
		t.Fatal("expected root@FOO.COM's own self-issuance to remain denied")
	}
}

// TestAuthorize_SelfPrincipalAugmentsGroupGrantedRequest is a regression test
// for a real-world report: pkilar is a member of a group that grants "root"
// only (NOT his own uid), and self_principal is enabled and would grant his
// own uid on its own. Requesting "root" alone works (group), requesting
// "pkilar" alone works (self-fallback in server.go), but requesting BOTH in
// one /sign call was wrongly denied — Authorize required every requested
// principal, including the caller's own uid, to be covered by the SAME
// group's allowed_principals, and self_principal was never consulted. Since
// self_principal is independent of group membership by design, the caller's
// own uid must ride along with whatever a matching group actually grants.
func TestAuthorize_SelfPrincipalAugmentsGroupGrantedRequest(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"root-admins": {
			Members: []string{"pkilar@W.PDTPARTNERS.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"}, // does NOT include "pkilar"
			},
		},
	})
	cfg.SelfPrincipal = config.SelfPrincipalConfig{
		Enabled:          true,
		Realms:           []string{"W.PDTPARTNERS.COM"},
		CertificateRules: config.CertificateRules{Validity: "8h"},
	}
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// Sanity: each principal individually succeeds.
	if res, err := a.Authorize(t.Context(), "pkilar@W.PDTPARTNERS.COM", []string{"root"}); err != nil || !res.Allowed {
		t.Fatalf("Authorize(root) = %+v, %v; want allowed", res, err)
	}
	if res, err := a.AuthorizeSelf(t.Context(), "pkilar@W.PDTPARTNERS.COM"); err != nil || !res.Allowed {
		t.Fatalf("AuthorizeSelf = %+v, %v; want allowed", res, err)
	}

	// The combined request must also succeed, via the root-admins group
	// augmented by self_principal covering "pkilar".
	result, err := a.Authorize(t.Context(), "pkilar@W.PDTPARTNERS.COM", []string{"root", "pkilar"})
	if err != nil {
		t.Fatalf("Authorize(root,pkilar): %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected [root, pkilar] to be allowed: root via the group, pkilar via self_principal")
	}
	if result.GroupName != "root-admins" {
		t.Errorf("GroupName = %q, want %q", result.GroupName, "root-admins")
	}
}

// TestAuthorize_SoloSelfUIDNotSatisfiedByUnrelatedGroup verifies the
// self-augmentation in Authorize does not let a solo request for the
// caller's own uid trivially "match" a candidate group that grants nothing
// relevant — that solo case must fall through to the dedicated self-fallback
// (server.go), not be silently attributed to an unrelated group.
func TestAuthorize_SoloSelfUIDNotSatisfiedByUnrelatedGroup(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"root-admins": {
			Members: []string{"pkilar@W.PDTPARTNERS.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	cfg.SelfPrincipal = config.SelfPrincipalConfig{
		Enabled:          true,
		Realms:           []string{"W.PDTPARTNERS.COM"},
		CertificateRules: config.CertificateRules{Validity: "1h"},
	}
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize(t.Context(), "pkilar@W.PDTPARTNERS.COM", []string{"pkilar"})
	if err != nil {
		t.Fatalf("Authorize(pkilar): %v", err)
	}
	if result.Allowed {
		t.Fatal("expected a solo self-uid request to NOT be satisfied by Authorize via an unrelated group; it belongs to the server.go self-fallback")
	}
}

// --- OIDC oidc_groups authorization ---------------------------------------
//
// OIDC group membership is carried on the request context (WithAssertedGroups),
// not derived from the principal string. The identity string is the synthetic
// Username@Realm; group matching is decided entirely by the asserted groups.

func TestAuthorize_OIDCGrantsMembership(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			OIDCGroups: []string{"platform-eng", "sre"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	ctx := WithAssertedGroups(t.Context(), []string{"sre", "some-other-team"})
	result, err := a.Authorize(ctx, "jsmith@OIDC", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed via oidc_groups")
	}
	if result.GroupName != "ssh-admins" {
		t.Errorf("got group %q, want ssh-admins", result.GroupName)
	}
	if result.Source != "oidc" {
		t.Errorf("got source %q, want oidc", result.Source)
	}
}

func TestAuthorize_OIDCNoMatch(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"ssh-admins": {
			OIDCGroups: []string{"platform-eng"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	ctx := WithAssertedGroups(t.Context(), []string{"marketing"})
	result, err := a.Authorize(ctx, "jsmith@OIDC", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied; asserted group binds no Cerberus group")
	}
}

// A group is configured with oidc_groups, but the request carries no asserted
// groups (the Kerberos path). The OIDC block must be a no-op and the request
// must be denied exactly as before OIDC support existed.
func TestAuthorize_OIDCNoAssertedGroupsIsInert(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"static-eng": {
			Members: []string{"alice@REALM.COM"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
		"oidc-admins": {
			OIDCGroups: []string{"platform-eng"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	// Plain context (no asserted groups): the static member still resolves...
	res, err := a.Authorize(t.Context(), "alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !res.Allowed || res.GroupName != "static-eng" || res.Source != "static" {
		t.Errorf("static path changed: allowed=%v group=%q source=%q", res.Allowed, res.GroupName, res.Source)
	}
	// ...and a would-be OIDC member with no asserted groups is denied.
	res, err = a.Authorize(t.Context(), "jsmith@OIDC", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected denied: no asserted groups on the context")
	}
}

// Two oidc-bound groups both match; the first alphabetical group wins, both for
// AuthorizeAll (selection) and Authorize (per-group scan order).
func TestAuthorize_OIDCFirstAlphabeticalWins(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"aardvark": {
			OIDCGroups: []string{"everyone"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"shared"},
			},
		},
		"zebra": {
			OIDCGroups: []string{"everyone"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"shared"},
			},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	ctx := WithAssertedGroups(t.Context(), []string{"everyone"})

	res, err := a.Authorize(ctx, "jsmith@OIDC", []string{"shared"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !res.Allowed || res.GroupName != "aardvark" {
		t.Errorf("Authorize picked %q, want aardvark (first alphabetical)", res.GroupName)
	}

	all, err := a.AuthorizeAll(ctx, "jsmith@OIDC")
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	if !all.Allowed || all.GroupName != "aardvark" || all.Source != "oidc" {
		t.Errorf("AuthorizeAll picked group=%q source=%q, want aardvark/oidc", all.GroupName, all.Source)
	}
}

// Namespace isolation: an OIDC request whose synthesized principal ALSO happens
// to match a static members: entry (the realm-collision scenario) must be
// authorized SOLELY via oidc_groups — the static group must not leak in. This
// is the structural guard against a colliding realm label granting a Kerberos
// group to an OIDC identity.
func TestAuthorize_OIDCIsolatedFromStaticMembership(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		// Sorts first alphabetically and lists the OIDC principal as a static
		// member; under union semantics it would win. Isolation must exclude it.
		"aa-static": {
			Members: []string{"jsmith@OIDC"},
			CertificateRules: config.CertificateRules{
				Validity:          "1h",
				AllowedPrincipals: []string{"shared"},
			},
		},
		"zz-oidc": {
			OIDCGroups: []string{"platform-eng"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"shared"},
			},
		},
	})
	a, err := NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	ctx := WithAssertedGroups(t.Context(), []string{"platform-eng"})
	all, err := a.AuthorizeAll(ctx, "jsmith@OIDC")
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	if all.GroupName != "zz-oidc" || all.Source != "oidc" {
		t.Errorf("OIDC request selected group %q source %q, want zz-oidc/oidc (static member must not leak)", all.GroupName, all.Source)
	}

	// Explicit-principals path: same isolation.
	res, err := a.Authorize(ctx, "jsmith@OIDC", []string{"shared"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !res.Allowed || res.GroupName != "zz-oidc" {
		t.Errorf("Authorize selected %q, want zz-oidc (static member must not leak)", res.GroupName)
	}
}

// An OIDC request does not consult LDAP at all, so a configured LDAP resolver
// that errors for other (Kerberos) principals does not affect it — it is still
// authorized via oidc_groups. (LDAP fail-closed applies only to the Kerberos
// path; see TestAuthorize_LDAPErrorFailsClosed.)
func TestAuthorize_OIDCUnaffectedByLDAPError(t *testing.T) {
	t.Parallel()
	cfg := newTestConfig(map[string]config.Group{
		"oidc-admins": {
			OIDCGroups: []string{"platform-eng"},
			CertificateRules: config.CertificateRules{
				Validity:          "8h",
				AllowedPrincipals: []string{"root"},
			},
		},
	})
	resolver := &fakeLDAPResolver{err: errors.New("ldap down")}
	a, err := NewCasbinAuthorizer(cfg, resolver)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}
	ctx := WithAssertedGroups(t.Context(), []string{"platform-eng"})
	res, err := a.Authorize(ctx, "jsmith@OIDC", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !res.Allowed || res.Source != "oidc" {
		t.Fatalf("OIDC request must authorize via oidc_groups regardless of LDAP resolver state; got allowed=%v source=%q", res.Allowed, res.Source)
	}
	if resolver.calls != 0 {
		t.Errorf("LDAP resolver was consulted %d times for an OIDC request; want 0", resolver.calls)
	}
}
