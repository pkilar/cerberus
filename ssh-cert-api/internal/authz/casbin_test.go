package authz

import (
	"context"
	"errors"
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
