package authz

import (
	"testing"

	"ssh-cert-api/internal/config"
)

func newTestConfig(groups map[string]config.Group) *config.Config {
	return &config.Config{
		Groups:     groups,
		KeytabPath: "/etc/krb5.keytab",
	}
}

func TestAuthorize_BasicAllow(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize("alice@REALM.COM", []string{"root"})
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
	result, err = a.Authorize("alice@REALM.COM", []string{"root", "ec2-user"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed for multiple principals")
	}
}

func TestAuthorize_BasicDeny(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize("alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied for unlisted principal")
	}
}

func TestAuthorize_UnknownUser(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize("unknown@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied for unknown user")
	}
}

func TestAuthorize_WildcardPrincipal(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// Wildcard should allow any SSH principal
	for _, principal := range []string{"root", "ec2-user", "anything", "deploy"} {
		result, err := a.Authorize("admin@REALM.COM", []string{principal})
		if err != nil {
			t.Fatalf("Authorize(%s): %v", principal, err)
		}
		if !result.Allowed {
			t.Fatalf("expected allowed for wildcard principal %q", principal)
		}
	}
}

func TestAuthorize_MultiGroup(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// Alice can sign for root but not analyst
	result, err := a.Authorize("alice@REALM.COM", []string{"root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("alice should be allowed for root")
	}

	result, err = a.Authorize("alice@REALM.COM", []string{"analyst"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("alice should be denied for analyst")
	}

	// Charlie can sign for analyst but not root
	result, err = a.Authorize("charlie@REALM.COM", []string{"analyst"})
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
		a, err := NewCasbinAuthorizer(cfg)
		if err != nil {
			t.Fatalf("NewCasbinAuthorizer (iteration %d): %v", i, err)
		}

		result, err := a.Authorize("bob@REALM.COM", []string{"root"})
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// alice requests "root" — should be allowed via alpha-admins with alpha-admins' rules
	result, err := a.Authorize("alice@REALM.COM", []string{"root"})
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
	result, err = a.Authorize("alice@REALM.COM", []string{"deploy"})
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
	result, err = a.Authorize("alice@REALM.COM", []string{"root", "deploy"})
	if err != nil {
		t.Fatalf("Authorize(root,deploy): %v", err)
	}
	if result.Allowed {
		t.Fatal("alice should be denied when requesting principals from different groups")
	}
}

func TestAuthorize_PartialDeny(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	// One allowed + one disallowed = denied
	result, err := a.Authorize("alice@REALM.COM", []string{"ec2-user", "root"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if result.Allowed {
		t.Fatal("expected denied when requesting mix of allowed and disallowed principals")
	}
}

func TestAuthorize_EmptyPrincipals(t *testing.T) {
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

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize("alice@REALM.COM", []string{})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !result.Allowed {
		t.Fatal("expected allowed for empty requested principals")
	}
}

func TestAuthorize_CertificateRulesReturned(t *testing.T) {
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
					"team":         "backend",
					"access-level": "production",
				},
				CriticalOptions: map[string]string{
					"source-address": "10.0.0.0/8",
				},
			},
		},
	})

	a, err := NewCasbinAuthorizer(cfg)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	result, err := a.Authorize("alice@REALM.COM", []string{"root"})
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
	if rules.StaticAttributes["team"] != "backend" {
		t.Fatalf("expected static attribute team=backend, got %q", rules.StaticAttributes["team"])
	}
	if rules.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("expected critical option source-address=10.0.0.0/8, got %q", rules.CriticalOptions["source-address"])
	}
}
