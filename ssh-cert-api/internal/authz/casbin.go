package authz

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (p.obj == "*" || r.obj == p.obj) && r.act == p.act
`

var _ Authorizer = (*CasbinAuthorizer)(nil)

// CasbinAuthorizer implements Authorizer using Casbin as the policy engine.
// User-to-group mappings are managed explicitly (not via Casbin RBAC grouping)
// to ensure that authorization decisions and CertificateRules always come from
// the same group. Membership candidates can come from two sources:
//   - userGroups: static `members:` mappings, computed once at startup.
//   - ldapGroupBindings + resolver: LDAP-backed `ldap_groups:` mappings,
//     resolved at request time. A nil resolver disables LDAP entirely and
//     behavior is identical to the static-only model.
//
// The Casbin policy itself is mutated only at startup. Authorize never calls
// AddPolicy — see loadPolicies for the one and only mutation site. The
// concurrency model relies on this invariant.
type CasbinAuthorizer struct {
	enforcer          *casbin.Enforcer
	groupRules        map[string]*config.CertificateRules // group name -> certificate rules
	userGroups        map[string][]string                 // user principal -> static groups in sorted order
	ldapGroupBindings map[string]map[string]struct{}      // Cerberus group name -> normalized DN set
	resolver          LDAPResolver                        // nil disables LDAP-backed authorization
}

// NewCasbinAuthorizer creates a CasbinAuthorizer with policies loaded from
// the given config. A nil resolver disables LDAP lookups; the resulting
// authorizer behaves identically to the pre-LDAP code path.
func NewCasbinAuthorizer(cfg *config.Config, resolver LDAPResolver) (*CasbinAuthorizer, error) {
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	ca := &CasbinAuthorizer{
		enforcer:          e,
		groupRules:        make(map[string]*config.CertificateRules),
		userGroups:        make(map[string][]string),
		ldapGroupBindings: make(map[string]map[string]struct{}),
		resolver:          resolver,
	}

	if err := ca.loadPolicies(cfg); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return ca, nil
}

// loadPolicies translates config.yaml groups into Casbin policies, static
// user-group assignments, and LDAP DN bindings. Group names are sorted
// alphabetically and policies/bindings are added in that order; this is the
// ONLY mutation site for the Casbin enforcer.
func (ca *CasbinAuthorizer) loadPolicies(cfg *config.Config) error {
	groupNames := make([]string, 0, len(cfg.Groups))
	for name := range cfg.Groups {
		groupNames = append(groupNames, name)
	}
	slices.Sort(groupNames)

	for _, groupName := range groupNames {
		group := cfg.Groups[groupName]
		rules := group.CertificateRules
		ca.groupRules[groupName] = &rules

		for _, principal := range rules.AllowedPrincipals {
			if _, err := ca.enforcer.AddPolicy(groupName, principal, "sign"); err != nil {
				return fmt.Errorf("failed to add policy for group %s, principal %s: %w", groupName, principal, err)
			}
		}

		// A group is either static-membership or LDAP-bound (validated at
		// config load); the two branches below are mutually exclusive.
		for _, member := range group.Members {
			ca.userGroups[member] = append(ca.userGroups[member], groupName)
		}
		if len(group.LDAPGroups) > 0 {
			dns := make(map[string]struct{}, len(group.LDAPGroups))
			for _, dn := range group.LDAPGroups {
				dns[normalizeDN(dn)] = struct{}{}
			}
			ca.ldapGroupBindings[groupName] = dns
		}
	}
	return nil
}

// Authorize checks if the user is allowed to sign for all requested SSH
// principals. Per-group enforcement: all requested principals must be allowed
// within a single group. The candidate set is the union of static-membership
// groups and LDAP-derived groups; first alphabetical Cerberus group name
// whose allowed_principals cover the request wins.
//
// LDAP failure mode is fail-closed: if a resolver is configured AND it
// returns an error for this principal, the request is denied without
// considering static groups. This avoids an inconsistent "LDAP outage opens
// the static-only door" semantic; static-only users are unaffected because
// the resolver returns ok=false for realms with no LDAP backend.
//
// An empty requestedPrincipals slice is refused. With nothing to check, the
// per-principal Casbin loop below would trivially "allow" and return the
// first group's full rules — wider than the empty request implied. The HTTP
// layer already refuses this (api/server.go); defense in depth catches any
// future caller that bypasses the handler.
func (ca *CasbinAuthorizer) Authorize(ctx context.Context, userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error) {
	if len(requestedPrincipals) == 0 {
		return &AuthorizationResult{Allowed: false}, nil
	}

	staticGroups := ca.userGroups[userPrincipal]
	candidates := slices.Clone(staticGroups)
	ldapMatchedGroups := map[string]struct{}{}

	if ca.resolver != nil {
		dns, ok, err := ca.resolver.GroupsForPrincipal(ctx, userPrincipal)
		if err != nil {
			slog.Warn("authz.ldap.error",
				"principal", userPrincipal,
				"error", err)
			return &AuthorizationResult{Allowed: false}, nil
		}
		if ok {
			for groupName, boundDNs := range ca.ldapGroupBindings {
				for _, dn := range dns {
					if _, hit := boundDNs[normalizeDN(dn)]; hit {
						candidates = append(candidates, groupName)
						ldapMatchedGroups[groupName] = struct{}{}
						break
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		return &AuthorizationResult{Allowed: false}, nil
	}

	// Deduplicate (a name could appear via both static and LDAP paths if a
	// future config relaxation allowed it) and sort to preserve the
	// established first-alphabetical-wins precedence rule.
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)

	for _, groupName := range candidates {
		allAllowed := true
		for _, reqPrincipal := range requestedPrincipals {
			allowed, err := ca.enforcer.Enforce(groupName, reqPrincipal, "sign")
			if err != nil {
				return nil, fmt.Errorf("casbin enforcement error: %w", err)
			}
			if !allowed {
				allAllowed = false
				break
			}
		}
		if allAllowed {
			source := "static"
			if _, viaLDAP := ldapMatchedGroups[groupName]; viaLDAP {
				source = "ldap"
			}
			return &AuthorizationResult{
				Allowed:          true,
				GroupName:        groupName,
				CertificateRules: ca.groupRules[groupName],
				Source:           source,
			}, nil
		}
	}

	return &AuthorizationResult{Allowed: false}, nil
}

// normalizeDN lowercases an LDAP DN for case-insensitive comparison. RFC 4514
// component names and most attribute values are case-insensitive; this
// approximation avoids pulling in a full DN parser for v1. Operators whose
// directory uses case-sensitive attribute values will need to align YAML
// strictly with LDAP output, but the lowercase normalization at least
// handles the universal "CN=" vs "cn=" mismatch.
func normalizeDN(dn string) string {
	return strings.ToLower(dn)
}
