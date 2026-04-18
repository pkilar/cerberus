package authz

import (
	"fmt"
	"slices"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"

	"ssh-cert-api/internal/config"
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

// CasbinAuthorizer implements Authorizer using Casbin as the policy engine.
// User-to-group mappings are managed explicitly (not via Casbin RBAC grouping)
// to ensure that authorization decisions and CertificateRules always come from
// the same group.
type CasbinAuthorizer struct {
	enforcer   *casbin.Enforcer
	groupRules map[string]*config.CertificateRules // group name -> certificate rules
	userGroups map[string][]string                  // user principal -> groups in sorted order
}

// NewCasbinAuthorizer creates a CasbinAuthorizer with policies loaded from the given config.
func NewCasbinAuthorizer(cfg *config.Config) (*CasbinAuthorizer, error) {
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	ca := &CasbinAuthorizer{
		enforcer:   e,
		groupRules: make(map[string]*config.CertificateRules),
		userGroups: make(map[string][]string),
	}

	if err := ca.loadPolicies(cfg); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return ca, nil
}

// loadPolicies translates config.yaml groups into Casbin policies and role assignments.
// Group names are sorted alphabetically for deterministic first-match semantics.
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

		// Add policy: p, groupName, sshPrincipal, sign
		for _, principal := range rules.AllowedPrincipals {
			if _, err := ca.enforcer.AddPolicy(groupName, principal, "sign"); err != nil {
				return fmt.Errorf("failed to add policy for group %s, principal %s: %w", groupName, principal, err)
			}
		}

		// Track user-to-group mappings (managed outside Casbin to prevent
		// cross-group privilege escalation via RBAC union semantics)
		for _, member := range group.Members {
			ca.userGroups[member] = append(ca.userGroups[member], groupName)
		}
	}

	return nil
}

// Authorize checks if the user is allowed to sign for all requested SSH principals.
// It enforces per-group: all requested principals must be allowed within a single
// group. This ensures the returned CertificateRules match the authorization scope.
func (ca *CasbinAuthorizer) Authorize(userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error) {
	groups, exists := ca.userGroups[userPrincipal]
	if !exists {
		return &AuthorizationResult{Allowed: false}, nil
	}

	// Check each group the user belongs to (in sorted order).
	// Return the first group where ALL requested principals are allowed.
	for _, groupName := range groups {
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
			return &AuthorizationResult{
				Allowed:          true,
				GroupName:        groupName,
				CertificateRules: ca.groupRules[groupName],
			}, nil
		}
	}

	return &AuthorizationResult{Allowed: false}, nil
}
