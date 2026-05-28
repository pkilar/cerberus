// Package authz resolves authenticated Kerberos principals to their
// configured certificate rules via a Casbin enforcer. Enforcement is
// strictly per-group: if a user is a member of multiple groups, they
// cannot combine principals across groups within a single signing
// request — the first group in alphabetical order whose allowed
// principals cover the full request wins. Membership may come from the
// static `members:` list in YAML, or from an LDAPResolver consulted at
// request time. The first-alphabetical rule applies to the combined
// candidate set.
package authz

import (
	"context"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

// AuthorizationResult contains the authorization decision and the associated
// certificate rules. Source records whether the matched group's membership
// came from static config or an LDAP query — surfaced as a log attribute on
// /sign success so operators can audit dynamic group assignments.
type AuthorizationResult struct {
	Allowed          bool
	GroupName        string
	CertificateRules *config.CertificateRules
	Source           string // "static" | "ldap" | "" when denied
}

// Authorizer decides whether a user is permitted to request specific SSH principals.
type Authorizer interface {
	// Authorize checks if the given user principal is allowed to sign for all
	// the requested SSH principals. If allowed, returns the CertificateRules
	// for the matched group. ctx is propagated to any directory-service
	// lookups; implementations that do not perform I/O may ignore it.
	Authorize(ctx context.Context, userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error)
}
