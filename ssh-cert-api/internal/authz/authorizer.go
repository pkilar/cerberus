// Package authz resolves authenticated Kerberos principals to their
// configured certificate rules via a Casbin enforcer. Enforcement is
// strictly per-group: if a user is a member of multiple groups, they
// cannot combine principals across groups within a single signing
// request — the first group in alphabetical order whose allowed
// principals cover the full request wins.
package authz

import "ssh-cert-api/internal/config"

// AuthorizationResult contains the authorization decision and the associated certificate rules.
type AuthorizationResult struct {
	Allowed          bool
	GroupName        string
	CertificateRules *config.CertificateRules
}

// Authorizer decides whether a user is permitted to request specific SSH principals.
type Authorizer interface {
	// Authorize checks if the given user principal is allowed to sign for all
	// the requested SSH principals. If allowed, returns the CertificateRules
	// for the matched group.
	Authorize(userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error)
}
