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
// certificate rules. Source records how the matched group's membership was
// determined — static config, an LDAP query, an OIDC token's groups claim, or
// the self-service path — surfaced as a log attribute on /sign success so
// operators can audit dynamic group assignments.
type AuthorizationResult struct {
	Allowed          bool
	GroupName        string
	CertificateRules *config.CertificateRules
	Source           string // "static" | "ldap" | "oidc" | "self" | "" when denied
}

// Authorizer decides whether a user is permitted to request specific SSH principals.
type Authorizer interface {
	// Authorize checks if the given user principal is allowed to sign for all
	// the requested SSH principals. If allowed, returns the CertificateRules
	// for the matched group. ctx is propagated to any directory-service
	// lookups; implementations that do not perform I/O may ignore it.
	Authorize(ctx context.Context, userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error)

	// AuthorizeAll selects the group for an all-principals expansion request:
	// the first alphabetical group the user belongs to. Unlike Authorize it
	// does not filter by requested principals — the caller expands the returned
	// group's AllowedPrincipals and is responsible for refusing a group whose
	// AllowedPrincipals contains "*" (an unbounded set can't be enumerated into
	// a cert). Returns Allowed=false if the user is in no group, or if LDAP is
	// configured and fails closed for this principal.
	AuthorizeAll(ctx context.Context, userPrincipal string) (*AuthorizationResult, error)

	// AuthorizeSelf decides the self-service path: whether userPrincipal may
	// obtain a certificate for its own short uid. It is independent of group
	// membership — no group the caller belongs to can block or override this
	// decision — and returns Allowed=true only when self_principal is enabled,
	// the caller's realm is in the allowlist, and the uid is not on the
	// operator-configured denylist. There is no hardcoded floor on "root": this
	// is the intended path for replacing static root SSH keys, so root
	// self-issuance is allowed by default unless an operator opts it out via
	// self_principal.deny. On success CertificateRules carries the
	// self_principal cert parameters; the caller issues the cert for the uid.
	AuthorizeSelf(ctx context.Context, userPrincipal string) (*AuthorizationResult, error)
}
