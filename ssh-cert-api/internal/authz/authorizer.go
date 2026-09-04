// Package authz resolves authenticated Kerberos principals to their
// configured certificate rules via a Casbin enforcer. Enforcement is
// strictly per-group: if a user is a member of multiple groups, they
// cannot combine principals across two different groups within a single
// signing request — the first group in alphabetical order whose allowed
// principals cover the full request wins. Membership may come from the
// static `members:` list in YAML, or from an LDAPResolver consulted at
// request time. The first-alphabetical rule applies to the combined
// candidate set.
//
// The one exception is self_principal: it is independent of group
// membership by design, so a caller's own self-issuable uid always rides
// along with whatever a single matching group grants, even if that group's
// allowed_principals doesn't list the caller's own uid. See Authorize and
// AuthorizeSelf.
package authz

import (
	"context"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

// AuthorizationResult contains the authorization decision, the certificate
// rules to apply, and the principals the certificate must carry. Source
// records how the matched group's membership was determined — static config,
// an LDAP query, an OIDC token's groups claim, or the self-service path —
// surfaced as a log attribute on /sign success so operators can audit dynamic
// group assignments.
//
// GrantedPrincipals is the ONLY principal set the caller may put in the
// certificate. It is sorted, deduplicated, and non-empty whenever Allowed is
// true; nil when denied. For Authorize it is the request translated through the
// matched group's allowed_principals (a `root: global-root` mapping issues
// "global-root", a plain or "*"-covered name is issued as requested); for
// AuthorizeAll it is the group's full issued set; for AuthorizeSelf it is the
// caller's own uid. Callers must not derive principals from the request body.
type AuthorizationResult struct {
	Allowed           bool
	GroupName         string
	CertificateRules  *config.CertificateRules
	Source            string   // "static" | "ldap" | "oidc" | "self" | "" when denied
	GrantedPrincipals []string // cert principals; non-empty iff Allowed
}

// Authorizer decides whether a user is permitted to request specific SSH principals.
type Authorizer interface {
	// Authorize checks if the given user principal is allowed to sign for all
	// the requested SSH principals. If allowed, returns the CertificateRules
	// for the matched group and, in GrantedPrincipals, the requested names
	// resolved through that group's allowed_principals mapping. The caller's
	// own self-issuable uid (per self_principal, when enabled) is treated as
	// automatically satisfied by any group that covers the rest of the
	// request — self_principal is independent of group membership, so it
	// must never be the reason a mixed request like ["root", "<own uid>"] is
	// denied. ctx is propagated to any directory-service lookups;
	// implementations that do not perform I/O may ignore it.
	Authorize(ctx context.Context, userPrincipal string, requestedPrincipals []string) (*AuthorizationResult, error)

	// AuthorizeAll selects the group for an all-principals expansion request:
	// the first alphabetical group the user belongs to. Unlike Authorize it
	// does not filter by requested principals — GrantedPrincipals carries the
	// group's issued set (mapping targets, not requested names); the caller is
	// still responsible for refusing a group whose AllowedPrincipals has a "*"
	// entry (an unbounded set can't be enumerated into a cert). Returns
	// Allowed=false if the user is in no group, or if LDAP is configured and
	// fails closed for this principal.
	AuthorizeAll(ctx context.Context, userPrincipal string) (*AuthorizationResult, error)

	// AuthorizeSelf decides the self-service path: whether userPrincipal may
	// obtain a certificate for its own short uid. It is independent of group
	// membership — no group the caller belongs to can block or override this
	// decision — and returns Allowed=true only when self_principal is enabled,
	// the caller's realm is in the allowlist, and the uid is not on the
	// operator-configured denylist. There is no hardcoded floor on "root": this
	// is the intended path for replacing static root SSH keys, so root
	// self-issuance is allowed by default unless an operator opts it out via
	// self_principal.deny. On success GrantedPrincipals is exactly [uid] and
	// CertificateRules carries the self_principal cert parameters.
	AuthorizeSelf(ctx context.Context, userPrincipal string) (*AuthorizationResult, error)
}
