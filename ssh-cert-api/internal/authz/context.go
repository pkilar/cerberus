package authz

import "context"

// assertedGroupsKey is the context key under which an OIDC request's assertion
// travels from the API auth middleware to candidateGroups. A struct type (not a
// string) guarantees no collision with any other package's context values.
type assertedGroupsKey struct{}

// oidcAssertion marks a request as OIDC-authenticated and carries the
// identity-provider-asserted group names. Its *presence* in the context — even
// with an empty Groups slice — is what tells candidateGroups to authorize the
// request SOLELY via oidc_groups bindings, never via static members: or LDAP.
// This keeps the OIDC identity namespace strictly separate from Kerberos/LDAP
// principals, so an OIDC identity can never match a static or LDAP-backed group
// even if its synthetic realm label were to collide with a Kerberos/LDAP realm.
type oidcAssertion struct {
	groups []string
}

// WithAssertedGroups marks ctx as an OIDC-authenticated request carrying the
// given identity-provider-asserted group names. The API auth middleware calls
// this for every Bearer-authenticated request (regardless of how many groups
// the token asserted). Kerberos requests never call it, so candidateGroups
// authorizes them via static members:/LDAP exactly as before OIDC existed.
//
// The Authorizer methods already take a ctx precisely so request-scoped
// resolution state (the LDAP resolver reads from it too) can reach the
// candidate-group computation, so the interface signatures do not change.
func WithAssertedGroups(ctx context.Context, groups []string) context.Context {
	return context.WithValue(ctx, assertedGroupsKey{}, oidcAssertion{groups: groups})
}

// oidcAssertionFromContext reports whether the request was OIDC-authenticated
// and, if so, the identity-provider-asserted group names (possibly empty).
func oidcAssertionFromContext(ctx context.Context) (groups []string, isOIDC bool) {
	a, ok := ctx.Value(assertedGroupsKey{}).(oidcAssertion)
	if !ok {
		return nil, false
	}
	return a.groups, true
}
