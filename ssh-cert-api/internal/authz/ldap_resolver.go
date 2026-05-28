package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/ldap"
)

// LDAPResolver maps an authenticated Kerberos principal to the LDAP group DNs
// it belongs to, by routing on the principal's realm.
//
// Return semantics:
//   - dns!=nil, ok=true, err=nil: LDAP was queried and returned these DNs
//     (possibly empty).
//   - ok=false, err=nil: no LDAP backend covers this principal's realm. The
//     caller should fall through to static-only authorization.
//   - ok=false, err!=nil: an LDAP error occurred. The caller MUST fail
//     closed; do not fall back to static.
type LDAPResolver interface {
	GroupsForPrincipal(ctx context.Context, userPrincipal string) (dns []string, ok bool, err error)
}

// ldapResolver is the default impl: split the principal on '@', route the
// realm to a backend, and query the backend for the user's group DNs.
type ldapResolver struct {
	backends   map[string]ldap.Client // backend name -> Client
	realmIndex map[string]string      // realm -> backend name
}

// NewLDAPResolver constructs a resolver from the per-backend Client map and a
// realm→backend index. realmIndex must be disjoint across backends (config
// validation rejects overlap), so a realm maps to at most one backend.
func NewLDAPResolver(backends map[string]ldap.Client, realmIndex map[string]string) LDAPResolver {
	return &ldapResolver{
		backends:   backends,
		realmIndex: realmIndex,
	}
}

var errMalformedPrincipal = errors.New("user principal is not in user@REALM form")

func (r *ldapResolver) GroupsForPrincipal(ctx context.Context, userPrincipal string) ([]string, bool, error) {
	uid, realm, hasAt := strings.Cut(userPrincipal, "@")
	if !hasAt || uid == "" || realm == "" {
		return nil, false, errMalformedPrincipal
	}
	backendName, covered := r.realmIndex[realm]
	if !covered {
		return nil, false, nil
	}
	client, ok := r.backends[backendName]
	if !ok {
		// Defensive: realmIndex and backends are populated together at
		// startup, so a mismatch indicates a programming bug.
		return nil, false, errors.New("ldap backend named in realmIndex is missing from client map")
	}
	dns, err := client.UserGroups(ctx, uid)
	if err != nil {
		return nil, false, err
	}
	return dns, true, nil
}
