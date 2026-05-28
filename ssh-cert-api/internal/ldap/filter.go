// Package ldap is the directory-service client used by the authorizer to
// resolve a Kerberos principal's LDAP group memberships at request time.
// Each backend in the YAML config produces one Client; the authorizer routes
// principals to backends by Kerberos realm.
//
// The package is fail-closed: any LDAP error surfaces to the caller as a
// hard failure, never a silent fallthrough. Errors are never cached. A short
// positive cache with singleflight collapsing protects the directory from
// thundering-herd load at TTL boundaries.
package ldap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// errFilterTemplate is returned when the user_filter template does not contain
// exactly one %s placeholder. Config validation rejects this at startup, but
// the runtime check is kept defensively in case a future code path bypasses
// validation.
var errFilterTemplate = errors.New("user_filter template must contain exactly one %s placeholder")

// SafeUserFilter substitutes shortUID into the user-filter template after
// running it through ldap.EscapeFilter to neutralize LDAP-syntax characters
// (*, (, ), \, NUL). This is the LDAP equivalent of SQL-statement escaping
// and is the only defense against filter-injection attacks — the value is
// then handed verbatim to the server as the search filter.
func SafeUserFilter(template, shortUID string) (string, error) {
	if strings.Count(template, "%s") != 1 {
		return "", errFilterTemplate
	}
	return fmt.Sprintf(template, ldap.EscapeFilter(shortUID)), nil
}
