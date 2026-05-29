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

// errFilterTemplate is returned when the user_filter template is not a single
// %s substitution. Config validation rejects this at startup, but the runtime
// check is kept defensively in case a future code path bypasses validation.
var errFilterTemplate = errors.New("user_filter template must contain exactly one %s placeholder and no other format directive")

// ValidFilterTemplate reports whether template is a safe user_filter: it must
// contain exactly one %s verb and no other fmt directive.
//
// strings.Count(template, "%s") == 1 is NOT sufficient: "(uid=%%s)" contains
// the substring "%s", but fmt reads "%%" as a literal percent, so it drops the
// substitution entirely and emits the escaped UID as an unused EXTRA argument —
// the resulting filter has no user value spliced in at all. Other malformed
// templates ("(uid=%s)(lvl=%d)", a stray trailing "%") corrupt the rendered
// filter the same way. We model fmt's own parsing by trial-formatting a
// sentinel that contains no format-error characters and rejecting any template
// fmt cannot fill cleanly (escaped %%s, extra/missing verbs, zero verbs).
func ValidFilterTemplate(template string) bool {
	const probe = "cerberusFilterProbe"
	out := fmt.Sprintf(template, probe)
	return strings.Contains(out, probe) && !strings.Contains(out, "%!")
}

// SafeUserFilter substitutes shortUID into the user-filter template after
// running it through ldap.EscapeFilter to neutralize LDAP-syntax characters
// (*, (, ), \, NUL). This is the LDAP equivalent of SQL-statement escaping
// and is the only defense against filter-injection attacks — the value is
// then handed verbatim to the server as the search filter.
func SafeUserFilter(template, shortUID string) (string, error) {
	if !ValidFilterTemplate(template) {
		return "", errFilterTemplate
	}
	return fmt.Sprintf(template, ldap.EscapeFilter(shortUID)), nil
}
