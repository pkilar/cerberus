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
//   - oidcGroupBindings: OIDC `oidc_groups:` mappings, matched at request time
//     against the identity-provider-asserted groups carried on the request
//     context (WithAssertedGroups). Empty when no group uses oidc_groups.
//
// The Casbin policy itself is mutated only at startup. Authorize never calls
// AddPolicy — see loadPolicies for the one and only mutation site. The
// concurrency model relies on this invariant.
type CasbinAuthorizer struct {
	enforcer          *casbin.Enforcer
	groupRules        map[string]*config.CertificateRules // group name -> certificate rules
	userGroups        map[string][]string                 // user principal -> static groups in sorted order
	ldapGroupBindings map[string]map[string]struct{}      // Cerberus group name -> normalized DN set
	oidcGroupBindings map[string]map[string]struct{}      // Cerberus group name -> accepted OIDC groups-claim values (exact match)
	resolver          LDAPResolver                        // nil disables LDAP-backed authorization
	stripRealms       map[string]struct{}                 // realms whose @REALM suffix is stripped for static members lookup; nil disables

	// Self-service issuance (self_principal). selfEnabled gates the whole path.
	selfRealms map[string]struct{}      // realms allowed to self-issue
	selfDeny   map[string]struct{}      // short uids that may never self-issue (operator-configured; "root" is NOT floored here)
	selfRules  *config.CertificateRules // cert parameters for self-issued certs
	selfOn     bool
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

	selfRules := cfg.SelfPrincipal.CertificateRules

	ca := &CasbinAuthorizer{
		enforcer:          e,
		groupRules:        make(map[string]*config.CertificateRules),
		userGroups:        make(map[string][]string),
		ldapGroupBindings: make(map[string]map[string]struct{}),
		oidcGroupBindings: make(map[string]map[string]struct{}),
		resolver:          resolver,
		stripRealms:       realmSet(cfg.StripRealms),
		selfOn:            cfg.SelfPrincipal.Enabled,
		selfRealms:        realmSet(cfg.SelfPrincipal.Realms),
		selfDeny:          selfDenySet(cfg.SelfPrincipal.Deny),
		selfRules:         &selfRules,
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

		// A group's membership has exactly one source — static, LDAP, or OIDC
		// (validated at config load); the branches below are mutually exclusive.
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
		if len(group.OIDCGroups) > 0 {
			// OIDC group-claim values are matched by exact string equality
			// (unlike LDAP DNs, which are structurally normalized): the values
			// come from the IdP's groups claim verbatim.
			vals := make(map[string]struct{}, len(group.OIDCGroups))
			for _, g := range group.OIDCGroups {
				vals[g] = struct{}{}
			}
			ca.oidcGroupBindings[groupName] = vals
		}
	}
	return nil
}

// Authorize checks if the user is allowed to sign for all requested SSH
// principals. Per-group enforcement: every requested principal other than the
// caller's own self-issuable uid must be allowed within a single group — a
// request still cannot combine principals granted by two different groups.
// The one exception is the caller's own uid when self_principal permits it
// (see selfEligibleUID): it is treated as automatically satisfied by whatever
// group is being evaluated, so self_principal — being independent of group
// membership by design — is never the reason a mixed request like
// ["root", "<own uid>"] gets denied just because no single group happens to
// list the caller's own uid alongside root. A group only "wins" this way if
// it genuinely covers at least one OTHER requested principal; a request for
// solely the caller's own uid is NOT satisfied here (see below) — that solo
// case is handled by the dedicated self-fallback in the API layer
// (server.go), which uses self_principal's own CertificateRules rather than
// attributing the grant to an unrelated group the caller happens to belong
// to. The candidate set is the static-membership groups plus — when an LDAP
// resolver is configured and matches — the LDAP-derived groups; the first
// alphabetical Cerberus group name whose allowed_principals (plus the self
// exception) cover the request wins.
//
// LDAP failure mode is fail-closed: if a resolver is configured AND it
// returns an error for this principal, the request is denied without
// considering static groups. This avoids an inconsistent "LDAP outage opens
// the static-only door" semantic; static-only users are unaffected because
// the resolver returns ok=false for realms with no LDAP backend.
//
// The static-membership lookup key is derived from userPrincipal via
// staticMemberKey: for realms listed in strip_realms the @REALM suffix is
// removed so `members:` can enumerate bare short names. This affects only the
// static lookup; the full user@REALM is still passed to the LDAP resolver so
// realm routing is unchanged.
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

	// Dedup requested principals: the per-group Casbin loop below need not
	// re-check the same principal, and a request padded with duplicates must
	// not inflate the per-request enforcement work. Order is irrelevant to the
	// all-must-be-allowed decision, and the granted principals returned to the
	// caller come from the matched group's config, not this slice.
	reqPrincipals := slices.Clone(requestedPrincipals)
	slices.Sort(reqPrincipals)
	reqPrincipals = slices.Compact(reqPrincipals)

	candidates, groupSources, ok := ca.candidateGroups(ctx, userPrincipal)
	if !ok || len(candidates) == 0 {
		return &AuthorizationResult{Allowed: false}, nil
	}

	selfUID, selfOK := ca.selfEligibleUID(userPrincipal)

	for _, groupName := range candidates {
		allAllowed := true
		sawGroupCheckedPrincipal := false
		for _, reqPrincipal := range reqPrincipals {
			if selfOK && reqPrincipal == selfUID {
				// The caller's own self-issuable uid rides along with
				// whatever this group actually grants; it is never the
				// reason a group fails to match.
				continue
			}
			sawGroupCheckedPrincipal = true
			allowed, err := ca.enforcer.Enforce(groupName, reqPrincipal, "sign")
			if err != nil {
				return nil, fmt.Errorf("casbin enforcement error: %w", err)
			}
			if !allowed {
				allAllowed = false
				break
			}
		}
		// sawGroupCheckedPrincipal guards against a solo self-uid request
		// trivially "matching" the first candidate group purely because
		// every requested principal was self-skipped — that case belongs to
		// the dedicated self-fallback, not to an unrelated group's rules.
		if allAllowed && sawGroupCheckedPrincipal {
			return &AuthorizationResult{
				Allowed:          true,
				GroupName:        groupName,
				CertificateRules: ca.groupRules[groupName],
				Source:           groupSources[groupName],
			}, nil
		}
	}

	return &AuthorizationResult{Allowed: false}, nil
}

// candidateGroups returns the user's candidate Cerberus groups, deduplicated
// and sorted alphabetically, together with a map from each candidate group name
// to the source that contributed it ("static" | "ldap" | "oidc"). The candidate
// set depends on how the request was authenticated:
//
//   - OIDC-authenticated requests (marked via WithAssertedGroups) are authorized
//     SOLELY from `oidc_groups:` bindings matched against the token's asserted
//     groups — never static `members:` or LDAP. This keeps the OIDC identity in
//     its own namespace, so an OIDC principal can never match a static or LDAP
//     group even if its synthetic realm label collides with a Kerberos/LDAP
//     realm.
//   - Kerberos requests are authorized from static `members:` plus LDAP-backed
//     `ldap_groups:`, exactly as before OIDC support existed.
//
// ok is false with no groups when authorization must fail closed — a configured
// LDAP resolver returned an error for a Kerberos principal — mirroring
// Authorize's fail-closed semantics. This is the single source of the
// candidate-set computation shared by Authorize and AuthorizeAll.
func (ca *CasbinAuthorizer) candidateGroups(ctx context.Context, userPrincipal string) (candidates []string, sources map[string]string, ok bool) {
	sources = map[string]string{}

	// OIDC-authenticated request: authorize solely via oidc_groups. Static
	// members: and LDAP are deliberately not consulted (namespace isolation).
	if asserted, isOIDC := oidcAssertionFromContext(ctx); isOIDC {
		if len(asserted) > 0 && len(ca.oidcGroupBindings) > 0 {
			want := make(map[string]struct{}, len(asserted))
			for _, g := range asserted {
				want[g] = struct{}{}
			}
			for groupName, boundVals := range ca.oidcGroupBindings {
				for v := range boundVals {
					if _, hit := want[v]; hit {
						candidates = append(candidates, groupName)
						sources[groupName] = "oidc"
						break
					}
				}
			}
		}
		slices.Sort(candidates)
		candidates = slices.Compact(candidates)
		return candidates, sources, true
	}

	// Kerberos request: static `members:` membership.
	for _, g := range ca.userGroups[ca.staticMemberKey(userPrincipal)] {
		candidates = append(candidates, g)
		sources[g] = "static"
	}

	// LDAP-backed `ldap_groups:` membership, resolved at request time. A
	// configured resolver that errors for this principal fails closed.
	if ca.resolver != nil {
		dns, resolved, err := ca.resolver.GroupsForPrincipal(ctx, userPrincipal)
		if err != nil {
			slog.Warn("authz.ldap.error",
				"principal", userPrincipal,
				"error", err)
			return nil, nil, false
		}
		if resolved {
			// The "match" half of LDAP debugging. dns are the user's group DNs
			// straight from the directory; matching lowercases both sides
			// (normalizeDN) and compares full DNs. If a user has DNs here but no
			// ldap.binding.match line follows, the `ldap_groups:` config values
			// do not equal any of these DNs — almost always because they were
			// written as a bare CN (`rootusers`) instead of the full DN
			// (`cn=rootusers,cn=groups,...`).
			slog.Debug("authz.ldap.resolved", "principal", userPrincipal, "dn_count", len(dns), "dns", dns)
			for groupName, boundDNs := range ca.ldapGroupBindings {
				for _, dn := range dns {
					if _, hit := boundDNs[normalizeDN(dn)]; hit {
						candidates = append(candidates, groupName)
						if _, taken := sources[groupName]; !taken {
							sources[groupName] = "ldap"
						}
						slog.Debug("authz.ldap.binding.match", "principal", userPrincipal, "group", groupName, "dn", dn)
						break
					}
				}
			}
		}
	}

	// Deduplicate (a name could appear via both static and LDAP if a future
	// config relaxation allowed it) and sort to preserve the established
	// first-alphabetical-wins precedence rule.
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	return candidates, sources, true
}

// AuthorizeAll implements the all-principals expansion group selection: it
// returns the first alphabetical group the user belongs to, with that group's
// CertificateRules. It does not consult requested principals — the caller
// expands CertificateRules.AllowedPrincipals and must refuse a "*" group. The
// same fail-closed LDAP semantics as Authorize apply.
func (ca *CasbinAuthorizer) AuthorizeAll(ctx context.Context, userPrincipal string) (*AuthorizationResult, error) {
	candidates, groupSources, ok := ca.candidateGroups(ctx, userPrincipal)
	if !ok || len(candidates) == 0 {
		return &AuthorizationResult{Allowed: false}, nil
	}

	groupName := candidates[0]
	return &AuthorizationResult{
		Allowed:          true,
		GroupName:        groupName,
		CertificateRules: ca.groupRules[groupName],
		Source:           groupSources[groupName],
	}, nil
}

// selfDenySet builds the self-issuance denylist from config. There is no
// hardcoded floor: self_principal is how Cerberus replaces static root SSH
// keys, so a caller's own uid — including "root" — is self-issuable unless an
// operator explicitly lists it in self_principal.deny.
func selfDenySet(deny []string) map[string]struct{} {
	m := make(map[string]struct{}, len(deny))
	for _, d := range deny {
		m[d] = struct{}{}
	}
	return m
}

// selfEligibleUID extracts the short uid from userPrincipal and reports
// whether self_principal currently permits that uid to be self-issued:
// self_principal is enabled, the caller's realm is in the allowlist, and the
// uid is neither empty, "*", nor on the operator-configured denylist. It
// contains no group or Casbin logic — AuthorizeSelf and Authorize both call
// this as the single source of self-eligibility, so a caller's own uid is
// judged identically whether requested alone or alongside a group-granted
// principal.
func (ca *CasbinAuthorizer) selfEligibleUID(userPrincipal string) (uid string, ok bool) {
	if !ca.selfOn {
		return "", false
	}
	at := strings.LastIndex(userPrincipal, "@")
	if at < 0 {
		return "", false
	}
	uid = userPrincipal[:at]
	realm := userPrincipal[at+1:]
	if uid == "" || realm == "" || uid == "*" {
		return "", false
	}
	if _, ok := ca.selfRealms[realm]; !ok {
		return "", false
	}
	if _, denied := ca.selfDeny[uid]; denied {
		return "", false
	}
	return uid, true
}

// AuthorizeSelf implements the self-service path: userPrincipal may obtain a
// certificate for its own short uid. It is independent of group membership —
// it never consults Casbin or userGroups, so no group the caller belongs to
// can block or shadow this path. On success the caller issues a cert for the
// uid using the returned CertificateRules. ctx is unused (no I/O) but kept
// for interface symmetry.
func (ca *CasbinAuthorizer) AuthorizeSelf(_ context.Context, userPrincipal string) (*AuthorizationResult, error) {
	if _, ok := ca.selfEligibleUID(userPrincipal); !ok {
		return &AuthorizationResult{Allowed: false}, nil
	}
	return &AuthorizationResult{
		Allowed:          true,
		GroupName:        "self",
		CertificateRules: ca.selfRules,
		Source:           "self",
	}, nil
}

// realmSet builds a lookup set from a list of Kerberos realms, returning nil
// for an empty list so callers can treat "no stripping configured" as a cheap
// nil check.
func realmSet(realms []string) map[string]struct{} {
	if len(realms) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(realms))
	for _, r := range realms {
		m[r] = struct{}{}
	}
	return m
}

// staticMemberKey returns the key used to look up static `members:`
// authorization for an authenticated principal. When the principal's realm is
// listed in strip_realms, the trailing @REALM is removed so operators can
// enumerate members by bare short name. Principals in unlisted realms — and
// principals with no realm — are returned unchanged, so cross-realm identities
// never collapse onto the same key. The realm is taken as everything after the
// final '@' (Kerberos short names may themselves be multi-component but do not
// contain '@'); only this static lookup is affected — the LDAP resolver still
// receives the full user@REALM string for realm routing.
func (ca *CasbinAuthorizer) staticMemberKey(userPrincipal string) string {
	if len(ca.stripRealms) == 0 {
		return userPrincipal
	}
	at := strings.LastIndex(userPrincipal, "@")
	if at < 0 {
		return userPrincipal
	}
	realm := userPrincipal[at+1:]
	if _, strip := ca.stripRealms[realm]; strip {
		return userPrincipal[:at]
	}
	return userPrincipal
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
