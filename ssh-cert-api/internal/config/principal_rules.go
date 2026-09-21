package config

import (
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// PrincipalRule is one allowed_principals entry: the name a caller may request
// (Requested) and the name written into the certificate (Issued). A plain YAML
// scalar yields an identity rule (Issued == Requested); a single-pair mapping
// `requested: issued` yields a mapping rule. "*" is only meaningful as a plain
// entry (the Casbin policy wildcard) and is never issued.
//
// Casbin policy is keyed on Requested only, so a mapping target is not itself
// requestable unless a plain entry or "*" in the same group covers it. A mapped
// certificate carries only Issued — never Requested as well — otherwise a role
// principal such as webserver-root would still open the root account on any
// host without an AuthorizedPrincipalsFile.
type PrincipalRule struct {
	Requested string
	Issued    string
}

// Mapped reports whether the rule rewrites the requested name.
func (r PrincipalRule) Mapped() bool { return r.Requested != r.Issued }

// SelfTarget is the reserved allowed_principals mapping target that resolves,
// per request, to the caller's own short uid — the same principal the
// top-level self_principal block issues. `- root: $self` means "a member
// requesting root receives a certificate for their own uid", which is how a
// group hands out identity-scoped certificates that sshd's
// AuthorizedPrincipalsFile maps back onto a shared account. The "$" prefix is
// reserved: it needs no YAML quoting (unlike "*" and "%", which are YAML
// indicator characters), it cannot collide with a POSIX account name, and any
// other $-prefixed target is refused at config load.
const SelfTarget = "$self"

// PrincipalRules is the parsed allowed_principals list, in YAML order.
type PrincipalRules []PrincipalRule

// PlainPrincipals builds identity rules — the pre-mapping shape of
// allowed_principals. Used by tests and programmatic callers.
func PlainPrincipals(names ...string) PrincipalRules {
	rs := make(PrincipalRules, 0, len(names))
	for _, n := range names {
		rs = append(rs, PrincipalRule{Requested: n, Issued: n})
	}
	return rs
}

// UnmarshalYAML implements yaml.Unmarshaler. allowed_principals must be a
// sequence whose items are either scalars (identity rules) or single-pair
// mappings with a scalar key and a scalar value (mapping rules). Every other
// shape is a hard error carrying the YAML line so the operator can find the
// typo — in particular a `- root:` trailing colon must not silently degrade
// into a plain entry. Aliases (`- *name`, `root: *name`) are resolved to their
// anchored node; null items are rejected. Content rules (empty names, "*"
// restrictions, conflicting duplicates) live in PrincipalRules.validate so
// programmatic configs are held to the same standard as YAML ones.
func (rs *PrincipalRules) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("allowed_principals at line %d: expected a sequence, got %s", n.Line, nodeKindName(n))
	}
	out := make(PrincipalRules, 0, len(n.Content))
	for _, item := range n.Content {
		// A YAML alias (`- *name`) stands for its anchored node; resolve it so a
		// shared anchor keeps working — every pre-mapping config must parse
		// unchanged. yaml.v3 never nests aliases, so one hop suffices.
		if item.Kind == yaml.AliasNode && item.Alias != nil {
			item = item.Alias
		}
		switch item.Kind {
		case yaml.ScalarNode:
			// `- ~`, `- null` and a bare `-` are !!null scalars, not principal
			// names; reject them here with the line number rather than letting
			// validate() report a confusing empty/"null" principal later.
			if item.ShortTag() == "!!null" {
				return fmt.Errorf("allowed_principals item at line %d is null (write the principal name, or remove the item)", item.Line)
			}
			out = append(out, PrincipalRule{Requested: item.Value, Issued: item.Value})
		case yaml.MappingNode:
			// A mapping node's Content alternates key, value.
			if len(item.Content) != 2 {
				return fmt.Errorf("allowed_principals item at line %d: a mapping item must have exactly one key/value pair, got %d",
					item.Line, len(item.Content)/2)
			}
			key, val := item.Content[0], item.Content[1]
			if val.Kind == yaml.AliasNode && val.Alias != nil {
				val = val.Alias
			}
			if key.Kind != yaml.ScalarNode {
				return fmt.Errorf("allowed_principals item at line %d: mapping key must be a scalar, got %s", key.Line, nodeKindName(key))
			}
			if val.Kind != yaml.ScalarNode {
				return fmt.Errorf("allowed_principals item at line %d: target of %q must be a single scalar, got %s",
					val.Line, key.Value, nodeKindName(val))
			}
			if val.ShortTag() == "!!null" {
				return fmt.Errorf("allowed_principals item at line %d: %q has no target (a plain entry needs no colon)", key.Line, key.Value)
			}
			out = append(out, PrincipalRule{Requested: key.Value, Issued: val.Value})
		default:
			return fmt.Errorf("allowed_principals item at line %d: item must be a scalar or a single-pair mapping, got %s",
				item.Line, nodeKindName(item))
		}
	}
	*rs = out
	return nil
}

// nodeKindName renders a yaml.Node kind for error messages.
func nodeKindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.DocumentNode:
		return "a document"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.ScalarNode:
		return "a scalar"
	case yaml.AliasNode:
		return "an alias"
	}
	return "an unknown node"
}

// Requestable returns every Requested name in list order (including "*").
// This is the Casbin policy object set and the shape logged as
// group_allowed_principals on sign.success, so it stays a plain []string.
func (rs PrincipalRules) Requestable() []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Requested)
	}
	return out
}

// HasWildcard reports whether a plain "*" entry is present.
func (rs PrincipalRules) HasWildcard() bool {
	return slices.ContainsFunc(rs, func(r PrincipalRule) bool { return r.Requested == "*" })
}

// Issued returns the sorted, deduplicated certificate names for the whole
// list — what an all_principals expansion mints. Callers must refuse a
// wildcard group first (HasWildcard); "*" is otherwise returned verbatim.
//
// A SelfTarget entry contributes selfUID, the caller's own self-issuable uid,
// and contributes nothing when selfUID is empty (self_principal does not
// permit this caller that uid). A group whose entries are all SelfTarget
// therefore expands to an empty set for such a caller, which the /sign handler
// refuses rather than minting an empty certificate.
func (rs PrincipalRules) Issued(selfUID string) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.Issued == SelfTarget {
			if selfUID != "" {
				out = append(out, selfUID)
			}
			continue
		}
		out = append(out, r.Issued)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// FirstSelfTarget reports the first requested name whose target is SelfTarget.
// Config validation uses it to refuse a group that issues the caller's own uid
// while self_principal — which supplies the realm allowlist and denylist that
// gate uid issuance — is disabled.
func (rs PrincipalRules) FirstSelfTarget() (requested string, ok bool) {
	for _, r := range rs {
		if r.Issued == SelfTarget {
			return r.Requested, true
		}
	}
	return "", false
}

// Resolve returns the certificate name for a requested name that has already
// been authorized against this list: the Issued name of the first rule whose
// Requested matches, else the requested name itself (it was covered by "*").
//
// A rule targeting SelfTarget resolves to selfUID, the caller's own
// self-issuable uid. ok is false when such a rule matches but selfUID is empty,
// i.e. self_principal does not permit this caller that uid: the group does not
// cover this request, and the caller must move on to the next candidate group
// rather than issue anything.
func (rs PrincipalRules) Resolve(requested, selfUID string) (string, bool) {
	for _, r := range rs {
		if r.Requested != requested {
			continue
		}
		if r.Issued == SelfTarget {
			if selfUID == "" {
				return "", false
			}
			return selfUID, true
		}
		return r.Issued, true
	}
	return requested, true
}

// validate enforces the content rules for one group's allowed_principals.
// Shape rules live in UnmarshalYAML; these hold for programmatic configs too.
// Index i is the 0-based item position (YAML line numbers are gone by now).
func (rs PrincipalRules) validate(group string) error {
	seen := make(map[string]string, len(rs)) // requested -> issued
	for i, r := range rs {
		if strings.TrimSpace(r.Requested) == "" {
			return fmt.Errorf("group '%s': allowed_principals[%d] has an empty principal", group, i)
		}
		if strings.TrimSpace(r.Issued) == "" {
			return fmt.Errorf("group '%s': allowed_principals[%d]: mapping for '%s' has an empty target", group, i, r.Requested)
		}
		if strings.HasPrefix(strings.TrimSpace(r.Requested), "$") {
			return fmt.Errorf("group '%s': allowed_principals[%d]: %q is reserved and cannot be requested (it is only valid as a mapping target)",
				group, i, r.Requested)
		}
		if t := strings.TrimSpace(r.Issued); strings.HasPrefix(t, "$") && t != SelfTarget {
			return fmt.Errorf("group '%s': allowed_principals[%d]: unknown reserved target %q for '%s' (only %q is defined)",
				group, i, r.Issued, r.Requested, SelfTarget)
		}
		if r.Mapped() && strings.TrimSpace(r.Requested) == "*" {
			return fmt.Errorf("group '%s': allowed_principals[%d]: the wildcard '*' cannot be mapped", group, i)
		}
		if r.Mapped() && strings.TrimSpace(r.Issued) == "*" {
			return fmt.Errorf("group '%s': allowed_principals[%d]: '%s' cannot be mapped to the wildcard '*'", group, i, r.Requested)
		}
		if prev, dup := seen[r.Requested]; dup && prev != r.Issued {
			return fmt.Errorf("group '%s': principal '%s' is listed twice with different targets ('%s' and '%s')",
				group, r.Requested, prev, r.Issued)
		}
		seen[r.Requested] = r.Issued
	}
	return nil
}
