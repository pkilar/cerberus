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
// into a plain entry. Content rules (empty names, "*" restrictions, conflicting
// duplicates) live in PrincipalRules.validate so programmatic configs are held
// to the same standard as YAML ones.
func (rs *PrincipalRules) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("allowed_principals at line %d: expected a sequence, got %s", n.Line, nodeKindName(n))
	}
	out := make(PrincipalRules, 0, len(n.Content))
	for _, item := range n.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			out = append(out, PrincipalRule{Requested: item.Value, Issued: item.Value})
		case yaml.MappingNode:
			// A mapping node's Content alternates key, value.
			if len(item.Content) != 2 {
				return fmt.Errorf("allowed_principals item at line %d: a mapping item must have exactly one key/value pair, got %d",
					item.Line, len(item.Content)/2)
			}
			key, val := item.Content[0], item.Content[1]
			if key.Kind != yaml.ScalarNode {
				return fmt.Errorf("allowed_principals item at line %d: mapping key must be a scalar, got %s", key.Line, nodeKindName(key))
			}
			if val.Kind != yaml.ScalarNode {
				return fmt.Errorf("allowed_principals item at line %d: target of %q must be a single scalar, got %s",
					val.Line, key.Value, nodeKindName(val))
			}
			if val.Tag == "!!null" {
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
func (rs PrincipalRules) Issued() []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Issued)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Resolve returns the certificate name for a requested name that has already
// been authorized against this list: the Issued name of the first rule whose
// Requested matches, else the requested name itself (it was covered by "*").
func (rs PrincipalRules) Resolve(requested string) string {
	for _, r := range rs {
		if r.Requested == requested {
			return r.Issued
		}
	}
	return requested
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
