package config

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPlainPrincipals(t *testing.T) {
	t.Parallel()
	got := PlainPrincipals("root", "ec2-user")
	want := PrincipalRules{{Requested: "root", Issued: "root"}, {Requested: "ec2-user", Issued: "ec2-user"}}
	if !slices.Equal(got, want) {
		t.Fatalf("PlainPrincipals = %+v, want %+v", got, want)
	}
	if len(PlainPrincipals()) != 0 {
		t.Fatal("PlainPrincipals() should be empty, not nil-panicky")
	}
	for _, r := range got {
		if r.Mapped() {
			t.Fatalf("identity rule %+v reported Mapped()", r)
		}
	}
}

func TestPrincipalRules_UnmarshalYAML_Shapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		yaml    string
		want    PrincipalRules
		errPart string // substring expected in the error; empty means success
	}{
		{
			name: "plain scalars",
			yaml: "- root\n- \"ec2-user\"\n",
			want: PrincipalRules{{"root", "root"}, {"ec2-user", "ec2-user"}},
		},
		{
			name: "wildcard scalar",
			yaml: "- \"*\"\n",
			want: PrincipalRules{{"*", "*"}},
		},
		{
			name: "mapping item",
			yaml: "- root: global-root\n",
			want: PrincipalRules{{"root", "global-root"}},
		},
		{
			name: "mixed list keeps order",
			yaml: "- deploy\n- root: global-root\n- admin: global-root\n- \"*\"\n",
			want: PrincipalRules{{"deploy", "deploy"}, {"root", "global-root"}, {"admin", "global-root"}, {"*", "*"}},
		},
		{
			name: "unquoted non-string scalars keep their source text",
			yaml: "- 123\n- yes\n- 42: 7\n",
			want: PrincipalRules{{"123", "123"}, {"yes", "yes"}, {"42", "7"}},
		},
		{
			name: "empty sequence",
			yaml: "[]\n",
			want: PrincipalRules{},
		},
		{
			name:    "trailing colon (null target)",
			yaml:    "- root:\n",
			errPart: `"root" has no target (a plain entry needs no colon)`,
		},
		{
			name:    "explicit null target",
			yaml:    "- root: null\n",
			errPart: `"root" has no target`,
		},
		{
			name:    "multi-pair mapping",
			yaml:    "- {root: a, admin: b}\n",
			errPart: "a mapping item must have exactly one key/value pair, got 2",
		},
		{
			name:    "sequence target",
			yaml:    "- root: [a, b]\n",
			errPart: `target of "root" must be a single scalar, got a sequence`,
		},
		{
			name:    "mapping target",
			yaml:    "- root: {x: y}\n",
			errPart: `target of "root" must be a single scalar, got a mapping`,
		},
		{
			name:    "sequence item",
			yaml:    "- [a, b]\n",
			errPart: "item must be a scalar or a single-pair mapping, got a sequence",
		},
		{
			name:    "not a sequence",
			yaml:    "root\n",
			errPart: "expected a sequence, got a scalar",
		},
		{
			name:    "mapping instead of sequence",
			yaml:    "root: global-root\n",
			errPart: "expected a sequence, got a mapping",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got PrincipalRules
			err := yaml.Unmarshal([]byte(tc.yaml), &got)
			if tc.errPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (parsed %+v)", tc.errPart, got)
				}
				if !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errPart)
				}
				if !strings.Contains(err.Error(), "line ") {
					t.Fatalf("error %q should carry the YAML line number", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPrincipalRules_Helpers(t *testing.T) {
	t.Parallel()
	rs := PrincipalRules{
		{"deploy", "deploy"},
		{"root", "global-root"},
		{"admin", "global-root"}, // many-to-one
		{"*", "*"},
	}
	if got, want := rs.Requestable(), []string{"deploy", "root", "admin", "*"}; !slices.Equal(got, want) {
		t.Fatalf("Requestable = %v, want %v (list order, includes the wildcard)", got, want)
	}
	if !rs.HasWildcard() {
		t.Fatal("HasWildcard should be true")
	}
	if PlainPrincipals("root").HasWildcard() {
		t.Fatal("HasWildcard should be false without a plain * entry")
	}
	if got, want := rs.Issued(), []string{"*", "deploy", "global-root"}; !slices.Equal(got, want) {
		t.Fatalf("Issued = %v, want sorted+deduped %v", got, want)
	}
	if got := rs.Resolve("root"); got != "global-root" {
		t.Fatalf("Resolve(root) = %q, want global-root", got)
	}
	if got := rs.Resolve("deploy"); got != "deploy" {
		t.Fatalf("Resolve(deploy) = %q, want identity", got)
	}
	if got := rs.Resolve("anything-else"); got != "anything-else" {
		t.Fatalf("Resolve of a name covered only by * must pass through, got %q", got)
	}
	if !rs[1].Mapped() || rs[0].Mapped() {
		t.Fatal("Mapped() wrong for mapping/identity rules")
	}
}

func TestPrincipalRules_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rules   PrincipalRules
		errPart string
	}{
		{name: "plain ok", rules: PlainPrincipals("root", "ec2-user")},
		{name: "mapping ok", rules: PrincipalRules{{"root", "global-root"}}},
		{name: "wildcard plain ok", rules: PrincipalRules{{"*", "*"}, {"root", "global-root"}}},
		{name: "many-to-one ok", rules: PrincipalRules{{"root", "ops"}, {"admin", "ops"}}},
		{name: "exact duplicate tolerated", rules: PrincipalRules{{"root", "ops"}, {"root", "ops"}, {"a", "a"}, {"a", "a"}}},
		{name: "target also plain elsewhere ok", rules: PrincipalRules{{"root", "ops"}, {"ops", "ops"}}},
		{name: "empty requested", rules: PrincipalRules{{"", "x"}}, errPart: "allowed_principals[0] has an empty principal"},
		{name: "blank requested", rules: PrincipalRules{{"root", "root"}, {"  ", "  "}}, errPart: "allowed_principals[1] has an empty principal"},
		{name: "empty target", rules: PrincipalRules{{"root", ""}}, errPart: "allowed_principals[0]: mapping for 'root' has an empty target"},
		{name: "wildcard as key", rules: PrincipalRules{{"*", "global-root"}}, errPart: "the wildcard '*' cannot be mapped"},
		{name: "wildcard as target", rules: PrincipalRules{{"root", "*"}}, errPart: "'root' cannot be mapped to the wildcard '*'"},
		{name: "conflicting duplicate", rules: PrincipalRules{{"root", "a"}, {"root", "b"}}, errPart: "principal 'root' is listed twice with different targets ('a' and 'b')"},
		{name: "plain then mapped conflict", rules: PrincipalRules{{"root", "root"}, {"root", "global-root"}}, errPart: "principal 'root' is listed twice with different targets ('root' and 'global-root')"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.rules.validate("g1")
			if tc.errPart == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("error %v does not contain %q", err, tc.errPart)
			}
			if !strings.Contains(err.Error(), "group 'g1'") {
				t.Fatalf("error %v should name the group", err)
			}
		})
	}
}

func FuzzPrincipalRulesUnmarshal(f *testing.F) {
	for _, s := range []string{"- root\n", "- root: global-root\n", "- root:\n", "- [a]\n", "- {a: b, c: d}\n", "x\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		var rs PrincipalRules
		_ = yaml.Unmarshal([]byte(in), &rs) // must never panic; errors are fine
	})
}
