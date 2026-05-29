package ldap

import (
	"testing"
)

func TestSafeUserFilter_Escaping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		template string
		uid      string
		want     string
		wantErr  bool
	}{
		{
			name:     "plain uid",
			template: "(sAMAccountName=%s)",
			uid:      "alice",
			want:     "(sAMAccountName=alice)",
		},
		{
			name:     "asterisk wildcard is escaped",
			template: "(uid=%s)",
			uid:      "alice*",
			want:     `(uid=alice\2a)`,
		},
		{
			name:     "filter-syntax injection is neutralized",
			template: "(uid=%s)",
			uid:      "*)(uid=*",
			want:     `(uid=\2a\29\28uid=\2a)`,
		},
		{
			name:     "parentheses and backslash escaped",
			template: "(uid=%s)",
			uid:      `(weird\name)`,
			want:     `(uid=\28weird\5cname\29)`,
		},
		{
			name:     "null byte escaped",
			template: "(uid=%s)",
			uid:      "x\x00y",
			want:     `(uid=x\00y)`,
		},
		{
			name:     "missing placeholder fails",
			template: "(uid=fixed)",
			uid:      "alice",
			wantErr:  true,
		},
		{
			name:     "multiple placeholders fail",
			template: "(|(uid=%s)(sAMAccountName=%s))",
			uid:      "alice",
			wantErr:  true,
		},
		{
			// "%%s" looks like it has a "%s" but fmt reads "%%" as a literal
			// percent and drops the substitution — the dangerous case
			// strings.Count would have accepted.
			name:     "escaped percent before s is rejected",
			template: "(uid=%%s)",
			uid:      "alice",
			wantErr:  true,
		},
		{
			name:     "extra format verb is rejected",
			template: "(uid=%s)(level=%d)",
			uid:      "alice",
			wantErr:  true,
		},
		{
			name:     "stray trailing percent is rejected",
			template: "(uid=%s)(x=100%)",
			uid:      "alice",
			wantErr:  true,
		},
		{
			// A legitimate literal percent (escaped as %%) alongside the single
			// %s must still be accepted and rendered correctly.
			name:     "legitimate escaped percent is accepted",
			template: "(&(uid=%s)(x=50%%))",
			uid:      "alice",
			want:     "(&(uid=alice)(x=50%))",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := SafeUserFilter(tt.template, tt.uid)
			switch {
			case tt.wantErr && err == nil:
				t.Errorf("expected error, got %q", got)
			case !tt.wantErr && err != nil:
				t.Errorf("unexpected error: %v", err)
			case !tt.wantErr && got != tt.want:
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
