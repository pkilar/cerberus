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
