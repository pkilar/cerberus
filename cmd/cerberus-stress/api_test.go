package main

import (
	"strings"
	"testing"
)

func TestDeriveSPN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		url       string
		want      string
		wantError bool
		errSubstr string
	}{
		{
			name: "plain hostname",
			url:  "https://signer.example.com/sign",
			want: "HTTP/signer.example.com",
		},
		{
			name: "host with explicit port - port stripped from SPN",
			url:  "https://signer.example.com:8443/sign",
			want: "HTTP/signer.example.com",
		},
		{
			name: " ipv6 literal - bracket-stripped",
			url:  "https://[::1]:8443/sign",
			want: "HTTP/::1",
		},
		{
			name: "ipv4 literal - passes through verbatim (KDC will reject if not registered)",
			url:  "https://127.0.0.1:8443/sign",
			want: "HTTP/127.0.0.1",
		},
		{
			name: "case preserved - no lowercasing",
			url:  "https://Signer.Example.COM/sign",
			want: "HTTP/Signer.Example.COM",
		},
		{
			name:      "empty url",
			url:       "",
			wantError: true,
			errSubstr: "no host",
		},
		{
			name:      "relative path with no host",
			url:       "/sign",
			wantError: true,
			errSubstr: "no host",
		},
		{
			name:      "malformed url with control byte",
			url:       "https://example.com\x7f/sign",
			wantError: true,
			errSubstr: "parse url",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := deriveSPN(tt.url)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error containing %q, got SPN %q", tt.errSubstr, got)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %v does not contain %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("deriveSPN(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
