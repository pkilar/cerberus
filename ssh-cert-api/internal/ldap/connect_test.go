package ldap

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

type fakeSRVResolver struct {
	recs  []*net.SRV
	err   error
	calls int
}

func (f *fakeSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.calls++
	return "", f.recs, f.err
}

func TestURLTarget(t *testing.T) {
	tests := []struct {
		url      string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"ldaps://ad.corp.example:636", "ad.corp.example", 636, false},
		{"ldaps://ad.corp.example", "ad.corp.example", 636, false},
		{"ldap://ad.corp.example", "ad.corp.example", 389, false},
		{"ldap://ad.corp.example:1389", "ad.corp.example", 1389, false},
		{"ldaps://", "", 0, true},
	}
	for _, tt := range tests {
		got, err := urlTarget(tt.url)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tt.url)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tt.url, err)
		}
		if got.host != tt.wantHost || got.port != tt.wantPort {
			t.Fatalf("%s: got %+v, want {%s %d}", tt.url, got, tt.wantHost, tt.wantPort)
		}
	}
}

func TestEffectiveTLSMode(t *testing.T) {
	cases := []struct {
		b    config.LDAPBackend
		want string
	}{
		{config.LDAPBackend{URL: "ldaps://x:636"}, config.LDAPTLSModeLDAPS},
		{config.LDAPBackend{URL: "ldap://x:389"}, config.LDAPTLSModeNone},
		{config.LDAPBackend{SRV: &config.LDAPSRV{Domain: "x"}, TLSMode: config.LDAPTLSModeStartTLS}, config.LDAPTLSModeStartTLS},
		{config.LDAPBackend{SRV: &config.LDAPSRV{Domain: "x"}, TLSMode: config.LDAPTLSModeLDAPS}, config.LDAPTLSModeLDAPS},
		{config.LDAPBackend{SRV: &config.LDAPSRV{Domain: "x"}, TLSMode: config.LDAPTLSModeNone}, config.LDAPTLSModeNone},
	}
	for _, c := range cases {
		if got := effectiveTLSMode(c.b); got != c.want {
			t.Fatalf("%+v: got %q want %q", c.b, got, c.want)
		}
	}
}

func TestPlanDial(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS12}

	ldaps := &client{backend: config.LDAPBackend{URL: "ldaps://x:636"}, tlsBase: base}
	p := ldaps.planDial(target{host: "dc1", port: 636})
	if p.dialURL != "ldaps://dc1:636" || p.startTLS || p.tlsConfig == nil || p.tlsConfig.ServerName != "dc1" {
		t.Fatalf("ldaps plan = %+v", p)
	}

	starttls := &client{backend: config.LDAPBackend{SRV: &config.LDAPSRV{Domain: "x"}, TLSMode: config.LDAPTLSModeStartTLS}, tlsBase: base}
	p = starttls.planDial(target{host: "dc2", port: 389})
	if p.dialURL != "ldap://dc2:389" || !p.startTLS || p.tlsConfig == nil || p.tlsConfig.ServerName != "dc2" {
		t.Fatalf("starttls plan = %+v", p)
	}

	none := &client{backend: config.LDAPBackend{SRV: &config.LDAPSRV{Domain: "x"}, TLSMode: config.LDAPTLSModeNone}}
	p = none.planDial(target{host: "dc3", port: 389})
	if p.dialURL != "ldap://dc3:389" || p.startTLS || p.tlsConfig != nil {
		t.Fatalf("none plan = %+v", p)
	}
}

func TestOrderedTargets_URL(t *testing.T) {
	c := &client{backend: config.LDAPBackend{URL: "ldaps://ad.corp.example:636"}}
	got, err := c.orderedTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (target{"ad.corp.example", 636}) {
		t.Fatalf("got %+v", got)
	}
}

func TestOrderedTargets_SRVCaching(t *testing.T) {
	f := &fakeSRVResolver{recs: []*net.SRV{{Target: "dc1.", Port: 389, Priority: 0, Weight: 0}}}
	c := &client{
		backend: config.LDAPBackend{
			Name:    "corp",
			SRV:     &config.LDAPSRV{Domain: "corp.example.com", Service: "ldap", Proto: "tcp", CacheTTL: time.Minute},
			TLSMode: config.LDAPTLSModeStartTLS,
		},
		resolver: f,
	}
	ctx := context.Background()

	got, err := c.orderedTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (target{"dc1", 389}) {
		t.Fatalf("got %+v", got)
	}
	if _, err := c.orderedTargets(ctx); err != nil { // within TTL -> cached
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Fatalf("expected 1 lookup (cache reuse), got %d", f.calls)
	}
	c.srvExpires = time.Now().Add(-time.Second) // force expiry
	if _, err := c.orderedTargets(ctx); err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 {
		t.Fatalf("expected re-resolve after expiry, got %d lookups", f.calls)
	}
}

func TestOrderedTargets_SRVNoUsableTargets(t *testing.T) {
	f := &fakeSRVResolver{recs: []*net.SRV{{Target: ".", Port: 0}}}
	c := &client{
		backend:  config.LDAPBackend{Name: "corp", SRV: &config.LDAPSRV{Domain: "x", Service: "ldap", Proto: "tcp", CacheTTL: time.Minute}, TLSMode: config.LDAPTLSModeNone},
		resolver: f,
	}
	if _, err := c.orderedTargets(context.Background()); err == nil {
		t.Fatal("expected error for single-dot (no usable targets)")
	}
}
