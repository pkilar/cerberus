package config

import (
	"regexp"
	"testing"
	"time"
)

// fingerprintConfig builds a two-group policy; mapped=true turns the sysadmins
// root entry into a mapping, which must change the fingerprint.
func fingerprintConfig(mapped bool) *Config {
	rules := PlainPrincipals("root", "ec2-user")
	if mapped {
		rules = PrincipalRules{{Requested: "root", Issued: "global-root"}, {Requested: "ec2-user", Issued: "ec2-user"}}
	}
	return &Config{
		KeytabPath: "/etc/krb5.keytab",
		Listen:     ":8443",
		Groups: map[string]Group{
			"sysadmins":  {Members: []string{"dave@REALM.COM"}, CertificateRules: CertificateRules{Validity: "8h", AllowedPrincipals: rules}},
			"webmasters": {Members: []string{"erin@REALM.COM"}, CertificateRules: CertificateRules{Validity: "4h", AllowedPrincipals: PlainPrincipals("www")}},
		},
	}
}

func TestPolicyFingerprint_ShapeAndDeterminism(t *testing.T) {
	t.Parallel()
	fp := fingerprintConfig(false).PolicyFingerprint()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fp) {
		t.Fatalf("fingerprint %q is not 64 lowercase hex chars", fp)
	}
	if again := fingerprintConfig(false).PolicyFingerprint(); again != fp {
		t.Fatalf("same policy produced different fingerprints: %s vs %s", fp, again)
	}
}

func TestPolicyFingerprint_IgnoresNonPolicyFields(t *testing.T) {
	t.Parallel()
	base := fingerprintConfig(false).PolicyFingerprint()
	c := fingerprintConfig(false)
	c.Listen = ":9443"
	c.KeytabPath = "/other/keytab"
	c.TlsCert = "/x/cert.pem"
	c.EnclaveMetricsInterval = 42 * time.Second
	c.OAuth.Enabled = true
	if got := c.PolicyFingerprint(); got != base {
		t.Fatalf("transport/credential fields must not affect the fingerprint: %s vs %s", got, base)
	}
}

func TestPolicyFingerprint_ChangesWithPolicy(t *testing.T) {
	t.Parallel()
	base := fingerprintConfig(false).PolicyFingerprint()
	if got := fingerprintConfig(true).PolicyFingerprint(); got == base {
		t.Fatal("enabling a principal mapping must change the fingerprint")
	}
	c := fingerprintConfig(false)
	wm := c.Groups["webmasters"]
	wm.Members = append(wm.Members, "frank@REALM.COM")
	c.Groups["webmasters"] = wm
	if got := c.PolicyFingerprint(); got == base {
		t.Fatal("changing a group's members must change the fingerprint")
	}
	c = fingerprintConfig(false)
	c.StripRealms = []string{"REALM.COM"}
	if got := c.PolicyFingerprint(); got == base {
		t.Fatal("strip_realms must be part of the fingerprint")
	}
	c = fingerprintConfig(false)
	c.SelfPrincipal = SelfPrincipalConfig{Enabled: true, Realms: []string{"REALM.COM"}, CertificateRules: CertificateRules{Validity: "1h"}}
	if got := c.PolicyFingerprint(); got == base {
		t.Fatal("self_principal must be part of the fingerprint")
	}
}

func TestPolicyFingerprint_MapOrderIndependent(t *testing.T) {
	t.Parallel()
	a := fingerprintConfig(false)
	b := &Config{Groups: map[string]Group{}}
	b.Groups["webmasters"] = a.Groups["webmasters"]
	b.Groups["sysadmins"] = a.Groups["sysadmins"]
	if a.PolicyFingerprint() != b.PolicyFingerprint() {
		t.Fatal("fingerprint must not depend on map insertion order or on non-policy fields")
	}
}
