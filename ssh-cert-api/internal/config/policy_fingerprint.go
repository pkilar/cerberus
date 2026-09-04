package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// policyDigestView is the subset of the configuration that decides who may
// obtain which certificate principals. It deliberately excludes transport and
// credential settings (keytab, TLS, listen address, LDAP backends, OAuth) so
// the fingerprint carries no secret-derived material and does not churn on
// unrelated edits.
type policyDigestView struct {
	Groups        map[string]Group
	StripRealms   []string
	SelfPrincipal SelfPrincipalConfig
}

// PolicyFingerprint returns a stable SHA-256 hex digest of the authorization
// policy (groups, strip_realms, self_principal). The host returns it on every
// successful /sign response and from GET /policy so a client can tell that a
// cached certificate was issued under a policy that has since changed — for
// example a principal mapping enabled after the certificate was minted — and
// re-sign instead of reusing the certificate until it expires. encoding/json
// sorts map keys, so the digest is deterministic across processes and hosts
// that load the same configuration.
func (c *Config) PolicyFingerprint() string {
	view := policyDigestView{Groups: c.Groups, StripRealms: c.StripRealms, SelfPrincipal: c.SelfPrincipal}
	data, err := json.Marshal(view)
	if err != nil {
		// The view holds only strings, slices, maps and structs of those, so
		// Marshal cannot fail today; keep the function total rather than panic.
		return "unavailable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
