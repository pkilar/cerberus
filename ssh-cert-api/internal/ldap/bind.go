package ldap

import (
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

// bindCreds is the runtime form of an LDAPBind: the password file has been
// read into memory (simple), and the GSSAPI parameters have been split into
// username/realm/keytab/krb5conf. Anonymous holds no fields.
type bindCreds struct {
	method string

	// simple
	dn       string
	password string

	// gssapi
	gssUsername  string
	gssRealm     string
	keytabPath   string
	krb5ConfPath string
}

func newBindCreds(backend config.LDAPBackend, keytabPath, password string) (*bindCreds, error) {
	bc := &bindCreds{method: backend.Bind.Method}
	switch backend.Bind.Method {
	case config.LDAPBindSimple:
		bc.dn = backend.Bind.DN
		bc.password = password
	case config.LDAPBindAnonymous:
		// no-op
	case config.LDAPBindGSSAPI:
		username, realm, ok := strings.Cut(backend.Bind.ClientPrincipal, "@")
		if !ok || username == "" || realm == "" {
			return nil, fmt.Errorf("client_principal %q must be user@REALM", backend.Bind.ClientPrincipal)
		}
		bc.gssUsername = username
		bc.gssRealm = realm
		bc.keytabPath = keytabPath
		bc.krb5ConfPath = backend.Bind.Krb5ConfPath
	default:
		return nil, fmt.Errorf("unknown bind method %q", backend.Bind.Method)
	}
	return bc, nil
}

// ldapServerSPN returns the conventional SPN of an LDAP server: "ldap/<host>".
// The host is the one actually dialed (URL host or SRV-discovered target), so
// a gssapi bind names the server it reached.
func ldapServerSPN(host string) string {
	return "ldap/" + host
}

// bind runs the configured bind sequence against conn. Returns an error
// classified as "bind" by the caller for metrics — see client.fetchUserGroups.
func bind(conn *goldap.Conn, bc *bindCreds, spn string) error {
	switch bc.method {
	case config.LDAPBindSimple:
		return conn.Bind(bc.dn, bc.password)
	case config.LDAPBindAnonymous:
		return conn.UnauthenticatedBind("")
	case config.LDAPBindGSSAPI:
		gssClient, err := ldapgssapi.NewClientWithKeytab(bc.gssUsername, bc.gssRealm, bc.keytabPath, bc.krb5ConfPath)
		if err != nil {
			return fmt.Errorf("gssapi client init: %w", err)
		}
		// The gssapi.Client holds an active security context and must be
		// closed after the bind exchange. The LDAP session itself stays open.
		defer func() { _ = gssClient.Close() }()
		return conn.GSSAPIBind(gssClient, spn, "")
	default:
		return fmt.Errorf("unknown bind method %q", bc.method)
	}
}
