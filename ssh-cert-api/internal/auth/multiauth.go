package auth

import (
	"fmt"
	"net/http"
	"strings"
)

var _ Authenticator = (*MultiAuthenticator)(nil)

// MultiAuthenticator dispatches a request to the Kerberos or OIDC authenticator
// by the Authorization scheme, letting both methods coexist behind the single
// Authenticator the API server depends on. A request with no Authorization
// header returns ErrNoAuthorizationHeader so the middleware's SPNEGO
// challenge/response round-trip (WWW-Authenticate) still fires. It is
// constructed only when OIDC is enabled; when disabled, main wires the bare
// KerberosAuthenticator instead and behavior is unchanged.
type MultiAuthenticator struct {
	kerberos Authenticator
	oidc     Authenticator
}

// NewMultiAuthenticator returns a dispatcher over the two authenticators. Both
// are expected to be non-nil.
func NewMultiAuthenticator(kerberos, oidc Authenticator) *MultiAuthenticator {
	return &MultiAuthenticator{kerberos: kerberos, oidc: oidc}
}

func (m *MultiAuthenticator) AuthenticateRequest(r *http.Request) (*AuthenticatedUser, error) {
	authHeader := r.Header.Get("Authorization")
	switch {
	case authHeader == "":
		return nil, ErrNoAuthorizationHeader
	case strings.HasPrefix(authHeader, "Negotiate "):
		return m.kerberos.AuthenticateRequest(r)
	case strings.HasPrefix(authHeader, "Bearer "):
		if m.oidc == nil {
			return nil, fmt.Errorf("bearer authentication is not enabled")
		}
		return m.oidc.AuthenticateRequest(r)
	default:
		return nil, fmt.Errorf("unsupported authorization scheme")
	}
}
