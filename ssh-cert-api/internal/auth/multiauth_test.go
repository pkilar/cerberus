package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubAuth records whether it was invoked so dispatch routing can be asserted.
type stubAuth struct {
	user  *AuthenticatedUser
	err   error
	calls int
}

func (s *stubAuth) AuthenticateRequest(_ *http.Request) (*AuthenticatedUser, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.user, nil
}

func TestMultiAuthenticator_Dispatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		authHeader   string // "" means unset
		wantKerberos int
		wantOIDC     int
		wantSentinel bool
		wantErr      bool
	}{
		{name: "no header returns sentinel", authHeader: "", wantSentinel: true, wantErr: true},
		{name: "negotiate routes to kerberos", authHeader: "Negotiate abc", wantKerberos: 1},
		{name: "bearer routes to oidc", authHeader: "Bearer abc", wantOIDC: 1},
		{name: "unknown scheme errors", authHeader: "Basic abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kerb := &stubAuth{user: &AuthenticatedUser{Username: "k", Method: "kerberos"}}
			oidc := &stubAuth{user: &AuthenticatedUser{Username: "o", Method: "oidc"}}
			m := NewMultiAuthenticator(kerb, oidc)

			r := httptest.NewRequest(http.MethodPost, "/sign", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			_, err := m.AuthenticateRequest(r)

			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantSentinel && !errors.Is(err, ErrNoAuthorizationHeader) {
				t.Fatalf("error = %v, want ErrNoAuthorizationHeader", err)
			}
			if kerb.calls != tt.wantKerberos {
				t.Errorf("kerberos calls = %d, want %d", kerb.calls, tt.wantKerberos)
			}
			if oidc.calls != tt.wantOIDC {
				t.Errorf("oidc calls = %d, want %d", oidc.calls, tt.wantOIDC)
			}
		})
	}
}

func TestMultiAuthenticator_BearerWithoutOIDC(t *testing.T) {
	t.Parallel()
	m := NewMultiAuthenticator(&stubAuth{}, nil)
	r := httptest.NewRequest(http.MethodPost, "/sign", nil)
	r.Header.Set("Authorization", "Bearer abc")
	if _, err := m.AuthenticateRequest(r); err == nil {
		t.Fatal("bearer with nil oidc authenticator must error, not panic")
	}
}
