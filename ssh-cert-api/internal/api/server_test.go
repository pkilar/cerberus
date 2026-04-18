package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cerberus/messages"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/authz"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"
)

// --- Test doubles for the three injection points on Server. ---

type fakeAuthenticator struct {
	user *auth.AuthenticatedUser
	err  error
}

func (f *fakeAuthenticator) AuthenticateRequest(*http.Request) (*auth.AuthenticatedUser, error) {
	return f.user, f.err
}

type fakeAuthorizer struct {
	result *authz.AuthorizationResult
	err    error
}

func (f *fakeAuthorizer) Authorize(string, []string) (*authz.AuthorizationResult, error) {
	return f.result, f.err
}

type fakeSigner struct {
	signed string
	err    error
	got    *messages.EnclaveSigningRequest
}

func (f *fakeSigner) SignPublicKey(req *messages.EnclaveSigningRequest) (string, error) {
	f.got = req
	return f.signed, f.err
}

func (f *fakeSigner) Close() error { return nil }

// newServerForTest constructs a Server with fake dependencies. A fresh Server
// gets a fresh rate-limiter, isolating tests from each other despite the
// package-level Prometheus counters.
func newServerForTest(t *testing.T, authN auth.Authenticator, authZ authz.Authorizer, signer enclave.Signer) *Server {
	t.Helper()
	s, err := NewServer(&config.Config{}, authN, authZ, signer)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// --- Tests ---

func TestHandleSignRequest(t *testing.T) {
	validRules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: []string{"root"},
		Permissions:       map[string]string{"permit-pty": ""},
		StaticAttributes:  map[string]string{"env": "test"},
	}
	validBody := `{"ssh_key":"ssh-rsa AAAAB3NzaC1yc2E","principals":["root"]}`

	tests := []struct {
		name         string
		method       string
		body         string
		authzResult  *authz.AuthorizationResult
		authzErr     error
		signerSigned string
		signerErr    error
		wantStatus   int
		wantBodyPart string
	}{
		{
			name:         "success",
			method:       http.MethodPost,
			body:         validBody,
			authzResult:  &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: validRules},
			signerSigned: "ssh-rsa-cert-v01@openssh.com AAAA...",
			wantStatus:   http.StatusOK,
			wantBodyPart: `"signed_key":`,
		},
		{
			name:         "method_not_allowed",
			method:       http.MethodGet,
			body:         "",
			wantStatus:   http.StatusMethodNotAllowed,
			wantBodyPart: "Method not allowed",
		},
		{
			name:         "invalid_json",
			method:       http.MethodPost,
			body:         "{not json",
			wantStatus:   http.StatusBadRequest,
			wantBodyPart: "Invalid request format",
		},
		{
			name:         "missing_ssh_key",
			method:       http.MethodPost,
			body:         `{"principals":["root"]}`,
			wantStatus:   http.StatusBadRequest,
			wantBodyPart: "Missing SSH key",
		},
		{
			name:         "body_too_large",
			method:       http.MethodPost,
			body:         `{"ssh_key":"` + strings.Repeat("A", 70*1024) + `"}`,
			wantStatus:   http.StatusRequestEntityTooLarge,
			wantBodyPart: "too large",
		},
		{
			name:         "authz_error",
			method:       http.MethodPost,
			body:         validBody,
			authzErr:     errors.New("policy backend down"),
			wantStatus:   http.StatusInternalServerError,
			wantBodyPart: "Authorization check failed",
		},
		{
			name:         "denied",
			method:       http.MethodPost,
			body:         validBody,
			authzResult:  &authz.AuthorizationResult{Allowed: false},
			wantStatus:   http.StatusForbidden,
			wantBodyPart: "Not authorized",
		},
		{
			name:         "enclave_error",
			method:       http.MethodPost,
			body:         validBody,
			authzResult:  &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: validRules},
			signerErr:    errors.New("vsock timeout"),
			wantStatus:   http.StatusInternalServerError,
			wantBodyPart: "Signing failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
			authZ := &fakeAuthorizer{result: tt.authzResult, err: tt.authzErr}
			signer := &fakeSigner{signed: tt.signerSigned, err: tt.signerErr}
			s := newServerForTest(t, authN, authZ, signer)

			r := httptest.NewRequest(tt.method, "/sign", strings.NewReader(tt.body))
			r.Header.Set("Authorization", "Negotiate stub")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body=%s", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.wantBodyPart != "" && !strings.Contains(w.Body.String(), tt.wantBodyPart) {
				t.Errorf("body does not contain %q; got: %s", tt.wantBodyPart, w.Body.String())
			}
		})
	}
}

// TestHandleSignRequest_SendsDefensiveCopy verifies that mutating the slice
// passed to the enclave doesn't bleed back to the authorizer's internal
// CertificateRules — the regression the defensive-copy change guards against.
func TestHandleSignRequest_SendsDefensiveCopy(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: []string{"root", "ubuntu"},
		Permissions:       map[string]string{"permit-pty": ""},
		CriticalOptions:   map[string]string{"force-command": "/usr/bin/true"},
		StaticAttributes:  map[string]string{"env": "test"},
	}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	s.Router().ServeHTTP(httptest.NewRecorder(), r)

	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	// Mutating the handed-off slice/map must not touch the config's copy.
	signer.got.Principals[0] = "hacked"
	signer.got.CriticalOptions["force-command"] = "/bin/sh"
	signer.got.Permissions["permit-pty"] = "tampered"

	if rules.AllowedPrincipals[0] != "root" {
		t.Errorf("config principals corrupted: %v", rules.AllowedPrincipals)
	}
	if rules.CriticalOptions["force-command"] != "/usr/bin/true" {
		t.Errorf("config critical_options corrupted: %v", rules.CriticalOptions)
	}
	if rules.Permissions["permit-pty"] != "" {
		t.Errorf("config permissions corrupted: %v", rules.Permissions)
	}
}

func TestHandleSignRequest_RateLimited(t *testing.T) {
	// Burst=1, rps=0 means the first request drains the bucket and every
	// subsequent one is denied until refill (which never happens at rps=0).
	t.Setenv("RATE_LIMIT_RPS", "0")
	t.Setenv("RATE_LIMIT_BURST", "1")

	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: []string{"root"},
	}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "x", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	send := func() int {
		r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
		r.Header.Set("Authorization", "Negotiate x")
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		return w.Code
	}

	if got := send(); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := send(); got != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", got)
	}
}

func TestAuthMiddleware_UnauthenticatedGets401(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("no token")}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, &fakeSigner{})

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Errorf("WWW-Authenticate = %q, want Negotiate", got)
	}
}

func TestHealth_BypassesAuth(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, &fakeSigner{})

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("health: got %d, want 200", w.Code)
	}
}

func TestMetrics_BypassesAuthAndExposesCounters(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, &fakeSigner{})

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("metrics: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"cerberus_sign_requests_total",
		"cerberus_sign_duration_seconds",
		"cerberus_enclave_errors_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing series %q", want)
		}
	}
}
