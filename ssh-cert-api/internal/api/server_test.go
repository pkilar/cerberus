package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/auth"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/authz"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
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

func (f *fakeAuthorizer) Authorize(context.Context, string, []string) (*authz.AuthorizationResult, error) {
	return f.result, f.err
}

type fakeSigner struct {
	signed       string
	err          error
	got          *messages.EnclaveSigningRequest
	pingResp     *messages.PingResponse
	pingErr      error
	pingCount    atomic.Int64 // total Ping calls, for the no-enclave-hit-on-flood assertion
	metricsResp  *messages.EnclaveMetricsResponse
	metricsErr   error
	metricsCount atomic.Int64
}

func (f *fakeSigner) SignPublicKey(_ context.Context, req *messages.EnclaveSigningRequest) (string, error) {
	f.got = req
	return f.signed, f.err
}

func (f *fakeSigner) Ping(_ context.Context) (*messages.PingResponse, error) {
	f.pingCount.Add(1)
	if f.pingErr != nil {
		return nil, f.pingErr
	}
	if f.pingResp != nil {
		return f.pingResp, nil
	}
	// Default: signer is loaded. Tests that need a different shape set
	// pingResp or pingErr explicitly.
	return &messages.PingResponse{SignerLoaded: true}, nil
}

func (f *fakeSigner) GetEnclaveMetrics(_ context.Context) (*messages.EnclaveMetricsResponse, error) {
	f.metricsCount.Add(1)
	if f.metricsErr != nil {
		return nil, f.metricsErr
	}
	if f.metricsResp != nil {
		return f.metricsResp, nil
	}
	// Default: a minimal valid snapshot. Tests that need specific values set
	// metricsResp explicitly.
	return &messages.EnclaveMetricsResponse{
		CPU:    messages.EnclaveCPUTimes{User: 1, System: 2, Idle: 100},
		Memory: messages.EnclaveMemoryStats{TotalBytes: 1 << 30, AvailableBytes: 1 << 29},
	}, nil
}

func (f *fakeSigner) Close() error { return nil }

// newServerForTest constructs a Server with fake dependencies. A fresh Server
// gets a fresh rate-limiter, isolating tests from each other despite the
// package-level Prometheus counters. The health monitor is built with a
// probe interval of 1h so the only probe is the synchronous one in Start —
// tests stay deterministic regardless of timing.
func newServerForTest(t *testing.T, authN auth.Authenticator, authZ authz.Authorizer, signer enclave.Signer) *Server {
	t.Helper()
	monitor := newHealthMonitor(signer, 1*time.Hour, 100*time.Millisecond)
	monitor.Start(t.Context())
	s, err := NewServer(&config.Config{}, authN, authZ, signer, monitor)
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
			name:       "method_not_allowed",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
			// Default ServeMux 405 body is "Method Not Allowed\n".
			wantBodyPart: "Method Not Allowed",
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
		t.Errorf("health: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestHealth_ReturnsServiceUnavailableWhenEnclaveUnreachable(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	signer := &fakeSigner{pingErr: errors.New("vsock dial: connection refused")}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, signer)

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("health: got %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "enclave unreachable") {
		t.Errorf("body missing reason: %s", w.Body.String())
	}
}

func TestHealth_ReturnsServiceUnavailableWhenSignerNotLoaded(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	signer := &fakeSigner{pingResp: &messages.PingResponse{SignerLoaded: false}}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, signer)

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("health: got %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signer not loaded") {
		t.Errorf("body missing reason: %s", w.Body.String())
	}
}

// TestHealth_FloodDoesNotProbeEnclave proves the Codex finding is addressed:
// a flood of unauthenticated /health requests must not consume any of the
// enclave's bounded connection budget. We construct a monitor that does
// exactly one synchronous probe at Start (1h probeInterval), then issue
// 100 concurrent /health requests. signer.pingCount must still be 1.
func TestHealth_FloodDoesNotProbeEnclave(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	signer := &fakeSigner{pingResp: &messages.PingResponse{SignerLoaded: true}}

	monitor := newHealthMonitor(signer, 1*time.Hour, 100*time.Millisecond)
	monitor.Start(t.Context())

	s, err := NewServer(&config.Config{}, authN, &fakeAuthorizer{}, signer, monitor)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if got := signer.pingCount.Load(); got != 1 {
		t.Fatalf("after Start: pingCount = %d, want 1 (the initial synchronous probe)", got)
	}

	const concurrent = 100
	var wg sync.WaitGroup
	for range concurrent {
		wg.Go(func() {
			r := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("flood /health: got %d, body=%s", w.Code, w.Body.String())
			}
		})
	}
	wg.Wait()

	if got := signer.pingCount.Load(); got != 1 {
		t.Errorf("after %d concurrent /health requests: pingCount = %d, want 1 (no enclave round trips from the request path)", concurrent, got)
	}
}

// TestHealth_StaleSnapshotReturnsUnhealthy verifies the staleness guard:
// if the background goroutine stops refreshing the snapshot, /health
// eventually reports unhealthy rather than serving an arbitrarily-old
// "looks fine" answer.
func TestHealth_StaleSnapshotReturnsUnhealthy(t *testing.T) {
	authN := &fakeAuthenticator{err: errors.New("should not be called")}
	signer := &fakeSigner{pingResp: &messages.PingResponse{SignerLoaded: true}}

	monitor := newHealthMonitor(signer, 1*time.Hour, 100*time.Millisecond)
	monitor.Start(t.Context())

	// Backdate the cached snapshot past the staleness threshold.
	stale := &healthSnapshot{
		SignerLoaded: true,
		LastChecked:  time.Now().Add(-2 * healthStaleAfter),
	}
	monitor.state.Store(stale)

	s, err := NewServer(&config.Config{}, authN, &fakeAuthorizer{}, signer, monitor)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("stale /health: got %d, want 503; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "stale") {
		t.Errorf("body missing stale reason: %s", w.Body.String())
	}
}

func TestMetrics_BypassesAuthAndExposesCounters(t *testing.T) {
	// Drive one /sign request first. Prometheus CounterVec omits a series
	// until at least one label combination has been observed, so without
	// this warm-up the assertion below would depend on a prior test having
	// exercised the counter — exactly the ordering dependency that
	// go test -shuffle=on is meant to catch.
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: []string{"root"},
	}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "metrics-warmup", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "x", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	warm := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	warm.Header.Set("Authorization", "Negotiate x")
	s.Router().ServeHTTP(httptest.NewRecorder(), warm)

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
