package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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
	"github.com/prometheus/client_golang/prometheus"
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
	result     *authz.AuthorizationResult
	err        error
	allResult  *authz.AuthorizationResult // returned by AuthorizeAll; falls back to result/err when nil
	allErr     error
	selfResult *authz.AuthorizationResult // returned by AuthorizeSelf; falls back to result/err when nil
	selfErr    error
}

// withGrant mirrors the real authorizer's contract — an Allowed result always
// carries the principals the cert must get — for fake results that don't set
// GrantedPrincipals themselves. The default is identity semantics (what the
// real authorizer returns for plain allowed_principals). A test that wants a
// mapped or deliberately empty grant sets the field explicitly; a non-nil
// slice (even an empty one) is passed through untouched. The result is copied
// so a shared pointer across subtests is never mutated.
func withGrant(res *authz.AuthorizationResult, granted []string) *authz.AuthorizationResult {
	if res == nil || !res.Allowed || res.GrantedPrincipals != nil {
		return res
	}
	cp := *res
	cp.GrantedPrincipals = granted
	return &cp
}

func (f *fakeAuthorizer) Authorize(_ context.Context, _ string, requested []string) (*authz.AuthorizationResult, error) {
	granted := slices.Clone(requested)
	slices.Sort(granted)
	return withGrant(f.result, slices.Compact(granted)), f.err
}

func (f *fakeAuthorizer) AuthorizeAll(context.Context, string) (*authz.AuthorizationResult, error) {
	res, err := f.result, f.err
	if f.allResult != nil || f.allErr != nil {
		res, err = f.allResult, f.allErr
	}
	if res != nil && res.CertificateRules != nil {
		return withGrant(res, res.CertificateRules.AllowedPrincipals.Issued()), err
	}
	return res, err
}

func (f *fakeAuthorizer) AuthorizeSelf(_ context.Context, principal string) (*authz.AuthorizationResult, error) {
	res, err := f.result, f.err
	if f.selfResult != nil || f.selfErr != nil {
		res, err = f.selfResult, f.selfErr
	}
	uid := principal
	if at := strings.LastIndex(principal, "@"); at >= 0 {
		uid = principal[:at] // same split as authz.selfEligibleUID
	}
	return withGrant(res, []string{uid}), err
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

func (f *fakeSigner) BeginKeyLoad(context.Context, *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	return nil, errors.New("fakeSigner.BeginKeyLoad not implemented")
}

func (f *fakeSigner) CompleteKeyLoad(context.Context, *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	return nil, errors.New("fakeSigner.CompleteKeyLoad not implemented")
}

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
		AllowedPrincipals: config.PlainPrincipals("root"),
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

// TestHandleSignRequest_SendsDefensiveCopy verifies that mutating the maps
// handed to the enclave doesn't bleed back to the authorizer's internal
// CertificateRules — the regression maps.Clone(Permissions) and
// maps.Clone(CriticalOptions) guard against. The signer.got.Principals
// mutation below only guards against config.PrincipalRules ([]PrincipalRule)
// corruption; it is NOT a test of principals slice aliasing — a []string and
// a []PrincipalRule's string field can never share a backing array, with or
// without a clone. The aliasing regression test for
// slices.Clone(grantedPrincipals) at the enclave-request construction is
// TestHandleSignRequest_ClonesGrantedPrincipals, below.
func TestHandleSignRequest_SendsDefensiveCopy(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: config.PlainPrincipals("root", "ubuntu"),
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
	// Mutating the handed-off maps must not touch the config's copy. The
	// principals mutation here cannot exercise aliasing (see doc comment
	// above) but is left in place as a config-slice-corruption guard.
	signer.got.Principals[0] = "hacked"
	signer.got.CriticalOptions["force-command"] = "/bin/sh"
	signer.got.Permissions["permit-pty"] = "tampered"

	if rules.AllowedPrincipals[0].Requested != "root" {
		t.Errorf("config principals corrupted: %v", rules.AllowedPrincipals)
	}
	if rules.CriticalOptions["force-command"] != "/usr/bin/true" {
		t.Errorf("config critical_options corrupted: %v", rules.CriticalOptions)
	}
	if rules.Permissions["permit-pty"] != "" {
		t.Errorf("config permissions corrupted: %v", rules.Permissions)
	}
}

// TestHandleSignRequest_ClonesGrantedPrincipals is the regression test for
// slices.Clone(grantedPrincipals) at the enclave-request construction
// (server.go): it proves the handler hands the enclave a copy of the
// authorizer's GrantedPrincipals slice, never an alias of its backing array.
// The fake authorizer's result carries the exact `granted` slice (see
// withGrant: a non-nil GrantedPrincipals is passed through untouched), so if
// the handler ever regresses to `Principals: grantedPrincipals` (no clone),
// mutating signer.got.Principals below would corrupt `granted` too.
func TestHandleSignRequest_ClonesGrantedPrincipals(t *testing.T) {
	granted := []string{"root"}
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{
		Allowed:           true,
		GroupName:         "admin",
		CertificateRules:  rules,
		Source:            "static",
		GrantedPrincipals: granted,
	}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"root"}) {
		t.Fatalf("enclave principals = %v, want [root]", signer.got.Principals)
	}

	// Mutate the enclave-bound slice; the authorizer's own backing array
	// (held here as `granted`) must be unaffected if server.go clones before
	// handing it to the enclave request.
	signer.got.Principals[0] = "hacked"
	if granted[0] != "root" {
		t.Errorf("authorizer's GrantedPrincipals corrupted: got %q, want \"root\" (handler must clone, not alias)", granted[0])
	}
}

// TestHandleSignRequest_CertScopedToRequest verifies that the certificate is
// issued for exactly the principals the user requested, not the group's full
// allowed_principals set. Requesting a subset must not silently widen the cert
// to every principal the group permits (least privilege).
func TestHandleSignRequest_CertScopedToRequest(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: config.PlainPrincipals("root", "ubuntu", "deploy"),
	}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["deploy"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"deploy"}) {
		t.Errorf("cert principals = %v, want exactly [deploy] (the requested subset)", signer.got.Principals)
	}
}

// TestHandleSignRequest_MappedPrincipalReachesSigner verifies that a group's
// `root: global-root` mapping is what reaches the enclave — the cert carries
// the mapped (issued) name, never the requested "root" itself.
func TestHandleSignRequest_MappedPrincipalReachesSigner(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: config.PrincipalRules{{Requested: "root", Issued: "global-root"}},
	}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{
		Allowed:           true,
		GroupName:         "sysadmins",
		CertificateRules:  rules,
		Source:            "static",
		GrantedPrincipals: []string{"global-root"}, // what the real authorizer returns for a "root" request
	}}
	signer := &fakeSigner{signed: "ssh-ed25519-cert-v01@openssh.com AAAA"}
	s := newServerForTest(t, &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer not called")
	}
	if want := []string{"global-root"}; !slices.Equal(signer.got.Principals, want) {
		t.Fatalf("enclave principals = %v, want %v (mapped name only, never the requested 'root')", signer.got.Principals, want)
	}
	if signer.got.KeyID != "dave@REALM.COM" {
		t.Fatalf("KeyID = %q must stay the authenticated identity", signer.got.KeyID)
	}
}

// TestHandleSignRequest_AllowedWithEmptyGrantDenied verifies the handler
// fails closed — 403, signer never called — when an Allowed result somehow
// carries no granted principals (an authorizer bug), rather than minting an
// empty (any-principal) certificate.
func TestHandleSignRequest_AllowedWithEmptyGrantDenied(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root")}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{
		Allowed:           true,
		GroupName:         "ops",
		CertificateRules:  rules,
		Source:            "static",
		GrantedPrincipals: []string{}, // non-nil empty: an authorizer bug the handler must fail closed on
	}}
	signer := &fakeSigner{signed: "ssh-ed25519-cert-v01@openssh.com AAAA"}
	s := newServerForTest(t, &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403; body %s", w.Code, w.Body.String())
	}
	if signer.got != nil {
		t.Fatal("signer must not be called for an empty grant")
	}
}

// TestHandleSignRequest_AllPrincipalsExpandsToIssuedSet verifies that an
// all_principals request expands to the matched group's issued set — mapping
// targets, not requested names.
func TestHandleSignRequest_AllPrincipalsExpandsToIssuedSet(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: config.PrincipalRules{{Requested: "root", Issued: "global-root"}, {Requested: "deploy", Issued: "deploy"}},
	}
	// GrantedPrincipals left nil: the fake fills in Issued(), exactly like authz.AuthorizeAll.
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "sysadmins", CertificateRules: rules, Source: "static"}}
	signer := &fakeSigner{signed: "ssh-ed25519-cert-v01@openssh.com AAAA"}
	s := newServerForTest(t, &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","all_principals":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if want := []string{"deploy", "global-root"}; signer.got == nil || !slices.Equal(signer.got.Principals, want) {
		t.Fatalf("enclave principals = %v, want issued set %v", signer.got, want)
	}
}

// TestHandleSignRequest_WildcardGroupGetsConcretePrincipal verifies that a group
// with allowed_principals: ["*"] yields a cert carrying the concrete requested
// principal, never a literal "*".
func TestHandleSignRequest_WildcardGroupGetsConcretePrincipal(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("*")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "superadmins", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"root"}) {
		t.Errorf("cert principals = %v, want exactly [root]", signer.got.Principals)
	}
}

// TestHandleSignRequest_WildcardRequestRejected verifies the host refuses a
// literal "*" as a requested principal before it ever reaches the signer.
func TestHandleSignRequest_WildcardRequestRejected(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("*")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "superadmins", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["*"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Wildcard principal not allowed") {
		t.Errorf("body missing wildcard rejection: %s", w.Body.String())
	}
	if signer.got != nil {
		t.Error("wildcard request must be rejected before reaching the signer")
	}
}

// TestHandleSignRequest_AllPrincipalsExpands verifies that all_principals mints
// a cert for the whole (finite) allowed_principals set of the matched group,
// sorted and deduplicated, without the caller enumerating them.
func TestHandleSignRequest_AllPrincipalsExpands(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root", "ec2-user", "deploy")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{allResult: &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: rules, Source: "static"}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","all_principals":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"deploy", "ec2-user", "root"}) {
		t.Errorf("cert principals = %v, want the group's full set sorted", signer.got.Principals)
	}
}

// TestHandleSignRequest_AllPrincipalsMutualExclusion verifies that combining
// all_principals with an explicit principals list is a 400 (ambiguous request).
func TestHandleSignRequest_AllPrincipalsMutualExclusion(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{allResult: &authz.AuthorizationResult{Allowed: true, GroupName: "admin", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","all_principals":true,"principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mutually exclusive") {
		t.Errorf("body missing mutual-exclusion error: %s", w.Body.String())
	}
	if signer.got != nil {
		t.Error("contradictory request must be rejected before the signer")
	}
}

// TestHandleSignRequest_AllPrincipalsWildcardGroupRefused verifies that
// all_principals against a group whose allowed_principals is ["*"] is refused
// with a 400 (an unbounded set can't be enumerated into a cert) rather than
// minting an any-principal certificate.
func TestHandleSignRequest_AllPrincipalsWildcardGroupRefused(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("*")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{allResult: &authz.AuthorizationResult{Allowed: true, GroupName: "superadmins", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","all_principals":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cannot be expanded") {
		t.Errorf("body missing wildcard-group refusal: %s", w.Body.String())
	}
	if signer.got != nil {
		t.Error("wildcard-group all_principals must be refused before the signer")
	}
}

// TestHandleSignRequest_AllPrincipalsDenied verifies a user in no group gets a
// 403 for an all_principals request.
func TestHandleSignRequest_AllPrincipalsDenied(t *testing.T) {
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "nobody", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{allResult: &authz.AuthorizationResult{Allowed: false}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","all_principals":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if signer.got != nil {
		t.Error("denied all_principals must not reach the signer")
	}
}

// TestHandleSignRequest_SelfPrincipalIssuesUID verifies that self_principal mints
// a cert for exactly the caller's short uid (the authenticated Username).
func TestHandleSignRequest_SelfPrincipalIssuesUID(t *testing.T) {
	rules := &config.CertificateRules{Validity: "8h", Permissions: map[string]string{"permit-pty": ""}}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "jsmith", Realm: "FOO.COM"}}
	authZ := &fakeAuthorizer{selfResult: &authz.AuthorizationResult{Allowed: true, GroupName: "self", CertificateRules: rules, Source: "self"}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","self_principal":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"jsmith"}) {
		t.Errorf("cert principals = %v, want exactly [jsmith] (the caller's uid)", signer.got.Principals)
	}
}

// TestHandleSignRequest_SelfPrincipalMutualExclusion verifies self_principal is
// rejected (400) when combined with an explicit principals list.
func TestHandleSignRequest_SelfPrincipalMutualExclusion(t *testing.T) {
	rules := &config.CertificateRules{Validity: "8h"}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "jsmith", Realm: "FOO.COM"}}
	authZ := &fakeAuthorizer{selfResult: &authz.AuthorizationResult{Allowed: true, GroupName: "self", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","self_principal":true,"principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "mutually exclusive") {
		t.Errorf("body missing mutual-exclusion error: %s", w.Body.String())
	}
	if signer.got != nil {
		t.Error("contradictory request must be rejected before the signer")
	}
}

// TestHandleSignRequest_SelfPrincipalDenied verifies a 403 when the authorizer
// refuses the self-principal request (disabled, realm not allowlisted, or uid
// denied).
func TestHandleSignRequest_SelfPrincipalDenied(t *testing.T) {
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "jsmith", Realm: "BAR.COM"}}
	authZ := &fakeAuthorizer{selfResult: &authz.AuthorizationResult{Allowed: false}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","self_principal":true}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if signer.got != nil {
		t.Error("denied self_principal must not reach the signer")
	}
}

// TestHandleSignRequest_SelfFallbackOwnIdentity verifies the implicit connect
// path: an explicit request for exactly the caller's own uid that no group
// covers is accepted via the self-fallback (AuthorizeSelf), so `cssh you@host`
// works without group membership. The group path denies; AuthorizeSelf allows.
func TestHandleSignRequest_SelfFallbackOwnIdentity(t *testing.T) {
	selfRules := &config.CertificateRules{Validity: "8h", Permissions: map[string]string{"permit-pty": ""}}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "jsmith", Realm: "FOO.COM"}}
	authZ := &fakeAuthorizer{
		result:     &authz.AuthorizationResult{Allowed: false}, // no group covers "jsmith"
		selfResult: &authz.AuthorizationResult{Allowed: true, GroupName: "self", CertificateRules: selfRules, Source: "self"},
	}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["jsmith"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (self-fallback); body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if !slices.Equal(signer.got.Principals, []string{"jsmith"}) {
		t.Errorf("cert principals = %v, want exactly [jsmith]", signer.got.Principals)
	}
}

// TestHandleSignRequest_SelfFallbackRejectsNonSelf verifies the fallback only
// applies when the request is EXACTLY the caller's own uid: a request for a
// different principal (root) by jsmith is NOT self-accepted even though
// AuthorizeSelf would allow the caller's own uid — it stays a 403. This is the
// "requested principal must equal the authenticated user" guard.
func TestHandleSignRequest_SelfFallbackRejectsNonSelf(t *testing.T) {
	selfRules := &config.CertificateRules{Validity: "8h"}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "jsmith", Realm: "FOO.COM"}}
	authZ := &fakeAuthorizer{
		result:     &authz.AuthorizationResult{Allowed: false},
		selfResult: &authz.AuthorizationResult{Allowed: true, GroupName: "self", CertificateRules: selfRules, Source: "self"},
	}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (request is not the caller's own uid); body=%s", w.Code, w.Body.String())
	}
	if signer.got != nil {
		t.Error("a non-self request must not reach the signer via the self-fallback")
	}
}

// TestHandleSignRequest_TooManyPrincipals verifies the host caps the requested
// principal count BEFORE authorization (the explicit DoS guard in
// handleSignRequest, so per-request Casbin work can't scale with attacker
// input). The enclave re-enforces the same cap; this asserts the host's 400
// and that the over-cap request never reaches the signer.
func TestHandleSignRequest_TooManyPrincipals(t *testing.T) {
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "alice", Realm: "EXAMPLE.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "x", CertificateRules: rules}}
	signer := &fakeSigner{signed: "ok"}
	s := newServerForTest(t, authN, authZ, signer)

	quoted := make([]string, 0, messages.MaxPrincipals+1)
	for i := range messages.MaxPrincipals + 1 {
		quoted = append(quoted, fmt.Sprintf("%q", fmt.Sprintf("p%d", i)))
	}
	body := `{"ssh_key":"ssh-rsa AAAA","principals":[` + strings.Join(quoted, ",") + `]}`

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(body))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Too many principals") {
		t.Errorf("body missing 'Too many principals': %s", w.Body.String())
	}
	if signer.got != nil {
		t.Error("over-cap request must be rejected before reaching the signer")
	}
}

func TestHandleSignRequest_RateLimited(t *testing.T) {
	// Burst=1, rps=0 means the first request drains the bucket and every
	// subsequent one is denied until refill (which never happens at rps=0).
	t.Setenv("RATE_LIMIT_RPS", "0")
	t.Setenv("RATE_LIMIT_BURST", "1")

	rules := &config.CertificateRules{
		Validity:          "1h",
		AllowedPrincipals: config.PlainPrincipals("root"),
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
		AllowedPrincipals: config.PlainPrincipals("root"),
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

// TestMetrics_ExposesEnclaveResourceSeries proves that the
// EnclaveMetricsCollector - once registered with the default Prometheus
// registry as main.go does - actually surfaces through the Server's /metrics
// endpoint. This is the integration step the unit-level collector tests
// don't cover: a regression in route registration, in promhttp.Handler's
// registry choice, or in the auth-bypass list would all fail this test.

// Cannot run in parallel: it registers and unregisters on the process-global
// default registry. Uses an authenticator that errors when invoked to prove
// /metrics genuinely bypasses auth (no header present on the request).
func TestMetrics_ExposesEnclaveResourceSeries(t *testing.T) {
	signer := &fakeSigner{
		metricsResp: &messages.EnclaveMetricsResponse{
			CPU: messages.EnclaveCPUTimes{
				User: 11, Nice: 0, System: 7, Idle: 9000,
				IOWait: 1, IRQ: 0, SoftIRQ: 0,
			},
			Memory: messages.EnclaveMemoryStats{
				TotalBytes:     4 * 1024 * 1024 * 1024,
				AvailableBytes: 2 * 1024 * 1024 * 1024,
				FreeBytes:      1 * 1024 * 1024 * 1024,
				BuffersBytes:   128 * 1024 * 1024,
				CachedBytes:    512 * 1024 * 1024,
			},
		},
	}
	collector := NewEnclaveMetricsCollector(signer, time.Hour)
	collector.probe(t.Context())

	if err := prometheus.Register(collector); err != nil {
		t.Fatalf("prometheus.Register: %v", err)
	}

	t.Cleanup(func() { prometheus.Unregister(collector) })

	authN := &fakeAuthenticator{err: errors.New("must not be called for /metrics")}
	s := newServerForTest(t, authN, &fakeAuthorizer{}, signer)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("/metrics: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()

	// Each labeled series should appear at least once for a representative
	// label value. We don't assert on the exact float formatting promhttp
	// emits "1,1e+10" or "11" depending on scale - just that the labeled
	// metric line is present.

	wantSubstrings := []string{
		`cerberus_enclave_cpu_seconds_total{mode="user"}`,
		`cerberus_enclave_cpu_seconds_total{mode="idle"}`,
		`cerberus_enclave_memory_bytes{type="total"}`,
		`cerberus_enclave_memory_bytes{type="available"}`,
		"cerberus_enclave_metrics_scrape_errors_total",
		"cerberus_enclave_metrics_last_scrape_timestamp_seconds",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics body missing %q\nfull body:\n%s", want, body)
		}
	}
}

// captureLogs swaps slog's default logger for one that records every record
// and returns a snapshot accessor plus the cleanup that restores the prior
// default. Cannot run in parallel with anything else that touches slog
// global state.
func captureLogs(t *testing.T) func() []slog.Record {
	t.Helper()
	h := &capturingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []slog.Record {
		h.mu.Lock()
		defer h.mu.Unlock()
		out := make([]slog.Record, len(h.records))
		copy(out, h.records)
		return out
	}
}

type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r)
	h.mu.Unlock()
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// TestAuthMiddleware_LogClassification proves the SPNEGO challenge round-trip
// (no Authorization header) is logged at Debug as auth.challenge, while a
// genuinely rejected token logs at Warn as auth.failed. Both still respond 401
// with the same WWW-Authenticate challenge - only the log channel differs.
func TestAuthMiddleware_LogClassification(t *testing.T) {
	tests := []struct {
		name      string
		authErr   error
		wantMsg   string
		wantLevel slog.Level
	}{
		{
			name:      "no auth header is challenge at debug",
			authErr:   auth.ErrNoAuthorizationHeader,
			wantMsg:   "auth.challenge",
			wantLevel: slog.LevelDebug,
		},
		{
			name:      "rejected token is failure at warn",
			authErr:   errors.New("AP-REQ verification failed: token rejected"),
			wantMsg:   "auth.failed",
			wantLevel: slog.LevelWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := captureLogs(t)

			authN := &fakeAuthenticator{err: tt.authErr}
			s := newServerForTest(t, authN, &fakeAuthorizer{}, &fakeSigner{})

			r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}

			var found bool
			for _, rec := range records() {
				if rec.Message == tt.wantMsg {
					found = true
					if rec.Level != tt.wantLevel {
						t.Errorf("%s: level = %v, want %v", tt.wantMsg, rec.Level, tt.wantLevel)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected log record with message %q; got: %+v", tt.wantMsg, records())
			}
		})
	}
}

// --- OIDC bearer authentication ---

// newServerWithConfig is like newServerForTest but lets a test supply a Config
// (e.g. with OAuth enabled) instead of the empty default.
func newServerWithConfig(t *testing.T, cfg *config.Config, authN auth.Authenticator, authZ authz.Authorizer, signer enclave.Signer) *Server {
	t.Helper()
	monitor := newHealthMonitor(signer, 1*time.Hour, 100*time.Millisecond)
	monitor.Start(t.Context())
	s, err := NewServer(cfg, authN, authZ, signer, monitor)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// A bearer-authenticated request whose token groups the authorizer accepts is
// signed; the cert KeyID is the synthetic Username@Realm identity.
func TestHandleSignRequest_OIDCBearerAllowed(t *testing.T) {
	rules := &config.CertificateRules{
		Validity:          "8h",
		AllowedPrincipals: config.PlainPrincipals("root"),
		Permissions:       map[string]string{"permit-pty": ""},
	}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{
		Username: "jsmith", Realm: "OIDC",
		Groups: []string{"platform-eng"}, Method: "oidc",
	}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "ssh-admins", CertificateRules: rules, Source: "oidc"}}
	signer := &fakeSigner{signed: "cert"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if signer.got == nil {
		t.Fatal("signer never invoked")
	}
	if signer.got.KeyID != "jsmith@OIDC" {
		t.Errorf("cert KeyID = %q, want jsmith@OIDC", signer.got.KeyID)
	}
	if !slices.Equal(signer.got.Principals, []string{"root"}) {
		t.Errorf("cert principals = %v, want [root]", signer.got.Principals)
	}
}

// A bearer-authenticated request whose token groups bind no Cerberus group is
// denied and the signer is never reached.
func TestHandleSignRequest_OIDCBearerNotAuthorized(t *testing.T) {
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{
		Username: "jsmith", Realm: "OIDC",
		Groups: []string{"marketing"}, Method: "oidc",
	}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: false}}
	signer := &fakeSigner{signed: "cert"}
	s := newServerForTest(t, authN, authZ, signer)

	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	if signer.got != nil {
		t.Error("signer must not be invoked for an unauthorized request")
	}
}

// When OAuth is enabled, an unauthenticated request is challenged with both
// Negotiate and Bearer; when disabled, only Negotiate (regression).
func TestAuthMiddleware_WWWAuthenticateChallenge(t *testing.T) {
	tests := []struct {
		name        string
		oauthOn     bool
		wantSchemes []string
	}{
		{name: "oauth enabled advertises both", oauthOn: true, wantSchemes: []string{"Negotiate", "Bearer"}},
		{name: "oauth disabled advertises only negotiate", oauthOn: false, wantSchemes: []string{"Negotiate"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{OAuth: config.OAuthConfig{Enabled: tt.oauthOn}}
			authN := &fakeAuthenticator{err: auth.ErrNoAuthorizationHeader}
			s := newServerWithConfig(t, cfg, authN, &fakeAuthorizer{}, &fakeSigner{})

			r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			got := w.Header().Values("WWW-Authenticate")
			if !slices.Equal(got, tt.wantSchemes) {
				t.Errorf("WWW-Authenticate = %v, want %v", got, tt.wantSchemes)
			}
		})
	}
}

// End-to-end through the REAL Casbin authorizer: proves the middleware threads
// the OIDC user's asserted groups into the request context and that
// candidateGroups matches them against oidc_groups. A bound group is signed; an
// unbound asserted group is denied — with the signer wired but unreached.
func TestHandleSignRequest_OIDCEndToEndRealAuthorizer(t *testing.T) {
	cfg := &config.Config{
		KeytabPath: "/etc/krb5.keytab",
		Groups: map[string]config.Group{
			"ssh-admins": {
				OIDCGroups: []string{"platform-eng"},
				CertificateRules: config.CertificateRules{
					Validity:          "8h",
					AllowedPrincipals: config.PlainPrincipals("root"),
				},
			},
		},
	}
	authorizer, err := authz.NewCasbinAuthorizer(cfg, nil)
	if err != nil {
		t.Fatalf("NewCasbinAuthorizer: %v", err)
	}

	cases := []struct {
		name       string
		groups     []string
		wantStatus int
	}{
		{name: "bound group signs", groups: []string{"platform-eng"}, wantStatus: http.StatusOK},
		{name: "unbound group denied", groups: []string{"marketing"}, wantStatus: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{
				Username: "jsmith", Realm: "OIDC", Groups: tc.groups, Method: "oidc",
			}}
			signer := &fakeSigner{signed: "cert"}
			s := newServerWithConfig(t, cfg, authN, authorizer, signer)

			r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
			r.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus == http.StatusOK && signer.got == nil {
				t.Error("signer should have been invoked for a bound group")
			}
			if tc.wantStatus == http.StatusForbidden && signer.got != nil {
				t.Error("signer must not be invoked for an unbound group")
			}
		})
	}
}

// policyTestConfig is a config whose fingerprint the /policy and /sign tests
// compare against; it must differ from the empty config newServerForTest uses.
func policyTestConfig() *config.Config {
	return &config.Config{
		Groups: map[string]config.Group{
			"sysadmins": {
				Members:          []string{"dave@REALM.COM"},
				CertificateRules: config.CertificateRules{Validity: "8h", AllowedPrincipals: config.PrincipalRules{{Requested: "root", Issued: "global-root"}}},
			},
		},
	}
}

// newServerWithConfigForTest is newServerForTest with a caller-supplied config.
func newServerWithConfigForTest(t *testing.T, cfg *config.Config, authN auth.Authenticator, authZ authz.Authorizer, signer enclave.Signer) *Server {
	t.Helper()
	monitor := newHealthMonitor(signer, 1*time.Hour, 100*time.Millisecond)
	monitor.Start(t.Context())
	s, err := NewServer(cfg, authN, authZ, signer, monitor)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

func TestPolicy_RequiresAuth(t *testing.T) {
	authN := &fakeAuthenticator{err: auth.ErrNoAuthorizationHeader}
	s := newServerWithConfigForTest(t, policyTestConfig(), authN, &fakeAuthorizer{}, &fakeSigner{})
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "policy_fingerprint") {
		t.Fatalf("unauthenticated /policy must not disclose the fingerprint: %s", w.Body.String())
	}
}

func TestPolicy_ReturnsConfigFingerprint(t *testing.T) {
	cfg := policyTestConfig()
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}
	s := newServerWithConfigForTest(t, cfg, authN, &fakeAuthorizer{}, &fakeSigner{})
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var body struct {
		PolicyFingerprint string `json:"policy_fingerprint"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if want := cfg.PolicyFingerprint(); body.PolicyFingerprint == "" || body.PolicyFingerprint != want {
		t.Fatalf("policy_fingerprint = %q, want %q", body.PolicyFingerprint, want)
	}
}

func TestPolicy_NotSubjectToSignRateLimit(t *testing.T) {
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}
	s := newServerWithConfigForTest(t, policyTestConfig(), authN, &fakeAuthorizer{}, &fakeSigner{})
	// Well past the default sign burst (10): every call must still succeed,
	// because a cache-hit cssh invocation must not spend a sign token.
	for i := range 40 {
		r := httptest.NewRequest(http.MethodGet, "/policy", nil)
		r.Header.Set("Authorization", "Negotiate x")
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, w.Code)
		}
	}
}

func TestHandleSignRequest_ResponseCarriesPolicyFingerprint(t *testing.T) {
	cfg := policyTestConfig()
	rules := &config.CertificateRules{Validity: "1h", AllowedPrincipals: config.PlainPrincipals("root")}
	authN := &fakeAuthenticator{user: &auth.AuthenticatedUser{Username: "dave", Realm: "REALM.COM"}}
	authZ := &fakeAuthorizer{result: &authz.AuthorizationResult{Allowed: true, GroupName: "sysadmins", CertificateRules: rules, Source: "static"}}
	signer := &fakeSigner{signed: "ssh-ed25519-cert-v01@openssh.com AAAA"}
	s := newServerWithConfigForTest(t, cfg, authN, authZ, signer)
	r := httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader(`{"ssh_key":"k","principals":["root"]}`))
	r.Header.Set("Authorization", "Negotiate x")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	var body messages.SigningResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SignedKey == "" || body.PolicyFingerprint != cfg.PolicyFingerprint() {
		t.Fatalf("body = %+v, want signed_key and policy_fingerprint %q", body, cfg.PolicyFingerprint())
	}
}
