package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/auth"
)

// obsTestServer builds a Server whose authenticator would reject every request,
// so anything the observability router answers is provably reachable without
// credentials — which is the point for /health and /metrics, and exactly what
// must not be true for /sign or /policy.
func obsTestServer(t *testing.T) *Server {
	t.Helper()
	return newServerForTest(t,
		&fakeAuthenticator{err: auth.ErrNoAuthorizationHeader},
		&fakeAuthorizer{},
		&fakeSigner{})
}

func TestObservabilityRouter_ServesHealthAndMetrics(t *testing.T) {
	t.Parallel()
	h := obsTestServer(t).ObservabilityRouter()

	for _, path := range []string{"/health", "/metrics"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code == http.StatusNotFound {
				t.Fatalf("GET %s = 404; the plain-HTTP listener must serve it", path)
			}
			// /health reports 503 when the enclave snapshot is stale, which is
			// a legitimate answer; only "routed at all" is under test here.
			if w.Code >= 500 && w.Code != http.StatusServiceUnavailable {
				t.Fatalf("GET %s = %d, want a routed response", path, w.Code)
			}
		})
	}
}

// The security property this listener lives or dies by: it is plain HTTP, so a
// client aimed at it would put a Kerberos ticket or an OIDC bearer token on the
// wire in cleartext. Those routes must be absent from the mux, not merely
// rejected by middleware.
func TestObservabilityRouter_DoesNotExposeSigningRoutes(t *testing.T) {
	t.Parallel()
	h := obsTestServer(t).ObservabilityRouter()

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/sign"},
		{http.MethodGet, "/sign"},
		{http.MethodGet, "/policy"},
		{http.MethodPost, "/policy"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, strings.NewReader("{}")))
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404: signing routes must not exist on the cleartext listener",
					tt.method, tt.path, w.Code)
			}
		})
	}
}

// A new route added to setupRoutes must not appear here by accident. Compare
// against the HTTPS router, which does serve /sign and /policy, so this test
// fails if the two routers are ever collapsed into one.
func TestObservabilityRouter_IsSeparateFromMainRouter(t *testing.T) {
	t.Parallel()
	s := obsTestServer(t)

	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader("{}")))
	if w.Code == http.StatusNotFound {
		t.Fatal("main router returned 404 for POST /sign; this test's premise is broken")
	}

	w = httptest.NewRecorder()
	s.ObservabilityRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sign", strings.NewReader("{}")))
	if w.Code != http.StatusNotFound {
		t.Errorf("observability router served POST /sign (%d); the two routers must not share a mux", w.Code)
	}
}

func TestObservabilityRouter_RejectsNonGET(t *testing.T) {
	t.Parallel()
	h := obsTestServer(t).ObservabilityRouter()

	for _, path := range []string{"/health", "/metrics"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, path, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE %s = %d, want 405", path, w.Code)
		}
	}
}

// Everything above drives the handler in-process. This serves it over a real
// TCP listener and speaks real HTTP to it, which is what main.go actually does
// and what the RUNBOOK tells operators to verify after enabling the listener.
func TestObservabilityRouter_OverRealListener(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(obsTestServer(t).ObservabilityRouter())
	t.Cleanup(srv.Close)

	t.Run("metrics returns prometheus exposition", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /metrics = %d, want 200", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), "# HELP") {
			t.Errorf("/metrics body is not Prometheus exposition format:\n%.200s", body)
		}
	})

	t.Run("health is reachable without credentials", func(t *testing.T) {
		resp, err := srv.Client().Get(srv.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		// healthy (200) or stale-enclave (503); both mean it is routed and
		// answered without a Kerberos ticket.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET /health = %d, want 200 or 503", resp.StatusCode)
		}
	})

	t.Run("sign is unreachable over the cleartext listener", func(t *testing.T) {
		resp, err := srv.Client().Post(srv.URL+"/sign", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST /sign: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST /sign = %d, want 404", resp.StatusCode)
		}
	})
}
