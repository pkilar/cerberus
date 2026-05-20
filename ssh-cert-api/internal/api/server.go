// Package api implements the HTTPS surface of ssh-cert-api: Kerberos SPNEGO
// authentication, per-principal rate limiting, Casbin-backed authorization,
// the /sign and /health endpoints, and Prometheus metrics at /metrics.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"runtime/debug"
	"slices"
	"strconv"
	"time"

	"cerberus/messages"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/authz"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type contextKey string

const (
	userContextKey contextKey = "user"

	// maxSignRequestBytes caps /sign body size. An SSH RSA-4096 public key is
	// ~750 bytes; with principals and JSON framing, 64 KB is generous.
	maxSignRequestBytes = 64 * 1024
)

type Server struct {
	config        *config.Config
	authenticator auth.Authenticator
	authorizer    authz.Authorizer
	enclaveClient enclave.Signer
	healthMonitor *HealthMonitor
	limiter       *principalLimiter
	router        *http.ServeMux
}

func NewServer(cfg *config.Config, authenticator auth.Authenticator, authorizer authz.Authorizer, enclaveClient enclave.Signer, healthMonitor *HealthMonitor) (*Server, error) {
	s := &Server{
		config:        cfg,
		authenticator: authenticator,
		authorizer:    authorizer,
		enclaveClient: enclaveClient,
		healthMonitor: healthMonitor,
		limiter:       newPrincipalLimiter(),
		router:        http.NewServeMux(),
	}

	s.setupRoutes()
	return s, nil
}

func (s *Server) Router() http.Handler {
	return recoverMiddleware(s.authMiddleware(s.router))
}

// recoverMiddleware catches panics from any handler below it, increments
// cerberus_handler_panics_total, logs the panic with a stack trace, and
// returns a generic 500. Without this wrapper, Go's http.Server still
// recovers per-connection but aborts the response mid-stream and writes
// the trace to the default error log without structure.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				handlerPanicsTotal.Inc()
				slog.Error("handler.panic", "path", r.URL.Path, "panic", p, "stack", string(debug.Stack()))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /health and /metrics are intentionally unauthenticated so
		// load balancers and Prometheus scrapers can reach them without
		// Kerberos tickets. Protect /metrics via network-level ACLs.
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		user, err := s.authenticator.AuthenticateRequest(r)
		if err != nil {
			slog.Warn("auth.failed", "remote_addr", r.RemoteAddr, "error", err)
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) setupRoutes() {
	// 1.22+ method-prefixed patterns: a non-POST to /sign returns 405 from the
	// mux automatically, so the handler does not need to re-check r.Method.
	s.router.Handle("POST /sign", s.limiter.middleware(http.HandlerFunc(s.handleSignRequest)))
	s.router.HandleFunc("GET /health", s.handleHealth)
	s.router.Handle("GET /metrics", promhttp.Handler())
}

func (s *Server) handleSignRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	outcome := outcomeFailed
	defer func() {
		signDurationSeconds.Observe(time.Since(start).Seconds())
		signRequestsTotal.WithLabelValues(outcome).Inc()
	}()

	user, ok := r.Context().Value(userContextKey).(*auth.AuthenticatedUser)
	if !ok {
		outcome = outcomeNoAuth
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Failed to get authenticated user"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSignRequestBytes)
	var req messages.SigningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			outcome = outcomeTooLarge
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Request body too large"})
			return
		}
		outcome = outcomeInvalidBody
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Invalid request format"})
		return
	}

	if req.SSHKey == "" {
		outcome = outcomeMissingKey
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Missing SSH key"})
		return
	}

	// Cap principals BEFORE authorization so the per-request Casbin work
	// doesn't scale with attacker-chosen input. The enclave enforces the
	// same cap downstream, but only after the API has already paid the cost.
	if len(req.Principals) > messages.MaxPrincipals {
		outcome = outcomeInvalidBody
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Too many principals"})
		return
	}

	principal := user.Username + "@" + user.Realm
	slog.Info("sign.request", "principal", principal, "requested_principals", req.Principals)

	// Check authorization and get user's group configuration
	result, authzErr := s.authorizer.Authorize(principal, req.Principals)
	if authzErr != nil {
		outcome = outcomeAuthzError
		slog.Error("authz.error", "principal", principal, "error", authzErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Authorization check failed"})
		return
	}
	if !result.Allowed {
		outcome = outcomeDenied
		slog.Warn("authz.denied", "principal", principal, "requested_principals", req.Principals)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Not authorized for requested principals"})
		return
	}

	// Create enclave request using config-based attributes
	// Merge static attributes from config with dynamic audit attributes
	customAttributes := make(map[string]string)
	maps.Copy(customAttributes, result.CertificateRules.StaticAttributes)
	// Add audit trail attributes
	customAttributes["issued_at"] = strconv.FormatInt(time.Now().Unix(), 10)

	enclaveReq := &messages.EnclaveSigningRequest{
		SSHKey:           req.SSHKey,
		KeyID:            principal,
		Principals:       slices.Clone(result.CertificateRules.AllowedPrincipals),
		Validity:         result.CertificateRules.Validity,
		Permissions:      maps.Clone(result.CertificateRules.Permissions),
		CustomAttributes: customAttributes,
		CriticalOptions:  maps.Clone(result.CertificateRules.CriticalOptions),
	}

	// Sign the key — propagate r.Context() so client disconnect or upstream
	// deadline tears the enclave call down rather than letting it run to the
	// wall-clock backstop.
	signedKey, err := s.enclaveClient.SignPublicKey(r.Context(), enclaveReq)
	if err != nil {
		outcome = outcomeFailed
		enclaveErrorsTotal.Inc()
		slog.Error("sign.failed", "principal", principal, "group", result.GroupName, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Signing failed"})
		return
	}

	outcome = outcomeSuccess
	slog.Info("sign.success",
		"principal", principal,
		"group", result.GroupName,
		"granted_principals", result.CertificateRules.AllowedPrincipals,
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(messages.SigningResponse{SignedKey: signedKey})
}

// handleHealth reads the cached enclave health snapshot maintained by the
// background healthMonitor. The handler never touches VSOCK directly, so a
// flood of unauthenticated /health requests cannot consume the signer's
// bounded connection budget — only the monitor's 5s background probe does.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	snap := s.healthMonitor.Snapshot()
	if snap == nil {
		// Background monitor hasn't completed its first probe.
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": "starting up"})
		return
	}
	if age := time.Since(snap.LastChecked); age > healthStaleAfter {
		slog.Warn("health.stale", "age", age)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": "health check stale"})
		return
	}
	if snap.LastError != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": "enclave unreachable"})
		return
	}
	if !snap.SignerLoaded {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": "signer not loaded"})
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "healthy"}`))
}
