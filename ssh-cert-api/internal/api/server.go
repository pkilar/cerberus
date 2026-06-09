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
	"strings"
	"time"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/auth"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/authz"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type contextKey string

const (
	userContextKey contextKey = "user"

	// maxSignRequestBytes caps /sign body size. An SSH RSA-4096 public key is
	// ~750 bytes; with principals and JSON framing, 64 KB is generous.
	maxSignRequestBytes = 64 * 1024

	// SignTimeout bounds the enclave round trip for a single /sign request.
	// It MUST be shorter than the enclave client's wall-clock backstop
	// (enclave.vsockRoundTripDeadline, 30s) so that a slow request aborts
	// with an observable handler error (500) rather than running to the
	// backstop, and it MUST be shorter than the http.Server WriteTimeout
	// (set in main from this value) so a slow-but-successful sign still gets
	// its response written instead of being truncated on a dead connection.
	SignTimeout = 25 * time.Second
)

type Server struct {
	config        *config.Config
	authenticator auth.Authenticator
	authorizer    authz.Authorizer
	enclaveClient enclave.Signer
	healthMonitor *HealthMonitor
	ldapHealth    *LDAPHealthMonitor
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

// SetLDAPHealth installs an LDAP health monitor used by the /health handler
// to surface per-backend status. Optional: a nil monitor (the default) means
// the /health body simply omits the ldap field. Called from main after the
// LDAP clients are constructed.
func (s *Server) SetLDAPHealth(m *LDAPHealthMonitor) {
	s.ldapHealth = m
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
			// SPNEGO is a challenge/response protocol: every real request
			// starts with a no-Authorization probe so the client can pick
			// up the WWW-Authenticate: Negotiate challenge. Logging that
			// as auth.failed at WARN floods logs and obscures genuine
			// rejected-token errors, so the authenticator returns a
			// sentinel for that case and we demote it to debug here.
			// Any other error means a token was submitted and rejected,
			// which stays at WARN.
			if errors.Is(err, auth.ErrNoAuthorizationHeader) {
				slog.Debug("auth.challenge", "remote_addr", r.RemoteAddr)
			} else {
				slog.Warn("auth.failed", "remote_addr", r.RemoteAddr, "error", err)
			}
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Authentication required"})
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
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Failed to get authenticated user"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSignRequestBytes)
	var req messages.SigningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			outcome = outcomeTooLarge
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Request body too large"})
			return
		}
		outcome = outcomeInvalidBody
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Invalid request format"})
		return
	}

	if req.SSHKey == "" {
		outcome = outcomeMissingKey
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Missing SSH key"})
		return
	}

	// Reject empty principals explicitly. An empty slice would trivially pass
	// the Casbin per-principal loop below (zero iterations = unanimously
	// allowed) and the user would receive a cert with the group's full
	// allowed_principals set — wider than the empty request implied.
	if len(req.Principals) == 0 {
		outcome = outcomeMissingPrincipals
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Missing principals"})
		return
	}

	// Cap principals BEFORE authorization so the per-request Casbin work
	// doesn't scale with attacker-chosen input. The enclave enforces the
	// same cap downstream, but only after the API has already paid the cost.
	if len(req.Principals) > messages.MaxPrincipals {
		outcome = outcomeInvalidBody
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Too many principals"})
		return
	}

	// Reject empty/whitespace principals before authorization. An empty
	// principal could be matched by a group whose allowed_principals contains
	// "" or "*"; the enclave rejects it regardless, so fail fast here with a
	// clear 400 instead of burning an enclave round trip on a 500.
	//
	// Also reject a literal "*": it is only meaningful as a wildcard inside a
	// group's allowed_principals policy, never as a certificate principal. The
	// cert below is minted for exactly what was requested, and sshd matches
	// cert principals literally (not as a glob), so a "*" would yield a useless
	// certificate while a wildcard group would silently authorize it.
	for _, p := range req.Principals {
		if strings.TrimSpace(p) == "" {
			outcome = outcomeInvalidBody
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Empty principal"})
			return
		}
		if strings.TrimSpace(p) == "*" {
			outcome = outcomeInvalidBody
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Wildcard principal not allowed"})
			return
		}
	}

	principal := user.Username + "@" + user.Realm
	slog.Info("sign.request", "principal", principal, "requested_principals", req.Principals, "remote_addr", r.RemoteAddr)

	// Check authorization and get user's group configuration
	result, authzErr := s.authorizer.Authorize(r.Context(), principal, req.Principals)
	if authzErr != nil {
		outcome = outcomeAuthzError
		slog.Error("authz.error", "principal", principal, "error", authzErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Authorization check failed"})
		return
	}
	if !result.Allowed {
		outcome = outcomeDenied
		slog.Warn("authz.denied", "principal", principal, "requested_principals", req.Principals)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Not authorized for requested principals"})
		return
	}

	// Static attributes from config become custom extensions on the cert.
	customAttributes := maps.Clone(result.CertificateRules.StaticAttributes)

	// Issue the certificate for exactly the principals the user requested, not
	// the group's full allowed_principals set. Authorization above has already
	// confirmed every requested principal is permitted by the matched group, so
	// honoring the request is least-privilege: a user asking for ["deploy"]
	// receives a cert valid only for "deploy", even if their group also allows
	// "root". This also makes wildcard groups (allowed_principals: ["*"]) behave
	// correctly — the cert carries the concrete requested names rather than a
	// literal "*". Deduplicate so a request padded with repeats does not bloat
	// the cert's ValidPrincipals.
	grantedPrincipals := slices.Clone(req.Principals)
	slices.Sort(grantedPrincipals)
	grantedPrincipals = slices.Compact(grantedPrincipals)

	enclaveReq := &messages.EnclaveSigningRequest{
		SSHKey:           req.SSHKey,
		KeyID:            principal,
		Principals:       grantedPrincipals,
		Validity:         result.CertificateRules.Validity,
		Permissions:      maps.Clone(result.CertificateRules.Permissions),
		CustomAttributes: customAttributes,
		CriticalOptions:  maps.Clone(result.CertificateRules.CriticalOptions),
	}

	// Sign the key. Propagate r.Context() so client disconnect tears the
	// enclave call down, but cap it with an explicit SignTimeout: that bounds
	// the round trip below the http.Server WriteTimeout so a slow-but-
	// successful sign still gets its response written, and makes an over-budget
	// sign abort observably (500 below) instead of writing to a connection the
	// server has already write-deadlined out from under us.
	signCtx, cancelSign := context.WithTimeout(r.Context(), SignTimeout)
	defer cancelSign()
	signedKey, err := s.enclaveClient.SignPublicKey(signCtx, enclaveReq)
	if err != nil {
		outcome = outcomeFailed
		enclaveErrorsTotal.Inc()
		slog.Error("sign.failed", "principal", principal, "group", result.GroupName, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Signing failed"})
		return
	}

	outcome = outcomeSuccess
	slog.Info("sign.success",
		"principal", principal,
		"group", result.GroupName,
		"source", result.Source,
		"granted_principals", grantedPrincipals,
		"group_allowed_principals", result.CertificateRules.AllowedPrincipals,
		"remote_addr", r.RemoteAddr,
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(messages.SigningResponse{SignedKey: signedKey})
}

// healthResponse is the JSON body /health emits. The top-level status is
// gated on the enclave staleness/error path; LDAP backend status is
// advisory — present in the body for observability but does not flip the
// top-level status. Operators wanting LDAP outages to fail health checks
// alert on the ldap[].healthy field directly.
type healthResponse struct {
	Status string                `json:"status"`
	Reason string                `json:"reason,omitempty"`
	LDAP   []LDAPBackendSnapshot `json:"ldap,omitempty"`
}

// handleHealth reads the cached enclave health snapshot maintained by the
// background healthMonitor and, if configured, the per-backend LDAP
// snapshots from ldapHealth. The handler never touches VSOCK or LDAP
// directly, so a flood of unauthenticated /health requests cannot consume
// the signer's bounded connection budget or pin LDAP server sockets — only
// the monitors' 5s background probes do.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ldapSnaps := s.ldapHealth.Snapshots() // safe on nil receiver

	writeReply := func(status int, reason string) {
		w.WriteHeader(status)
		body := healthResponse{
			Status: "unhealthy",
			Reason: reason,
			LDAP:   ldapSnaps,
		}
		if status == http.StatusOK {
			body.Status = "healthy"
			body.Reason = ""
		}
		_ = json.NewEncoder(w).Encode(body)
	}

	snap := s.healthMonitor.Snapshot()
	switch {
	case snap == nil:
		writeReply(http.StatusServiceUnavailable, "starting up")
	case time.Since(snap.LastChecked) > healthStaleAfter:
		slog.Warn("health.stale", "age", time.Since(snap.LastChecked))
		writeReply(http.StatusServiceUnavailable, "health check stale")
	case snap.LastError != "":
		writeReply(http.StatusServiceUnavailable, "enclave unreachable")
	case !snap.SignerLoaded:
		writeReply(http.StatusServiceUnavailable, "signer not loaded")
	default:
		writeReply(http.StatusOK, "")
	}
}
