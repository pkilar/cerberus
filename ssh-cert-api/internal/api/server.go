package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"

	"cerberus/messages"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/authz"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"
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
	router        *http.ServeMux
}

func NewServer(cfg *config.Config, authenticator auth.Authenticator, authorizer authz.Authorizer, enclaveClient enclave.Signer) (*Server, error) {
	s := &Server{
		config:        cfg,
		authenticator: authenticator,
		authorizer:    authorizer,
		enclaveClient: enclaveClient,
		router:        http.NewServeMux(),
	}

	s.setupRoutes()
	return s, nil
}

func (s *Server) Router() http.Handler {
	return s.authMiddleware(s.router)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
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
	s.router.HandleFunc("/sign", s.handleSignRequest)
	s.router.HandleFunc("/health", s.handleHealth)
}

func (s *Server) handleSignRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Method not allowed"})
		return
	}

	user, ok := r.Context().Value(userContextKey).(*auth.AuthenticatedUser)
	if !ok {
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Request body too large"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Invalid request format"})
		return
	}

	if req.SSHKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Missing SSH key"})
		return
	}

	principal := user.Username + "@" + user.Realm
	slog.Info("sign.request", "principal", principal, "requested_principals", req.Principals)

	// Check authorization and get user's group configuration
	result, authzErr := s.authorizer.Authorize(principal, req.Principals)
	if authzErr != nil {
		slog.Error("authz.error", "principal", principal, "error", authzErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Authorization check failed"})
		return
	}
	if !result.Allowed {
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
	customAttributes["issued_at"] = fmt.Sprintf("%d", time.Now().Unix())

	enclaveReq := &messages.EnclaveSigningRequest{
		SSHKey:           req.SSHKey,
		KeyID:            principal,
		Principals:       slices.Clone(result.CertificateRules.AllowedPrincipals),
		Validity:         result.CertificateRules.Validity,
		Permissions:      maps.Clone(result.CertificateRules.Permissions),
		CustomAttributes: customAttributes,
		CriticalOptions:  maps.Clone(result.CertificateRules.CriticalOptions),
	}

	// Sign the key
	signedKey, err := s.enclaveClient.SignPublicKey(enclaveReq)
	if err != nil {
		slog.Error("sign.failed", "principal", principal, "group", result.GroupName, "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Signing failed"})
		return
	}

	slog.Info("sign.success",
		"principal", principal,
		"group", result.GroupName,
		"granted_principals", result.CertificateRules.AllowedPrincipals,
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(messages.SigningResponse{SignedKey: signedKey})
}


func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy"}`))
}
