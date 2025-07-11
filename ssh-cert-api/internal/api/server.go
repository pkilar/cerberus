package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"time"

	"cerberus/messages"
	"ssh-cert-api/internal/auth"
	"ssh-cert-api/internal/config"
	"ssh-cert-api/internal/enclave"
)

type contextKey string

const userContextKey contextKey = "user"

type Server struct {
	config        *config.Config
	authenticator auth.Authenticator
	enclaveClient enclave.Signer
	router        *http.ServeMux
}

func NewServer(cfg *config.Config, authenticator auth.Authenticator, enclaveClient enclave.Signer) (*Server, error) {
	s := &Server{
		config:        cfg,
		authenticator: authenticator,
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
			log.Printf("Authentication failed: %v", err)
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

	var req messages.SigningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	log.Printf("Signing request from user: %s", principal)

	// Check authorization and get user's group configuration
	groupConfig, authorized := s.getAuthorizationConfig(principal, req.Principals)
	if !authorized {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Not authorized for requested principals"})
		return
	}

	// Create enclave request using config-based attributes
	// Merge static attributes from config with dynamic audit attributes
	customAttributes := make(map[string]string)
	maps.Copy(customAttributes, groupConfig.StaticAttributes)
	// Add audit trail attributes
	customAttributes["issued_at"] = fmt.Sprintf("%d", time.Now().Unix())

	enclaveReq := &messages.EnclaveSigningRequest{
		SSHKey:           req.SSHKey,
		KeyID:            principal,
		Principals:       groupConfig.AllowedPrincipals,
		Validity:         groupConfig.Validity,
		Permissions:      groupConfig.Permissions,
		CustomAttributes: customAttributes,
		CriticalOptions:  groupConfig.CriticalOptions,
	}

	// Sign the key
	signedKey, err := s.enclaveClient.SignPublicKey(enclaveReq)
	if err != nil {
		log.Printf("Signing failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(messages.SigningResponse{Error: "Signing failed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(messages.SigningResponse{SignedKey: signedKey})
}

// getAuthorizationConfig checks if the user is authorized and returns their group configuration
func (s *Server) getAuthorizationConfig(principal string, requestedPrincipals []string) (*config.CertificateRules, bool) {
	for _, group := range s.config.Groups {
		for _, member := range group.Members {
			if member == principal {
				// Check if all requested principals are allowed for this user's group
				for _, reqPrincipal := range requestedPrincipals {
					found := slices.Contains(group.CertificateRules.AllowedPrincipals, reqPrincipal)
					if !found {
						return nil, false
					}
				}
				// All requested principals are authorized, return the group's certificate rules
				return &group.CertificateRules, true
			}
		}
	}
	return nil, false
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy"}`))
}
