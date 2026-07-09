package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

// oidcTestEnv is a fully wired OIDC authenticator backed by an in-process IdP:
// an httptest server that serves an OIDC discovery document and a JWKS built
// from an ephemeral RSA key. The clock is pinned so exp/nbf/iat checks are
// deterministic.
type oidcTestEnv struct {
	auth   *OIDCAuthenticator
	priv   *rsa.PrivateKey
	issuer string
	now    time.Time
}

const testKeyID = "test-key"

func newOIDCTestEnv(t *testing.T) *oidcTestEnv {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"jwks_uri":               issuer + "/jwks",
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       priv.Public(),
			KeyID:     testKeyID,
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	cfg := config.OAuthConfig{
		Enabled:       true,
		Issuer:        issuer,
		Audiences:     []string{"cerberus"},
		UsernameClaim: "sub",
		GroupsClaim:   "groups",
		Realm:         "OIDC",
		Algorithms:    []string{"RS256"},
		Leeway:        60 * time.Second,
		HTTPTimeout:   5 * time.Second,
	}
	a, err := NewOIDCAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	return &oidcTestEnv{auth: a, priv: priv, issuer: issuer, now: now}
}

// baseClaims returns a valid claim set relative to the pinned clock.
func (e *oidcTestEnv) baseClaims() map[string]any {
	return map[string]any{
		"iss":    e.issuer,
		"aud":    []string{"cerberus"},
		"sub":    "jsmith",
		"groups": []string{"platform-eng", "sre"},
		"iat":    e.now.Add(-1 * time.Minute).Unix(),
		"exp":    e.now.Add(1 * time.Hour).Unix(),
	}
}

func (e *oidcTestEnv) signRS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	return signJWT(t, jose.RS256, e.priv, testKeyID, claims)
}

func signJWT(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatalf("NewSigner(%s): %v", alg, err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return s
}

func (e *oidcTestEnv) authenticate(t *testing.T, token string) (*AuthenticatedUser, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/sign", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return e.auth.AuthenticateRequest(r)
}

func TestOIDC_ValidToken(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	user, err := env.authenticate(t, env.signRS256(t, env.baseClaims()))
	if err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}
	if user.Username != "jsmith" {
		t.Errorf("Username = %q, want jsmith", user.Username)
	}
	if user.Realm != "OIDC" {
		t.Errorf("Realm = %q, want OIDC", user.Realm)
	}
	if user.Method != "oidc" {
		t.Errorf("Method = %q, want oidc", user.Method)
	}
	if !slices.Equal(user.Groups, []string{"platform-eng", "sre"}) {
		t.Errorf("Groups = %v, want [platform-eng sre]", user.Groups)
	}
}

func TestOIDC_ClaimAndTimeVariations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		mutate     func(e *oidcTestEnv, c map[string]any)
		wantErr    string // "" means success
		wantGroups []string
	}{
		{
			name:       "single-string groups claim",
			mutate:     func(_ *oidcTestEnv, c map[string]any) { c["groups"] = "solo" },
			wantGroups: []string{"solo"},
		},
		{
			name:       "missing groups claim",
			mutate:     func(_ *oidcTestEnv, c map[string]any) { delete(c, "groups") },
			wantGroups: nil,
		},
		{
			name:   "expired beyond leeway",
			mutate: func(e *oidcTestEnv, c map[string]any) { c["exp"] = e.now.Add(-2 * time.Hour).Unix() },
			// 2h past, leeway 60s
			wantErr: "expired",
		},
		{
			name:       "expired within leeway",
			mutate:     func(e *oidcTestEnv, c map[string]any) { c["exp"] = e.now.Add(-30 * time.Second).Unix() },
			wantGroups: []string{"platform-eng", "sre"},
		},
		{
			name:    "nbf in the future beyond leeway",
			mutate:  func(e *oidcTestEnv, c map[string]any) { c["nbf"] = e.now.Add(2 * time.Minute).Unix() },
			wantErr: "not yet valid",
		},
		{
			name:       "nbf in the future within leeway",
			mutate:     func(e *oidcTestEnv, c map[string]any) { c["nbf"] = e.now.Add(30 * time.Second).Unix() },
			wantGroups: []string{"platform-eng", "sre"},
		},
		{
			name:    "iat in the future beyond leeway",
			mutate:  func(e *oidcTestEnv, c map[string]any) { c["iat"] = e.now.Add(2 * time.Minute).Unix() },
			wantErr: "future",
		},
		{
			name:    "missing exp claim rejected",
			mutate:  func(_ *oidcTestEnv, c map[string]any) { delete(c, "exp") },
			wantErr: "no exp",
		},
		{
			name:    "wrong issuer",
			mutate:  func(_ *oidcTestEnv, c map[string]any) { c["iss"] = "https://evil.example.com" },
			wantErr: "verification failed",
		},
		{
			name:    "audience not in allowed set",
			mutate:  func(_ *oidcTestEnv, c map[string]any) { c["aud"] = []string{"some-other-service"} },
			wantErr: "audience",
		},
		{
			name:       "audience array contains a valid one",
			mutate:     func(_ *oidcTestEnv, c map[string]any) { c["aud"] = []string{"other", "cerberus"} },
			wantGroups: []string{"platform-eng", "sre"},
		},
		{
			name:    "empty username claim",
			mutate:  func(_ *oidcTestEnv, c map[string]any) { c["sub"] = "" },
			wantErr: "empty or missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newOIDCTestEnv(t)
			claims := env.baseClaims()
			tt.mutate(env, claims)
			user, err := env.authenticate(t, env.signRS256(t, claims))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(user.Groups, tt.wantGroups) {
				t.Errorf("Groups = %v, want %v", user.Groups, tt.wantGroups)
			}
		})
	}
}

func TestOIDC_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	// Hand-craft an unsigned (alg:none) token.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(env.baseClaims())
	body := base64.RawURLEncoding.EncodeToString(payload)
	token := header + "." + body + "."
	if _, err := env.authenticate(t, token); err == nil {
		t.Fatal("alg:none token must be rejected")
	}
}

func TestOIDC_AlgConfusionHS256Rejected(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	// Classic algorithm-confusion: forge an HS256 token using the issuer's
	// RSA public-key bytes as the HMAC secret. The asymmetric allowlist must
	// reject it before any signature check.
	pubDER, err := x509.MarshalPKIXPublicKey(env.priv.Public())
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	token := signJWT(t, jose.HS256, pubDER, testKeyID, env.baseClaims())
	if _, err := env.authenticate(t, token); err == nil {
		t.Fatal("HS256-with-public-key token must be rejected (algorithm confusion)")
	}
}

func TestOIDC_UnknownKeyID(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	token := signJWT(t, jose.RS256, env.priv, "some-other-kid", env.baseClaims())
	if _, err := env.authenticate(t, token); err == nil {
		t.Fatal("token signed with an unknown kid must be rejected")
	}
}

func TestOIDC_BadSignature(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Sign with a different key but advertise the JWKS kid; signature won't verify.
	token := signJWT(t, jose.RS256, other, testKeyID, env.baseClaims())
	if _, err := env.authenticate(t, token); err == nil {
		t.Fatal("token with an invalid signature must be rejected")
	}
}

func TestOIDC_MalformedToken(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)
	if _, err := env.authenticate(t, "not.a.valid.jwt"); err == nil {
		t.Fatal("malformed token must be rejected")
	}
}

func TestOIDC_HeaderHandling(t *testing.T) {
	t.Parallel()
	env := newOIDCTestEnv(t)

	// No Authorization header → sentinel so the challenge path fires.
	r := httptest.NewRequest(http.MethodPost, "/sign", nil)
	if _, err := env.auth.AuthenticateRequest(r); !errors.Is(err, ErrNoAuthorizationHeader) {
		t.Fatalf("no header: got %v, want ErrNoAuthorizationHeader", err)
	}

	// Wrong scheme → non-sentinel error.
	r = httptest.NewRequest(http.MethodPost, "/sign", nil)
	r.Header.Set("Authorization", "Negotiate abc")
	if _, err := env.auth.AuthenticateRequest(r); err == nil || errors.Is(err, ErrNoAuthorizationHeader) {
		t.Fatalf("Negotiate scheme: got %v, want a non-sentinel scheme error", err)
	}
}

func TestNewOIDCAuthenticator_DiscoveryFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	cfg := config.OAuthConfig{
		Enabled:     true,
		Issuer:      srv.URL,
		Audiences:   []string{"cerberus"},
		Realm:       "OIDC",
		Algorithms:  []string{"RS256"},
		HTTPTimeout: 2 * time.Second,
	}
	if _, err := NewOIDCAuthenticator(context.Background(), cfg); err == nil {
		t.Fatal("expected discovery failure to error at construction")
	}
}
