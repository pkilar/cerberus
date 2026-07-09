package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

var _ Authenticator = (*OIDCAuthenticator)(nil)

// OIDCAuthenticator authenticates `Authorization: Bearer <JWT>` requests against
// an OIDC identity provider. Tokens are validated entirely offline: the issuer's
// JWKS (fetched and cached at startup, refreshed on key rotation) verifies the
// signature, and the issuer, audience, and exp/nbf/iat claims are checked here.
// A validated token yields an AuthenticatedUser whose Username comes from the
// configured username claim, Realm is the configured synthetic label, and Groups
// are the values of the configured groups claim (matched downstream against
// oidc_groups bindings).
type OIDCAuthenticator struct {
	verifier      *oidc.IDTokenVerifier
	audiences     []string
	usernameClaim string
	groupsClaim   string
	realm         string
	leeway        time.Duration
	// now is injectable so tests can pin the clock; production uses time.Now.
	now func() time.Time
}

// NewOIDCAuthenticator performs OIDC discovery against cfg.Issuer and returns an
// authenticator ready to validate bearer tokens. Discovery and all JWKS fetches
// use an HTTP client bounded by cfg.HTTPTimeout with standard TLS verification.
// It returns an error if discovery fails, so main can fail fast at startup —
// mirroring the LDAP initial-bind probe.
func NewOIDCAuthenticator(ctx context.Context, cfg config.OAuthConfig) (*OIDCAuthenticator, error) {
	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	// go-oidc reads its HTTP client from the context. The remote key set that
	// backs the verifier captures the context passed to VerifierContext (not the
	// per-request Verify context) for JWKS fetches, so both discovery and later
	// key-rotation refreshes go through this bounded client. Verifier() alone
	// would fall back to http.DefaultClient (no timeout).
	clientCtx := oidc.ClientContext(ctx, httpClient)

	provider, err := oidc.NewProvider(clientCtx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for issuer %q failed: %w", cfg.Issuer, err)
	}

	verifier := provider.VerifierContext(clientCtx, &oidc.Config{
		// We validate the audience ourselves against the configured set (an IdP
		// may mint multiple audiences), so skip go-oidc's single-clientID check.
		SkipClientIDCheck: true,
		// We validate exp/nbf/iat ourselves so we can apply cfg.Leeway; go-oidc
		// has no leeway knob.
		SkipExpiryCheck: true,
		// Restricting verification to an asymmetric allowlist is the
		// algorithm-confusion defense: a token whose header alg is `none` or any
		// HMAC HS* is rejected before signature verification, so the issuer's
		// public keys can never be abused as an HMAC secret. Config validation
		// guarantees these entries are asymmetric.
		SupportedSigningAlgs: cfg.Algorithms,
	})

	return &OIDCAuthenticator{
		verifier:      verifier,
		audiences:     slices.Clone(cfg.Audiences),
		usernameClaim: cfg.UsernameClaim,
		groupsClaim:   cfg.GroupsClaim,
		realm:         cfg.Realm,
		leeway:        cfg.Leeway,
		now:           time.Now,
	}, nil
}

// AuthenticateRequest validates the request's Bearer token and returns the
// authenticated identity. Token bytes are never logged (they are replayable
// within their validity window).
func (o *OIDCAuthenticator) AuthenticateRequest(r *http.Request) (*AuthenticatedUser, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoAuthorizationHeader
	}
	rawToken, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return nil, fmt.Errorf("authorization header must use Bearer scheme")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	// Verify signature (against the issuer's JWKS), the signing-algorithm
	// allowlist, and the issuer. Expiry and audience are checked below.
	idToken, err := o.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Audience: at least one of the token's audiences must be configured.
	if !audienceAllowed(idToken.Audience, o.audiences) {
		return nil, fmt.Errorf("token audience %v is not in the allowed set", idToken.Audience)
	}

	// Time validation with leeway. A token with no exp never expires, which is
	// unacceptable for a signing CA — require it (OIDC ID tokens always carry
	// one; go-oidc leaves Expiry zero when the claim is absent).
	now := o.now()
	if idToken.Expiry.IsZero() {
		return nil, fmt.Errorf("token has no exp claim")
	}
	if now.After(idToken.Expiry.Add(o.leeway)) {
		return nil, fmt.Errorf("token expired at %s", idToken.Expiry.UTC().Format(time.RFC3339))
	}
	if !idToken.IssuedAt.IsZero() && idToken.IssuedAt.After(now.Add(o.leeway)) {
		return nil, fmt.Errorf("token issued in the future (iat %s)", idToken.IssuedAt.UTC().Format(time.RFC3339))
	}

	// Custom-named claims (username, groups) and nbf require the raw claim set.
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}
	if nbf, present, err := numericDateClaim(claims, "nbf"); err != nil {
		return nil, err
	} else if present && now.Add(o.leeway).Before(nbf) {
		return nil, fmt.Errorf("token not yet valid (nbf %s)", nbf.UTC().Format(time.RFC3339))
	}

	username, err := stringClaim(claims, o.usernameClaim)
	if err != nil {
		return nil, err
	}
	if username == "" {
		return nil, fmt.Errorf("username claim %q is empty or missing", o.usernameClaim)
	}
	groups, err := stringOrStringsClaim(claims, o.groupsClaim)
	if err != nil {
		return nil, err
	}

	slog.Info("auth.success", "principal", username+"@"+o.realm, "method", "oidc", "remote_addr", r.RemoteAddr)

	return &AuthenticatedUser{
		Username: username,
		Realm:    o.realm,
		Groups:   groups,
		Method:   "oidc",
	}, nil
}

// audienceAllowed reports whether any of the token's audiences appears in the
// configured allowlist.
func audienceAllowed(tokenAudiences, allowed []string) bool {
	for _, a := range tokenAudiences {
		if slices.Contains(allowed, a) {
			return true
		}
	}
	return false
}

// numericDateClaim parses a JWT NumericDate claim (seconds since the epoch, per
// RFC 7519, possibly fractional). present is false when the claim is absent.
func numericDateClaim(claims map[string]json.RawMessage, key string) (t time.Time, present bool, err error) {
	raw, ok := claims[key]
	if !ok {
		return time.Time{}, false, nil
	}
	var secs float64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return time.Time{}, false, fmt.Errorf("claim %q is not a numeric date", key)
	}
	whole, frac := math.Modf(secs)
	return time.Unix(int64(whole), int64(frac*float64(time.Second))), true, nil
}

// stringClaim reads a string-valued claim. A missing claim returns "" with no
// error (the caller decides whether emptiness is fatal); a present-but-non-string
// claim is an error.
func stringClaim(claims map[string]json.RawMessage, key string) (string, error) {
	raw, ok := claims[key]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("claim %q is not a string", key)
	}
	return s, nil
}

// stringOrStringsClaim reads a groups-style claim that is normally a JSON array
// of strings but which some IdPs emit as a single scalar string for a lone
// group. A missing claim yields nil (no groups). Any other shape is an error.
func stringOrStringsClaim(claims map[string]json.RawMessage, key string) ([]string, error) {
	raw, ok := claims[key]
	if !ok {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}, nil
	}
	return nil, fmt.Errorf("claim %q is neither a string nor an array of strings", key)
}
