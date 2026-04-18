package api

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"

	"golang.org/x/time/rate"

	"ssh-cert-api/internal/auth"
)

const (
	defaultRateLimitRPS   = 5.0
	defaultRateLimitBurst = 10
)

// principalLimiter enforces per-principal token-bucket rate limits on /sign.
// Limiters are created lazily on first use and retained for the process
// lifetime. Footprint is O(unique principals) and bounded by the Kerberos
// realm, so unbounded growth is not a practical concern.
type principalLimiter struct {
	rps      rate.Limit
	burst    int
	limiters sync.Map // principal (string) -> *rate.Limiter
}

func newPrincipalLimiter() *principalLimiter {
	rps := defaultRateLimitRPS
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 {
			rps = parsed
		}
	}
	burst := defaultRateLimitBurst
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			burst = parsed
		}
	}
	return &principalLimiter{
		rps:   rate.Limit(rps),
		burst: burst,
	}
}

// allow reports whether one event is currently permitted for principal.
// It is safe for concurrent use.
func (p *principalLimiter) allow(principal string) bool {
	if v, ok := p.limiters.Load(principal); ok {
		return v.(*rate.Limiter).Allow()
	}
	v, _ := p.limiters.LoadOrStore(principal, rate.NewLimiter(p.rps, p.burst))
	return v.(*rate.Limiter).Allow()
}

// middleware wraps next and enforces per-principal rate limiting using the
// authenticated user stored in the request context by authMiddleware.
// Unauthenticated requests (e.g. /health) pass through unchanged.
func (p *principalLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(userContextKey).(*auth.AuthenticatedUser)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		principal := user.Username + "@" + user.Realm
		if !p.allow(principal) {
			slog.Warn("ratelimit.denied", "principal", principal)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
