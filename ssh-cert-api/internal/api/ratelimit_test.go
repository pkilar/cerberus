package api

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestPrincipalLimiter_PerPrincipalBuckets(t *testing.T) {
	// rps=0 means no replenishment within the test window; only the burst
	// pool is available. Two hits allowed for alice, the third denied.
	p := &principalLimiter{rps: 0, burst: 2}

	if !p.allow("alice@EXAMPLE.COM") {
		t.Fatal("alice: first request should be allowed")
	}
	if !p.allow("alice@EXAMPLE.COM") {
		t.Fatal("alice: second request should be allowed (burst)")
	}
	if p.allow("alice@EXAMPLE.COM") {
		t.Fatal("alice: third request should be denied after burst")
	}

	// Different principal gets its own bucket.
	if !p.allow("bob@EXAMPLE.COM") {
		t.Fatal("bob: first request should be allowed (independent bucket)")
	}
}

func TestPrincipalLimiter_DefaultsFromEnv(t *testing.T) {
	t.Setenv("RATE_LIMIT_RPS", "1")
	t.Setenv("RATE_LIMIT_BURST", "3")

	p := newPrincipalLimiter()
	if p.rps != rate.Limit(1) {
		t.Errorf("expected rps=1 from env, got %v", p.rps)
	}
	if p.burst != 3 {
		t.Errorf("expected burst=3 from env, got %d", p.burst)
	}
}

func TestPrincipalLimiter_InvalidEnvFallsBackToDefault(t *testing.T) {
	t.Setenv("RATE_LIMIT_RPS", "not-a-number")
	t.Setenv("RATE_LIMIT_BURST", "-5")

	p := newPrincipalLimiter()
	if p.rps != rate.Limit(defaultRateLimitRPS) {
		t.Errorf("expected default rps after invalid env, got %v", p.rps)
	}
	if p.burst != defaultRateLimitBurst {
		t.Errorf("expected default burst after invalid env, got %d", p.burst)
	}
}
