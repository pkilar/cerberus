package api

import (
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/time/rate"
)

func TestPrincipalLimiter_PerPrincipalBuckets(t *testing.T) {
	// rps=0 means no replenishment within the test window; only the burst
	// pool is available. Two hits allowed for alice, the third denied.
	p := &principalLimiter{rps: 0, burst: 2, m: make(map[string]*rate.Limiter)}

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

// TestPrincipalLimiter_Concurrent exercises the map+mutex under concurrent
// load to catch regressions under `go test -race`. With rps=0 and burst=N,
// the total number of allowed requests across all goroutines MUST equal N
// per principal regardless of scheduling.
func TestPrincipalLimiter_Concurrent(t *testing.T) {
	const (
		burst       = 10
		goroutines  = 50
		perGoroutine = 4 // 50 * 4 = 200 requests per principal
		principals  = 8
	)
	p := &principalLimiter{rps: 0, burst: burst, m: make(map[string]*rate.Limiter)}

	var wg sync.WaitGroup
	allowed := make(map[string]*atomic.Int64, principals)
	for i := range principals {
		allowed[principalName(i)] = new(atomic.Int64)
	}

	for i := range goroutines {
		for pIdx := range principals {
			wg.Add(1)
			go func(who string) {
				defer wg.Done()
				for range perGoroutine {
					if p.allow(who) {
						allowed[who].Add(1)
					}
				}
			}(principalName(pIdx))
		}
		_ = i
	}
	wg.Wait()

	// Each principal has its own bucket; at rps=0 the total allowed equals
	// the burst exactly — no more, no fewer.
	for who, n := range allowed {
		got := n.Load()
		if got != int64(burst) {
			t.Errorf("%s: allowed %d, want %d (burst only)", who, got, burst)
		}
	}
}

func principalName(i int) string {
	return "user" + string(rune('a'+i)) + "@EXAMPLE.COM"
}
