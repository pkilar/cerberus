package ldap

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCache_HitWithinTTL(t *testing.T) {
	t.Parallel()
	c := newCache(time.Minute)
	calls := atomic.Int64{}
	fetch := func(ctx context.Context) ([]string, error) {
		calls.Add(1)
		return []string{"g1", "g2"}, nil
	}
	for range 5 {
		got, _, err := c.groups(t.Context(), "alice", fetch)
		if err != nil {
			t.Fatalf("groups: %v", err)
		}
		if !slices.Equal(got, []string{"g1", "g2"}) {
			t.Fatalf("got %v", got)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("fetch called %d times, want 1", got)
	}
	if c.Hits() != 4 || c.Misses() != 1 {
		t.Errorf("counters: hits=%d misses=%d, want 4/1", c.Hits(), c.Misses())
	}
}

func TestCache_ExpiryTriggersRefresh(t *testing.T) {
	t.Parallel()
	c := newCache(50 * time.Millisecond)
	// Inject a controllable clock so the test is wall-clock-independent.
	current := time.Unix(0, 0)
	c.now = func() time.Time { return current }

	calls := atomic.Int64{}
	fetch := func(ctx context.Context) ([]string, error) {
		calls.Add(1)
		return []string{"g1"}, nil
	}

	if _, _, err := c.groups(t.Context(), "alice", fetch); err != nil {
		t.Fatalf("first: %v", err)
	}
	current = current.Add(100 * time.Millisecond) // past TTL
	if _, _, err := c.groups(t.Context(), "alice", fetch); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("fetch called %d times, want 2", got)
	}
}

func TestCache_ErrorsNotCached(t *testing.T) {
	t.Parallel()
	c := newCache(time.Minute)
	sentinel := errors.New("ldap down")
	calls := atomic.Int64{}
	fetch := func(ctx context.Context) ([]string, error) {
		calls.Add(1)
		return nil, sentinel
	}
	for range 3 {
		_, _, err := c.groups(t.Context(), "alice", fetch)
		if !errors.Is(err, sentinel) {
			t.Fatalf("expected sentinel, got %v", err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("fetch called %d times, want 3 (errors never cached)", got)
	}
}

// TestCache_Singleflight_Collapses verifies that many concurrent goroutines
// requesting the same uid simultaneously result in exactly one underlying
// fetch. This is the boundary case the cache exists to defend against —
// without singleflight, a TTL expiry burst would N-multiply the LDAP load.
func TestCache_Singleflight_Collapses(t *testing.T) {
	t.Parallel()
	c := newCache(time.Minute)
	start := make(chan struct{})
	gate := make(chan struct{})
	calls := atomic.Int64{}
	fetch := func(ctx context.Context) ([]string, error) {
		calls.Add(1)
		<-gate // hold the leader until all followers have arrived
		return []string{"g1"}, nil
	}

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			_, _, err := c.groups(t.Context(), "alice", fetch)
			if err != nil {
				t.Errorf("groups: %v", err)
			}
		}()
	}
	close(start)
	// Give goroutines a moment to all enter singleflight.Do for the same key.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("fetch called %d times, want 1 (singleflight should have collapsed)", got)
	}
}

// TestCache_GroupsReportsHitMiss asserts that groups reports hit/miss for the
// calling goroutine directly (the value the Prometheus counters key on), not
// inferred from a shared counter snapshot.
func TestCache_GroupsReportsHitMiss(t *testing.T) {
	t.Parallel()
	c := newCache(time.Minute)
	fetch := func(ctx context.Context) ([]string, error) { return []string{"g1"}, nil }

	if _, hit, err := c.groups(t.Context(), "alice", fetch); err != nil || hit {
		t.Fatalf("first call: hit=%v err=%v, want hit=false (miss)", hit, err)
	}
	if _, hit, err := c.groups(t.Context(), "alice", fetch); err != nil || !hit {
		t.Fatalf("second call: hit=%v err=%v, want hit=true", hit, err)
	}

	// A propagated error is reported as a miss (errors are never cached).
	sentinel := errors.New("ldap down")
	failing := func(ctx context.Context) ([]string, error) { return nil, sentinel }
	if _, hit, err := c.groups(t.Context(), "bob", failing); !errors.Is(err, sentinel) || hit {
		t.Fatalf("error call: hit=%v err=%v, want hit=false and sentinel error", hit, err)
	}
}
