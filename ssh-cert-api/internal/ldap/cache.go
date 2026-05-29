package ldap

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// cacheEntry is one positive-cached uid lookup. Stored values are reused
// directly so callers MUST treat the returned slice as read-only.
type cacheEntry struct {
	groups  []string
	fetched time.Time
}

// fetchFunc populates the cache for a missing or expired key. Errors are
// propagated to the caller and never cached.
type fetchFunc func(ctx context.Context) ([]string, error)

// cache is a positive-only, TTL-bounded LDAP-result cache with singleflight
// collapsing of concurrent fetches for the same key. Errors are never cached.
//
// The cache is intentionally small in surface: callers pass a fetch closure
// per call rather than a long-lived fetcher object, so the cache can be unit-
// tested without standing up an LDAP backend.
type cache struct {
	ttl time.Duration
	now func() time.Time // injection point for tests; defaults to time.Now

	mu    sync.RWMutex
	items map[string]cacheEntry

	sf singleflight.Group

	hits   atomic.Int64
	misses atomic.Int64
}

func newCache(ttl time.Duration) *cache {
	return &cache{
		ttl:   ttl,
		now:   time.Now,
		items: map[string]cacheEntry{},
	}
}

// groups returns the cached groups for key, fetching them on miss or expiry.
// Concurrent calls with the same key collapse to one fetch via singleflight.
// Errors are propagated and never cached. The returned hit reports whether
// THIS call was served from cache — derived from this call's own lookup, not
// from a shared counter snapshot, so concurrent callers attribute their own
// hit/miss correctly.
func (c *cache) groups(ctx context.Context, key string, fetch fetchFunc) (groups []string, hit bool, err error) {
	if v, ok := c.lookup(key); ok {
		c.hits.Add(1)
		return v, true, nil
	}
	c.misses.Add(1)

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Double-check under singleflight: another goroutine may have
		// repopulated this key between our lookup miss and the leader
		// running, in which case we skip the network call.
		if v, ok := c.lookup(key); ok {
			return v, nil
		}
		fetched, ferr := fetch(ctx)
		if ferr != nil {
			return nil, ferr
		}
		c.mu.Lock()
		c.items[key] = cacheEntry{groups: fetched, fetched: c.now()}
		c.mu.Unlock()
		return fetched, nil
	})
	if err != nil {
		return nil, false, err
	}
	return v.([]string), false, nil
}

func (c *cache) lookup(key string) ([]string, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || c.now().Sub(e.fetched) >= c.ttl {
		return nil, false
	}
	return e.groups, true
}

// Hits and Misses expose the aggregate cache counters for tests. Per-call
// hit/miss attribution (for Prometheus) comes from groups' return value, not
// these shared counters, to stay correct under concurrency.
func (c *cache) Hits() int64   { return c.hits.Load() }
func (c *cache) Misses() int64 { return c.misses.Load() }
