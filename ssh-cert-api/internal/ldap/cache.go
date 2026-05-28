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
// Errors are propagated and never cached.
func (c *cache) groups(ctx context.Context, key string, fetch fetchFunc) ([]string, error) {
	if v, ok := c.lookup(key); ok {
		c.hits.Add(1)
		return v, nil
	}
	c.misses.Add(1)

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Double-check under singleflight: another goroutine may have
		// repopulated this key between our lookup miss and the leader
		// running, in which case we skip the network call.
		if v, ok := c.lookup(key); ok {
			return v, nil
		}
		groups, err := fetch(ctx)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.items[key] = cacheEntry{groups: groups, fetched: c.now()}
		c.mu.Unlock()
		return groups, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
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

// Hits and Misses are exposed so the surrounding Client can publish them
// as Prometheus counters without the cache depending on prometheus directly.
func (c *cache) Hits() int64   { return c.hits.Load() }
func (c *cache) Misses() int64 { return c.misses.Load() }
