package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/pkilar/cerberus/ssh-cert-api/internal/auth"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
)

// Client is the surface the authorizer and /health prober use. Two concrete
// implementations exist in-tree: the real *client backed by goldap, and a
// fake used in unit tests for the authorizer package. Both must be safe for
// concurrent use.
type Client interface {
	UserGroups(ctx context.Context, shortUID string) ([]string, error)
	HealthCheck(ctx context.Context) error
	Close() error
}

var _ Client = (*client)(nil)

// client is the production implementation. One *client per LDAPBackend
// declared in config. A single mutex serializes dial, bind, and search; QPS
// is bounded by the cache TTL and the upstream signing-request rate, so
// connection pooling is deliberately out of scope.
//
// TEST COVERAGE NOTE: the dial/bind/search round trip in this file and in
// bind.go is currently exercised only against a live directory — there is no
// in-tree stub speaking the LDAP wire protocol, so fetchUserGroups,
// searchWithReconnect, HealthCheck, and the bind methods are not run in CI.
// The filter-injection defense (SafeUserFilter) and the cache are unit-tested
// directly; the connection plumbing is not. Analogous to the VSOCK-vs-TCP gap
// documented in CLAUDE.md, this is a known gap, not an oversight. Closing it
// would mean introducing a seam over *goldap.Conn so a stub can return canned
// search results and errors (asserting the escaped filter is what gets sent
// and that errors propagate fail-closed).
type client struct {
	backend  config.LDAPBackend
	bindCred *bindCreds
	tls      *tls.Config

	cache   *cache
	metrics *Metrics

	mu   sync.Mutex
	conn *goldap.Conn
}

// NewClient builds a real LDAP client from one validated config block. The
// API's keytabPath is threaded in so a gssapi bind can re-load it; password
// files for simple bind are read once at this point and held in memory.
// Permission-checked the same way as the keytab (CheckSecretFilePerms).
func NewClient(backend config.LDAPBackend, keytabPath string, metrics *Metrics) (Client, error) {
	var password string
	if backend.Bind.Method == config.LDAPBindSimple {
		if err := auth.CheckSecretFilePerms(backend.Bind.PasswordFile, "ldap password file"); err != nil {
			return nil, err
		}
		// #nosec G304 -- path comes from the operator's config, validated
		// already at config load; same trust model as the keytab path.
		data, err := os.ReadFile(backend.Bind.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read ldap password_file: %w", err)
		}
		password = strings.TrimRight(string(data), "\n\r")
		if password == "" {
			return nil, fmt.Errorf("ldap password_file %s is empty", backend.Bind.PasswordFile)
		}
	}

	bc, err := newBindCreds(backend, keytabPath, password)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := buildTLSConfig(backend)
	if err != nil {
		return nil, err
	}

	return &client{
		backend:  backend,
		bindCred: bc,
		tls:      tlsCfg,
		cache:    newCache(backend.CacheTTL),
		metrics:  metrics,
	}, nil
}

// UserGroups returns the LDAP group DNs that shortUID belongs to. Cached for
// backend.CacheTTL. Concurrent calls for the same uid collapse into one live
// LDAP query via singleflight. Errors are not cached and bubble up so the
// authorizer can fail closed.
func (c *client) UserGroups(ctx context.Context, shortUID string) ([]string, error) {
	groups, hit, err := c.cache.groups(ctx, shortUID, func(ctx context.Context) ([]string, error) {
		start := time.Now()
		g, err := c.fetchUserGroups(ctx, shortUID)
		if c.metrics != nil {
			c.metrics.QueryDuration.WithLabelValues(c.backend.Name).Observe(time.Since(start).Seconds())
		}
		return g, err
	})
	// Publish cache counters from this call's own hit/miss result. Doing it
	// here (not inside cache.groups) keeps the cache prometheus-free for unit
	// testability; using the returned bool (not a shared-counter snapshot)
	// keeps attribution correct when calls run concurrently.
	if c.metrics != nil {
		if hit {
			c.metrics.CacheHits.WithLabelValues(c.backend.Name).Inc()
		} else {
			c.metrics.CacheMisses.WithLabelValues(c.backend.Name).Inc()
		}
	}
	return groups, err
}

func (c *client) fetchUserGroups(ctx context.Context, shortUID string) ([]string, error) {
	filter, err := SafeUserFilter(c.backend.UserFilter, shortUID)
	if err != nil {
		return nil, err
	}
	req := goldap.NewSearchRequest(
		c.backend.UserBaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		2, // size limit 2: cap parsing while still detecting a duplicate uid
		searchTimeLimitSeconds(c.backend.Timeout),
		false,
		filter,
		[]string{c.backend.GroupMembershipAttr},
		nil,
	)
	// Enforce the cap client-side so a duplicate uid surfaces as 2 parsed
	// entries (handled below) rather than a server-dependent size-limit error.
	req.EnforceSizeLimit = true
	res, err := c.searchWithReconnect(ctx, req)
	if err != nil {
		slog.Warn("ldap.query.failure",
			"backend", c.backend.Name,
			"uid", shortUID,
			"error", err)
		return nil, err
	}
	if len(res.Entries) == 0 {
		// A non-existent user is not an error — they simply have no LDAP
		// groups, so they qualify for no LDAP-backed Cerberus groups.
		return nil, nil
	}
	if len(res.Entries) > 1 {
		// user_filter is supposed to be unique. Multiple matches is a
		// directory misconfiguration we'd rather surface than silently
		// pick one.
		return nil, fmt.Errorf("user_filter matched more than one entry for uid %q; expected exactly one", shortUID)
	}
	groups := res.Entries[0].GetAttributeValues(c.backend.GroupMembershipAttr)
	slog.Debug("ldap.query.success",
		"backend", c.backend.Name,
		"uid", shortUID,
		"group_count", len(groups))
	return groups, nil
}

// HealthCheck probes the backend by dialing, binding (if needed), and
// issuing a base-scope search of UserBaseDN with no attributes. Cheap on the
// server side and exercises the same connection path as UserGroups.
func (c *client) HealthCheck(ctx context.Context) error {
	req := goldap.NewSearchRequest(
		c.backend.UserBaseDN,
		goldap.ScopeBaseObject,
		goldap.NeverDerefAliases,
		1,
		searchTimeLimitSeconds(c.backend.Timeout),
		false,
		"(objectClass=*)",
		[]string{},
		nil,
	)
	_, err := c.searchWithReconnect(ctx, req)
	return err
}

// searchTimeLimitSeconds converts a connection timeout into the server-side
// search TimeLimit (whole seconds), flooring at 1. Without the floor a
// sub-second timeout would truncate to 0, which LDAP interprets as "no server
// time limit" — the opposite of the operator's intent. The client read
// deadline (conn.SetTimeout) is the authoritative bound; this is belt-and-
// suspenders for servers that ignore TCP deadlines.
func searchTimeLimitSeconds(timeout time.Duration) int {
	return max(1, int(timeout.Seconds()))
}

func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// searchWithReconnect issues req under the client mutex, transparently
// re-dialing and re-binding once on a network-class error. The mutex is held
// for the entire round trip: per-backend QPS is low enough that contention
// is not worth a more complex pooled design.
//
// goldap v3.4.13 exposes no context-aware dial, so an in-flight round trip is
// bounded by conn.SetTimeout, not ctx. We do honor an already-cancelled ctx
// by failing fast before opening a socket.
func (c *client) searchWithReconnect(ctx context.Context, req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureConnLocked(); err != nil {
		return nil, err
	}
	res, err := c.conn.Search(req)
	if err == nil {
		return res, nil
	}
	if !isReconnectable(err) {
		c.recordQueryError("search")
		return nil, err
	}

	// Network/closed-connection error: drop the conn and try once more.
	c.closeLocked()
	if err := c.ensureConnLocked(); err != nil {
		return nil, err
	}
	res, err = c.conn.Search(req)
	if err != nil {
		c.recordQueryError("search")
	}
	return res, err
}

// ensureConnLocked dials and binds if no conn is held. Caller MUST hold c.mu.
func (c *client) ensureConnLocked() error {
	if c.conn != nil && !c.conn.IsClosing() {
		return nil
	}
	dialOpts := []goldap.DialOpt{
		goldap.DialWithDialer(&net.Dialer{Timeout: c.backend.Timeout}),
	}
	if c.tls != nil {
		dialOpts = append(dialOpts, goldap.DialWithTLSConfig(c.tls))
	}
	conn, err := goldap.DialURL(c.backend.URL, dialOpts...)
	if err != nil {
		c.recordQueryError("dial")
		return fmt.Errorf("ldap dial %s: %w", c.backend.Name, err)
	}
	conn.SetTimeout(c.backend.Timeout)

	if err := bind(conn, c.bindCred); err != nil {
		_ = conn.Close()
		c.recordQueryError("bind")
		slog.Warn("ldap.bind.failure",
			"backend", c.backend.Name,
			"bind_method", c.bindCred.method,
			"error", err)
		return fmt.Errorf("ldap bind %s: %w", c.backend.Name, err)
	}
	slog.Info("ldap.bind.success",
		"backend", c.backend.Name,
		"bind_method", c.bindCred.method)
	c.conn = conn
	return nil
}

func (c *client) closeLocked() {
	if c.conn == nil {
		return
	}
	_ = c.conn.Close()
	c.conn = nil
}

func (c *client) recordQueryError(kind string) {
	if c.metrics != nil {
		c.metrics.QueryErrors.WithLabelValues(c.backend.Name, kind).Inc()
	}
}

// isReconnectable returns true for errors that indicate the underlying TCP
// connection is dead and a retry against a fresh conn might succeed. goldap
// wraps every transport-level failure (dial error, closed connection, closed
// response channel, send failure) with result code ErrorNetwork, so that
// single coded check covers all reconnectable cases; auth failures,
// search-syntax errors, and server-side denials carry other result codes and
// are correctly treated as permanent.
func isReconnectable(err error) bool {
	return goldap.IsErrorWithCode(err, goldap.ErrorNetwork)
}

// buildTLSConfig returns a *tls.Config for ldaps:// URLs, or nil for plain
// ldap://. InsecureSkipVerify is honored but is warned about at config load.
func buildTLSConfig(b config.LDAPBackend) (*tls.Config, error) {
	if !strings.HasPrefix(b.URL, "ldaps://") {
		return nil, nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: b.TLS.InsecureSkipVerify, // #nosec G402 -- operator-opt-in, warned at startup
	}
	if b.TLS.CAFile != "" {
		// #nosec G304 -- path comes from operator config
		data, err := os.ReadFile(b.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ldap ca_file %s: %w", b.TLS.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("ldap ca_file: no certificates loaded (not PEM?)")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
