package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
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
//
// The target ordering and selection logic (rfc2782Order, orderedTargets behind
// a fake resolver, urlTarget, planDial) IS unit-tested in srv_test.go and
// connect_test.go; only the live dial/StartTLS/bind/search round trip remains
// out of CI.
type client struct {
	backend  config.LDAPBackend
	bindCred *bindCreds
	tlsBase  *tls.Config
	resolver srvResolver

	cache   *cache
	metrics *Metrics

	mu         sync.Mutex
	conn       *goldap.Conn
	srvRecords []*net.SRV
	srvExpires time.Time
}

// NewClient builds a real LDAP client from one validated config block. The
// API's keytabPath is threaded in so a gssapi bind can re-load it; password
// files for simple bind are read once at this point and held in memory.
// Permission-checked the same way as the keytab (CheckSecretFilePerms).
func NewClient(backend config.LDAPBackend, keytabPath string, metrics *Metrics) (Client, error) {
	var password string
	if backend.Bind.Method == config.LDAPBindSimple {
		if err := auth.CheckSecretFilePerms(backend.Bind.PasswordFile, "ldap password file"); err != nil {
			return nil, fmt.Errorf("ldap password file validation failed: %w", err)
		}
		// #nosec G304 -- path comes from the operator's config, validated
		// already at config load; same trust model as the keytab path.
		data, err := os.ReadFile(backend.Bind.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read ldap password_file: %w", err)
		}
		password = strings.TrimRight(string(data), "\n\r")
		if password == "" {
			return nil, fmt.Errorf("ldap password_file is empty")
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
		tlsBase:  tlsCfg,
		resolver: net.DefaultResolver,
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
	// Log the exact search we are about to issue. This is the "query" half of
	// LDAP debugging: the escaped filter (what SafeUserFilter produced from the
	// uid), the base DN, and the membership attribute. A user_filter that does
	// not match the directory's schema (e.g. the AD `sAMAccountName` example
	// pointed at a FreeIPA server, whose users key on `uid`) shows up here as a
	// filter that then returns zero entries below.
	slog.Debug("ldap.query.request",
		"backend", c.backend.Name,
		"uid", shortUID,
		"base_dn", c.backend.UserBaseDN,
		"filter", filter,
		"membership_attr", c.backend.GroupMembershipAttr)

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
	// group_count stays for cheap at-a-glance triage; the full DN list is the
	// "response" half of LDAP debugging — it is what the authorizer compares
	// against each group's `ldap_groups:` binding, so seeing the exact DNs here
	// (e.g. `cn=rootusers,cn=groups,...`) is what reveals a binding written as a
	// bare CN instead of a full DN. Guarded by DEBUG: these DNs expose directory
	// structure and should not appear in production logs.
	slog.Debug("ldap.query.success",
		"backend", c.backend.Name,
		"uid", shortUID,
		"group_count", len(groups),
		"groups", groups)
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

	if err := c.ensureConnLocked(ctx); err != nil {
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
	if err := c.ensureConnLocked(ctx); err != nil {
		return nil, err
	}
	res, err = c.conn.Search(req)
	if err != nil {
		c.recordQueryError("search")
	}
	return res, err
}

// effectiveTLSMode collapses the url and srv config styles into a single TLS
// mode. For a url backend the scheme decides (ldaps:// -> ldaps, else none);
// for an srv backend the explicit tls_mode is authoritative.
func effectiveTLSMode(b config.LDAPBackend) string {
	if b.SRV != nil {
		return b.TLSMode
	}
	if strings.HasPrefix(b.URL, "ldaps://") {
		return config.LDAPTLSModeLDAPS
	}
	return config.LDAPTLSModeNone
}

// urlTarget parses a backend url into one dial target, applying default ports
// (636 for ldaps, 389 for ldap) when the url omits one.
func urlTarget(rawURL string) (target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return target{}, fmt.Errorf("parse ldap url %q: %w", rawURL, err)
	}
	host := u.Hostname()
	if host == "" {
		return target{}, fmt.Errorf("ldap url %q has no host", rawURL)
	}
	port := 389
	if u.Scheme == "ldaps" {
		port = 636
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return target{}, fmt.Errorf("ldap url %q has invalid port: %w", rawURL, err)
		}
		port = n
	}
	return target{host: host, port: port}, nil
}

func srvQueryName(s *config.LDAPSRV) string {
	return "_" + s.Service + "._" + s.Proto + "." + s.Domain
}

// orderedTargets returns the connection candidates in priority order. A url
// backend yields exactly one static target; an srv backend resolves its record
// (cached for srv.cache_ttl) and orders it per RFC 2782. Caller MUST hold c.mu.
func (c *client) orderedTargets(ctx context.Context) ([]target, error) {
	if c.backend.SRV == nil {
		t, err := urlTarget(c.backend.URL)
		if err != nil {
			return nil, err
		}
		return []target{t}, nil
	}
	recs, err := c.srvRecordsCached(ctx)
	if err != nil {
		return nil, err
	}
	targets := rfc2782Order(recs)
	if len(targets) == 0 {
		return nil, fmt.Errorf("ldap srv %s: no usable targets", srvQueryName(c.backend.SRV))
	}
	return targets, nil
}

// srvRecordsCached returns the SRV answer, reusing the cached copy until it
// expires. Caller MUST hold c.mu.
func (c *client) srvRecordsCached(ctx context.Context) ([]*net.SRV, error) {
	if c.srvRecords != nil && time.Now().Before(c.srvExpires) {
		return c.srvRecords, nil
	}
	s := c.backend.SRV
	_, recs, err := c.resolver.LookupSRV(ctx, s.Service, s.Proto, s.Domain)
	if err != nil {
		c.recordQueryError("srv")
		return nil, fmt.Errorf("ldap srv lookup %s: %w", c.backend.Name, err)
	}
	c.srvRecords = recs
	c.srvExpires = time.Now().Add(s.CacheTTL)
	return recs, nil
}

// dialPlan captures how to dial a target without performing any I/O, so the
// per-mode branch selection is unit-testable.
type dialPlan struct {
	dialURL   string
	startTLS  bool
	tlsConfig *tls.Config
}

// tlsFor clones the base TLS config and pins ServerName to the target host, so
// the server certificate validates against the host actually dialed (essential
// for SRV, where the target differs from the configured domain).
func (c *client) tlsFor(t target) *tls.Config {
	cfg := c.tlsBase.Clone()
	cfg.ServerName = t.host
	return cfg
}

// planDial computes the dial plan for t under the backend's effective TLS mode.
func (c *client) planDial(t target) dialPlan {
	hostport := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	switch effectiveTLSMode(c.backend) {
	case config.LDAPTLSModeLDAPS:
		return dialPlan{dialURL: "ldaps://" + hostport, tlsConfig: c.tlsFor(t)}
	case config.LDAPTLSModeStartTLS:
		return dialPlan{dialURL: "ldap://" + hostport, startTLS: true, tlsConfig: c.tlsFor(t)}
	default: // none
		return dialPlan{dialURL: "ldap://" + hostport}
	}
}

// dialTarget opens (and, for starttls, upgrades) a connection to t. The caller
// binds and stores it.
func (c *client) dialTarget(t target) (*goldap.Conn, error) {
	plan := c.planDial(t)
	dialOpts := []goldap.DialOpt{
		goldap.DialWithDialer(&net.Dialer{Timeout: c.backend.Timeout}),
	}
	if plan.tlsConfig != nil && !plan.startTLS {
		dialOpts = append(dialOpts, goldap.DialWithTLSConfig(plan.tlsConfig))
	}
	conn, err := goldap.DialURL(plan.dialURL, dialOpts...)
	if err != nil {
		return nil, err
	}
	// Bound the post-dial exchange (StartTLS handshake, bind, search) by the
	// backend timeout before performing any of it. goldap's default request
	// timeout is 0 (unbounded); without this a server that accepts the TCP
	// connection then stalls the StartTLS response would block the backend on
	// the held mutex indefinitely (net.Dialer only bounds the TCP connect).
	conn.SetTimeout(c.backend.Timeout)
	if plan.startTLS {
		if err := conn.StartTLS(plan.tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}

// ensureConnLocked dials and binds if no live conn is held, failing over across
// the ordered targets. Caller MUST hold c.mu.
func (c *client) ensureConnLocked(ctx context.Context) error {
	if c.conn != nil && !c.conn.IsClosing() {
		return nil
	}
	targets, err := c.orderedTargets(ctx)
	if err != nil {
		return err
	}
	var lastErr error
	for _, t := range targets {
		conn, err := c.dialTarget(t)
		if err != nil {
			c.recordQueryError("dial")
			slog.Warn("ldap.dial.failure",
				"backend", c.backend.Name,
				"target", t.host,
				"error", err)
			lastErr = err
			continue
		}
		if err := bind(conn, c.bindCred, ldapServerSPN(t.host)); err != nil {
			_ = conn.Close()
			c.recordQueryError("bind")
			slog.Warn("ldap.bind.failure",
				"backend", c.backend.Name,
				"target", t.host,
				"bind_method", c.bindCred.method,
				"error", err)
			lastErr = err
			continue
		}
		slog.Info("ldap.bind.success",
			"backend", c.backend.Name,
			"target", t.host,
			"bind_method", c.bindCred.method)
		c.conn = conn
		return nil
	}
	return fmt.Errorf("ldap connect %s: all targets failed: %w", c.backend.Name, lastErr)
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

// buildTLSConfig returns the base *tls.Config used for ldaps and starttls
// connections, or nil for plaintext (ldap:// url or tls_mode: none). ServerName
// is intentionally left unset here; it is filled in per-target at dial time so
// each discovered host validates against its own name.
func buildTLSConfig(b config.LDAPBackend) (*tls.Config, error) {
	switch effectiveTLSMode(b) {
	case config.LDAPTLSModeLDAPS, config.LDAPTLSModeStartTLS:
	default:
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
