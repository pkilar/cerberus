package ldap

import "github.com/prometheus/client_golang/prometheus"

// Metrics bundles the Prometheus collectors the package emits. A nil *Metrics
// is treated as "no metrics" — call sites guard against nil so unit tests and
// callers without a registry don't need to construct a stub.
type Metrics struct {
	CacheHits     *prometheus.CounterVec
	CacheMisses   *prometheus.CounterVec
	QueryErrors   *prometheus.CounterVec
	QueryDuration *prometheus.HistogramVec
	BackendUp     *prometheus.GaugeVec
}

// NewMetrics constructs and registers the LDAP metrics with reg. The returned
// pointer is held by every Client and the /health prober. The set of labels
// is fixed: backend (and kind on QueryErrors); high-cardinality dimensions
// like user principal are deliberately NOT labels.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		CacheHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_ldap_cache_hits_total",
			Help: "LDAP group-membership cache hits, per backend.",
		}, []string{"backend"}),
		CacheMisses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_ldap_cache_misses_total",
			Help: "LDAP group-membership cache misses (resulted in a live query), per backend.",
		}, []string{"backend"}),
		QueryErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cerberus_ldap_query_errors_total",
			Help: "LDAP errors by stage. kind is one of: dial, bind, search.",
		}, []string{"backend", "kind"}),
		QueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cerberus_ldap_query_duration_seconds",
			Help:    "Wall-clock duration of one UserGroups call, including reconnects but excluding cache hits.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		}, []string{"backend"}),
		BackendUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cerberus_ldap_backend_up",
			Help: "1 if the most recent /health probe to this LDAP backend succeeded, else 0.",
		}, []string{"backend"}),
	}
	reg.MustRegister(m.CacheHits, m.CacheMisses, m.QueryErrors, m.QueryDuration, m.BackendUp)
	return m
}
