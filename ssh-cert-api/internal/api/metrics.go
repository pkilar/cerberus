package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metric outcomes for /sign. Keep this set small and stable —
// adding labels bumps cardinality across every scrape.
const (
	outcomeSuccess       = "success"
	outcomeDenied        = "denied"
	outcomeFailed        = "failed"
	outcomeRatelimited   = "ratelimited"
	outcomeInvalidBody   = "invalid_body"
	outcomeTooLarge      = "too_large"
	outcomeMissingKey    = "missing_key"
	outcomeInvalidMethod = "invalid_method"
	outcomeAuthzError    = "authz_error"
	outcomeNoAuth        = "no_auth"
)

var (
	signRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cerberus_sign_requests_total",
			Help: "Total /sign requests by terminal outcome.",
		},
		[]string{"outcome"},
	)

	// Tailored bucket set for SSH cert signing: most successful requests
	// complete in 50–500 ms, with KMS/VSOCK tails out to a few seconds.
	signDurationSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cerberus_sign_duration_seconds",
			Help:    "End-to-end /sign handler duration in seconds.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
	)

	enclaveErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "cerberus_enclave_errors_total",
			Help: "Total errors returned from the signing enclave (VSOCK transport + enclave-side failures).",
		},
	)
)
