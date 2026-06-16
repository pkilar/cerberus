// Command ssh-cert-api is the host-side HTTPS gateway. It authenticates users
// via Kerberos SPNEGO, enforces per-group authorization via Casbin, rate-limits
// per principal, and forwards approved signing requests over VSOCK to the
// ssh-cert-signer running in a Nitro Enclave.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkilar/cerberus/logging"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/api"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/auth"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/authz"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/config"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/keyload"
	cerberusldap "github.com/pkilar/cerberus/ssh-cert-api/internal/ldap"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
)

const shutdownGrace = 10 * time.Second

func main() {
	log.Println("Starting SSH Certificate API...")

	// --- 1. Load Configuration ---
	configPath := cmp.Or(os.Getenv("CONFIG_PATH"), "configs/config.yaml")
	logging.Debug("Using config path: %s", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	logging.Debug("Configuration loaded successfully.")

	// Non-fatal config-hygiene warnings: bare static_attributes keys and any
	// LDAP-block diagnostics that don't justify refusing to start (e.g.,
	// long cache TTL, plaintext URL). Logged once at startup; the service
	// continues. The Kind field is the slog event name.
	for _, w := range cfg.Warnings() {
		attrs := []any{"detail", w.Detail}
		if w.Backend != "" {
			attrs = append(attrs, "backend", w.Backend)
		}
		if w.Group != "" {
			attrs = append(attrs, "group", w.Group)
		}
		if w.Key != "" {
			attrs = append(attrs, "key", w.Key)
		}
		slog.Warn(w.Kind, attrs...)
	}

	// --- 2. Initialize Dependencies ---
	kerberosAuthenticator, err := auth.NewKerberosAuthenticator(cfg.KeytabPath, cfg.ServicePrincipal)
	if err != nil {
		log.Fatalf("Failed to initialize Kerberos authenticator: %v", err)
	}
	enclaveClient := enclave.New()
	defer func() { _ = enclaveClient.Close() }()

	// --- 3. Load the CA key into the enclave (host-mediated attested decrypt) ---
	// The enclave has no network. Rather than proxy its KMS traffic, the host
	// performs the KMS Decrypt itself using its own instance-role credentials and
	// the enclave's attestation document; KMS returns the plaintext encrypted to
	// the enclave's attestation public key, so the host never sees the plaintext
	// CA key. Bounded so a hung KMS call cannot wedge startup; 60s comfortably
	// covers attestation + KMS round trip + key parse.
	//
	// Operator reminder: the host holds both the ciphertext and kms:Decrypt, so the
	// CMK policy MUST grant Decrypt only under a kms:RecipientAttestation (PCR0)
	// condition and MUST NOT grant an unconditioned Decrypt. See docs/kms-attestation-policy.md.
	slog.Info("startup.kms_policy_reminder",
		"detail", "KMS key policy must deny non-attested Decrypt (kms:RecipientAttestation:PCR0 condition, no unconditioned Decrypt); see docs/kms-attestation-policy.md")
	region := cmp.Or(os.Getenv("AWS_REGION"), "us-east-1")
	logging.Debug("Loading CA key into enclave (host-mediated attested KMS decrypt)...")
	loadCtx, loadCancel := context.WithTimeout(context.Background(), 60*time.Second)
	kmsDecrypter, err := keyload.NewAWSDecrypter(loadCtx, region)
	if err != nil {
		loadCancel()
		log.Fatalf("Failed to initialize KMS client: %v", err)
	}
	if err := keyload.Run(loadCtx, enclaveClient, kmsDecrypter); err != nil {
		loadCancel()
		log.Fatalf("Failed to load CA key into enclave: %v", err)
	}
	loadCancel()
	logging.Debug("Enclave CA key loaded successfully")

	// --- 4. Initialize LDAP backends (optional) ---
	// One Client per configured backend. Refuse to start if any initial
	// HealthCheck fails: a misconfigured directory is operator error, not
	// a state we want to discover for the first time during a /sign denial.
	// A nil resolver disables LDAP entirely and Authorize behaves as
	// pre-LDAP code did. The clients themselves are also retained so the
	// /health prober (task 7) can poll them.
	var (
		ldapResolver authz.LDAPResolver
		ldapClients  map[string]cerberusldap.Client
		ldapMetrics  *cerberusldap.Metrics
	)
	if len(cfg.LDAP) > 0 {
		ldapMetrics = cerberusldap.NewMetrics(prometheus.DefaultRegisterer)
		ldapClients = make(map[string]cerberusldap.Client, len(cfg.LDAP))
		realmIndex := make(map[string]string, len(cfg.LDAP))
		for _, backend := range cfg.LDAP {
			client, err := cerberusldap.NewClient(backend, cfg.KeytabPath, ldapMetrics)
			if err != nil {
				log.Fatalf("Failed to initialize LDAP backend %q due to invalid configuration", backend.Name)
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), backend.Timeout)
			err = client.HealthCheck(probeCtx)
			probeCancel()
			if err != nil {
				log.Fatalf("LDAP backend %q failed initial probe: %v", backend.Name, err)
			}
			ldapClients[backend.Name] = client
			for _, realm := range backend.Realms {
				realmIndex[realm] = backend.Name
			}
		}
		ldapResolver = authz.NewLDAPResolver(ldapClients, realmIndex)
		slog.Info("ldap.startup.ready", "backends", len(ldapClients))
	}

	// Ensure LDAP clients are closed on shutdown (proxy / signer paths
	// already have their own cleanup).
	defer func() {
		for name, c := range ldapClients {
			if err := c.Close(); err != nil {
				slog.Warn("ldap.shutdown.close_failed", "backend", name, "error", err)
			}
		}
	}()

	// --- 4. Initialize Authorizer ---
	authorizer, err := authz.NewCasbinAuthorizer(cfg, ldapResolver)
	if err != nil {
		log.Fatalf("Failed to initialize authorizer: %v", err)
	}

	// --- 4b. Start background enclave health monitor ---
	// /health reads from the cached snapshot this populates, so flooding the
	// unauthenticated /health endpoint can't consume signer capacity needed
	// by /sign — only the monitor's background tick hits VSOCK.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()
	healthMonitor := api.NewHealthMonitor(enclaveClient)
	healthMonitor.Start(rootCtx)

	// --- 4c. Start background enclave-resource metrics poller ---
	// Independent of the health monitor: the metrics path samples
	// /proc/stat and /proc/meminfo inside the enclave on a slow cadence
	// (default 15s, override via ENCLAVE_METRICS_INTERVAL) and exposes
	// the snapshot through /metrics. Failed polls do not page anyone —
	// stale metrics are detectable via
	// cerberus_enclave_metrics_last_scrape_timestamp_seconds.
	enclaveMetrics := api.NewEnclaveMetricsCollector(enclaveClient, cfg.EnclaveMetricsInterval)
	if err := prometheus.Register(enclaveMetrics); err != nil {
		log.Fatalf("Failed to register enclave metrics collector: %v", err)
	}
	enclaveMetrics.Start(rootCtx)

	// --- 5. Setup API Server ---
	server, err := api.NewServer(cfg, kerberosAuthenticator, authorizer, enclaveClient, healthMonitor)
	if err != nil {
		log.Fatalf("Failed to initialize API server: %v", err)
	}

	// LDAP health monitor — advisory: /health JSON exposes per-backend
	// state but the top-level status remains gated on the enclave path.
	if len(ldapClients) > 0 {
		ldapMon := api.NewLDAPHealthMonitor(ldapClients, ldapMetrics)
		server.SetLDAPHealth(ldapMon)
		ldapMon.Start(rootCtx)
	}

	// --- 5. Define the HTTP server with authentication middleware ---
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Router(), // The router now includes the middleware
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// WriteTimeout must exceed the per-/sign budget (api.SignTimeout) so a
		// legitimately slow signing round trip is not truncated mid-response:
		// the handler's own context deadline (SignTimeout) governs and aborts
		// observably, while this connection-level write deadline stays a
		// backstop above it. ReadHeaderTimeout/ReadTimeout cover slow-loris on
		// the request side.
		WriteTimeout: api.SignTimeout + 10*time.Second,
		IdleTimeout:  60 * time.Second,
		// Pin the TLS policy explicitly rather than relying on Go's defaults.
		// TLS 1.2 minimum keeps older Kerberos-aware HTTP clients working; the
		// cipher list is restricted to AEAD constructions (TLS 1.3 has its
		// own AEAD-only set and ignores this field).
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	// --- 6. Start Server with graceful shutdown ---
	// http.Server treats an empty host in Addr (e.g. ":8443") as "all
	// interfaces". Render that as 0.0.0.0:port so operators don't have to
	// decode the missing host themselves.
	displayAddr := cfg.Listen
	if host, port, err := net.SplitHostPort(cfg.Listen); err == nil && host == "" {
		displayAddr = net.JoinHostPort("0.0.0.0", port)
	}
	log.Printf("Server listening on https://%s", displayAddr)

	g, gctx := errgroup.WithContext(rootCtx)

	g.Go(func() error {
		if err := httpServer.ListenAndServeTLS(cfg.TlsCert, cfg.TlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("https server (cert=%s key=%s): %w", cfg.TlsCert, cfg.TlsKey, err)
		}
		return nil
	})

	g.Go(func() error {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigChan)

		select {
		case sig := <-sigChan:
			log.Printf("Received %s — draining connections (deadline %s)", sig, shutdownGrace)
		case <-gctx.Done():
			// Server goroutine errored; propagate by returning nil here.
			return nil
		}

		// Intentionally detach from gctx here: a grace-timeout for
		// draining must not be cut short by the parent's cancellation.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx) //nolint:contextcheck // graceful shutdown ctx is independent by design

	})

	if err := g.Wait(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
