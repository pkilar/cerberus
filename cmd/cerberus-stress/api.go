package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cerberus/messages"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

func runAPI(args []string) {
	var (
		common     commonFlags
		url        string
		spn        string
		krb5Conf   string
		ccachePath string
		princs     string
		skipVerify bool
		noAuth     bool
		timeout    time.Duration
	)

	fs := flag.NewFlagSet("api", flag.ExitOnError)
	common.bind(fs)
	fs.StringVar(&url, "url", "https://127.0.0.1:8443/sign", "API /sign endpoint URL")
	fs.StringVar(&spn, "spn", "", "Kerberos service principal (e.g. HTTP/host.realm.com); required unless -no-auth")
	fs.StringVar(&krb5Conf, "krb5-conf", "/etc/krb5.conf", "Kerberos config file path")
	fs.StringVar(&ccachePath, "ccache", "", "credential cache path (default: $KRB5CCNAME or /tmp/krb5cc_<uid>)")
	fs.StringVar(&princs, "principals", "stress-user", "comma-separated SSH principals to request in cert (must be allowed by server config)")
	fs.BoolVar(&skipVerify, "insecure-skip-verify", false, "skip TLS certificate verification (self-signed certs)")
	fs.BoolVar(&noAuth, "no-auth", false, "send unauthenticated requests (expect HTTP 401 — useful as a TLS+auth-reject baseline; bypasses rate limiter)")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "per-request HTTP timeout")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: cerberus-stress api [flags]

The /sign endpoint enforces a per-principal token-bucket rate limit
(default 5 rps, burst 10). To get past it during stress testing, raise
RATE_LIMIT_RPS / RATE_LIMIT_BURST on the server side.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	sshKey, err := makeTestSSHKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test SSH key: %v\n", err)
		os.Exit(1)
	}

	body, err := json.Marshal(messages.SigningRequest{
		SSHKey:     sshKey,
		Principals: strings.Split(princs, ","),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal request: %v\n", err)
		os.Exit(1)
	}

	httpClient := &http.Client{
		Timeout: timeout,
		// Reuse connections aggressively — stress test wants to amortize
		// TLS handshake cost rather than measure it on every request.
		Transport: &http.Transport{
			MaxIdleConns:        common.concurrency * 2,
			MaxIdleConnsPerHost: common.concurrency * 2,
			MaxConnsPerHost:     common.concurrency * 2,
			IdleConnTimeout:     90 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipVerify}, //#nosec G402 — opt-in via flag
		},
	}

	ctx, cancel := makeContext()
	defer cancel()

	var (
		do    func(ctx context.Context) error
		label string
	)

	if noAuth {
		label = "api-noauth"
		do = func(ctx context.Context) error {
			return doUnauthRequest(ctx, httpClient, url, body)
		}
	} else {
		if spn == "" {
			fmt.Fprintln(os.Stderr, "-spn is required (or pass -no-auth for an unauthenticated baseline)")
			os.Exit(2)
		}
		spnegoCli, cleanup, err := buildSpnegoClient(httpClient, krb5Conf, ccachePath, spn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to set up SPNEGO: %v\n", err)
			os.Exit(1)
		}
		defer cleanup()
		label = "api"
		do = func(ctx context.Context) error {
			return doSpnegoRequest(ctx, spnegoCli, url, body)
		}
	}

	fmt.Printf("Stress-testing API at %s — %d workers, %s\n",
		url, common.concurrency, formatStopCondition(common))

	runner(ctx, common, label, do)
}

// buildSpnegoClient loads the Kerberos credential cache and wraps the given
// http.Client with a SPNEGO authenticator. Returns a cleanup func the
// caller must invoke to destroy the krb5 client session.
func buildSpnegoClient(httpClient *http.Client, krb5Conf, ccachePath, spn string) (*spnego.Client, func(), error) {
	cfg, err := config.Load(krb5Conf)
	if err != nil {
		return nil, nil, fmt.Errorf("load krb5 conf %s: %w", krb5Conf, err)
	}

	if ccachePath == "" {
		ccachePath = os.Getenv("KRB5CCNAME")
		if ccachePath == "" {
			ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
		}
		// gokrb5 expects a plain path; krb5 sometimes prefixes with FILE:
		ccachePath = strings.TrimPrefix(ccachePath, "FILE:")
	}

	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load ccache %s: %w (run `kinit` first?)", ccachePath, err)
	}

	cl, err := client.NewFromCCache(cc, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("krb5 client: %w", err)
	}

	return spnego.NewClient(cl, httpClient, spn), cl.Destroy, nil
}

func doSpnegoRequest(ctx context.Context, cli *spnego.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var sr messages.SigningResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	// Decoder may stop at the end of the JSON object and leave trailing bytes
	// (typically a newline). Without this drain the conn can't return to the
	// keepalive pool, silently negating the Transport's connection sizing and
	// charging a TLS handshake per request — exactly the kind of perturbation
	// a stress tool must not introduce into its own measurements.
	_, _ = io.Copy(io.Discard, resp.Body)
	if sr.Error != "" {
		return fmt.Errorf("server error: %s", sr.Error)
	}
	if sr.SignedKey == "" {
		return errors.New("empty signed key in response")
	}
	return nil
}

// doUnauthRequest sends a request without SPNEGO. The server will reject it
// at the auth middleware with HTTP 401 — that's the expected outcome and
// is recorded as success. Anything else (5xx, timeout, transport error)
// is recorded as a failure.
func doUnauthRequest(ctx context.Context, cli *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("HTTP %d (expected 401)", resp.StatusCode)
	}
	return nil
}
