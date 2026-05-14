// Command cerberus-stress is a load-testing tool for the SSH CA. It has two
// subcommands:
//
//	signer  - Drive the enclave signer directly over TCP or VSOCK.
//	          Useful for measuring raw cryptographic throughput.
//	api     - Drive the HTTPS API end-to-end (Kerberos SPNEGO + Casbin
//	          authorization + rate limiter + VSOCK to enclave).
//	          Useful for measuring full-pipeline behavior.
//
// Each subcommand reports per-operation latency percentiles, throughput, and
// an error breakdown.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "signer":
		runSigner(os.Args[2:])
	case "api":
		runAPI(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cerberus-stress — load testing tool for the Cerberus SSH CA

Usage:
  cerberus-stress signer [flags]   Stress test the enclave signer directly (TCP or VSOCK)
  cerberus-stress api    [flags]   Stress test the HTTPS API (with SPNEGO auth)

Run "cerberus-stress <subcommand> -h" for subcommand-specific flags.
`)
}

// commonFlags holds flags shared by both subcommands.
type commonFlags struct {
	concurrency  int
	duration     time.Duration
	requests     int
	progressTick time.Duration
}

func (c *commonFlags) bind(fs flagSet) {
	fs.IntVar(&c.concurrency, "concurrency", 10, "number of parallel workers")
	fs.DurationVar(&c.duration, "duration", 30*time.Second, "test duration (0 = no time limit; use -requests or Ctrl-C)")
	fs.IntVar(&c.requests, "requests", 0, "stop after N total requests (0 = no count limit)")
	fs.DurationVar(&c.progressTick, "progress-tick", 2*time.Second, "live progress reporting interval")
}

// flagSet is the subset of *flag.FlagSet methods we use; defined as an
// interface so commonFlags.bind doesn't depend directly on the flag package
// (keeps the signature uncluttered).
type flagSet interface {
	IntVar(p *int, name string, value int, usage string)
	DurationVar(p *time.Duration, name string, value time.Duration, usage string)
}

// result records the outcome of one operation.
type result struct {
	elapsed time.Duration
	err     error
}

// runner drives a worker pool that calls do() until ctx is done or the
// request count is reached, feeding each outcome to a stats aggregator.
func runner(ctx context.Context, c commonFlags, label string, do func(ctx context.Context) error) {
	if c.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.duration)
		defer cancel()
	}

	results := make(chan result, c.concurrency*2)
	var wg sync.WaitGroup
	var sent atomic.Int64
	maxReq := int64(c.requests)

	for range c.concurrency {
		wg.Go(func() {
			for ctx.Err() == nil {
				if maxReq > 0 && sent.Add(1) > maxReq {
					return
				}
				start := time.Now()
				err := do(ctx)
				elapsed := time.Since(start)
				select {
				case results <- result{elapsed, err}:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	s := newStats(label)
	s.run(results, c.progressTick)
}

// stats accumulates latency samples and error counts.
type stats struct {
	label   string
	started time.Time
	samples []time.Duration
	errors  map[string]int
	success int64
	total   int64
}

func newStats(label string) *stats {
	return &stats{
		label:   label,
		started: time.Now(),
		errors:  make(map[string]int),
	}
}

func (s *stats) add(r result) {
	s.total++
	s.samples = append(s.samples, r.elapsed)
	if r.err != nil {
		s.errors[r.err.Error()]++
	} else {
		s.success++
	}
}

func (s *stats) run(results <-chan result, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	var lastTotal int64
	lastTime := s.started

	for {
		select {
		case r, ok := <-results:
			if !ok {
				s.printFinal()
				return
			}
			s.add(r)
		case now := <-ticker.C:
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed <= 0 {
				continue
			}
			rate := float64(s.total-lastTotal) / elapsed
			fmt.Printf("[%s] +%s | total=%d ok=%d err=%d | %.1f req/s\n",
				s.label, now.Sub(s.started).Truncate(time.Second),
				s.total, s.success, s.total-s.success, rate)
			lastTotal = s.total
			lastTime = now
		}
	}
}

func (s *stats) printFinal() {
	elapsed := time.Since(s.started)
	rate := float64(s.total) / elapsed.Seconds()
	fmt.Printf("\n=== %s — final report ===\n", s.label)
	fmt.Printf("Duration:   %s\n", elapsed.Truncate(time.Millisecond))
	fmt.Printf("Total:      %d requests (%.1f req/s)\n", s.total, rate)
	fmt.Printf("Successful: %d (%.2f%%)\n", s.success, percent(s.success, s.total))
	fmt.Printf("Errors:     %d (%.2f%%)\n", s.total-s.success, percent(s.total-s.success, s.total))

	if len(s.samples) > 0 {
		sorted := append([]time.Duration(nil), s.samples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		fmt.Println("Latency:")
		fmt.Printf("  min:  %s\n", sorted[0])
		fmt.Printf("  p50:  %s\n", percentile(sorted, 50))
		fmt.Printf("  p95:  %s\n", percentile(sorted, 95))
		fmt.Printf("  p99:  %s\n", percentile(sorted, 99))
		fmt.Printf("  p999: %s\n", percentile(sorted, 99.9))
		fmt.Printf("  max:  %s\n", sorted[len(sorted)-1])
	}

	if len(s.errors) > 0 {
		fmt.Println("Error breakdown (top 10):")
		type kv struct {
			msg   string
			count int
		}
		ranked := make([]kv, 0, len(s.errors))
		for m, n := range s.errors {
			ranked = append(ranked, kv{m, n})
		}
		sort.Slice(ranked, func(i, j int) bool { return ranked[i].count > ranked[j].count })
		for i, e := range ranked {
			if i >= 10 {
				fmt.Printf("  ...and %d more error types\n", len(ranked)-10)
				break
			}
			fmt.Printf("  [%dx] %s\n", e.count, e.msg)
		}
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := p / 100.0 * float64(len(sorted)-1)
	idx := int(rank)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func percent(num, denom int64) float64 {
	if denom == 0 {
		return 0
	}
	return 100 * float64(num) / float64(denom)
}

// makeContext returns a context cancelled by SIGINT/SIGTERM.
func makeContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// makeTestSSHKey generates an ED25519 SSH public key suitable as input to
// the signer. The corresponding private key is discarded — we never need
// to use it, only the cert that wraps the public part.
func makeTestSSHKey() (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

func formatStopCondition(c commonFlags) string {
	switch {
	case c.requests > 0 && c.duration > 0:
		return fmt.Sprintf("until %d requests OR %s", c.requests, c.duration)
	case c.requests > 0:
		return fmt.Sprintf("until %d requests", c.requests)
	case c.duration > 0:
		return fmt.Sprintf("for %s", c.duration)
	default:
		return "until interrupted (Ctrl-C)"
	}
}
