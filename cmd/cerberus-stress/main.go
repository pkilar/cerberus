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
	"math"
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
	// Reject a non-positive worker count up front: make(chan, c.concurrency*2)
	// below would otherwise panic ("makechan: size out of range") on a negative
	// value, and 0 silently produces an empty no-op run.
	if c.concurrency < 1 {
		fmt.Fprintln(os.Stderr, "error: -concurrency must be >= 1")
		os.Exit(2)
	}

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

// stats accumulates latency samples and error counts. Samples flow into a
// bounded log-linear histogram so memory stays flat across arbitrarily long
// stress runs — the unbounded-slice approach previously OOMed on multi-hour
// or high-RPS jobs and lost the final report entirely.
type stats struct {
	label   string
	started time.Time
	hist    *histogram
	errors  map[string]int
	success int64
	total   int64
}

func newStats(label string) *stats {
	return &stats{
		label:   label,
		started: time.Now(),
		hist:    newHistogram(),
		errors:  make(map[string]int),
	}
}

func (s *stats) add(r result) {
	s.total++
	s.hist.record(r.elapsed)
	if r.err != nil {
		s.errors[r.err.Error()]++
	} else {
		s.success++
	}
}

func (s *stats) run(results <-chan result, tick time.Duration) {
	// A non-positive tick disables live progress reporting instead of panicking
	// in time.NewTicker ("non-positive interval"). Just drain to the final
	// report — a natural "final report only" mode for -progress-tick 0.
	if tick <= 0 {
		for r := range results {
			s.add(r)
		}
		s.printFinal()
		return
	}

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

	if s.hist.count > 0 {
		fmt.Println("Latency:")
		fmt.Printf("  min:  %s\n", s.hist.min)
		fmt.Printf("  p50:  %s\n", s.hist.percentile(50))
		fmt.Printf("  p95:  %s\n", s.hist.percentile(95))
		fmt.Printf("  p99:  %s\n", s.hist.percentile(99))
		fmt.Printf("  p999: %s\n", s.hist.percentile(99.9))
		fmt.Printf("  max:  %s\n", s.hist.max)
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

// histogram is a bounded log-linear latency histogram with 9 buckets per
// decade from 100ns up — ~11% resolution at decade boundaries, finer within.
// Total memory is fixed (~1.5 KB) so a multi-hour stress run cannot OOM on
// the latency buffer. min/max are tracked exactly; percentiles read out of
// the buckets and are clamped at the observed max so sparse runs don't
// report inflated tails.
type histogram struct {
	bounds  []time.Duration
	buckets []uint64
	count   uint64
	min     time.Duration
	max     time.Duration
}

func newHistogram() *histogram {
	var bounds []time.Duration
	for decade := time.Duration(100); decade <= time.Duration(1e11); decade *= 10 {
		for m := time.Duration(1); m <= 9; m++ {
			bounds = append(bounds, decade*m)
		}
	}
	bounds = append(bounds, time.Duration(math.MaxInt64))
	return &histogram{
		bounds:  bounds,
		buckets: make([]uint64, len(bounds)),
		min:     time.Duration(math.MaxInt64),
	}
}

func (h *histogram) record(d time.Duration) {
	h.count++
	if d < h.min {
		h.min = d
	}
	if d > h.max {
		h.max = d
	}
	for i, b := range h.bounds {
		if d <= b {
			h.buckets[i]++
			return
		}
	}
}

func (h *histogram) percentile(p float64) time.Duration {
	if h.count == 0 {
		return 0
	}
	target := uint64(p / 100 * float64(h.count))
	if target == 0 {
		target = 1
	}
	var cum uint64
	for i, c := range h.buckets {
		cum += c
		if cum >= target {
			if h.bounds[i] > h.max {
				return h.max
			}
			return h.bounds[i]
		}
	}
	return h.max
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
