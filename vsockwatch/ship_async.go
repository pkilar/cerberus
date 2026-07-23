package vsockwatch

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// This file decouples alert delivery from event classification. Both
// AuditWatcher and ebpf.Watcher call Shipper.Ship synchronously from their
// single event-consumption goroutine (docs/vsock-connect-detection.md §4.2).
// Without this layer, a slow or hung external channel — WebhookShipper's
// HTTP POST, bounded only by webhookTimeout (default 10s) — stalls that
// goroutine on every alert. For the eBPF path specifically, that stall lets
// the kernel-side ring buffer keep filling from new connect() events with no
// consumer draining it; once full, the BPF program's bpf_ringbuf_reserve()
// fails and the kernel silently drops the event with no signal to userspace
// at all. It also delays the opt-in reactive-kill Blocker for whatever event
// is stuck behind the stalled Ship call.

// defaultShipQueueSize bounds how many not-yet-delivered alerts AsyncShipper
// buffers before it starts dropping. Sized generously for a detective
// control that should see anomalies rarely in healthy operation — this is
// not a high-throughput pipeline — while still bounding worst-case memory if
// a delivery channel is down for an extended period.
const defaultShipQueueSize = 256

// shipDrainTimeout bounds how long AsyncShipper.Run spends attempting to
// flush its queue after ctx is canceled, so shutdown doesn't hang
// indefinitely on a dead delivery channel. A var (not const) so tests can
// shorten it.
var shipDrainTimeout = 5 * time.Second

// AsyncShipper wraps a Shipper so Ship never blocks its caller: it enqueues
// the Alert on a bounded channel and returns immediately, while Run drains
// the channel on a separate goroutine and performs the actual (potentially
// slow) delivery via the wrapped Shipper. The caller must start Run in its
// own goroutine before any Ship call can be delivered; Run returns once ctx
// is canceled and a best-effort drain (bounded by shipDrainTimeout)
// completes.
type AsyncShipper struct {
	inner Shipper
	queue chan Alert
}

// NewAsyncShipper builds an AsyncShipper around inner with a bounded queue
// of size. A size <= 0 uses defaultShipQueueSize.
func NewAsyncShipper(inner Shipper, size int) *AsyncShipper {
	if size <= 0 {
		size = defaultShipQueueSize
	}
	return &AsyncShipper{inner: inner, queue: make(chan Alert, size)}
}

var _ Shipper = (*AsyncShipper)(nil)

// Ship enqueues the given Alert for delivery and returns immediately. If the
// queue is full — inner is delivering slower than alerts arrive — the Alert
// is dropped rather than blocking the caller; the caller is expected to log
// the returned error (see AuditWatcher.handleLine / ebpf.Watcher.Run), since
// a full delivery queue must never be a silent gap in an already-fired
// alert.
func (s *AsyncShipper) Ship(_ context.Context, a Alert) error {
	select {
	case s.queue <- a:
		return nil
	default:
		return fmt.Errorf("vsockwatch: ship queue full (size %d), alert dropped", cap(s.queue))
	}
}

// Run drains the queue and calls inner.Ship for each Alert until ctx is
// canceled, then makes a best-effort attempt (bounded by shipDrainTimeout)
// to flush whatever is still queued before returning — an alert Ship already
// accepted should not be silently lost just because shutdown began a moment
// later.
func (s *AsyncShipper) Run(ctx context.Context) error {
	for {
		select {
		case a := <-s.queue:
			s.deliver(ctx, a)
		case <-ctx.Done():
			// drain() deliberately does not take ctx (already canceled here)
			// -- it uses its own independent context internally so a
			// best-effort final delivery isn't killed by the same
			// cancellation it's racing. Same false-positive shape as
			// main.go's fatalShutdown; see that nolint for precedent.
			s.drain() //nolint:contextcheck
			return ctx.Err()
		}
	}
}

func (s *AsyncShipper) deliver(ctx context.Context, a Alert) {
	if err := s.inner.Ship(ctx, a); err != nil {
		slog.Error("vsockwatch.ship.delivery_failed", "kind", a.Kind, "detector", a.Detector, "error", err)
	}
}

// drain makes a bounded best-effort delivery attempt for whatever is left in
// the queue at shutdown, using an independent context (not the one Run was
// canceled with) so delivery isn't killed by the same cancellation it's
// racing — the same pattern main.go's fatalShutdown uses for its own final
// alert.
func (s *AsyncShipper) drain() {
	deadline := time.NewTimer(shipDrainTimeout)
	defer deadline.Stop()
	for {
		select {
		case a := <-s.queue:
			s.deliver(context.Background(), a)
		case <-deadline.C:
			if n := len(s.queue); n > 0 {
				slog.Error("vsockwatch.ship.drain_timed_out", "queued_undelivered", n)
			}
			return
		default:
			return
		}
	}
}
