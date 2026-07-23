package vsockwatch

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// shipperFunc adapts a plain function to the Shipper interface, for tests
// that don't need a full fakeShipper's call-recording.
type shipperFunc func(context.Context, Alert) error

func (f shipperFunc) Ship(ctx context.Context, a Alert) error { return f(ctx, a) }

// blockingShipper blocks in Ship until unblock is closed, then records the
// Alert. Simulates a stalled webhook peer without needing a real HTTP server.
type blockingShipper struct {
	unblock <-chan struct{}

	mu      sync.Mutex
	shipped []Alert
}

func (b *blockingShipper) Ship(_ context.Context, a Alert) error {
	<-b.unblock
	b.mu.Lock()
	b.shipped = append(b.shipped, a)
	b.mu.Unlock()
	return nil
}

func (b *blockingShipper) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.shipped)
}

// startAndWait runs shipper.Run(ctx) in a goroutine and registers a
// t.Cleanup that cancels ctx and blocks until Run has fully returned
// (including any drain() call). Without waiting, a straggler goroutine from
// one test can still be running drain() -- which reads the package-level
// shipDrainTimeout -- while a later test mutates that var, a real data race
// under -race (not just a hypothetical one: this is exactly what
// TestAsyncShipper_RunDrainsQueuedAlertOnShutdown's mutation used to race
// against before this helper existed).
func startAndWait(t *testing.T, ctx context.Context, cancel context.CancelFunc, shipper *AsyncShipper) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = shipper.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("AsyncShipper.Run did not return within 5s of cancellation")
		}
	})
}

func TestAsyncShipper_ShipDoesNotBlockOnSlowDelivery(t *testing.T) {
	unblock := make(chan struct{})
	inner := &blockingShipper{unblock: unblock}
	shipper := NewAsyncShipper(inner, 4)

	ctx, cancel := context.WithCancel(t.Context())
	startAndWait(t, ctx, cancel, shipper)

	start := time.Now()
	if err := shipper.Ship(ctx, Alert{Kind: KindVSockAnomaly}); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Ship took %v, want it to return immediately while delivery is stalled", elapsed)
	}

	close(unblock)
	deadline := time.Now().Add(2 * time.Second)
	for inner.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if inner.count() != 1 {
		t.Fatalf("inner shipper received %d alerts, want 1 once unblocked", inner.count())
	}
}

func TestAsyncShipper_OverflowDropsRatherThanBlocks(t *testing.T) {
	// Deliberately never closed by the test body: this exercises delivery
	// that's stalled for the entire test. Closed via defer so the Run
	// goroutine can eventually unwind during cleanup instead of leaking past
	// this test and racing a later test's package-level var mutations (see
	// startAndWait's doc comment) -- defers run before t.Cleanup callbacks,
	// so by the time startAndWait's cleanup calls cancel() and waits on
	// done, unblock is already closed and the stuck inner.Ship can return.
	unblock := make(chan struct{})
	defer close(unblock)
	inner := &blockingShipper{unblock: unblock}
	shipper := NewAsyncShipper(inner, 1)

	ctx, cancel := context.WithCancel(t.Context())
	startAndWait(t, ctx, cancel, shipper)

	// The first Ship is picked up by Run and blocks delivery for the rest of
	// this test's active body; the second Ship fills the size-1 queue; the
	// third must overflow rather than block.
	if err := shipper.Ship(ctx, Alert{Kind: KindVSockAnomaly}); err != nil {
		t.Fatalf("first Ship: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let Run's goroutine pick up the first alert
	if err := shipper.Ship(ctx, Alert{Kind: KindVSockAnomaly}); err != nil {
		t.Fatalf("second Ship: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- shipper.Ship(ctx, Alert{Kind: KindVSockAnomaly}) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an overflow error for the third Ship call")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("third Ship call blocked instead of returning an overflow error")
	}
}

func TestAsyncShipper_RunDeliversEveryEnqueuedAlert(t *testing.T) {
	var mu sync.Mutex
	var got []Alert
	inner := shipperFunc(func(_ context.Context, a Alert) error {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		return nil
	})
	shipper := NewAsyncShipper(inner, 8)

	ctx, cancel := context.WithCancel(t.Context())
	startAndWait(t, ctx, cancel, shipper)

	for i := range 3 {
		if err := shipper.Ship(ctx, Alert{Reason: fmt.Sprintf("alert-%d", i)}); err != nil {
			t.Fatalf("Ship: %v", err)
		}
	}

	countGot := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for countGot() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := countGot(); n != 3 {
		t.Fatalf("delivered %d alerts, want 3", n)
	}
}

func TestAsyncShipper_DeliveryErrorIsLoggedNotPropagated(t *testing.T) {
	// Run's job is to attempt delivery and log failures itself (the caller
	// that called Ship has long since returned by the time delivery
	// happens) -- this test just confirms an erroring inner Shipper doesn't
	// crash or wedge the drain loop, leaving it able to keep processing.
	inner := shipperFunc(func(context.Context, Alert) error {
		return fmt.Errorf("delivery failed")
	})
	shipper := NewAsyncShipper(inner, 4)

	ctx, cancel := context.WithCancel(t.Context())
	startAndWait(t, ctx, cancel, shipper)

	for range 3 {
		if err := shipper.Ship(ctx, Alert{Kind: KindVSockAnomaly}); err != nil {
			t.Fatalf("Ship: %v", err)
		}
	}
	// No assertion beyond "this doesn't hang or panic" -- give Run a moment
	// to process before the test ends.
	time.Sleep(50 * time.Millisecond)
}

func TestAsyncShipper_RunDrainsQueuedAlertOnShutdown(t *testing.T) {
	orig := shipDrainTimeout
	shipDrainTimeout = 500 * time.Millisecond
	defer func() { shipDrainTimeout = orig }()

	var mu sync.Mutex
	var got []Alert
	inner := shipperFunc(func(_ context.Context, a Alert) error {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		return nil
	})
	shipper := NewAsyncShipper(inner, 8)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		_ = shipper.Run(ctx)
		close(done)
	}()

	// Enqueue, then cancel almost immediately: whether Run's main select
	// picks up the item before noticing ctx.Done(), or drain() picks it up
	// during shutdown, the alert must be delivered either way.
	if err := shipper.Ship(context.Background(), Alert{Reason: "before-cancel"}); err != nil {
		t.Fatalf("Ship: %v", err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancellation + drain")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("delivered %d alerts, want 1 (queued-before-cancel alert must still be flushed on shutdown)", len(got))
	}
}

func TestNewAsyncShipper_NonPositiveSizeUsesDefault(t *testing.T) {
	shipper := NewAsyncShipper(shipperFunc(func(context.Context, Alert) error { return nil }), 0)
	if cap(shipper.queue) != defaultShipQueueSize {
		t.Errorf("queue capacity = %d, want defaultShipQueueSize (%d)", cap(shipper.queue), defaultShipQueueSize)
	}
}
