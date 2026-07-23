package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSdNotifyReady_NoSocketConfigured(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := sdNotifyReady(); err != nil {
		t.Fatalf("sdNotifyReady() = %v, want nil when NOTIFY_SOCKET is unset", err)
	}
}

func TestSdNotifyReady_SendsReadyDatagram(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "notify.sock")

	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer l.Close()

	t.Setenv("NOTIFY_SOCKET", sockPath)
	if err := sdNotifyReady(); err != nil {
		t.Fatalf("sdNotifyReady: %v", err)
	}

	if err := l.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := l.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("received %q, want %q", got, "READY=1")
	}
}

func TestSdNotifyReady_AbstractNamespace(t *testing.T) {
	// Abstract-namespace sockets aren't scoped to a directory the way
	// filesystem ones are; use a name unlikely to collide with a
	// concurrently running test binary.
	notifyVar := fmt.Sprintf("@cerberus-vsock-watch-test-%d", os.Getpid())
	listenAddr := "\x00" + notifyVar[1:]

	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: listenAddr, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram (abstract): %v", err)
	}
	defer l.Close()

	t.Setenv("NOTIFY_SOCKET", notifyVar)
	if err := sdNotifyReady(); err != nil {
		t.Fatalf("sdNotifyReady: %v", err)
	}

	if err := l.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := l.Read(buf)
	if err != nil {
		t.Fatalf("Read (abstract): %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("received %q, want %q", got, "READY=1")
	}
}

func TestSdNotifyReady_DialFailureReturnsError(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/nonexistent/dir/notify.sock")
	if err := sdNotifyReady(); err == nil {
		t.Fatal("expected an error when the notify socket cannot be dialed")
	}
}

func TestReadyNotifier_FiresExactlyOnceOnSuccess(t *testing.T) {
	r := &readyNotifier{}
	calls := 0
	notify := func() error {
		calls++
		return nil
	}

	r.tryNotify(notify)
	r.tryNotify(notify)
	r.tryNotify(notify)

	if calls != 1 {
		t.Errorf("notify called %d times, want 1", calls)
	}
}

func TestReadyNotifier_RetriesAfterAFailedAttempt(t *testing.T) {
	// Unlike sync.Once, a failed attempt must not permanently give up: a
	// transient failure on the first detector's onReady call must not
	// forfeit READY=1 for the rest of the process's life if a second
	// detector's onReady call could still succeed moments later.
	r := &readyNotifier{}
	calls := 0
	notify := func() error {
		calls++
		if calls == 1 {
			return errors.New("dial failed")
		}
		return nil
	}

	r.tryNotify(notify) // fails, must not mark done
	r.tryNotify(notify) // succeeds

	if calls != 2 {
		t.Fatalf("notify called %d times, want 2 (a failed attempt must be retried)", calls)
	}

	r.tryNotify(notify) // already succeeded: must not call notify again
	if calls != 2 {
		t.Errorf("notify called %d times after success, want still 2 (must not fire again once done)", calls)
	}
}

func TestReadyNotifier_ConcurrentCallersFireAtLeastOnceAndStopAfterSuccess(t *testing.T) {
	r := &readyNotifier{}
	var calls int
	var mu sync.Mutex
	notify := func() error {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	}

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			r.tryNotify(notify)
		})
	}
	wg.Wait()

	mu.Lock()
	got := calls
	mu.Unlock()
	if got < 1 {
		t.Fatalf("notify called %d times across concurrent callers, want at least 1", got)
	}

	// A later call, after concurrent success, must be a no-op.
	r.tryNotify(notify)
	mu.Lock()
	defer mu.Unlock()
	if calls != got {
		t.Errorf("notify called again (%d -> %d) after tryNotify had already succeeded", got, calls)
	}
}
