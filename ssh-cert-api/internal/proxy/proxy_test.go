package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestForwarder constructs a Forwarder that listens on a loopback TCP port
// (instead of vsock) and dials via TCP. The returned listenerAddr is the
// loopback address callers should dial to reach the forwarder's input side.
func newTestForwarder(t *testing.T, targetAddr string) (*Forwarder, string) {
	t.Helper()
	// Pre-bind so we can hand the test the dial address before Start runs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	return &Forwarder{
		targetAddr: targetAddr,
		listen:     func(uint32) (net.Listener, error) { return ln, nil },
		dial:       (&net.Dialer{}).DialContext,
	}, addr
}

// startEchoServer accepts one connection and echoes bytes back until EOF.
// Returns the listen address and a stop func that closes the listener and
// blocks until the accept goroutine exits.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	stop := func() {
		_ = ln.Close()
		<-done
	}
	return ln.Addr().String(), stop
}

func TestForwarder_BidirectionalCopy(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	f, fwdAddr := newTestForwarder(t, echoAddr)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := f.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	// Client → Forwarder → Echo → Forwarder → Client.
	conn, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("hello forwarder")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("got %q, want %q", buf, payload)
	}
}

func TestForwarder_StopDrainsAfterConnsClose(t *testing.T) {
	// Stop is graceful: it cancels the listener but waits for in-flight
	// forwards to finish naturally rather than ripping them mid-stream.
	// Confirm that once the client closes, Stop returns promptly.
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	f, fwdAddr := newTestForwarder(t, echoAddr)
	if err := f.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	// Close the client to let the forwarder's io.Copy goroutines exit.
	_ = conn.Close()

	done := make(chan struct{})
	go func() {
		f.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s after client closed — wg drain wedged")
	}
}

func TestForwarder_ContextCancelStopsAcceptLoop(t *testing.T) {
	// Stop should also return cleanly when the supplied ctx is cancelled.
	// The listener-close + context.AfterFunc seam must unblock Accept().
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	f, _ := newTestForwarder(t, echoAddr)
	ctx, cancel := context.WithCancel(t.Context())
	if err := f.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cancel()
	// Stop must still complete; under the AfterFunc path the listener was
	// already closed, so wg.Wait should return promptly.
	done := make(chan struct{})
	go func() {
		f.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s after ctx cancel")
	}
}

func TestForwarder_DialTargetFailureKeepsAccepting(t *testing.T) {
	// Point the forwarder at an unreachable target. The first client should
	// see its conn close (because the dial fails), but the forwarder must
	// keep accepting — a single bad target dial is not fatal.
	f, fwdAddr := newTestForwarder(t, "127.0.0.1:1") // port 1 = nothing listening
	if err := f.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	// First dial: forwarder accepts, then fails to dial target, closes vsock side.
	c1, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	// Reading should EOF promptly (the forwarder closed vsockConn).
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c1.Read(buf); err == nil {
		t.Error("expected EOF on first conn after target-dial failure")
	}
	c1.Close()

	// Second dial: forwarder still accepts.
	c2, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	c2.Close()
}

func TestForwarder_StartListenFailurePropagates(t *testing.T) {
	sentinel := errors.New("simulated listen failure")
	f := &Forwarder{
		listen: func(uint32) (net.Listener, error) { return nil, sentinel },
		dial:   (&net.Dialer{}).DialContext,
	}
	err := f.Start(t.Context())
	if err == nil {
		t.Fatal("expected Start to fail when listen errors")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got: %v", err)
	}
}

func TestForwarder_OneDirectionEOFTearsDownOther(t *testing.T) {
	// Build a "target" that closes its end after a single byte. The forwarder
	// must then close the other side too rather than leaking either copy.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer tcpLn.Close()
	tcpAccepted := make(chan struct{})
	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		close(tcpAccepted)
		// Send one byte, then close. The forwarder's TCP→VSOCK copy returns
		// (EOF on the TCP side); the per-conn defers must then close vsockConn
		// so the client's read also returns.
		_, _ = conn.Write([]byte{'X'})
		_ = conn.Close()
	}()

	f, fwdAddr := newTestForwarder(t, tcpLn.Addr().String())
	if err := f.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	client, err := net.Dial("tcp", fwdAddr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	<-tcpAccepted

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read first byte: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("got %q, want X", buf)
	}
	// Next read must EOF because the forwarder tore down the client side
	// when the target side closed.
	_, err = client.Read(buf)
	if err == nil {
		t.Error("expected EOF after target closed")
	}
}

func TestForwarder_ManyConnectionsConcurrently(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	f, fwdAddr := newTestForwarder(t, echoAddr)
	if err := f.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.Stop()

	const N = 25
	var wg sync.WaitGroup
	var errCount atomic.Int64
	for i := range N {
		wg.Go(func() {
			conn, err := net.Dial("tcp", fwdAddr)
			if err != nil {
				errCount.Add(1)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte{byte(i)}
			if _, err := conn.Write(payload); err != nil {
				errCount.Add(1)
				return
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(conn, buf); err != nil {
				errCount.Add(1)
				return
			}
			if buf[0] != payload[0] {
				errCount.Add(1)
			}
		})
	}
	wg.Wait()
	if got := errCount.Load(); got != 0 {
		t.Errorf("%d/%d concurrent forwards failed", got, N)
	}
}
