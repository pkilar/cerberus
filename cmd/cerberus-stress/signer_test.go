package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkilar/cerberus/messages"
)

func TestParseVsock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		wantCID  uint32
		wantPort uint32
		wantErr  bool
	}{
		{"valid", "16:5000", 16, 5000, false},
		{"valid zero CID", "0:1", 0, 1, false},
		{"empty", "", 0, 0, true},
		{"missing port", "16", 0, 0, true},
		{"missing CID", ":5000", 0, 0, true},
		{"non-numeric CID", "abc:5000", 0, 0, true},
		{"non-numeric port", "16:xyz", 0, 0, true},
		{"negative CID", "-1:5000", 0, 0, true},
		{"CID overflow uint32", "5000000000:5000", 0, 0, true},
		{"trailing junk", "16:5000:extra", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cid, port, err := parseVsock(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseVsock(%q) err = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && (cid != tt.wantCID || port != tt.wantPort) {
				t.Errorf("parseVsock(%q) = (%d, %d), want (%d, %d)",
					tt.input, cid, port, tt.wantCID, tt.wantPort)
			}
		})
	}
}

func TestBuildSignerDialer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		transport string
		target    string
		wantErr   bool
	}{
		// TCP target is not validated at factory time — only at dial time.
		{"tcp valid", "tcp", "127.0.0.1:5000", false},
		{"tcp empty target", "tcp", "", false},
		// VSOCK target is parsed up-front so bad input fails fast.
		{"vsock valid", "vsock", "16:5000", false},
		{"vsock invalid", "vsock", "bad", true},
		{"unknown transport", "udp", "127.0.0.1:5000", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dialer, err := buildSignerDialer(tt.transport, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildSignerDialer(%q, %q) err = %v, wantErr = %v",
					tt.transport, tt.target, err, tt.wantErr)
			}
			if !tt.wantErr && dialer == nil {
				t.Error("expected non-nil dialer for valid input")
			}
		})
	}
}

// trackingConn wraps a net.Conn to report whether Close was called.
type trackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackingConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func TestDialRaceCtx_DialSucceedsFirst(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	got, err := dialRaceCtx(context.Background(), func() (net.Conn, error) {
		return a, nil
	})
	if err != nil {
		t.Fatalf("dialRaceCtx: %v", err)
	}
	if got != a {
		t.Errorf("got conn %v, want %v", got, a)
	}
}

func TestDialRaceCtx_DialErrorReturned(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("dial failed")
	_, err := dialRaceCtx(context.Background(), func() (net.Conn, error) {
		return nil, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want sentinel %v", err, sentinel)
	}
}

func TestDialRaceCtx_CtxFiresFirst(t *testing.T) {
	t.Parallel()
	// Simulates the pre-fix vsock.Dial behavior: dial ignores ctx and blocks
	// until the test releases it. Without dialRaceCtx, signOnce would wedge.
	release := make(chan struct{})
	dialDone := make(chan struct{})

	dial := func() (net.Conn, error) {
		defer close(dialDone)
		<-release
		return nil, errors.New("not reached")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := dialRaceCtx(ctx, dial)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want DeadlineExceeded", err)
	}
	// Bound: should return shortly after the ctx fires, not wait for dial.
	if elapsed > 500*time.Millisecond {
		t.Errorf("dialRaceCtx took %v, expected ~50ms — ctx was not honored", elapsed)
	}

	// Unblock the orphaned dial so its goroutine and the drainer can exit.
	close(release)
	<-dialDone
}

func TestDialRaceCtx_DrainerClosesLateConn(t *testing.T) {
	t.Parallel()
	// Verify the FD-safe drainer: ctx fires, dial returns a conn later,
	// the drainer goroutine must Close that conn so we don't leak the FD.
	a, b := net.Pipe()
	defer b.Close()

	tracked := &trackingConn{Conn: a}
	release := make(chan struct{})
	dialDone := make(chan struct{})

	dial := func() (net.Conn, error) {
		defer close(dialDone)
		<-release
		return tracked, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	if _, err := dialRaceCtx(ctx, dial); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}

	// Release the dial; the drainer should Close the late-arriving conn.
	close(release)
	<-dialDone

	// Drainer runs asynchronously after the dial goroutine sends to the
	// channel. Poll briefly for the Close to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if tracked.closed.Load() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Errorf("drainer did not close the late-arriving conn within 500ms")
}

func TestDialRaceCtx_DrainerHandlesLateError(t *testing.T) {
	t.Parallel()
	// If dial returns (nil, err) after ctx fires, the drainer must not panic
	// trying to close a nil conn.
	release := make(chan struct{})
	dialDone := make(chan struct{})

	dial := func() (net.Conn, error) {
		defer close(dialDone)
		<-release
		return nil, errors.New("late failure")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := dialRaceCtx(ctx, dial); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}

	close(release)
	<-dialDone
	// If the drainer panicked, the goroutine would have crashed the test
	// process. Give it a moment to run cleanly.
	time.Sleep(20 * time.Millisecond)
}

func TestSignOnce_DialTimeout(t *testing.T) {
	t.Parallel()
	// Codex-named regression: a stuck dialer must not wedge a worker past
	// the user-advertised -timeout. Uses a ctx-honoring fake dial (matches
	// both the TCP DialContext path and the new vsockDialContext wrapper).
	dial := func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	timeout := 50 * time.Millisecond
	start := time.Now()
	err := signOnce(context.Background(), dial, messages.Request{}, timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "dial:") {
		t.Errorf("error %q should be wrapped as a dial error", err)
	}
	// Generous upper bound to tolerate CI scheduling jitter; the point is
	// that signOnce returns near `timeout`, not orders of magnitude past it.
	if elapsed > 10*timeout {
		t.Errorf("signOnce took %v with timeout=%v — timeout was not honored", elapsed, timeout)
	}
}

func TestSignOnce_ParentCtxCancelled(t *testing.T) {
	t.Parallel()
	dial := func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// Large internal timeout so we know it's the parent ctx that unblocks us.
	err := signOnce(ctx, dial, messages.Request{}, time.Hour)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("signOnce took %v — parent ctx cancellation did not propagate", elapsed)
	}
}

func TestSignOnce_DialError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("connection refused")
	dial := func(_ context.Context) (net.Conn, error) {
		return nil, sentinel
	}
	err := signOnce(context.Background(), dial, messages.Request{}, time.Second)
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want wrapped sentinel %v", err, sentinel)
	}
}

func TestSignOnce_HappyPath(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	var wg sync.WaitGroup
	wg.Go(func() {
		defer server.Close()
		// Read the request line then reply with a canned success response.
		if _, err := bufio.NewReader(server).ReadBytes('\n'); err != nil {
			return
		}
		body, _ := json.Marshal(messages.Response{
			SignSshKey: &messages.SigningResponse{SignedKey: "ssh-cert-stub"},
		})
		_, _ = server.Write(append(body, '\n'))
	})

	err := signOnce(context.Background(),
		func(_ context.Context) (net.Conn, error) { return client, nil },
		messages.Request{}, 5*time.Second)
	if err != nil {
		t.Errorf("signOnce: %v", err)
	}
	wg.Wait()
}

func TestSignOnce_ServerErrorResponse(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	var wg sync.WaitGroup
	wg.Go(func() {
		defer server.Close()
		if _, err := bufio.NewReader(server).ReadBytes('\n'); err != nil {
			return
		}
		errMsg := "signer rejected request"
		body, _ := json.Marshal(messages.Response{Error: &errMsg})
		_, _ = server.Write(append(body, '\n'))
	})

	err := signOnce(context.Background(),
		func(_ context.Context) (net.Conn, error) { return client, nil },
		messages.Request{}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "signer rejected") {
		t.Errorf("got %v, want error containing 'signer rejected'", err)
	}
	wg.Wait()
}

func TestSignOnce_EmptySignedKey(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	var wg sync.WaitGroup
	wg.Go(func() {
		defer server.Close()
		if _, err := bufio.NewReader(server).ReadBytes('\n'); err != nil {
			return
		}
		body, _ := json.Marshal(messages.Response{
			SignSshKey: &messages.SigningResponse{SignedKey: ""},
		})
		_, _ = server.Write(append(body, '\n'))
	})

	err := signOnce(context.Background(),
		func(_ context.Context) (net.Conn, error) { return client, nil },
		messages.Request{}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "empty signed key") {
		t.Errorf("got %v, want error containing 'empty signed key'", err)
	}
	wg.Wait()
}
