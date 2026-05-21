package enclave

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"cerberus/messages"
)

// pipePair returns two ends of a net.Pipe. Both ends honor deadlines.
func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	client, server = net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// canned sends responseBytes (then EOF) when serverConn is read, after
// consuming one line of request. Returns when the goroutine exits.
func canned(t *testing.T, serverConn net.Conn, responseBytes []byte) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		// Consume one request line so the client's Write completes.
		if _, err := bufio.NewReader(serverConn).ReadBytes('\n'); err != nil {
			return
		}
		_, _ = serverConn.Write(responseBytes)
	}()
	return done
}

func TestRoundTrip_HappyPath(t *testing.T) {
	client, server := pipePair(t)
	body, _ := json.Marshal(messages.Response{
		SignSshKey: &messages.SigningResponse{SignedKey: "ssh-cert-stub"},
	})
	done := canned(t, server, append(body, '\n'))

	var resp messages.Response
	if err := roundTrip(t.Context(), client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp); err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if resp.SignSshKey == nil || resp.SignSshKey.SignedKey != "ssh-cert-stub" {
		t.Errorf("response payload not decoded: %+v", resp)
	}
	<-done
}

func TestRoundTrip_ErrorResponseDecoded(t *testing.T) {
	// roundTrip itself doesn't interpret response.Error — that's the caller's
	// job (Ping/SignPublicKey/main.go) — but the bytes must decode cleanly.
	client, server := pipePair(t)
	errMsg := "enclave rejected"
	body, _ := json.Marshal(messages.Response{Error: &errMsg})
	done := canned(t, server, append(body, '\n'))

	var resp messages.Response
	if err := roundTrip(t.Context(), client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp); err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if resp.Error == nil || *resp.Error != errMsg {
		t.Errorf("error payload not decoded: %+v", resp)
	}
	<-done
}

func TestRoundTrip_CtxCancelClosesConn(t *testing.T) {
	// The AfterFunc seam must close the conn on ctx cancellation so the read
	// returns instead of waiting on the wall-clock backstop.
	client, server := pipePair(t)
	// Server never replies. The test goroutine will cancel ctx.
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Drain one request, then block (no reply).
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		// Goroutine exits without replying. The client's read blocks until
		// the AfterFunc seam (ctx cancel / deadline path) closes its conn.
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	var resp messages.Response
	err := roundTrip(ctx, client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after ctx cancel, got nil")
	}
	// Should return well under the 30s wall-clock backstop.
	if elapsed > 2*time.Second {
		t.Errorf("roundTrip blocked %v after ctx cancel — AfterFunc seam not wired", elapsed)
	}
	_ = server.Close()
	<-done
}

func TestRoundTrip_CtxDeadlineNarrowsBackstop(t *testing.T) {
	// A short ctx deadline must clamp the conn deadline so a non-responsive
	// peer doesn't keep us blocked for the full wall-clock budget.
	client, server := pipePair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		// No reply. Client's read blocks until the conn deadline fires.
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()

	start := time.Now()
	var resp messages.Response
	err := roundTrip(ctx, client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("roundTrip blocked %v under 80ms ctx deadline", elapsed)
	}
	_ = server.Close()
	<-done
}

func TestRoundTrip_MalformedJSONResponse(t *testing.T) {
	client, server := pipePair(t)
	done := canned(t, server, []byte("not json\n"))

	var resp messages.Response
	err := roundTrip(t.Context(), client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to unmarshal response") {
		t.Errorf("got %v, want unmarshal error", err)
	}
	<-done
}

func TestRoundTrip_ServerClosesWithoutResponse(t *testing.T) {
	client, server := pipePair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		_ = server.Close()
	}()

	var resp messages.Response
	err := roundTrip(t.Context(), client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp)
	if err == nil {
		t.Fatal("expected read error after server EOF, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read response") {
		t.Errorf("got %v, want read error", err)
	}
	<-done
}

func TestRoundTrip_FragmentedResponseRecombined(t *testing.T) {
	// The bufio.NewReader.ReadBytes('\n') framing must concatenate bytes
	// across multiple Write calls — a single conn.Read might short-read on
	// MTU-sensitive transport. Two small writes here, separated by a tiny
	// sleep, exercise that join.
	client, server := pipePair(t)
	body, _ := json.Marshal(messages.Response{
		SignSshKey: &messages.SigningResponse{SignedKey: "x"},
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		half := len(body) / 2
		_, _ = server.Write(body[:half])
		time.Sleep(5 * time.Millisecond)
		_, _ = server.Write(body[half:])
		_, _ = server.Write([]byte{'\n'})
	}()

	var resp messages.Response
	if err := roundTrip(t.Context(), client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp); err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	if resp.SignSshKey == nil || resp.SignSshKey.SignedKey != "x" {
		t.Errorf("response payload not assembled: %+v", resp)
	}
	<-done
}

func TestRoundTrip_AfterFuncStopsOnReturn(t *testing.T) {
	// Regression: the deferred stopOnCancel must keep cancelling the AfterFunc
	// after roundTrip returns; otherwise a parent ctx that fires later would
	// close a conn this function no longer owns. Construct a parent ctx,
	// finish the round trip happily, then cancel — the (already-closed) conn
	// must accept the close idempotently without panicking the test.
	client, server := pipePair(t)
	body, _ := json.Marshal(messages.Response{
		SignSshKey: &messages.SigningResponse{SignedKey: "x"},
	})
	done := canned(t, server, append(body, '\n'))

	parent, cancel := context.WithCancel(t.Context())
	var resp messages.Response
	if err := roundTrip(parent, client, messages.Request{
		Ping: &messages.PingRequest{},
	}, &resp); err != nil {
		t.Fatalf("roundTrip: %v", err)
	}
	// roundTrip returned; cancelling the parent must not panic or race.
	cancel()
	// Net.Conn.Close is idempotent per stdlib; this is a smoke check.
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("idempotent Close: got %v", err)
	}
	<-done
}
