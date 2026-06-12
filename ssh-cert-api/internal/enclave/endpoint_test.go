package enclave

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// dialAndCheck stands up a listener, dials it through dialSigner via the
// endpoint env var, and confirms a real connection was established by
// round-tripping a byte.
func dialAndCheck(t *testing.T, network, addr, endpoint string) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, addr, err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			_, _ = c.Write(buf) // echo
		}
	}()

	t.Setenv(SignerEndpointEnv, endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := dialSigner(ctx, 16)
	if err != nil {
		t.Fatalf("dialSigner(%q): %v", endpoint, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x42}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err != nil || buf[0] != 0x42 {
		t.Fatalf("echo failed: %v (got %v)", err, buf)
	}
	<-done
}

func TestDialSignerTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // reuse the picked address
	dialAndCheck(t, "tcp", addr, "tcp://"+addr)
}

func TestDialSignerUnix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "signer.sock")
	dialAndCheck(t, "unix", sock, "unix://"+sock)
}

func TestDialSignerUnixBareSlash(t *testing.T) {
	// `unix:/path` (single slash) must work too.
	sock := filepath.Join(t.TempDir(), "signer.sock")
	dialAndCheck(t, "unix", sock, "unix:"+sock)
}

func TestDialSignerErrors(t *testing.T) {
	for _, ep := range []string{
		"ftp://nope",
		"garbage-without-scheme",
		"vsock://notanumber:5000",
		"vsock://16",
	} {
		t.Setenv(SignerEndpointEnv, ep)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialSigner(ctx, 16)
		cancel()
		if err == nil {
			_ = conn.Close()
			t.Errorf("expected error for endpoint %q, got nil", ep)
		}
	}
}
