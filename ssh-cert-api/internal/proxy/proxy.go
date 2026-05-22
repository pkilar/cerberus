// Package proxy implements a VSOCK-to-TCP forwarder. Nitro Enclaves have no
// network stack; the enclave dials a VSOCK address on the parent instance,
// and this forwarder relays the bytes on to the target TCP endpoint
// (typically kms.<region>.amazonaws.com:443). TLS is terminated inside the
// enclave, so the host sees only ciphertext on the wire.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/pkilar/cerberus/logging"

	"github.com/mdlayher/vsock"
)

// Forwarder forwards VSOCK connections from the enclave to a target TCP
// endpoint. One instance handles many concurrent connections; Stop waits for
// all in-flight forwards to drain.
//
// listen and dial are seams swapped by tests; New populates them with the
// production vsock/tcp implementations. Production callers do not interact
// with these fields.
type Forwarder struct {
	vsockPort  uint32
	targetAddr string
	listen     func(port uint32) (net.Listener, error)
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	listener   net.Listener
	wg         sync.WaitGroup
	cancel     context.CancelFunc
}

// New creates a Forwarder that listens on the given VSOCK port and forwards
// each accepted connection to targetAddr ("host:port", e.g.
// "kms.us-east-1.amazonaws.com:443").
func New(vsockPort uint32, targetAddr string) *Forwarder {
	return &Forwarder{
		vsockPort:  vsockPort,
		targetAddr: targetAddr,
		listen:     func(p uint32) (net.Listener, error) { return vsock.Listen(p, nil) },
		dial:       (&net.Dialer{}).DialContext,
	}
}

// Start launches the forwarder's accept loop in a background goroutine.
func (f *Forwarder) Start(ctx context.Context) error {
	// Create a cancellable context for the forwarder's lifecycle.
	proxyCtx, cancel := context.WithCancel(ctx)
	f.cancel = cancel

	// Listen on the specified port (vsock in production; TCP in tests).
	listener, err := f.listen(f.vsockPort)
	if err != nil {
		return fmt.Errorf("proxy failed to listen on port %d: %w", f.vsockPort, err)
	}
	f.listener = listener

	logging.Debug("Proxy listening on vsock port %d, forwarding to %s", f.vsockPort, f.targetAddr)

	f.wg.Go(func() { f.run(proxyCtx) })

	return nil
}

// Stop gracefully shuts down the forwarder and waits for it to finish.
func (f *Forwarder) Stop() {
	logging.Debug("Stopping proxy...")
	if f.cancel != nil {
		f.cancel()
	}
	f.wg.Wait()
	logging.Debug("Proxy stopped.")
}

// run is the main loop that accepts and handles connections.
func (f *Forwarder) run(ctx context.Context) {
	// Close the listener exactly once across the two paths that need to do
	// it: AfterFunc closes early on ctx cancellation (to unblock Accept), and
	// the deferred wrapper closes on normal return.
	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = f.listener.Close() }) }
	defer closeListener()
	context.AfterFunc(ctx, closeListener)

	for {
		conn, err := f.listener.Accept()
		if err != nil {
			// Check if the context was cancelled, indicating a graceful shutdown.
			select {
			case <-ctx.Done():
				return // Exit the loop.
			default:
				slog.Error("proxy.accept_failed", "error", err)
				// If the listener is closed for other reasons, we should exit.
				if _, ok := errors.AsType[*net.OpError](err); ok {
					return
				}
				continue
			}
		}

		f.wg.Go(func() { f.handleConnection(ctx, conn) })
	}
}

// handleConnection forwards data between the VSOCK client and the TCP target.
func (f *Forwarder) handleConnection(ctx context.Context, vsockConn net.Conn) {
	defer vsockConn.Close()

	logging.Debug("Proxy accepted connection from %s", vsockConn.RemoteAddr().String())

	// Dial the target TCP endpoint with the forwarder's lifecycle context so
	// shutdown cancels in-flight dials instead of waiting on TCP timeouts.
	tcpConn, err := f.dial(ctx, "tcp", f.targetAddr)
	if err != nil {
		slog.Error("proxy.dial_failed", "target", f.targetAddr, "error", err)
		return
	}
	defer tcpConn.Close()

	logging.Debug("Proxy connected to TCP endpoint %s", tcpConn.RemoteAddr().String())

	// Goroutine to copy data from VSOCK to TCP.
	f.wg.Go(func() {
		defer tcpConn.Close()
		defer vsockConn.Close()
		if _, err := io.Copy(tcpConn, vsockConn); err != nil && !errors.Is(err, net.ErrClosed) {
			logging.Debug("proxy vsock→tcp copy ended: %v", err)
		}
	})

	// Copy data from TCP to VSOCK.
	if _, err := io.Copy(vsockConn, tcpConn); err != nil && !errors.Is(err, net.ErrClosed) {
		logging.Debug("proxy tcp→vsock copy ended: %v", err)
	}
}
