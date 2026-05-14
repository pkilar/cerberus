// Package proxy implements a VSOCK-to-TCP forwarder. Nitro Enclaves have no
// network stack; the enclave dials a VSOCK address on the parent instance,
// and this proxy forwards the bytes on to the target TCP endpoint
// (typically kms.<region>.amazonaws.com:443). TLS is terminated inside the
// enclave, so the host sees only ciphertext on the wire.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"cerberus/logging"

	"github.com/mdlayher/vsock"
)

// Proxy defines a VSOCK-to-TCP proxy.
type Proxy struct {
	vsockPort  uint32
	targetAddr string
	listener   net.Listener
	wg         sync.WaitGroup
	cancel     context.CancelFunc
}

// New creates a new Proxy instance.
// targetAddr should be in "host:port" format (e.g., "kms.us-east-1.amazonaws.com:443").
func New(vsockPort uint32, targetAddr string) *Proxy {
	return &Proxy{
		vsockPort:  vsockPort,
		targetAddr: targetAddr,
	}
}

// Start launches the proxy listener in a background goroutine.
func (p *Proxy) Start(ctx context.Context) error {
	// Create a cancellable context for the proxy's lifecycle.
	proxyCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	// Listen on the specified VSOCK port.
	listener, err := vsock.Listen(p.vsockPort, nil)
	if err != nil {
		return fmt.Errorf("proxy failed to listen on vsock port %d: %w", p.vsockPort, err)
	}
	p.listener = listener

	logging.Debug("Proxy listening on vsock port %d, forwarding to %s", p.vsockPort, p.targetAddr)

	p.wg.Go(func() { p.run(proxyCtx) })

	return nil
}

// Stop gracefully shuts down the proxy and waits for it to finish.
func (p *Proxy) Stop() {
	logging.Debug("Stopping proxy...")
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	logging.Debug("Proxy stopped.")
}

// run is the main loop that accepts and handles connections.
func (p *Proxy) run(ctx context.Context) {
	defer p.listener.Close()

	// Close the listener when ctx is cancelled to unblock Accept.
	context.AfterFunc(ctx, func() { _ = p.listener.Close() })

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			// Check if the context was cancelled, indicating a graceful shutdown.
			select {
			case <-ctx.Done():
				return // Exit the loop.
			default:
				log.Printf("Proxy failed to accept vsock connection: %v", err)
				// If the listener is closed for other reasons, we should exit.
				if _, ok := errors.AsType[*net.OpError](err); ok {
					return
				}
				continue
			}
		}

		p.wg.Go(func() { p.handleConnection(ctx, conn) })
	}
}

// handleConnection forwards data between the VSOCK client and the TCP target.
func (p *Proxy) handleConnection(ctx context.Context, vsockConn net.Conn) {
	defer vsockConn.Close()

	logging.Debug("Proxy accepted connection from %s", vsockConn.RemoteAddr().String())

	// Dial the target TCP endpoint with the proxy's lifecycle context so
	// shutdown cancels in-flight dials instead of waiting on TCP timeouts.
	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, "tcp", p.targetAddr)
	if err != nil {
		log.Printf("Proxy failed to dial TCP endpoint %s: %v", p.targetAddr, err)
		return
	}
	defer tcpConn.Close()

	logging.Debug("Proxy connected to TCP endpoint %s", tcpConn.RemoteAddr().String())

	// Goroutine to copy data from VSOCK to TCP.
	p.wg.Go(func() {
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
