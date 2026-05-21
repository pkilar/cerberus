// Command ssh-cert-signer runs inside an AWS Nitro Enclave. It loads the
// KMS-encrypted CA key on startup (using NSM attestation when /dev/nsm is
// available) and then accepts SSH-certificate signing requests over VSOCK
// from the parent instance's ssh-cert-api.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os/signal"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/ssh"

	"cerberus/constants"
	"cerberus/logging"
	"cerberus/messages"
	"ssh-cert-signer/internal/attestation"
	"ssh-cert-signer/internal/handlers"
)

const (
	// maxConcurrentConnections caps in-flight signing requests so a
	// misbehaving host cannot exhaust enclave memory by opening many
	// simultaneous VSOCK connections.
	maxConcurrentConnections = 32
	// connDeadline bounds each request's read and write window. The host
	// client (see ssh-cert-api/internal/enclave/client.go) sets a 30s
	// connection deadline; this is the per-message slice within that.
	connDeadline = 5 * time.Second
	// maxRequestBytes is the largest single request the scanner accepts.
	// The host caps inbound /sign bodies at 64 KiB; the enclave envelope
	// adds principals/permissions/audit attributes on top, so 256 KiB
	// gives generous headroom while still bounding memory per connection.
	maxRequestBytes = 256 * 1024
)

var (
	// caSigner is written by handleLoadKeySigner and read by every
	// concurrent handleSignSshKey. atomic.Pointer prevents a data race
	// between a (re-)load and an in-flight sign on the hot path.
	caSigner atomic.Pointer[ssh.Signer]
	// attestProvider is initialized in main before any goroutines spawn,
	// so the goroutine-spawn happens-before edge makes plain access safe.
	attestProvider *attestation.Provider

	// errUnexpectedCommand is returned when a Request arrives with no
	// recognized variant set. Named so log parsing can match it.
	errUnexpectedCommand = errors.New("unexpected command")
)

func main() {
	log.Println("Starting Enclave Signing Service...")

	// Initialize attestation provider (gracefully degrades outside enclaves)
	attestProvider = attestation.NewProvider()
	defer attestProvider.Close()
	if attestProvider.IsAvailable() {
		log.Println("NSM device detected — attestation enabled")
	} else {
		log.Println("NSM device not found — running without attestation (development mode)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listener, err := vsock.Listen(constants.EnclaveListeningPort, nil)
	if err != nil {
		log.Fatalf("FATAL: failed to listen on vsock port %d: %v", constants.EnclaveListeningPort, err)
	}
	// Close the listener exactly once across the two paths that need to do
	// it: AfterFunc closes early on ctx cancellation (to unblock Accept), and
	// the deferred wrapper closes on normal return.
	var listenerCloseOnce sync.Once
	closeListener := func() { listenerCloseOnce.Do(func() { _ = listener.Close() }) }
	defer closeListener()
	context.AfterFunc(ctx, closeListener)
	log.Printf("Listening on vsock port %d...", constants.EnclaveListeningPort)

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentConnections)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				log.Println("Shutdown signal received — stopping accept loop")
				break
			}
			log.Printf("ERROR: failed to accept connection: %v", err)
			continue
		}

		// Bounded concurrency: block here if at the per-process limit.
		// During shutdown, drop the just-accepted conn instead of queueing.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			continue
		}

		wg.Go(func() {
			defer func() { <-sem }()
			handleConnection(ctx, conn)
		})
	}

	log.Println("Draining in-flight connections...")
	wg.Wait()
	log.Println("Enclave signing service stopped cleanly")
}

// handleConnection reads requests from conn, signing each one and writing the
// response, until the peer closes, the deadline expires, or ctx is cancelled.
func handleConnection(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// Tear the connection down immediately on shutdown rather than waiting
	// up to connDeadline for the in-flight Scan to time out.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()
	logging.Debug("Accepted new connection from parent instance.")

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxRequestBytes)

	for {
		// Reset the read deadline at the top of every iteration so a
		// connection that serves multiple requests doesn't burn its
		// budget on processing time of the previous one.
		if err := conn.SetReadDeadline(time.Now().Add(connDeadline)); err != nil {
			log.Printf("ERROR: failed to set read deadline: %v", err)
			return
		}

		if !scanner.Scan() {
			err := scanner.Err()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("ERROR: scanner.Scan() failed: %s", err)
			}
			// Turn an oversize request into a structured reply so the host
			// sees "request too large" instead of a bare connection drop.
			if errors.Is(err, bufio.ErrTooLong) {
				resp := createErrorResponse(fmt.Errorf("request exceeds %d bytes", maxRequestBytes))
				_ = sendResponse(conn, resp)
			}
			return
		}

		response := processRequest(ctx, scanner.Bytes())
		if err := sendResponse(conn, response); err != nil {
			log.Printf("ERROR: failed to send response: %v", err)
			return
		}

		if ctx.Err() != nil {
			return
		}
	}
}

// processRequest handles a single request and returns the response. It
// recovers from panics so a single buggy handler doesn't drop the connection
// without a structured log, and redacts the parsed request before debug
// logging so LoadKeySigner credentials never reach stderr.
func processRequest(ctx context.Context, requestBytes []byte) (resp messages.Response) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("signer.panic", "panic", p, "stack", string(debug.Stack()))
			resp = createErrorResponse(fmt.Errorf("internal error"))
		}
	}()

	var req messages.Request
	if err := json.Unmarshal(requestBytes, &req); err != nil {
		// Don't log requestBytes — they may carry unredactable secret material
		// for a payload that just happens to fail JSON parsing.
		logging.Debug("recv: <unparseable JSON: %v>", err)
		return createErrorResponse(fmt.Errorf("json.Unmarshal failed: %w", err))
	}
	logging.Debug("recv: %s", messages.RedactedJSON(req))

	// The wire-protocol contract in messages.Request says exactly one variant
	// is non-nil. Refuse ambiguous payloads rather than silently picking the
	// first one — a misbehaving host that sets two variants must not be able
	// to smuggle one operation past host-side checks while another executes.
	nVariants := 0
	if req.LoadKeySigner != nil {
		nVariants++
	}
	if req.SignSshKey != nil {
		nVariants++
	}
	if req.Ping != nil {
		nVariants++
	}
	if req.GetEnclaveMetrics != nil {
		nVariants++
	}
	if nVariants > 1 {
		return createErrorResponse(errors.New("multiple request variants set; expected exactly one"))
	}

	switch {
	case req.LoadKeySigner != nil:
		return handleLoadKeySigner(ctx, *req.LoadKeySigner)
	case req.SignSshKey != nil:
		return handleSignSshKey(ctx, *req.SignSshKey)
	case req.Ping != nil:
		return handlePing()
	case req.GetEnclaveMetrics != nil:
		return handleGetEnclaveMetrics()
	default:
		return createErrorResponse(errUnexpectedCommand)
	}
}

// handlePing returns a Pong reporting whether the CA signer has been loaded.
// Used by the host's /health endpoint to surface enclave health to a load
// balancer; intentionally does no KMS or crypto work.
func handlePing() messages.Response {
	loaded := caSigner.Load() != nil
	return messages.Response{
		Pong: &messages.PingResponse{SignerLoaded: loaded},
	}
}

// handleGetEnclaveMetrics samples /proc/stat and /proc/meminfo inside the
// enclave and returns the snapshot. The host polls this on a slow cadence
// and exposes the values through its /metrics endpoint.
func handleGetEnclaveMetrics() messages.Response {
	resp, err := handlers.ReadEnclaveMetrics()
	if err != nil {
		return createErrorResponse(err)
	}
	return messages.Response{
		EnclaveMetrics: &resp,
	}
}

func handleLoadKeySigner(ctx context.Context, req messages.LoadKeySignerRequest) messages.Response {
	signer, err := handlers.LoadKeySignerHandler(ctx, req, attestProvider)
	if err != nil {
		return createErrorResponse(err)
	}
	caSigner.Store(&signer)

	return messages.Response{
		LoadKeySigner: &messages.LoadKeySignerResponse{Success: true},
	}
}

func handleSignSshKey(ctx context.Context, req messages.EnclaveSigningRequest) messages.Response {
	signer := caSigner.Load()
	if signer == nil {
		return createErrorResponse(errors.New("CA signer is not initialized; call LoadKeySigner first"))
	}

	signResponse, err := handlers.SignPublicKey(ctx, *signer, req)
	if err != nil {
		return createErrorResponse(err)
	}

	logging.Debug("res: %v", signResponse.SignedKey)
	return messages.Response{
		SignSshKey: signResponse,
	}
}

func createErrorResponse(err error) messages.Response {
	log.Printf("request failed: %s", err)
	errMsg := err.Error()
	return messages.Response{
		Error: &errMsg,
	}
}

func sendResponse(conn net.Conn, response messages.Response) error {
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(connDeadline)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Single Write so the JSON object and its newline framing land in the
	// same syscall — mirrors the host client's append-then-write pattern in
	// ssh-cert-api/internal/enclave/client.go.
	if _, err := conn.Write(append(responseBytes, '\n')); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}
