// Package enclave is the host-side client for the Nitro Enclave signing
// service. It dials the enclave over VSOCK, sends a JSON SignSshKey
// request, and returns the signed certificate. Authentication and
// authorization happen in the api package; this package assumes the
// caller has already decided the signing should proceed.
package enclave

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/pkilar/cerberus/constants"
	"github.com/pkilar/cerberus/logging"
	"github.com/pkilar/cerberus/messages"
)

// Signer is the host-side interface to the enclave's signing service.
// Implementations must respect ctx: a cancelled or expired context tears the
// VSOCK call down rather than letting it run to its wall-clock deadline.
type Signer interface {
	SignPublicKey(ctx context.Context, req *messages.EnclaveSigningRequest) (string, error)
	Ping(ctx context.Context) (*messages.PingResponse, error)
	GetEnclaveMetrics(ctx context.Context) (*messages.EnclaveMetricsResponse, error)
	// BeginKeyLoad and CompleteKeyLoad drive the host-mediated CA-key load at
	// startup; see internal/keyload.
	BeginKeyLoad(ctx context.Context, req *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error)
	CompleteKeyLoad(ctx context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error)
	Close() error
}

// vsockSigner implements Signer over the production VSOCK transport. It holds
// no state — the dial parameters are fixed by constants/ and the per-call
// deadline lives in the function body. Kept as a typed value so tests can
// continue to substitute via the Signer interface.
type vsockSigner struct{}

var _ Signer = vsockSigner{}

// New returns the default VSOCK-based Signer implementation.
func New() Signer { return vsockSigner{} }

func (vsockSigner) Close() error {
	logging.Debug("Enclave signer closed")
	return nil
}

// vsockRoundTripDeadline is the wall-clock cap on a single enclave call when
// the caller's context has no deadline of its own. KMS attestation + signing
// fits comfortably within this window in practice.
const vsockRoundTripDeadline = 30 * time.Second

// Call sends a JSON request to the enclave and decodes the response into
// response. The supplied ctx governs the call: if it is cancelled or expires,
// the underlying connection is closed so any in-flight Read/Write unblocks
// promptly. A wall-clock backstop bounds requests whose context lacks a
// deadline.
//
// The dial target defaults to the enclave VSOCK CID/port but can be overridden
// via SignerEndpointEnv to point at an alternative signer (e.g. the usbhsm
// hardware bridge) over TCP/Unix/VSOCK. Framing and deadlines are identical
// across transports.
func Call(ctx context.Context, enclaveCID uint32, request messages.Request, response *messages.Response) error {
	conn, err := dialSigner(ctx, enclaveCID)
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return roundTrip(ctx, conn, request, response)
}

// roundTrip is the post-dial half of Call: framing, deadline application,
// cancel-on-context, write the request, read one newline-delimited response,
// decode. Split out so unit tests can drive it over net.Pipe without needing
// a vsock device.
func roundTrip(ctx context.Context, conn net.Conn, request messages.Request, response *messages.Response) error {
	// Cancel-on-context: close the conn when ctx is done so the Read/Write
	// below return immediately rather than waiting on the wall-clock deadline.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()

	deadline := time.Now().Add(vsockRoundTripDeadline)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set connection deadline: %w", err)
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	logging.DebugContext(ctx, "Sending request to enclave: %s", messages.RedactedJSON(request))
	if _, err := conn.Write(append(requestBytes, '\n')); err != nil {
		return fmt.Errorf("failed to send request to enclave: %w", err)
	}

	reader := bufio.NewReader(conn)
	responseBytes, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("failed to read response from enclave: %w", err)
	}
	logging.DebugContext(ctx, "Received response from enclave: %s", string(responseBytes))

	if err := json.Unmarshal(responseBytes, response); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return nil
}

// Ping sends a no-op request to verify the enclave is reachable and has a
// loaded CA signer. /health uses this to surface enclave health to a load
// balancer; it's cheap (no KMS or crypto work) so it's safe to call often.
func (vsockSigner) Ping(ctx context.Context) (*messages.PingResponse, error) {
	request := messages.Request{Ping: &messages.PingRequest{}}

	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, request, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.Pong == nil {
		return nil, fmt.Errorf("no pong in response")
	}
	return response.Pong, nil
}

// GetEnclaveMetrics asks the enclave for one snapshot of its CPU and memory
// usage. The enclave reads /proc/stat and /proc/meminfo and returns
// pre-converted values (CPU seconds, memory bytes). Used by the host's
// background EnclaveMetricsCollector; do not call from the request hot path.
func (vsockSigner) GetEnclaveMetrics(ctx context.Context) (*messages.EnclaveMetricsResponse, error) {
	request := messages.Request{GetEnclaveMetrics: &messages.GetEnclaveMetricsRequest{}}

	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, request, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.EnclaveMetrics == nil {
		return nil, fmt.Errorf("no enclaveMetrics in response")
	}
	return response.EnclaveMetrics, nil
}

func (vsockSigner) SignPublicKey(ctx context.Context, req *messages.EnclaveSigningRequest) (string, error) {
	request := messages.Request{
		SignSshKey: req,
	}

	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, request, &response); err != nil {
		return "", err
	}

	if response.Error != nil {
		return "", fmt.Errorf("enclave error: %s", *response.Error)
	}

	if response.SignSshKey != nil && response.SignSshKey.SignedKey != "" {
		slog.Info("sign.signed", "key_id", req.KeyID)
		return response.SignSshKey.SignedKey, nil
	}

	return "", fmt.Errorf("no signed key in response")
}

// BeginKeyLoad asks the enclave to start loading the CA key. In production the
// reply carries an attestation document + the KMS-encrypted CA key for the host
// to decrypt; in development the enclave reports Loaded=true having decrypted
// the key itself.
func (vsockSigner) BeginKeyLoad(ctx context.Context, req *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, messages.Request{BeginKeyLoad: req}, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.BeginKeyLoad == nil {
		return nil, fmt.Errorf("no beginKeyLoad in response")
	}
	return response.BeginKeyLoad, nil
}

// CompleteKeyLoad returns the KMS CiphertextForRecipient to the enclave, which
// decrypts it inside and installs the CA signer.
func (vsockSigner) CompleteKeyLoad(ctx context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	var response messages.Response
	if err := Call(ctx, constants.EnclaveCID, messages.Request{CompleteKeyLoad: req}, &response); err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, fmt.Errorf("enclave error: %s", *response.Error)
	}
	if response.CompleteKeyLoad == nil {
		return nil, fmt.Errorf("no completeKeyLoad in response")
	}
	return response.CompleteKeyLoad, nil
}
