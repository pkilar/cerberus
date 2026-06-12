package enclave

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/mdlayher/vsock"

	"github.com/pkilar/cerberus/constants"
)

// SignerEndpointEnv overrides the signer dial target. It lets ssh-cert-api talk
// to a non-enclave signer — e.g. the usbhsm hardware bridge — without code
// changes. Unset (the default) preserves the production behavior: dial the
// Nitro Enclave over VSOCK at the constants-defined CID/port.
//
// Accepted forms:
//
//	tcp://host:port            e.g. tcp://127.0.0.1:5000
//	unix:///run/usbhsm.sock    (unix:/path is also accepted)
//	vsock://CID:port           e.g. vsock://16:5000
//
// This exists because a bare Linux host running the usbhsm bridge cannot bind a
// VSOCK listener as CID 16 (loopback is CID 1), so a true drop-in points the
// API at the bridge's TCP/Unix socket instead. The dialed connection is the
// same net.Conn the rest of this package uses, so framing, deadlines, and
// cancel-on-context are unchanged regardless of transport.
const SignerEndpointEnv = "CERBERUS_SIGNER_ENDPOINT"

// dialSigner dials the signer. With SignerEndpointEnv unset it dials the
// enclave over VSOCK at fallbackCID (the production path); otherwise it honors
// the configured endpoint.
func dialSigner(ctx context.Context, fallbackCID uint32) (net.Conn, error) {
	ep := strings.TrimSpace(os.Getenv(SignerEndpointEnv))
	if ep == "" {
		return vsock.Dial(fallbackCID, constants.EnclaveListeningPort, nil)
	}

	scheme, rest, ok := strings.Cut(ep, ":")
	if !ok {
		return nil, fmt.Errorf("invalid %s %q: want scheme:addr", SignerEndpointEnv, ep)
	}
	rest = strings.TrimPrefix(rest, "//")

	switch scheme {
	case "tcp":
		var d net.Dialer
		return d.DialContext(ctx, "tcp", rest)
	case "unix":
		var d net.Dialer
		return d.DialContext(ctx, "unix", rest)
	case "vsock":
		host, port, ok := strings.Cut(rest, ":")
		if !ok {
			return nil, fmt.Errorf("invalid vsock endpoint %q: want vsock://CID:port", ep)
		}
		cid, err := strconv.ParseUint(host, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock CID in %q: %w", ep, err)
		}
		p, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid vsock port in %q: %w", ep, err)
		}
		return vsock.Dial(uint32(cid), uint32(p), nil)
	default:
		return nil, fmt.Errorf("unsupported %s scheme %q (want tcp, unix, or vsock)", SignerEndpointEnv, scheme)
	}
}
