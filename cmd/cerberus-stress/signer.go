package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cerberus/messages"

	"github.com/mdlayher/vsock"
)

func runSigner(args []string) {
	var (
		common    commonFlags
		transport string
		target    string
		princs    string
		validity  string
		timeout   time.Duration
	)

	fs := flag.NewFlagSet("signer", flag.ExitOnError)
	common.bind(fs)
	fs.StringVar(&transport, "transport", "tcp", "transport: tcp or vsock")
	fs.StringVar(&target, "target", "127.0.0.1:5000", "target address — for tcp: host:port, for vsock: CID:port (e.g. 16:5000)")
	fs.StringVar(&princs, "principals", "stress-user", "comma-separated SSH principals to request in cert")
	fs.StringVar(&validity, "validity", "1h", "certificate validity duration")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "per-request connection deadline")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: cerberus-stress signer [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	sshKey, err := makeTestSSHKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate test SSH key: %v\n", err)
		os.Exit(1)
	}

	dial, err := buildSignerDialer(transport, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid target: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := makeContext()
	defer cancel()

	fmt.Printf("Stress-testing signer via %s://%s — %d workers, %s\n",
		transport, target, common.concurrency, formatStopCondition(common))

	principalList := strings.Split(princs, ",")
	var counter atomic.Int64

	do := func(ctx context.Context) error {
		n := counter.Add(1)
		req := messages.Request{
			SignSshKey: &messages.EnclaveSigningRequest{
				SSHKey:           sshKey,
				KeyID:            fmt.Sprintf("stress-%d", n),
				Principals:       principalList,
				Validity:         validity,
				Permissions:      map[string]string{},
				CustomAttributes: map[string]string{},
			},
		}
		return signOnce(ctx, dial, req, timeout)
	}

	runner(ctx, common, "signer", do)
}

type dialFunc func(ctx context.Context) (net.Conn, error)

func buildSignerDialer(transport, target string) (dialFunc, error) {
	switch transport {
	case "tcp":
		var d net.Dialer
		return func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", target)
		}, nil
	case "vsock":
		cid, port, err := parseVsock(target)
		if err != nil {
			return nil, err
		}
		// vsock.Dial does not accept a context; the per-request deadline
		// (set after dial) bounds the overall operation.
		return func(_ context.Context) (net.Conn, error) {
			return vsock.Dial(cid, port, nil)
		}, nil
	default:
		return nil, fmt.Errorf("unknown transport %q (want tcp or vsock)", transport)
	}
}

func parseVsock(target string) (uint32, uint32, error) {
	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("vsock target must be CID:PORT, got %q", target)
	}
	cid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid CID: %w", err)
	}
	port, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port: %w", err)
	}
	return uint32(cid), uint32(port), nil
}

// signOnce performs one full request/response round-trip on a fresh
// connection, matching the wire protocol used by ssh-cert-api/internal/enclave.
func signOnce(ctx context.Context, dial dialFunc, req messages.Request, timeout time.Duration) error {
	conn, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	var resp messages.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if resp.Error != nil {
		return fmt.Errorf("signer error: %s", *resp.Error)
	}
	if resp.SignSshKey == nil || resp.SignSshKey.SignedKey == "" {
		return errors.New("empty signed key in response")
	}
	return nil
}
