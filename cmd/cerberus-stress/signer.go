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
		return func(ctx context.Context) (net.Conn, error) {
			return vsockDialContext(ctx, cid, port)
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

// vsockDialContext is a context-aware adapter over vsock.Dial. The library's
// Dial takes no context; dialRaceCtx supplies the race-and-drain pattern so
// the racing logic is testable in isolation from the unmockable vsock syscall.
func vsockDialContext(ctx context.Context, cid, port uint32) (net.Conn, error) {
	return dialRaceCtx(ctx, func() (net.Conn, error) {
		return vsock.Dial(cid, port, nil)
	})
}

// dialRaceCtx races a context-unaware dial against ctx. If ctx wins, a
// drainer goroutine waits for the dial to finish and closes any connection
// it produced — without that, every timed-out worker would leak the FD the
// kernel eventually hands back when its own connect attempt completes.
func dialRaceCtx(ctx context.Context, dial func() (net.Conn, error)) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := dial()
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() {
			r := <-ch
			if r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// signOnce performs one full request/response round-trip on a fresh
// connection, matching the wire protocol used by ssh-cert-api/internal/enclave.
// The whole operation is bounded by a context derived from timeout so a stuck
// dial cannot wedge a worker past the user-advertised -timeout.
func signOnce(ctx context.Context, dial dialFunc, req messages.Request, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set deadline: %w", err)
		}
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
