// cerberus-session keeps certificate renewal credentials on the SSH client.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const challengePrefix = "cerberus-session-renewal-v1\x00"
const maxMessage = 64 << 10

type request struct {
	Challenge []byte `json:"challenge"`
	Serial    uint64 `json:"serial"`
}
type response struct {
	Certificate string         `json:"certificate,omitempty"`
	Signature   *ssh.Signature `json:"signature,omitempty"`
	Error       string         `json:"error,omitempty"`
}
type bridge struct {
	seen                                               map[string]struct{}
	recent                                             []string
	agentConnection                                    io.Closer
	original                                           *ssh.Certificate
	signer                                             ssh.Signer
	script, pubkey, url, cacert, auth, principals, dir string
	mu                                                 sync.Mutex
}

func certificate(path string) (*ssh.Certificate, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	k, _, _, _, e := ssh.ParseAuthorizedKey(b)
	if e != nil {
		return nil, e
	}
	c, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("identity is not a certificate")
	}
	return c, nil
}
func renewable(c *ssh.Certificate) bool {
	a, ok := c.Extensions["permit-session-renewal@cerberus"]
	b, ok2 := c.Extensions["terminate-on-cert-expiry@cerberus"]
	return ok && ok2 && a == "" && b == "" && c.CertType == ssh.UserCert && c.ValidBefore != ssh.CertTimeInfinity
}
func matchingSigner(key string, public ssh.PublicKey) (ssh.Signer, io.Closer, error) {
	b, e := os.ReadFile(key)
	if e == nil {
		s, err := ssh.ParsePrivateKey(b)
		if err == nil && bytes.Equal(s.PublicKey().Marshal(), public.Marshal()) {
			return s, nil, nil
		}
	}
	c, e := net.DialTimeout("unix", os.Getenv("SSH_AUTH_SOCK"), 3*time.Second)
	if e != nil {
		return nil, nil, errors.New("original key unavailable; unlock it in ssh-agent")
	}
	_ = c.SetDeadline(time.Now().Add(90 * time.Second))
	ss, e := agent.NewClient(c).Signers()
	if e == nil {
		for _, s := range ss {
			p := s.PublicKey()
			if cert, ok := p.(*ssh.Certificate); ok {
				p = cert.Key
			}
			if bytes.Equal(p.Marshal(), public.Marshal()) {
				return s, c, nil
			}
		}
	}
	c.Close()
	return nil, nil, errors.New("original key not present in ssh-agent")
}
func (b *bridge) renew(ctx context.Context, r request) response {
	if r.Serial != b.original.Serial || len(r.Challenge) != len(challengePrefix)+32 || !bytes.HasPrefix(r.Challenge, []byte(challengePrefix)) {
		return response{Error: "invalid renewal challenge"}
	}
	if !b.mu.TryLock() {
		return response{Error: "renewal already in progress"}
	}
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = make(map[string]struct{})
	}
	challengeID := string(r.Challenge)
	if _, used := b.seen[challengeID]; used {
		return response{Error: "challenge already used"}
	}
	if len(b.recent) >= 128 {
		delete(b.seen, b.recent[0])
		b.recent = b.recent[1:]
	}
	b.recent = append(b.recent, challengeID)
	b.seen[challengeID] = struct{}{}
	// Each renewal has its own output; concurrent normal cssh calls cannot replace it.
	out := filepath.Join(b.dir, "renewed-cert.pub")
	args := []string{"--force", "--sign-only", "--pubkey", b.pubkey, "--url", b.url, "--principals", b.principals}
	if b.cacert != "" {
		args = append(args, "--cacert", b.cacert)
	}
	cmd := exec.CommandContext(ctx, "sh", append([]string{"-c", `. "$CSSH_SCRIPT_PATH"; cssh "$@"`, "cssh"}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(), "CSSH_SCRIPT_PATH="+b.script, "CSSH_AUTH="+b.auth, "CSSH_CERT_OUTPUT="+out)
	cmd.Stderr = os.Stderr
	if e := cmd.Run(); e != nil {
		return response{Error: "local certificate authentication failed"}
	}
	c, e := certificate(out)
	if e != nil {
		return response{Error: "invalid renewed certificate"}
	}
	if c.KeyId != b.original.KeyId || !bytes.Equal(c.Key.Marshal(), b.original.Key.Marshal()) || !bytes.Equal(c.SignatureKey.Marshal(), b.original.SignatureKey.Marshal()) || !renewable(c) {
		return response{Error: "renewed certificate changed identity or policy"}
	}
	if c, ok := b.agentConnection.(net.Conn); ok {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	sig, e := b.signer.Sign(rand.Reader, r.Challenge)
	if e != nil {
		return response{Error: "original key could not sign renewal proof"}
	}
	return response{Certificate: string(ssh.MarshalAuthorizedKey(c)), Signature: sig}
}
func (b *bridge) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	line, e := bufio.NewReader(io.LimitReader(c, maxMessage+1)).ReadBytes('\n')
	if e != nil || len(line) > maxMessage {
		return
	}
	var r request
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	_ = json.NewEncoder(c).Encode(b.renew(requestCtx, r))
}
func run() error {
	f := flag.NewFlagSet("cerberus-session", flag.ContinueOnError)
	cert := f.String("cert", "", "original certificate")
	key := f.String("key", "", "original private key")
	script := f.String("script", "/etc/profile.d/cssh.sh", "cssh script")
	pub := f.String("pubkey", "", "public key")
	url := f.String("url", "", "API URL")
	ca := f.String("cacert", "", "CA bundle")
	auth := f.String("auth", "kerberos", "authentication mode")
	principals := f.String("principals", "", "original requested principals")
	if e := f.Parse(os.Args[1:]); e != nil {
		return e
	}
	if len(f.Args()) == 0 {
		return errors.New("missing SSH arguments")
	}
	original, e := certificate(*cert)
	if e != nil {
		return e
	}
	sshArgs := []string{"-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey", "-i", *key, "-o", "CertificateFile=" + *cert}
	if !renewable(original) {
		cmd := exec.Command("ssh", append(sshArgs, f.Args()...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if value, ok := original.Extensions["permit-port-forwarding"]; !ok || value != "" {
		return errors.New("renewable certificate must permit port forwarding")
	}
	signer, closer, e := matchingSigner(*key, original.Key)
	if e != nil {
		return e
	}
	if closer != nil {
		defer closer.Close()
	}
	dir, e := os.MkdirTemp("", "cerberus-renew-")
	if e != nil {
		return e
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "cerberus-session: cleanup:", err)
		}
	}()
	// Pin the actual login certificate as well as the renewal identity.
	pinned := filepath.Join(dir, "login-cert.pub")
	if e = os.WriteFile(pinned, ssh.MarshalAuthorizedKey(original), 0600); e != nil {
		return e
	}
	sshArgs[len(sshArgs)-1] = "CertificateFile=" + pinned
	socket := filepath.Join(dir, "bridge.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	if e = os.Chmod(socket, 0600); e != nil {
		return e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	remote := "/tmp/cerberus-renew-" + hex.EncodeToString(nonce) + ".sock"
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	b := &bridge{original: original, signer: signer, agentConnection: closer, script: *script, pubkey: *pub, url: *url, cacert: *ca, auth: *auth, principals: *principals, dir: dir}
	var handlers sync.WaitGroup
	slots := make(chan struct{}, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				handlers.Add(1)
				go func() {
					defer handlers.Done()
					defer func() { <-slots }()
					done := make(chan struct{})
					go func() {
						select {
						case <-ctx.Done():
							c.Close()
						case <-done:
						}
					}()
					b.handle(ctx, c)
					close(done)
				}()
			default:
				c.Close()
			}
		}
	}()

	sshArgs = append(sshArgs, "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindMask=0177", "-o", "SetEnv=CERBERUS_RENEW_SOCKET="+remote, "-R", remote+":"+socket)
	cmd := exec.CommandContext(ctx, "ssh", append(sshArgs, f.Args()...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	cancel()
	listener.Close()
	<-acceptDone
	handlers.Wait()
	return err
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "cerberus-session:", e)
		var x *exec.ExitError
		if errors.As(e, &x) {
			os.Exit(x.ExitCode())
		}
		os.Exit(1)
	}
}
