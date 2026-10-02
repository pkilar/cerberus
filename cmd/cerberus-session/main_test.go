package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRenewalOptInRequiresBothEmptyFlags(t *testing.T) {
	for _, tc := range []struct {
		flags map[string]string
		want  bool
	}{
		{nil, false}, {map[string]string{"permit-session-renewal@cerberus": ""}, false},
		{map[string]string{"permit-session-renewal@cerberus": "", "terminate-on-cert-expiry@cerberus": ""}, true},
		{map[string]string{"permit-session-renewal@cerberus": "yes", "terminate-on-cert-expiry@cerberus": ""}, false},
	} {
		if got := renewable(&ssh.Certificate{CertType: ssh.UserCert, ValidBefore: 12345, Permissions: ssh.Permissions{Extensions: tc.flags}}); got != tc.want {
			t.Fatalf("flags %v: %v", tc.flags, got)
		}
	}
}
func TestRejectArbitrarySigningAndWrongSerial(t *testing.T) {
	b := bridge{original: &ssh.Certificate{Serial: 12}}
	for _, r := range []request{{Serial: 13, Challenge: append([]byte(challengePrefix), make([]byte, 32)...)}, {Serial: 12, Challenge: []byte("arbitrary SSH signature")}, {Serial: 12, Challenge: []byte(challengePrefix)}} {
		if out := b.renew(context.Background(), r); out.Error == "" || out.Signature != nil {
			t.Fatal("unsafe signing request accepted")
		}
	}
}
func TestMatchingOriginalPrivateKey(t *testing.T) {
	_, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := ssh.NewSignerFromKey(k)
	if e != nil {
		t.Fatal(e)
	}
	// Without a key file or agent the helper fails closed, rather than choosing another identity.
	t.Setenv("SSH_AUTH_SOCK", t.TempDir()+"/missing")
	if _, _, e = matchingSigner(t.TempDir()+"/missing", s.PublicKey()); e == nil {
		t.Fatal("missing original key accepted")
	}
	challenge := append([]byte(challengePrefix), bytes.Repeat([]byte{1}, 32)...)
	sig, e := s.Sign(rand.Reader, challenge)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PublicKey().Verify(challenge, sig); e != nil {
		t.Fatal(e)
	}
}

func TestRenewalUsesPinnedKeyAndPrivateOutput(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	_, caPrivate, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPrivate)
	cert := &ssh.Certificate{Key: signer.PublicKey(), KeyId: "original-user", Serial: 7, CertType: ssh.UserCert, ValidBefore: uint64(time.Now().Add(time.Hour).Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{"permit-session-renewal@cerberus": "", "terminate-on-cert-expiry@cerberus": ""}}}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fresh := *cert
	fresh.Serial = 8
	if err := fresh.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	source := dir + "/source.pub"
	if err := os.WriteFile(source, ssh.MarshalAuthorizedKey(&fresh), 0600); err != nil {
		t.Fatal(err)
	}
	script := dir + "/cssh.sh"
	if err := os.WriteFile(script, []byte(`cssh() { [ "$1" = --force ] && [ "$2" = --sign-only ] || return 2; cp "$TEST_CERT" "$CSSH_CERT_OUTPUT"; }`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CERT", source)
	b := bridge{original: cert, signer: signer, script: script, principals: "root-ro", dir: dir}
	challenge := append([]byte(challengePrefix), bytes.Repeat([]byte{42}, 32)...)
	out := b.renew(context.Background(), request{Serial: 7, Challenge: challenge})
	if out.Error != "" {
		t.Fatal(out.Error)
	}
	if err := signer.PublicKey().Verify(challenge, out.Signature); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(out.Certificate), ssh.MarshalAuthorizedKey(&fresh)) {
		t.Fatal("wrong certificate returned")
	}
	fresh.KeyId = "other-user"
	fresh.SignCert(rand.Reader, ca)
	os.WriteFile(source, ssh.MarshalAuthorizedKey(&fresh), 0600)
	challenge[len(challenge)-1]++
	if out = b.renew(context.Background(), request{Serial: 7, Challenge: challenge}); out.Error == "" {
		t.Fatal("changed identity accepted")
	}
}

func TestSSHBridgeArgumentsAndCleanup(t *testing.T) {
	for _, opted := range []bool{false, true} {
		t.Run(fmt.Sprint(opted), func(t *testing.T) {
			dir := t.TempDir()
			_, private, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := ssh.NewSignerFromKey(private)
			key := dir + "/identity"
			block, err := ssh.MarshalPrivateKey(private, "")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(key, pem.EncodeToMemory(block), 0600); err != nil {
				t.Fatal(err)
			}
			cert := &ssh.Certificate{Key: signer.PublicKey(), KeyId: "user", Serial: 21, CertType: ssh.UserCert, ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
			if opted {
				cert.Extensions = map[string]string{"permit-session-renewal@cerberus": "", "terminate-on-cert-expiry@cerberus": "", "permit-port-forwarding": ""}
			}
			cert.SignCert(rand.Reader, signer)
			certPath := dir + "/cert.pub"
			os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600)
			mock := `#!/bin/sh
printf '%s\n' "$@" > "$TEST_SSH_ARGS"
for arg do case "$arg" in CertificateFile=*) cp "${arg#CertificateFile=}" "$TEST_SSH_CERT";; esac; done
exit 23
`
			os.WriteFile(dir+"/ssh", []byte(mock), 0700)
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			t.Setenv("TEST_SSH_ARGS", dir+"/args")
			t.Setenv("TEST_SSH_CERT", dir+"/usedcert")
			old := os.Args
			os.Args = []string{"cerberus-session", "--cert", certPath, "--key", key, "--pubkey", key + ".pub", "--principals", "root-ro", "--", "host"}
			defer func() { os.Args = old }()
			err = run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("exit status %v", err)
			}
			raw, _ := os.ReadFile(dir + "/args")
			args := string(raw)
			if opted {
				for _, want := range []string{"-R\n/tmp/cerberus-renew-", "SetEnv=CERBERUS_RENEW_SOCKET=", "ControlMaster=no", "ControlPath=none", "ExitOnForwardFailure=yes"} {
					if !strings.Contains(args, want) {
						t.Fatalf("missing %s in %s", want, args)
					}
				}
				for _, arg := range strings.Split(args, "\n") {
					if strings.HasPrefix(arg, "CertificateFile=") {
						if _, err = os.Stat(strings.TrimPrefix(arg, "CertificateFile=")); !os.IsNotExist(err) {
							t.Fatal("pinned certificate not cleaned")
						}
					}
				}
			} else if strings.Contains(args, "SetEnv=") || strings.Contains(args, "-R\n") {
				t.Fatal("nonrenewable cert starts forwarding")
			}
			used, _ := os.ReadFile(dir + "/usedcert")
			if !bytes.Equal(used, ssh.MarshalAuthorizedKey(cert)) {
				t.Fatal("login certificate not pinned")
			}
		})
	}
}

func TestCanceledRenewalKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/cssh.sh"
	// A descendant waits, then tries to overwrite the private output. Cancellation
	// must kill the process group before that write can occur.
	source := `cssh() { (sleep 0.3; printf leaked > "$TEST_CHILD_OUTPUT") & wait; }`
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CHILD_OUTPUT", dir+"/leaked")
	b := bridge{original: &ssh.Certificate{Serial: 9}, script: script, dir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := request{Serial: 9, Challenge: append([]byte(challengePrefix), make([]byte, 32)...)}
	if result := b.renew(ctx, r); result.Error == "" {
		t.Fatal("canceled signing accepted")
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := os.Stat(dir + "/leaked"); !os.IsNotExist(err) {
		t.Fatal("signing descendant survived cancellation")
	}

}

func TestReplayHistoryDoesNotLimitRenewalAttempts(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/cssh.sh"
	if err := os.WriteFile(script, []byte("cssh() { return 1; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b := bridge{original: &ssh.Certificate{Serial: 4}, script: script, dir: dir}
	challenge := append([]byte(challengePrefix), make([]byte, 32)...)
	for i := 0; i < 140; i++ {
		challenge[len(challenge)-1] = byte(i)
		result := b.renew(context.Background(), request{Serial: 4, Challenge: challenge})
		if result.Error != "local certificate authentication failed" {
			t.Fatalf("attempt %d: %s", i, result.Error)
		}
	}
	if len(b.seen) != 128 || len(b.recent) != 128 {
		t.Fatalf("unbounded history %d/%d", len(b.seen), len(b.recent))
	}
	if result := b.renew(context.Background(), request{Serial: 4, Challenge: challenge}); result.Error != "challenge already used" {
		t.Fatalf("recent replay: %s", result.Error)
	}
	challenge[len(challenge)-1] = 0
	if result := b.renew(context.Background(), request{Serial: 4, Challenge: challenge}); result.Error != "local certificate authentication failed" {
		t.Fatalf("evicted replay: %s", result.Error)
	}
}
