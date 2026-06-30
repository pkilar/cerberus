package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-signer/internal/handlers"

	"golang.org/x/crypto/ssh"
)

// Test-key caches mirror the same pattern as the handlers package: RSA-2048
// generation is expensive, and most callers just need "a test CA signer" /
// "a test user pubkey" — generating fresh per call is wasted CI time.
var (
	cachedCAKey   = sync.OnceValue(func() *rsa.PrivateKey { return mustGenRSA(2048) })
	cachedUserKey = sync.OnceValue(func() *rsa.PrivateKey { return mustGenRSA(2048) })
)

func mustGenRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err) // process-local fixture; failure here means rand.Reader is broken
	}
	return k
}

func createTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(cachedCAKey())
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

// freshTestSigner generates a brand-new signer per call. Use for tests that
// MUST observe two distinct signer identities (e.g. the atomic swap test);
// otherwise prefer createTestSigner.
func freshTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(mustGenRSA(2048))
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

func createTestSignerForBenchmark(b *testing.B) ssh.Signer {
	b.Helper()
	signer, err := ssh.NewSignerFromKey(cachedCAKey())
	if err != nil {
		b.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

func createTestPublicKey(t *testing.T) string {
	t.Helper()
	publicKey, err := ssh.NewPublicKey(&cachedUserKey().PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func createTestPublicKeyForBenchmark(b *testing.B) string {
	b.Helper()
	publicKey, err := ssh.NewPublicKey(&cachedUserKey().PublicKey)
	if err != nil {
		b.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(publicKey))
}

func TestSignPublicKey(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	tests := []struct {
		name        string
		request     messages.EnclaveSigningRequest
		expectError bool
	}{
		{
			name: "valid request",
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-1",
				Principals: []string{"user1", "user2"},
				Validity:   "1h",
				Permissions: map[string]string{
					"permit-pty": "",
				},
				CustomAttributes: map[string]string{
					"environment": "test",
				},
			},
			expectError: false,
		},
		{
			name: "invalid public key",
			request: messages.EnclaveSigningRequest{
				SSHKey:     "invalid-key-format",
				KeyID:      "test-key-2",
				Principals: []string{"user1"},
				Validity:   "1h",
			},
			expectError: true,
		},
		{
			name: "invalid validity duration",
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-3",
				Principals: []string{"user1"},
				Validity:   "invalid-duration",
			},
			expectError: true,
		},
		{
			name: "empty principals",
			request: messages.EnclaveSigningRequest{
				SSHKey:     testPublicKey,
				KeyID:      "test-key-4",
				Principals: []string{},
				Validity:   "1h",
			},
			expectError: true, // Empty principals are now refused at the enclave
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := handlers.SignPublicKey(t.Context(), signer, tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if response != nil {
					t.Error("expected nil response on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if response == nil || response.SignedKey == "" {
					t.Error("expected signed key but got empty response")
				}

				if response != nil && response.SignedKey != "" {
					// Verify the signed key format
					if !strings.Contains(response.SignedKey, "ssh-rsa-cert-v01@openssh.com") {
						t.Error("signed key should contain certificate type identifier")
					}

					// Try to parse the signed certificate
					publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
					if err != nil {
						t.Errorf("failed to parse signed certificate: %v", err)
					}

					cert, ok := publicKey.(*ssh.Certificate)
					if !ok {
						t.Error("expected SSH certificate")
					} else {
						// Verify certificate fields
						if cert.KeyId != tt.request.KeyID {
							t.Errorf("expected KeyId %s, got %s", tt.request.KeyID, cert.KeyId)
						}

						if len(cert.ValidPrincipals) != len(tt.request.Principals) {
							t.Errorf("expected %d principals, got %d", len(tt.request.Principals), len(cert.ValidPrincipals))
						}

						for i, principal := range tt.request.Principals {
							if i < len(cert.ValidPrincipals) && cert.ValidPrincipals[i] != principal {
								t.Errorf("expected principal %s, got %s", principal, cert.ValidPrincipals[i])
							}
						}

						// Verify permissions and custom attributes are in extensions
						for k, v := range tt.request.Permissions {
							if cert.Permissions.Extensions[k] != v {
								t.Errorf("expected permission %s=%s, got %s", k, v, cert.Permissions.Extensions[k])
							}
						}

						for k, v := range tt.request.CustomAttributes {
							if cert.Permissions.Extensions[k] != v {
								t.Errorf("expected attribute %s=%s, got %s", k, v, cert.Permissions.Extensions[k])
							}
						}
					}
				}
			}
		})
	}
}

// JSON round-trip tests for messages.Response and messages.EnclaveSigningRequest
// live in messages/messages_test.go (TestResponse_JSON, TestResponse_WithError,
// TestSshSigningRequest_JSON). Duplicating them here was pure cost.

func TestCertificateFields(t *testing.T) {
	signer := createTestSigner(t)
	testPublicKey := createTestPublicKey(t)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-cert-fields",
		Principals: []string{"testuser", "admin"},
		Validity:   "2h",
		Permissions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		},
		CustomAttributes: map[string]string{
			"department": "engineering",
			"project":    "cerberus",
		},
	}

	response, err := handlers.SignPublicKey(t.Context(), signer, req)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if response == nil || response.SignedKey == "" {
		t.Fatal("expected signed key in response")
	}

	// Parse certificate
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SignedKey))
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cert := publicKey.(*ssh.Certificate)

	// Test certificate type
	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert type, got %d", cert.CertType)
	}

	// Test validity period
	now := time.Now().Unix()
	if cert.ValidAfter > uint64(now) {
		t.Error("certificate should be valid now (considering clock skew)")
	}

	expectedValidBefore := time.Now().Add(2 * time.Hour).Unix()
	// Allow some variance for test execution time
	if cert.ValidBefore < uint64(expectedValidBefore-60) || cert.ValidBefore > uint64(expectedValidBefore+60) {
		t.Errorf("certificate validity period incorrect, expected around %d, got %d", expectedValidBefore, cert.ValidBefore)
	}

	// Test serial number is set
	if cert.Serial == 0 {
		t.Error("certificate serial should be non-zero")
	}
}

// Benchmark tests
func BenchmarkSignPublicKey(b *testing.B) {
	signer := createTestSignerForBenchmark(b)
	testPublicKey := createTestPublicKeyForBenchmark(b)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "benchmark-key",
		Principals: []string{"user"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
	}

	for b.Loop() {
		_, err := handlers.SignPublicKey(b.Context(), signer, req)
		if err != nil {
			b.Fatalf("signing failed: %v", err)
		}
	}
}

func BenchmarkJSONMarshalUnmarshal(b *testing.B) {
	req := messages.EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "benchmark-key",
		Principals: []string{"user1", "user2"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
		},
	}

	for b.Loop() {
		data, err := json.Marshal(req)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}

		var decoded messages.EnclaveSigningRequest
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}

// TestCASignerAtomicSwapUnderLoad exercises the atomic.Pointer[ssh.Signer]
// swap that backs the load-key-then-sign hot path. N readers continuously
// load the pointer and run a full sign while a writer replaces it. With
// -race, a regression that downgrades the primitive (e.g. to a bare pointer
// + mutex held incorrectly, or a non-atomic *ssh.Signer field) surfaces as
// a data race. Nil loads or sign errors fail the test.
func TestCASignerAtomicSwapUnderLoad(t *testing.T) {
	// Two distinct signer identities — the cached helper would hand back the
	// same pointer twice and turn the swap into a no-op.
	signer1 := freshTestSigner(t)
	signer2 := freshTestSigner(t)
	caSigner.Store(&signer1)
	t.Cleanup(func() {
		var zero *ssh.Signer
		caSigner.Store(zero)
	})

	pub := createTestPublicKey(t)
	const readers = 8
	stop := make(chan struct{})
	errs := make(chan error, readers)
	var wg sync.WaitGroup

	for range readers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				sp := caSigner.Load()
				if sp == nil {
					errs <- fmt.Errorf("caSigner.Load returned nil during swap")
					return
				}
				_, err := handlers.SignPublicKey(t.Context(), *sp, messages.EnclaveSigningRequest{
					SSHKey:     pub,
					KeyID:      "swap-load",
					Principals: []string{"u1"},
					Validity:   "1h",
				})
				if err != nil {
					errs <- fmt.Errorf("SignPublicKey under swap: %w", err)
					return
				}
			}
		})
	}

	// Hammer the swap. The 2 ms pacing gives readers many chances per
	// iteration to observe both halves of the swap.
	for i := range 50 {
		time.Sleep(2 * time.Millisecond)
		if i%2 == 0 {
			caSigner.Store(&signer2)
		} else {
			caSigner.Store(&signer1)
		}
	}

	close(stop)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// TestProcessRequest_RejectsAmbiguousVariants verifies that processRequest
// refuses a Request payload with more than one variant set (PR #35). The
// wire-protocol contract says exactly one of BeginKeyLoad / CompleteKeyLoad /
// SignSshKey / Ping is non-nil; a malicious or buggy host that sets two must
// not have one operation silently picked while the other is "smuggled".
func TestProcessRequest_RejectsAmbiguousVariants(t *testing.T) {
	cases := []messages.Request{
		{
			BeginKeyLoad: &messages.BeginKeyLoadRequest{},
			SignSshKey:   &messages.EnclaveSigningRequest{},
		},
		{
			CompleteKeyLoad: &messages.CompleteKeyLoadRequest{},
			Ping:            &messages.PingRequest{},
		},
		{
			SignSshKey: &messages.EnclaveSigningRequest{},
			Ping:       &messages.PingRequest{},
		},
		{
			BeginKeyLoad: &messages.BeginKeyLoadRequest{},
			SignSshKey:   &messages.EnclaveSigningRequest{},
			Ping:         &messages.PingRequest{},
		},
	}
	for i, req := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			body, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			resp := processRequest(t.Context(), body)
			if resp.Error == nil {
				t.Fatalf("expected error response, got: %+v", resp)
			}
			if !strings.Contains(*resp.Error, "multiple request variants") {
				t.Errorf("expected 'multiple request variants' in error, got: %s", *resp.Error)
			}
			// Belt-and-braces: no variant of the response should be set.
			if resp.BeginKeyLoad != nil || resp.SignSshKey != nil || resp.Pong != nil {
				t.Errorf("ambiguous request must not be dispatched; got resp=%+v", resp)
			}
		})
	}
}

// TestProcessRequest_PingNoSigner verifies that Ping works before the CA key
// has been loaded — /health depends on this being cheap and non-failing.
func TestProcessRequest_PingNoSigner(t *testing.T) {
	// Force caSigner to its zero state.
	var zero *ssh.Signer
	caSigner.Store(zero)

	body, err := json.Marshal(messages.Request{Ping: &messages.PingRequest{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := processRequest(t.Context(), body)
	if resp.Error != nil {
		t.Fatalf("Ping returned error: %s", *resp.Error)
	}
	if resp.Pong == nil {
		t.Fatal("expected Pong, got nil")
	}
	if resp.Pong.SignerLoaded {
		t.Error("SignerLoaded should be false when caSigner is nil")
	}
}

// TestHandleConnection_RejectsOversizeRequest drives a request larger than
// maxRequestBytes through the enclave's scanner loop over an in-memory pipe
// (no VSOCK needed) and asserts a structured "request exceeds" error comes
// back rather than a silent truncation or hang. This is the enclave-side
// mirror of the host's 413 body-cap test; CLAUDE.md calls the host/enclave
// body-cap asymmetry a load-bearing invariant.
func TestHandleConnection_RejectsOversizeRequest(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		handleConnection(ctx, serverConn)
		close(done)
	}()

	// Push more than maxRequestBytes with no newline so the scanner overflows
	// its buffer and returns bufio.ErrTooLong. Write in a goroutine: net.Pipe
	// is unbuffered and the server stops reading once the token is too long, so
	// the tail of this write stays blocked until the server closes the conn.
	go func() {
		_, _ = clientConn.Write(bytes.Repeat([]byte("A"), maxRequestBytes+1024))
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	respBytes, err := bufio.NewReader(clientConn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("reading error response: %v", err)
	}
	var resp messages.Response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Error == nil {
		t.Fatalf("expected error response, got %+v", resp)
	}
	if !strings.Contains(*resp.Error, "request exceeds") {
		t.Errorf("got error %q, want it to contain 'request exceeds'", *resp.Error)
	}

	_ = clientConn.Close()
	cancel()
	<-done
}

// Test for the nil signer case in SignPublicKey handler
func TestSignPublicKey_NilSigner(t *testing.T) {
	testPublicKey := createTestPublicKey(t)

	req := messages.EnclaveSigningRequest{
		SSHKey:     testPublicKey,
		KeyID:      "test-key",
		Principals: []string{"user1"},
		Validity:   "1h",
	}

	// Test with nil signer
	_, err := handlers.SignPublicKey(t.Context(), nil, req)
	if err == nil {
		t.Error("expected error with nil signer")
	}
	if !strings.Contains(err.Error(), "CA signer is not initialized") {
		t.Errorf("expected 'CA signer is not initialized' error, got: %v", err)
	}
}

// reset returns the gate to its initial (unarmed) state between tests. Defined
// here because it's test-only; the gate type and its production methods live in
// main.go.
func (g *keyLoadGate) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = false
}

// resetCASigner clears the package caSigner pointer (which the gate's identity
// check reads) and restores it on cleanup, so gate/handler tests don't leak load
// state into each other.
func resetCASigner(t *testing.T) {
	t.Helper()
	var zero *ssh.Signer
	caSigner.Store(zero)
	t.Cleanup(func() { caSigner.Store(zero) })
}

// TestKeyLoadGate_CompleteWithoutBegin asserts the core adversarial property:
// a CompleteKeyLoad with no preceding BeginKeyLoad is refused and the install
// (the CMS decrypt + signer parse) never runs. This is the host-mediated
// protocol's load-injection guard — KMS recipient attestation proves the
// envelope is for this enclave, not that the host followed the handshake.
func TestKeyLoadGate_CompleteWithoutBegin(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate

	_, err := g.completeLoad(func() (ssh.Signer, error) {
		t.Fatal("install must not run when no BeginKeyLoad armed the load")
		return nil, nil
	})
	if !errors.Is(err, errCompleteWithoutBegin) {
		t.Fatalf("want errCompleteWithoutBegin refusal, got %v", err)
	}
	if caSigner.Load() != nil {
		t.Error("no signer should be installed after a refused CompleteKeyLoad")
	}
}

// TestKeyLoadGate_CompleteRefusesDifferentKeyAfterLoad is the swap-attack guard:
// once a signer is installed, a CompleteKeyLoad that decrypts to a DIFFERENT key
// is refused and the live CA is untouched — even though a BeginKeyLoad re-armed
// the load (so the host followed the handshake).
func TestKeyLoadGate_CompleteRefusesDifferentKeyAfterLoad(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate
	first := freshTestSigner(t)

	g.arm()
	if _, err := g.completeLoad(func() (ssh.Signer, error) { return first, nil }); err != nil {
		t.Fatalf("first completeLoad: %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, first) {
		t.Fatalf("first signer was not installed")
	}

	// A second handshake that decrypts to a different key is a host-driven swap.
	second := freshTestSigner(t)
	g.arm()
	_, err := g.completeLoad(func() (ssh.Signer, error) { return second, nil })
	if !errors.Is(err, errCompleteDifferentKey) {
		t.Fatalf("want different-key swap refusal, got %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, first) {
		t.Error("a refused swap must leave the original CA signer installed")
	}
}

// TestKeyLoadGate_CompleteIdempotentReloadSameKey is the regression guard for the
// decoupled host/enclave lifecycle: the host re-drives Begin→Complete on every
// restart while the enclave keeps the key loaded, so a re-load of the SAME key
// must succeed (else the API would wedge in a restart loop).
func TestKeyLoadGate_CompleteIdempotentReloadSameKey(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate
	ca := freshTestSigner(t)

	g.arm()
	if _, err := g.completeLoad(func() (ssh.Signer, error) { return ca, nil }); err != nil {
		t.Fatalf("first completeLoad: %v", err)
	}

	// Host restart: re-arm, re-complete with the same key — idempotent success.
	g.arm()
	reloadRan := false
	if _, err := g.completeLoad(func() (ssh.Signer, error) {
		reloadRan = true
		return ca, nil
	}); err != nil {
		t.Fatalf("idempotent re-completeLoad of the same key should succeed, got %v", err)
	}
	if !reloadRan {
		t.Error("install should run on re-load — the gate compares the decrypted key")
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, ca) {
		t.Error("idempotent re-load must keep the same CA signer installed")
	}
}

// TestKeyLoadGate_LoadDirect covers the development path's loadDirect: first
// install, idempotent same-key re-load (dev host restart), and different-key
// refusal. Without this, the loadDirect guard — one of the two production entry
// points that install caSigner — would be entirely untested.
func TestKeyLoadGate_LoadDirect(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate
	first := freshTestSigner(t)

	if err := g.loadDirect(first); err != nil {
		t.Fatalf("first loadDirect: %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, first) {
		t.Fatal("loadDirect did not install the signer")
	}

	// Re-loading the same key is idempotent.
	if err := g.loadDirect(first); err != nil {
		t.Errorf("idempotent re-loadDirect of the same key should succeed, got %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, first) {
		t.Error("idempotent loadDirect must keep the installed signer")
	}

	// Re-loading a different key is refused; the installed signer is untouched.
	second := freshTestSigner(t)
	if err := g.loadDirect(second); !errors.Is(err, errLoadDirectDifferentKey) {
		t.Fatalf("want different-key refusal, got %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, first) {
		t.Error("a refused loadDirect must leave the original signer installed")
	}
}

// TestKeyLoadGate_FailedCompleteStaysArmed verifies a transient install failure
// (e.g. a dropped KMS relay) leaves the load armed so the host can retry
// CompleteKeyLoad without re-driving BeginKeyLoad.
func TestKeyLoadGate_FailedCompleteStaysArmed(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate
	g.arm()
	if _, err := g.completeLoad(func() (ssh.Signer, error) {
		return nil, fmt.Errorf("transient relay failure")
	}); err == nil {
		t.Fatal("want install error to propagate")
	}
	if caSigner.Load() != nil {
		t.Fatal("failed install must not install a signer")
	}
	// Retry succeeds without a new arm.
	want := freshTestSigner(t)
	if _, err := g.completeLoad(func() (ssh.Signer, error) { return want, nil }); err != nil {
		t.Fatalf("retry completeLoad should succeed while still armed, got %v", err)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, want) {
		t.Error("retry should install the signer")
	}
}

// TestKeyLoadGate_ConcurrentCompleteInstallsOnce hammers completeLoad from many
// goroutines against a single armed load and asserts exactly one install runs
// and succeeds. With -race this also guards the gate's serialization.
func TestKeyLoadGate_ConcurrentCompleteInstallsOnce(t *testing.T) {
	resetCASigner(t)
	var g keyLoadGate
	g.arm()

	const n = 16
	signers := make([]ssh.Signer, n)
	for i := range signers {
		signers[i] = freshTestSigner(t)
	}
	var installCount, okCount atomic.Int32
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			if _, err := g.completeLoad(func() (ssh.Signer, error) {
				installCount.Add(1)
				return signers[i], nil
			}); err == nil {
				okCount.Add(1)
			}
		})
	}
	wg.Wait()

	if okCount.Load() != 1 {
		t.Errorf("exactly one completeLoad should succeed, got %d", okCount.Load())
	}
	if installCount.Load() != 1 {
		t.Errorf("install should run exactly once, got %d", installCount.Load())
	}
	if caSigner.Load() == nil {
		t.Error("a signer should be installed after the race")
	}
}

// TestProcessRequest_CompleteWithoutBegin wires the gate through the real
// dispatch path: a CompleteKeyLoad arriving cold (no BeginKeyLoad) is refused by
// the handshake guard, not dispatched into the attestation/decrypt path.
func TestProcessRequest_CompleteWithoutBegin(t *testing.T) {
	resetCASigner(t)
	gate.reset()
	t.Cleanup(gate.reset)

	body, err := json.Marshal(messages.Request{CompleteKeyLoad: &messages.CompleteKeyLoadRequest{
		CiphertextForRecipient: []byte("attacker-supplied-envelope"),
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := processRequest(t.Context(), body)
	if resp.Error == nil {
		t.Fatalf("want error response, got %+v", resp)
	}
	if !strings.Contains(*resp.Error, "without a preceding BeginKeyLoad") {
		t.Errorf("want handshake refusal, got %q", *resp.Error)
	}
	if caSigner.Load() != nil {
		t.Error("no signer should be installed")
	}
}

// TestProcessRequest_ColdCompleteDoesNotDisturbLoadedSigner wires a cold
// CompleteKeyLoad (no preceding BeginKeyLoad) against an already-installed CA
// through dispatch: it is refused by the handshake guard and the live CA is
// untouched. (The swap-with-a-valid-key property is proven at the gate level by
// TestKeyLoadGate_CompleteRefusesDifferentKeyAfterLoad, which uses a real
// install func — that path needs an attestation provider the dispatch test lacks.)
func TestProcessRequest_ColdCompleteDoesNotDisturbLoadedSigner(t *testing.T) {
	resetCASigner(t)
	gate.reset()
	t.Cleanup(gate.reset)

	loaded := freshTestSigner(t)
	caSigner.Store(&loaded)

	body, err := json.Marshal(messages.Request{CompleteKeyLoad: &messages.CompleteKeyLoadRequest{
		CiphertextForRecipient: []byte("attacker-supplied-envelope"),
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := processRequest(t.Context(), body)
	if resp.Error == nil || !strings.Contains(*resp.Error, "without a preceding BeginKeyLoad") {
		t.Fatalf("want handshake refusal, got %+v", resp)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, loaded) {
		t.Error("a cold CompleteKeyLoad must not disturb the installed CA signer")
	}
}

// TestProcessRequest_BeginAfterLoadReDrivesHandshake is the dispatch-level
// regression guard for the decoupled host/enclave lifecycle (see workflow
// finding): with the CA already installed, a BeginKeyLoad must NOT be
// short-circuited by a gate refusal — that would wedge the host (keyload.Run ->
// log.Fatalf) in a systemd restart loop on every routine API restart. It must
// reach the loader; here that fails only because the test env has no key file,
// proving it was not gate-blocked, and the installed signer is left intact.
func TestProcessRequest_BeginAfterLoadReDrivesHandshake(t *testing.T) {
	resetCASigner(t)
	gate.reset()
	t.Cleanup(gate.reset)
	t.Setenv("REQUIRE_ATTESTATION", "false")
	t.Setenv("CA_KEY_FILE_PATH", "/nonexistent/cerberus-test/ca_key.enc")

	loaded := freshTestSigner(t)
	caSigner.Store(&loaded)

	body, err := json.Marshal(messages.Request{BeginKeyLoad: &messages.BeginKeyLoadRequest{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := processRequest(t.Context(), body)
	if resp.Error == nil {
		t.Fatalf("want the dev-path file-read error, got %+v", resp)
	}
	if !strings.Contains(*resp.Error, "failed to read encrypted key file") {
		t.Errorf("BeginKeyLoad after load should reach the loader (file error), not a gate refusal; got %q", *resp.Error)
	}
	if got := caSigner.Load(); got == nil || !samePublicKey(*got, loaded) {
		t.Error("BeginKeyLoad after load must not disturb the installed signer")
	}
}
