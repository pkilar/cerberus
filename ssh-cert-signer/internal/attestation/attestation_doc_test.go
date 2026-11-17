package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// NSM replies, written out by hand from the CBOR rules so that they do not
// depend on the encoder under test. The NSM encodes a Rust enum: a reply is a
// one-entry map keyed by the reply's name.
const (
	// {"Attestation": {"document": h'deadbeef'}}
	replyAttestation = "a1" + "6b4174746573746174696f6e" +
		"a1" + "68646f63756d656e74" + "44deadbeef"
	// {"Attestation": {"document": h''}}
	replyEmptyDocument = "a1" + "6b4174746573746174696f6e" +
		"a1" + "68646f63756d656e74" + "40"
	// {"GetRandom": {"random": h'00010203'}}, a well-formed reply to a
	// request this package never sends.
	replyGetRandom = "a1" + "6947657452616e646f6d" +
		"a1" + "6672616e646f6d" + "4400010203"
	// {"Error": "InvalidOperation"}
	replyRefusal = "a1" + "654572726f72" + "70496e76616c69644f7065726174696f6e"
)

// fakeNSM stands in for /dev/nsm. It records each encoded request and answers
// with a fixed reply, or fails the exchange when err is set.
type fakeNSM struct {
	reply    []byte
	err      error
	requests [][]byte
	closes   int
}

func (d *fakeNSM) Exchange(request, response []byte) (int, error) {
	d.requests = append(d.requests, bytes.Clone(request))
	if d.err != nil {
		return 0, d.err
	}
	return copy(response, d.reply), nil
}

func (d *fakeNSM) Close() error {
	d.closes++
	return nil
}

func fromHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func newTestKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func TestGenerateAttestationDoc(t *testing.T) {
	t.Parallel()
	key := newTestKey(t)
	device := &fakeNSM{reply: fromHex(t, replyAttestation)}
	p := &Provider{session: nsm.NewSession(device), rsaKey: key}

	doc, err := p.GenerateAttestationDoc()
	if err != nil {
		t.Fatalf("GenerateAttestationDoc: %v", err)
	}
	if want := []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(doc, want) {
		t.Errorf("document: got %x, want %x", doc, want)
	}

	// KMS encrypts its reply to the key the document vouches for, so the
	// request must carry this provider's public key, and nothing else.
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// An RSA-2048 key with the exponent 65537 always encodes to 294 bytes,
	// which is what lets the length below be written as a literal.
	if len(pubKeyDER) != 294 {
		t.Fatalf("public key is %d bytes of DER, want 294", len(pubKeyDER))
	}
	want := cat(
		fromHex(t, "a1"+"6b4174746573746174696f6e"), // {"Attestation":
		fromHex(t, "a3"),                        //   {
		fromHex(t, "69757365725f64617461"+"f6"), //     "user_data": null,
		fromHex(t, "656e6f6e6365"+"f6"),         //     "nonce": null,
		fromHex(t, "6a7075626c69635f6b6579"),    //     "public_key":
		fromHex(t, "590126"),                    //       294 bytes
		pubKeyDER,
	)

	if len(device.requests) != 1 {
		t.Fatalf("the NSM got %d requests, want 1", len(device.requests))
	}
	if got := device.requests[0]; !bytes.Equal(got, want) {
		t.Errorf("request to the NSM:\n got %x\nwant %x", got, want)
	}
}

func TestGenerateAttestationDoc_Failures(t *testing.T) {
	t.Parallel()
	key := newTestKey(t)
	errDevice := errors.New("device failed")

	tests := []struct {
		name   string
		device *fakeNSM
		// wantCode is the error code of an NSM refusal. When it is empty,
		// wantIs must be in the error's chain.
		wantCode response.ErrorCode
		wantIs   error
	}{
		{
			name:     "the NSM refuses",
			device:   &fakeNSM{reply: fromHex(t, replyRefusal)},
			wantCode: response.ECInvalidOperation,
		},
		{
			name:   "the device call fails",
			device: &fakeNSM{err: errDevice},
			wantIs: errDevice,
		},
		{
			name:   "the reply answers another request",
			device: &fakeNSM{reply: fromHex(t, replyGetRandom)},
			wantIs: errNoAttestationDocument,
		},
		{
			name:   "the document is empty",
			device: &fakeNSM{reply: fromHex(t, replyEmptyDocument)},
			wantIs: errNoAttestationDocument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &Provider{session: nsm.NewSession(tt.device), rsaKey: key}

			doc, err := p.GenerateAttestationDoc()
			if doc != nil {
				t.Errorf("got the document %x from a failed request", doc)
			}

			if tt.wantCode != "" {
				var nsmErr *nsm.Error
				if !errors.As(err, &nsmErr) {
					t.Fatalf("got error %v, want an *nsm.Error in its chain", err)
				}
				if nsmErr.Code != tt.wantCode {
					t.Errorf("NSM error code: got %q, want %q", nsmErr.Code, tt.wantCode)
				}
				return
			}
			if !errors.Is(err, tt.wantIs) {
				t.Fatalf("got error %v, want %v in its chain", err, tt.wantIs)
			}
		})
	}
}

func TestGenerateAttestationDoc_Unavailable(t *testing.T) {
	t.Parallel()
	key := newTestKey(t)
	device := &fakeNSM{reply: fromHex(t, replyAttestation)}

	tests := []struct {
		name string
		p    *Provider
	}{
		{"nil provider", nil},
		{"no session and no key", &Provider{}},
		{"no session", &Provider{rsaKey: key}},
		{"no key", &Provider{session: nsm.NewSession(device)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.p.IsAvailable() {
				t.Fatal("IsAvailable: got true, want false")
			}
			doc, err := tt.p.GenerateAttestationDoc()
			if err == nil {
				t.Fatalf("got the document %x, want an error", doc)
			}
		})
	}
	if len(device.requests) != 0 {
		t.Errorf("the NSM got %d requests, want none", len(device.requests))
	}
}

func TestClose(t *testing.T) {
	t.Parallel()
	device := &fakeNSM{reply: fromHex(t, replyAttestation)}
	p := &Provider{session: nsm.NewSession(device), rsaKey: newTestKey(t)}

	p.Close()
	if device.closes != 1 {
		t.Fatalf("the NSM device was closed %d times, want 1", device.closes)
	}

	// A request after Close is an error. It must not reach the closed device.
	doc, err := p.GenerateAttestationDoc()
	if !errors.Is(err, nsm.ErrSessionClosed) {
		t.Fatalf("after Close: got document %x and error %v, want nsm.ErrSessionClosed", doc, err)
	}
	if len(device.requests) != 0 {
		t.Errorf("the closed NSM device got %d requests, want none", len(device.requests))
	}

	// A second Close does not close the device again.
	p.Close()
	if device.closes != 1 {
		t.Errorf("the NSM device was closed %d times after two calls, want 1", device.closes)
	}
}

func TestClose_WithoutSession(t *testing.T) {
	t.Parallel()
	// Neither call may panic: main defers Close on a provider that has no
	// session whenever the signer runs outside an enclave.
	(*Provider)(nil).Close()
	(&Provider{}).Close()
}
