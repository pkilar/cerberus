package keyload

import (
	"context"
	"errors"
	"testing"

	"github.com/pkilar/cerberus/messages"
)

// fakeSigner implements just enough of enclave.Signer for keyload.Run. The
// unused interface methods are present so it satisfies enclave.Signer.
type fakeSigner struct {
	begin       *messages.BeginKeyLoadResponse
	beginErr    error
	complete    *messages.CompleteKeyLoadResponse
	completeErr error

	gotCiphertextForRecipient []byte
	completeCalled            bool
}

func (f *fakeSigner) SignPublicKey(context.Context, *messages.EnclaveSigningRequest) (string, error) {
	return "", errors.New("unused")
}
func (f *fakeSigner) Ping(context.Context) (*messages.PingResponse, error) {
	return nil, errors.New("unused")
}
func (f *fakeSigner) GetEnclaveMetrics(context.Context) (*messages.EnclaveMetricsResponse, error) {
	return nil, errors.New("unused")
}
func (f *fakeSigner) Close() error { return nil }
func (f *fakeSigner) BeginKeyLoad(context.Context, *messages.BeginKeyLoadRequest) (*messages.BeginKeyLoadResponse, error) {
	return f.begin, f.beginErr
}
func (f *fakeSigner) CompleteKeyLoad(_ context.Context, req *messages.CompleteKeyLoadRequest) (*messages.CompleteKeyLoadResponse, error) {
	f.completeCalled = true
	f.gotCiphertextForRecipient = req.CiphertextForRecipient
	return f.complete, f.completeErr
}

type fakeKMS struct {
	out     []byte
	err     error
	gotBlob []byte
	gotDoc  []byte
	called  bool
}

func (k *fakeKMS) DecryptForEnclave(_ context.Context, blob, doc []byte) ([]byte, error) {
	k.called = true
	k.gotBlob = blob
	k.gotDoc = doc
	return k.out, k.err
}

func TestRun_DevPath_LoadedSkipsKMS(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{Loaded: true}}
	kms := &fakeKMS{}
	if err := Run(t.Context(), signer, kms); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if kms.called {
		t.Error("KMS must not be called on the dev (Loaded) path")
	}
	if signer.completeCalled {
		t.Error("CompleteKeyLoad must not be called on the dev path")
	}
}

func TestRun_AttestedPath_HappyPath(t *testing.T) {
	signer := &fakeSigner{
		begin:    &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")},
		complete: &messages.CompleteKeyLoadResponse{Success: true},
	}
	kms := &fakeKMS{out: []byte("cms-envelope")}
	if err := Run(t.Context(), signer, kms); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if string(kms.gotBlob) != "blob" || string(kms.gotDoc) != "doc" {
		t.Errorf("KMS received blob=%q doc=%q", kms.gotBlob, kms.gotDoc)
	}
	if string(signer.gotCiphertextForRecipient) != "cms-envelope" {
		t.Errorf("CompleteKeyLoad received %q", signer.gotCiphertextForRecipient)
	}
}

func TestRun_AttestedPath_MissingFields(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc")}} // no ciphertext
	if err := Run(t.Context(), signer, &fakeKMS{}); err == nil {
		t.Fatal("expected error when ciphertext blob is missing")
	}
}

func TestRun_KMSError(t *testing.T) {
	signer := &fakeSigner{begin: &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")}}
	kms := &fakeKMS{err: errors.New("AccessDenied")}
	if err := Run(t.Context(), signer, kms); err == nil {
		t.Fatal("expected error when KMS decrypt fails")
	}
}

func TestRun_CompleteNotSuccessful(t *testing.T) {
	signer := &fakeSigner{
		begin:    &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")},
		complete: &messages.CompleteKeyLoadResponse{Success: false},
	}
	kms := &fakeKMS{out: []byte("cms-envelope")}
	if err := Run(t.Context(), signer, kms); err == nil {
		t.Fatal("expected error when enclave reports load did not succeed")
	}
}

func TestRun_BeginError(t *testing.T) {
	signer := &fakeSigner{beginErr: errors.New("vsock dial failed")}
	if err := Run(t.Context(), signer, &fakeKMS{}); err == nil {
		t.Fatal("expected error when BeginKeyLoad fails")
	}
}

func TestRun_NilBegin(t *testing.T) {
	// A misbehaving signer that returns (nil, nil) must not panic Run.
	signer := &fakeSigner{begin: nil}
	if err := Run(t.Context(), signer, &fakeKMS{}); err == nil {
		t.Fatal("expected error when BeginKeyLoad returns a nil response")
	}
}

func TestRun_NilComplete(t *testing.T) {
	// CompleteKeyLoad returning (nil, nil) on the attested path must not panic.
	signer := &fakeSigner{
		begin:    &messages.BeginKeyLoadResponse{AttestationDocument: []byte("doc"), CiphertextBlob: []byte("blob")},
		complete: nil,
	}
	kms := &fakeKMS{out: []byte("cms-envelope")}
	if err := Run(t.Context(), signer, kms); err == nil {
		t.Fatal("expected error when CompleteKeyLoad returns a nil response")
	}
}
