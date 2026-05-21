package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
)

// Wire-format SPNEGO InitialContextToken captured from gokrb5's own test
// vectors (spnego/spnego_test.go: testGSSAPIInit). It is a GSS-API
// `[APPLICATION 0] IMPLICIT SEQUENCE { SPNEGO-OID, NegTokenInit }` whose
// mechToken is a Kerberos GSS mech token wrapping a real AP-REQ — i.e. the
// exact shape MIT GSSAPI / Heimdal / curl --negotiate / browsers /
// requests-kerberos send on the wire.
const realWorldSPNEGOInitHex = "608202b606062b0601050502a08202aa308202a6a027302506092a864886f71201020206052b0501050206092a864882f71201020206062b0601050205a2820279048202756082027106092a864886f71201020201006e8202603082025ca003020105a10302010ea20703050000000000a38201706182016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b30820127a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd6767abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d9740b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b878356f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9b64f41a481d23081cfa003020112a281c70481c4eb593beb5afcb1a2a669d54cb85a3772231559f2d40c9f8f053f218ba6eb084ed7efc467d94b88bcd189dda920d6e675ec001a6a2bca11f0a1de37f2f7ae9929f94a86d625b2ec1b213a88cbae6099dda7b172cd3bd1802cb177ae4554d59277004bfd3435248f55044fe7af7b2c9c5a3c43763278c585395aebe2856cdff9f2569d8b823564ce6be2d19748b910ec06bd3c0a9bc5de51ddcf7d875f1108ca6ad935f52d90cb62a18197d9b8e796bef0fbe1463f61df61cfbce6008ae9e1a2d2314a986d"

// TestParseSPNEGOAPReq_AcceptsGSSWrappedInitialToken is a regression test for
// the wire-format SPNEGO bug: the previous implementation called
// spnego.UnmarshalNegToken directly on the Authorization-header bytes, which
// rejects any client that sends the standard GSS-API InitialContextToken
// wrapper with:
//
//	failed to parse SPNEGO token: error unmarshalling NegotiationToken type 0
//	(Init): asn1: structure error: tags don't match (16 vs {class:0 tag:6 …})
//
// On a fixed parser the call must reach the embedded AP-REQ.
func TestParseSPNEGOAPReq_AcceptsGSSWrappedInitialToken(t *testing.T) {
	t.Parallel()
	raw, err := hex.DecodeString(realWorldSPNEGOInitHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	apReq, err := parseSPNEGOAPReq(raw)
	if err != nil {
		t.Fatalf("parseSPNEGOAPReq rejected wire-format SPNEGO token: %v", err)
	}
	if apReq == nil {
		t.Fatal("parseSPNEGOAPReq returned nil AP-REQ without error")
	}
	if apReq.MsgType != msgtype.KRB_AP_REQ {
		t.Errorf("AP-REQ message type = %d, want %d", apReq.MsgType, msgtype.KRB_AP_REQ)
	}
}

func TestParseSPNEGOAPReq_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := parseSPNEGOAPReq(nil); err == nil {
		t.Error("expected error for nil token, got nil")
	}
	if _, err := parseSPNEGOAPReq([]byte{}); err == nil {
		t.Error("expected error for empty token, got nil")
	}
}

func TestParseSPNEGOAPReq_RejectsNegTokenResp(t *testing.T) {
	t.Parallel()
	// gokrb5 testGSSAPIResp: a bare NegTokenResp (byte 0 = 0xA1). Continuation
	// tokens have no place in the initial Authenticate request.
	raw, err := hex.DecodeString("a1143012a0030a0100a10b06092a864886f712010202")
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	_, err = parseSPNEGOAPReq(raw)
	if err == nil {
		t.Fatal("expected error for NegTokenResp, got nil")
	}
	if !errors.Is(err, errNotNegTokenInit) {
		t.Errorf("expected errNotNegTokenInit, got: %v", err)
	}
}

func TestCheckKeytabPermissions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr string // substring expected in error, "" means no error
	}{
		{"owner-read-write 0600", 0o600, ""},
		{"owner-read-only 0400", 0o400, ""},
		{"group-readable 0640", 0o640, "insecure permissions"},
		{"world-readable 0604", 0o604, "insecure permissions"},
		{"world-readable 0644", 0o644, "insecure permissions"},
		{"group-writable 0620", 0o620, "insecure permissions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "test.keytab")
			if err := os.WriteFile(path, []byte("stub"), tt.mode); err != nil {
				t.Fatalf("failed to create keytab: %v", err)
			}
			// os.WriteFile applies the umask, so force the mode explicitly.
			if err := os.Chmod(path, tt.mode); err != nil {
				t.Fatalf("failed to chmod keytab: %v", err)
			}

			err := checkKeytabPermissions(path)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("expected no error for mode %#o, got: %v", tt.mode, err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("expected error containing %q for mode %#o, got nil", tt.wantErr, tt.mode)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestCheckKeytabPermissions_MissingFile(t *testing.T) {
	t.Parallel()
	err := checkKeytabPermissions(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "failed to stat keytab") {
		t.Errorf("expected stat error, got: %v", err)
	}
}
