package attestation

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"strconv"
	"testing"
)

// OID for rsaOaep — the parser ignores its bytes, we include it only to match
// the structure KMS emits so the test stays close to production reality.
var oidRSAOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}

// --- minimal manual ASN.1 DER helpers ---
//
// We avoid encoding/asn1.Marshal for structural composition because it has
// subtle interactions between asn1.RawValue.FullBytes and struct tags like
// `asn1:"explicit,tag:0"`. Hand-written TLV is predictable and only ~20
// lines, which is less than the debugging time saved.

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encLen(len(content))...)
	out = append(out, content...)
	return out
}

func encLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var lenBytes []byte
	for x := n; x > 0; x >>= 8 {
		lenBytes = append([]byte{byte(x & 0xff)}, lenBytes...)
	}
	return append([]byte{0x80 | byte(len(lenBytes))}, lenBytes...)
}

func cat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func mustMarshal(tb testing.TB, v any) []byte {
	tb.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// buildCMSEnvelope encodes a CMS EnvelopedData (RFC 5652) matching what KMS
// returns in CiphertextForRecipient: AES-128-CBC content encryption with the
// CEK wrapped via RSA-OAEP-SHA256 under pub.
func buildCMSEnvelope(tb testing.TB, pub *rsa.PublicKey, plaintext []byte) []byte {
	tb.Helper()

	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		tb.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		tb.Fatal(err)
	}

	// PKCS#7 pad + AES-CBC encrypt.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, 0, len(plaintext)+padLen)
	padded = append(padded, plaintext...)
	for range padLen {
		padded = append(padded, byte(padLen))
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		tb.Fatal(err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// RSA-OAEP-SHA256 wrap the CEK.
	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		tb.Fatal(err)
	}

	// OIDs as pre-marshaled TLV bytes.
	aesOID := mustMarshal(tb, oidAES128CBC)
	dataOID := mustMarshal(tb, oidData)
	envOID := mustMarshal(tb, oidEnvelopedData)
	oaepOID := mustMarshal(tb, oidRSAOAEP)

	// AES-CBC AlgorithmIdentifier: SEQUENCE { aesOID, OCTET STRING(iv) }.
	ivOctet := tlv(0x04, iv)
	aesAlgID := tlv(0x30, cat(aesOID, ivOctet))

	// EncryptedContentInfo: SEQUENCE { dataOID, aesAlgID, [0] IMPLICIT OCTET STRING(ciphertext) }.
	ctx0Cipher := tlv(0x80, ciphertext)
	eci := tlv(0x30, cat(dataOID, aesAlgID, ctx0Cipher))

	// KeyEncryptionAlgorithmIdentifier: SEQUENCE { oaepOID }.
	keyEncAlgID := tlv(0x30, oaepOID)

	// Rid: [0] SubjectKeyIdentifier — arbitrary bytes; parser captures as RawValue.
	rid := tlv(0x80, []byte{0xaa, 0xbb, 0xcc, 0xdd})

	// INTEGER 2.
	ver2 := tlv(0x02, []byte{0x02})

	// EncryptedKey: OCTET STRING.
	encKey := tlv(0x04, wrappedKey)

	// KeyTransRecipientInfo: SEQUENCE { ver, rid, keyEncAlg, encKey }.
	ktri := tlv(0x30, cat(ver2, rid, keyEncAlgID, encKey))

	// RecipientInfos: SET { KTRI, … }.
	ris := tlv(0x31, ktri)

	// EnvelopedData: SEQUENCE { ver, ris, eci }.
	ed := tlv(0x30, cat(ver2, ris, eci))

	// ContentInfo: SEQUENCE { envelopedDataOID, [0] EXPLICIT EnvelopedData }.
	ed0 := tlv(0xa0, ed)
	return tlv(0x30, cat(envOID, ed0))
}

func TestDecryptCMSEnvelope_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{rsaKey: key}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"short", []byte("hello")},
		{"one block", bytes.Repeat([]byte{'A'}, 16)},
		{"multi block", bytes.Repeat([]byte{'B'}, 64)},
		{"PEM-ish", []byte("-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----\n")},
		{"empty", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := buildCMSEnvelope(t, &key.PublicKey, tt.plaintext)
			got, err := p.DecryptCMSEnvelope(envelope)
			if err != nil {
				t.Fatalf("DecryptCMSEnvelope: %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Errorf("plaintext mismatch: got %q, want %q", got, tt.plaintext)
			}
		})
	}
}

func TestDecryptCMSEnvelope_NoKey(t *testing.T) {
	tests := []struct {
		name string
		p    *Provider
	}{
		{"nil provider", nil},
		{"nil rsaKey", &Provider{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.p.DecryptCMSEnvelope([]byte("anything"))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDecryptCMSEnvelope_MalformedInput(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{rsaKey: key}

	validButNotCMS := mustMarshal(t, 42)
	tests := map[string][]byte{
		"empty":                  {},
		"single byte":            {0x30},
		"indefinite len":         {0x30, 0x80},
		"random garbage":         bytes.Repeat([]byte{0xff}, 64),
		"valid asn1 but not CMS": validButNotCMS,
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			// Must return error, not panic.
			_, err := p.DecryptCMSEnvelope(data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDecryptCMSEnvelope_Truncated(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{rsaKey: key}
	envelope := buildCMSEnvelope(t, &key.PublicKey, []byte("hello"))

	for cut := 1; cut < len(envelope); cut += 23 {
		t.Run("cut_"+strconv.Itoa(cut), func(t *testing.T) {
			_, err := p.DecryptCMSEnvelope(envelope[:cut])
			if err == nil {
				t.Errorf("truncation to %d bytes: expected error", cut)
			}
		})
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr bool
	}{
		{"normal padding", []byte{'a', 'b', 3, 3, 3}, []byte{'a', 'b'}, false},
		{"one byte pad", []byte{'a', 'b', 'c', 1}, []byte{'a', 'b', 'c'}, false},
		{"full block only padding", bytes.Repeat([]byte{16}, 16), []byte{}, false},
		{"zero pad byte", []byte{'x', 0}, nil, true},
		{"pad exceeds block", []byte{'x', 17}, nil, true},
		{"pad exceeds data", []byte{'x', 3}, nil, true},
		{"inconsistent pad bytes", []byte{'x', 'y', 2, 3}, nil, true},
		{"empty", []byte{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := removePKCS7Padding(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// FuzzDecryptCMSEnvelope asserts the parser never panics on arbitrary input.
// A bug here could be triggered by a malicious VSOCK proxy injecting garbage
// as the KMS response body — fail closed with an error, never crash.
func FuzzDecryptCMSEnvelope(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	p := &Provider{rsaKey: key}

	f.Add(buildCMSEnvelope(f, &key.PublicKey, []byte("seed")))
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x80})
	f.Add(bytes.Repeat([]byte{0xff}, 200))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must return an error or []byte — never panic.
		_, _ = p.DecryptCMSEnvelope(data)
	})
}
