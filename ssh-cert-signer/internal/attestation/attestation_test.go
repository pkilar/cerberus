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

// OIDs used to build CMS test fixtures. The parser ignores most of these
// values directly and recovers them via the cms package, but we include them
// to keep the fixture structurally identical to what KMS emits.
var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidRSAOAEP       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
)

// --- minimal manual ASN.1 helpers ---
//
// We avoid encoding/asn1.Marshal for structural composition because it has
// subtle interactions between asn1.RawValue.FullBytes and struct tags like
// `asn1:"explicit,tag:0"`. Hand-written TLV is predictable and only ~40
// lines, which is less than the debugging time saved.

// tlv emits a definite-length DER TLV.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encLen(len(content))...)
	out = append(out, content...)
	return out
}

// tlvIndef emits an indefinite-length BER TLV. tag must already have the
// constructed bit (0x20) set; the content is followed by an end-of-contents
// marker (0x00 0x00) per X.690 §8.1.5.
func tlvIndef(tag byte, content []byte) []byte {
	out := []byte{tag, 0x80}
	out = append(out, content...)
	return append(out, 0x00, 0x00)
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

// envelopeForm controls whether buildCMSEnvelope emits the outer wrappers
// using definite-length DER (formDER) or BER with indefinite-length form on
// the EnvelopedData SEQUENCE — which is what KMS actually emits.
type envelopeForm int

const (
	formDER envelopeForm = iota
	formBERIndefinite
)

// buildCMSEnvelope encodes a CMS EnvelopedData (RFC 5652) matching what KMS
// returns in CiphertextForRecipient: AES-256-CBC content encryption with the
// CEK wrapped via RSA-OAEP-SHA256 under pub. When form is formBERIndefinite,
// the EnvelopedData SEQUENCE uses BER indefinite-length encoding to mimic
// real KMS responses.
func buildCMSEnvelope(tb testing.TB, pub *rsa.PublicKey, plaintext []byte, form envelopeForm) []byte {
	tb.Helper()

	cek := make([]byte, 32) // AES-256
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
	aesOID := mustMarshal(tb, oidAES256CBC)
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
	edBody := cat(ver2, ris, eci)
	var ed []byte
	switch form {
	case formBERIndefinite:
		ed = tlvIndef(0x30, edBody)
	default:
		ed = tlv(0x30, edBody)
	}

	// ContentInfo: SEQUENCE { envelopedDataOID, [0] EXPLICIT EnvelopedData }.
	ed0 := tlv(0xa0, ed)
	return tlv(0x30, cat(envOID, ed0))
}

// Note: cannot use t.Parallel here or on any subtest below. The upstream
// github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms package has a data
// race in ber2der's asn1Structured.EncodeTo path that surfaces when valid
// envelopes are parsed concurrently. Keep this file fully sequential.
func TestDecryptCMSEnvelope_RoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{rsaKey: key}

	tests := []struct {
		name      string
		plaintext []byte
		form      envelopeForm
	}{
		{"DER short", []byte("hello"), formDER},
		{"DER one block", bytes.Repeat([]byte{'A'}, 16), formDER},
		{"DER multi block", bytes.Repeat([]byte{'B'}, 64), formDER},
		{"DER PEM-ish", []byte("-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----\n"), formDER},
		// BER with indefinite-length on EnvelopedData — locks in the regression
		// from KMS emitting BER (not DER) in CiphertextForRecipient.
		{"BER indefinite short", []byte("hello"), formBERIndefinite},
		{"BER indefinite multi block", bytes.Repeat([]byte{'C'}, 64), formBERIndefinite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := buildCMSEnvelope(t, &key.PublicKey, tt.plaintext, tt.form)
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
		"truncated indefinite":   {0x30, 0x80}, // no EOC → ber2der must fail closed
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
	envelope := buildCMSEnvelope(t, &key.PublicKey, []byte("hello"), formDER)

	for cut := 1; cut < len(envelope); cut += 23 {
		t.Run("cut_"+strconv.Itoa(cut), func(t *testing.T) {
			_, err := p.DecryptCMSEnvelope(envelope[:cut])
			if err == nil {
				t.Errorf("truncation to %d bytes: expected error", cut)
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

	f.Add(buildCMSEnvelope(f, &key.PublicKey, []byte("seed"), formDER))
	f.Add(buildCMSEnvelope(f, &key.PublicKey, []byte("seed"), formBERIndefinite))
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x80})
	f.Add(bytes.Repeat([]byte{0xff}, 200))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must return an error or []byte — never panic.
		_, _ = p.DecryptCMSEnvelope(data)
	})
}
