// Package attestation provides Nitro Enclave attestation for KMS Decrypt calls.
// When running inside a Nitro Enclave, it generates NSM attestation documents
// and decrypts the CMS envelopes returned by KMS. Outside an enclave, it
// gracefully degrades to a no-op so the signer can run without attestation
// during development.
package attestation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// Provider wraps NSM attestation document generation and CMS envelope decryption.
// If the NSM device is not available (outside an enclave), all operations
// gracefully return nil/false so callers can fall back to standard KMS Decrypt.
type Provider struct {
	session *nsm.Session
	rsaKey  *rsa.PrivateKey
}

// NewProvider creates an attestation Provider. It attempts to open the NSM
// device at /dev/nsm and generate an RSA-2048 keypair. If NSM is unavailable
// (not running inside an enclave), the provider is returned in a degraded state
// where IsAvailable() returns false.
func NewProvider() *Provider {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Printf("NSM device not available: %v (attestation disabled)", err)
		return &Provider{}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		sess.Close()
		log.Printf("Failed to generate RSA keypair for attestation: %v", err)
		return &Provider{}
	}

	return &Provider{session: sess, rsaKey: key}
}

// IsAvailable returns true if the provider has an active NSM session and
// can generate attestation documents.
func (p *Provider) IsAvailable() bool {
	return p != nil && p.session != nil && p.rsaKey != nil
}

// GenerateAttestationDoc requests an attestation document from the NSM device.
// The document includes the provider's RSA public key so that KMS can encrypt
// the response plaintext under it.
func (p *Provider) GenerateAttestationDoc() ([]byte, error) {
	if !p.IsAvailable() {
		return nil, errors.New("attestation not available")
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&p.rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
	}

	res, err := p.session.Send(&request.Attestation{
		PublicKey: pubKeyDER,
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation request failed: %w", err)
	}

	if res.Error != "" {
		return nil, fmt.Errorf("NSM returned error: %s", res.Error)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("NSM did not return an attestation document")
	}

	return res.Attestation.Document, nil
}

// DecryptCMSEnvelope decrypts a CMS EnvelopedData structure (RFC 5652) as
// returned by KMS in the CiphertextForRecipient field. The envelope uses
// RSA-OAEP-SHA256 key transport and AES-CBC content encryption.
func (p *Provider) DecryptCMSEnvelope(data []byte) ([]byte, error) {
	if !p.IsAvailable() {
		return nil, errors.New("attestation not available")
	}

	encryptedKey, iv, encryptedContent, err := parseCMSEnvelopedData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CMS envelope: %w", err)
	}

	// Decrypt the content encryption key (CEK) with our RSA private key.
	cek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.rsaKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content encryption key: %w", err)
	}

	// Decrypt the content with AES-CBC.
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length %d does not match AES block size %d", len(iv), aes.BlockSize)
	}

	if len(encryptedContent)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted content length %d is not a multiple of AES block size", len(encryptedContent))
	}

	plaintext := make([]byte, len(encryptedContent))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, encryptedContent)

	// Remove PKCS#7 padding.
	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to remove PKCS#7 padding: %w", err)
	}

	return plaintext, nil
}

// Close releases the NSM session.
func (p *Provider) Close() {
	if p != nil && p.session != nil {
		p.session.Close()
	}
}

// --- CMS ASN.1 parsing ---
//
// KMS returns a CMS EnvelopedData (RFC 5652) with:
//   - KeyTransRecipientInfo using RSA-OAEP-SHA256
//   - EncryptedContentInfo using AES-CBC (128 or 256)

// OIDs used in CMS parsing.
var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
)

// parseCMSEnvelopedData extracts the encrypted key, IV, and encrypted content
// from a CMS EnvelopedData structure.
func parseCMSEnvelopedData(data []byte) (encryptedKey, iv, encryptedContent []byte, err error) {
	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err = asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	if !contentInfo.ContentType.Equal(oidEnvelopedData) {
		return nil, nil, nil, fmt.Errorf("unexpected content type: %v", contentInfo.ContentType)
	}

	// EnvelopedData ::= SEQUENCE { version INTEGER, recipientInfos SET OF, encryptedContentInfo SEQUENCE }
	var envelopedData struct {
		Version        int
		RecipientInfos asn1.RawValue `asn1:"set"`
		EncryptedCI    asn1.RawValue
	}
	if _, err = asn1.Unmarshal(contentInfo.Content.Bytes, &envelopedData); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal EnvelopedData: %w", err)
	}

	// Parse the first RecipientInfo (KeyTransRecipientInfo).
	encryptedKey, err = parseKeyTransRecipientInfo(envelopedData.RecipientInfos.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// Parse EncryptedContentInfo.
	iv, encryptedContent, err = parseEncryptedContentInfo(envelopedData.EncryptedCI.FullBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return encryptedKey, iv, encryptedContent, nil
}

// parseKeyTransRecipientInfo extracts the encrypted key from a KeyTransRecipientInfo.
func parseKeyTransRecipientInfo(data []byte) ([]byte, error) {
	// KeyTransRecipientInfo ::= SEQUENCE { version INTEGER, rid ANY, keyEncAlg AlgorithmIdentifier, encryptedKey OCTET STRING }
	var ktri struct {
		Version      int
		Rid          asn1.RawValue
		KeyEncAlg    asn1.RawValue
		EncryptedKey []byte
	}
	if _, err := asn1.Unmarshal(data, &ktri); err != nil {
		return nil, fmt.Errorf("unmarshal KeyTransRecipientInfo: %w", err)
	}
	return ktri.EncryptedKey, nil
}

// parseEncryptedContentInfo extracts the IV and encrypted content.
func parseEncryptedContentInfo(data []byte) (iv, encryptedContent []byte, err error) {
	// EncryptedContentInfo ::= SEQUENCE { contentType OID, contentEncAlg AlgorithmIdentifier, encryptedContent [0] IMPLICIT OCTET STRING }
	var eci struct {
		ContentType    asn1.ObjectIdentifier
		ContentEncAlg  asn1.RawValue
		EncryptedBytes asn1.RawValue `asn1:"tag:0,optional"`
	}
	if _, err = asn1.Unmarshal(data, &eci); err != nil {
		return nil, nil, fmt.Errorf("unmarshal EncryptedContentInfo: %w", err)
	}

	// Parse AlgorithmIdentifier to get the IV.
	var algID struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	if _, err = asn1.Unmarshal(eci.ContentEncAlg.FullBytes, &algID); err != nil {
		return nil, nil, fmt.Errorf("unmarshal content encryption AlgorithmIdentifier: %w", err)
	}

	if !algID.Algorithm.Equal(oidAES256CBC) && !algID.Algorithm.Equal(oidAES128CBC) {
		return nil, nil, fmt.Errorf("unsupported content encryption algorithm: %v", algID.Algorithm)
	}

	// The IV is the parameter of the AES-CBC algorithm (OCTET STRING).
	if _, err = asn1.Unmarshal(algID.Parameters.FullBytes, &iv); err != nil {
		return nil, nil, fmt.Errorf("unmarshal AES-CBC IV: %w", err)
	}

	encryptedContent = eci.EncryptedBytes.Bytes
	return iv, encryptedContent, nil
}

// removePKCS7Padding removes PKCS#7 padding from decrypted plaintext.
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid PKCS#7 padding length: %d", padLen)
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("invalid PKCS#7 padding bytes")
		}
	}

	return data[:len(data)-padLen], nil
}
