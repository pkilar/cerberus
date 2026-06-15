// Package keyload drives the host-mediated CA-key load. The enclave has no
// network, so rather than proxy its KMS traffic, the host performs the KMS
// Decrypt itself with its own instance-role credentials and the enclave's
// attestation document. KMS encrypts the plaintext to the enclave's attestation
// public key (CiphertextForRecipient), so the host never sees the plaintext CA
// key — only the enclave can open the envelope.
package keyload

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/pkilar/cerberus/messages"
	"github.com/pkilar/cerberus/ssh-cert-api/internal/enclave"
)

// KMSDecrypter performs an attested KMS Decrypt on behalf of the enclave: given
// the KMS ciphertext blob and the enclave's attestation document, it returns the
// CiphertextForRecipient (a CMS envelope only the enclave can open).
type KMSDecrypter interface {
	DecryptForEnclave(ctx context.Context, ciphertextBlob, attestationDocument []byte) ([]byte, error)
}

// Run executes the Begin→(KMS)→Complete handshake. On the development path
// (enclave without /dev/nsm) the enclave decrypts the key itself and reports
// Loaded=true, so no KMS call or CompleteKeyLoad is needed.
func Run(ctx context.Context, signer enclave.Signer, kmsDecrypter KMSDecrypter) error {
	begin, err := signer.BeginKeyLoad(ctx, &messages.BeginKeyLoadRequest{})
	if err != nil {
		return fmt.Errorf("begin key load: %w", err)
	}
	if begin == nil {
		return errors.New("enclave returned a nil BeginKeyLoad response")
	}
	if begin.Loaded {
		// Development enclave decrypted the key itself; nothing more to do.
		return nil
	}
	if len(begin.AttestationDocument) == 0 || len(begin.CiphertextBlob) == 0 {
		return errors.New("enclave returned neither a loaded signer nor an attestation document + ciphertext")
	}

	ciphertextForRecipient, err := kmsDecrypter.DecryptForEnclave(ctx, begin.CiphertextBlob, begin.AttestationDocument)
	if err != nil {
		return fmt.Errorf("host-mediated KMS decrypt: %w", err)
	}

	complete, err := signer.CompleteKeyLoad(ctx, &messages.CompleteKeyLoadRequest{CiphertextForRecipient: ciphertextForRecipient})
	if err != nil {
		return fmt.Errorf("complete key load: %w", err)
	}
	if !complete.Success {
		return errors.New("enclave reported CA key load did not succeed")
	}
	return nil
}

// awsDecrypter is the production KMSDecrypter. It uses the host's own network and
// AWS credential chain (the EC2 instance role).
type awsDecrypter struct{ client *kms.Client }

// NewAWSDecrypter builds a KMSDecrypter backed by AWS KMS in the given region.
func NewAWSDecrypter(ctx context.Context, region string) (KMSDecrypter, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return awsDecrypter{client: kms.NewFromConfig(cfg)}, nil
}

func (d awsDecrypter) DecryptForEnclave(ctx context.Context, ciphertextBlob, attestationDocument []byte) ([]byte, error) {
	out, err := d.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertextBlob,
		Recipient: &types.RecipientInfo{
			AttestationDocument:    attestationDocument,
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt failed: %w", err)
	}
	if len(out.CiphertextForRecipient) == 0 {
		return nil, errors.New("KMS returned empty CiphertextForRecipient despite Recipient being set")
	}
	return out.CiphertextForRecipient, nil
}
