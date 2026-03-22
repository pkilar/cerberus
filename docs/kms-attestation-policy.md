# KMS Key Policy for Nitro Enclave Attestation

## Overview

When the signer service runs inside a Nitro Enclave, it attaches an NSM attestation document to KMS Decrypt calls. This document cryptographically proves the enclave's identity (its image hash, kernel, and application measurements) to AWS KMS. KMS can then enforce conditions on the key policy that restrict decryption to a specific enclave image.

Without a PCR condition in the key policy, KMS validates the attestation document signature (proving it came from *some* Nitro Enclave) but does not restrict *which* enclave image can decrypt. Adding PCR conditions is what completes the attestation chain.

## PCR Values

PCR (Platform Configuration Register) values are SHA-384 hashes generated during `nitro-cli build-enclave`:

| PCR  | Description                     | Changes when...                         |
| ---- | ------------------------------- | --------------------------------------- |
| PCR0 | Enclave image file hash         | Any code, binary, or dependency changes |
| PCR1 | Linux kernel and bootstrap hash | Base image or kernel changes            |
| PCR2 | Application hash                | Application binary changes              |

After building the EIF, PCR values are saved to `ssh-cert-signer/pcr-manifest-{arch}.json`:

```bash
make eif-amd64   # produces pcr-manifest-amd64.json
make eif-arm64   # produces pcr-manifest-arm64.json
```

Example manifest:

```json
{
  "Architecture": "amd64",
  "EIF": "ssh-cert-signer-amd64.eif",
  "PCR0": "abc123...",
  "PCR1": "def456...",
  "PCR2": "ghi789..."
}
```

## Production Key Policy

For production, add a `Condition` block to the KMS key policy that restricts `kms:Decrypt` to the specific enclave image:

```json
{
  "Sid": "AllowEnclaveDecrypt",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT_ID:role/ENCLAVE_INSTANCE_ROLE"
  },
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "PCR0_VALUE_FROM_MANIFEST"
    }
  }
}
```

Replace `ACCOUNT_ID`, `ENCLAVE_INSTANCE_ROLE`, and `PCR0_VALUE_FROM_MANIFEST` with actual values. The PCR0 value comes from `pcr-manifest-{arch}.json` after building the EIF.

You can also enforce multiple PCR values for stricter validation:

```json
"Condition": {
  "StringEqualsIgnoreCase": {
    "kms:RecipientAttestation:PCR0": "...",
    "kms:RecipientAttestation:PCR1": "...",
    "kms:RecipientAttestation:PCR2": "..."
  }
}
```

## Development Mode

During development, omit the `Condition` block entirely:

```json
{
  "Sid": "AllowEnclaveDecrypt",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT_ID:role/ENCLAVE_INSTANCE_ROLE"
  },
  "Action": "kms:Decrypt",
  "Resource": "*"
}
```

KMS will still validate that the attestation document is properly signed by AWS (proving it came from a real Nitro Enclave), but it will not enforce specific PCR values. This avoids friction when rebuilding the enclave frequently during development, since PCR values change with every build.

**This is NOT suitable for production.** Without PCR conditions, any Nitro Enclave running under the same IAM role can decrypt the CA key.

## Updating the Policy After a Build

PCR values change with every build. After deploying a new enclave image to production:

1. Build the EIF: `make eif-amd64`
2. Read the new PCR values from `ssh-cert-signer/pcr-manifest-amd64.json`
3. Update the KMS key policy with the new PCR0 value
4. Deploy the new EIF and restart the enclave

## Fallback Behavior

If the signer runs outside an enclave (e.g., during integration testing), the NSM device (`/dev/nsm`) is not available. The signer detects this at startup and falls back to standard KMS Decrypt without attestation. This logs a warning:

```
NSM device not found — running without attestation (development mode)
```

In this mode, the KMS key policy must NOT have PCR conditions, or decryption will fail.
