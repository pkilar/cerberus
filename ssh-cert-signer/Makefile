# Makefile for the ssh-cert-signer enclave service

# Go build parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# Nitro Enclave CLI tool
# This Makefile assumes 'nitro-cli', 'nitro-cli-devel', and 'python3' are
# installed and in the system's PATH. python3 parses the build-enclave JSON
# output to emit the PCR manifest used to pin the KMS attestation policy.
#
# The eif-* targets require both 'ca_key.enc' and 'ca_key.pub' to be present in
# this directory (the docker build context) before invocation, since the
# Dockerfile COPYs both into the image: ca_key.enc is the KMS-encrypted CA key,
# and ca_key.pub is baked in as the CA_PUBLIC_KEY_PATH integrity pin. Both are
# produced by `make encrypt-ca-key KMS_KEY_ARN=...`. To build an EIF without the
# pin, remove the ca_key.pub COPY/ENV from the Dockerfile.
NITRO_CLI=nitro-cli

# Output names for the binary and the final Enclave Image File
BINARY_NAME=ssh-cert-signer
EIF_NAME_AMD64=ssh-cert-signer-amd64.eif
EIF_NAME_ARM64=ssh-cert-signer-arm64.eif

# Version stamped into the binary's -V flag output; single source of truth is
# the top-level VERSION file.
VERSION := $(shell cat $(CURDIR)/../VERSION)

# Build flags for stripped release binary
LDFLAGS_STRIP = -ldflags="-s -w -X github.com/pkilar/cerberus/version.Version=$(VERSION)"

# Default target executed when you just run `make`
all: eif

# Target to build the Go binary specifically for the enclave environment.
# Nitro Enclaves support both linux/amd64 and linux/arm64.
build:
	@echo "Building Go binary for enclave environment (GOOS=linux, GOARCH=amd64, GOARCH=arm64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS_STRIP) -v -o $(BINARY_NAME).amd64 ./cmd/ssh-cert-signer
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS_STRIP) -v -o $(BINARY_NAME).arm64 ./cmd/ssh-cert-signer

# Target to package the compiled binaries into deployable Enclave Image Files (.eif).
# This uses Docker to create a root filesystem with the binary and its dependencies.
# The --docker-uri specifies the base image for the enclave's filesystem.
# The --docker-dir specifies the context for the Docker build.
eif: eif-amd64 eif-arm64

# Verify the CA key material the Dockerfile bakes into the EIF is present, with
# an actionable message, instead of failing deep inside `docker buildx` on a
# missing COPY source.
require-ca-files:
	@test -s ca_key.enc || { echo "ERROR: ca_key.enc not found or empty in $(CURDIR). Run 'make encrypt-ca-key KMS_KEY_ARN=...' first."; exit 1; }
	@test -f ca_key.pub || { echo "ERROR: ca_key.pub not found in $(CURDIR). It is baked into the EIF as the CA_PUBLIC_KEY_PATH pin; keep the ca_key.pub from 'make encrypt-ca-key', or remove the ca_key.pub COPY/ENV from the Dockerfile to build without the pin."; exit 1; }

eif-amd64: build require-ca-files
	@echo "Building AMD64 Enclave Image File ($(EIF_NAME_AMD64))..."
	docker buildx build --platform linux/amd64 --build-arg TARGETARCH=amd64 -t ssh-cert-signer:amd64 .
	$(NITRO_CLI) build-enclave --docker-uri ssh-cert-signer:amd64 --output-file $(EIF_NAME_AMD64) | tee /dev/stderr | \
		python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('Measurements',{}); \
		json.dump({'Architecture':'amd64','EIF':'$(EIF_NAME_AMD64)','PCR0':m.get('PCR0',''),'PCR1':m.get('PCR1',''),'PCR2':m.get('PCR2','')}, \
		open('pcr-manifest-amd64.json','w'),indent=2)"
	@echo "Successfully created $(EIF_NAME_AMD64)."
	@if [ -f pcr-manifest-amd64.json ]; then echo "PCR manifest: pcr-manifest-amd64.json"; cat pcr-manifest-amd64.json; fi

eif-arm64: build require-ca-files
	@echo "Building ARM64 Enclave Image File ($(EIF_NAME_ARM64))..."
	docker buildx build --platform linux/arm64 --build-arg TARGETARCH=arm64 -t ssh-cert-signer:arm64 .
	$(NITRO_CLI) build-enclave --docker-uri ssh-cert-signer:arm64 --output-file $(EIF_NAME_ARM64) | tee /dev/stderr | \
		python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('Measurements',{}); \
		json.dump({'Architecture':'arm64','EIF':'$(EIF_NAME_ARM64)','PCR0':m.get('PCR0',''),'PCR1':m.get('PCR1',''),'PCR2':m.get('PCR2','')}, \
		open('pcr-manifest-arm64.json','w'),indent=2)"
	@echo "Successfully created $(EIF_NAME_ARM64)."
	@if [ -f pcr-manifest-arm64.json ]; then echo "PCR manifest: pcr-manifest-arm64.json"; cat pcr-manifest-arm64.json; fi

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Create and encrypt the SSH CA key with KMS.
# Usage: make encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:region:account:key/key-id
# This will:
# 1. REFUSE to run if any CA key material (ca_key, ca_key.pub, ca_key.enc) is
#    already present. Regenerating would mint a DIFFERENT CA and force a
#    re-distribution of ca_key.pub to every SSH server that trusts it. Rotation
#    is deliberate: remove the old material first with `make clean-ca-key`.
# 2. Generate a new ed25519 SSH CA private key.
# 3. Encrypt it with the specified KMS key -> ca_key.enc.
# 4. Securely delete the plaintext private key (shred, falling back to rm).
# The public half (ca_key.pub) is kept: it is distributed to SSH servers for
# certificate validation AND baked into the EIF as the CA_PUBLIC_KEY_PATH pin.
encrypt-ca-key:
	@if [ -z "$(KMS_KEY_ARN)" ]; then \
		echo "Error: KMS_KEY_ARN parameter is required"; \
		echo "Usage: make encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:region:account:key/key-id"; \
		exit 1; \
	fi
	@for f in ca_key ca_key.pub ca_key.enc; do \
		if [ -e "$$f" ]; then \
			echo "ERROR: refusing to generate a new CA key — $(CURDIR)/$$f already exists."; \
			echo "  Overwriting it would create a DIFFERENT CA. Every SSH server that trusts the"; \
			echo "  current CA would reject certificates until you re-distribute the new ca_key.pub."; \
			echo "  If you really intend to rotate the CA, remove the existing key material first:"; \
			echo "      make clean-ca-key        # or: rm -f ca_key ca_key.pub ca_key.enc"; \
			echo "  then re-run 'make encrypt-ca-key KMS_KEY_ARN=...'."; \
			exit 1; \
		fi; \
	done
	@# Generate and encrypt inside a RAM-backed working directory when one is
	@# available (/dev/shm is tmpfs on Linux) so the plaintext CA key never touches
	@# durable storage — closing the SC-6 residual where shred(1) cannot guarantee
	@# erasure on copy-on-write filesystems, journaled filesystems, or SSDs with
	@# wear-leveling. Only the two safe artifacts (KMS-encrypted ca_key.enc and the
	@# public ca_key.pub) are moved into the working tree.
	@#
	@# Everything runs in a SINGLE shell so the temp dir and its cleanup trap share
	@# one process; the trap shreds+removes the plaintext on ANY exit path (success,
	@# KMS failure, or Ctrl-C). The ciphertext is captured into a variable rather
	@# than piped so a KMS error (bad creds, wrong region, missing kms:Encrypt) is
	@# caught by aws's own exit status instead of being masked behind base64. Falls
	@# back to the working directory + shred where /dev/shm is absent (e.g. macOS),
	@# preserving the previous behavior with a warning.
	@set -e; \
	if [ -d /dev/shm ] && [ -w /dev/shm ]; then \
		work=$$(mktemp -d -p /dev/shm cerberus-ca.XXXXXX); \
		trap 'shred -u "$$work"/ca_key 2>/dev/null || rm -f "$$work"/ca_key 2>/dev/null || true; rm -rf "$$work"' EXIT INT TERM; \
		ram=1; \
		echo "Generating SSH CA private key in RAM-backed $$work ..."; \
	else \
		work=.; ram=0; \
		echo "WARNING: /dev/shm is unavailable; generating in $(CURDIR)."; \
		echo "         The plaintext CA key will briefly touch durable storage and rely on shred,"; \
		echo "         which is not a guaranteed erase on SSD/CoW/journaled filesystems. Prefer a"; \
		echo "         Linux host with /dev/shm (tmpfs) for CA key generation."; \
		echo "Generating SSH CA private key..."; \
	fi; \
	ssh-keygen -t ed25519 -f "$$work/ca_key" -N "" -C "SSH CA Key for Nitro Enclave"; \
	echo "Encrypting CA private key with KMS..."; \
	b64=$$(aws kms encrypt --key-id $(KMS_KEY_ARN) --plaintext "fileb://$$work/ca_key" --output text --query CiphertextBlob) || { \
		echo "ERROR: KMS encrypt failed. Fix credentials/region/kms:Encrypt and re-run."; \
		if [ "$$ram" != 1 ]; then shred -u "$$work/ca_key" 2>/dev/null || rm -f "$$work/ca_key"; fi; \
		echo "       The unencrypted CA key was removed; a fresh key is generated on re-run."; \
		exit 1; \
	}; \
	printf '%s' "$$b64" | base64 -d > "$$work/ca_key.enc"; \
	if [ ! -s "$$work/ca_key.enc" ]; then \
		echo "ERROR: ca_key.enc is empty after KMS encrypt — investigate and re-run."; \
		rm -f "$$work/ca_key.enc"; \
		if [ "$$ram" != 1 ]; then shred -u "$$work/ca_key" 2>/dev/null || rm -f "$$work/ca_key"; fi; \
		exit 1; \
	fi; \
	if [ "$$ram" = 1 ]; then \
		mv "$$work/ca_key.enc" ./ca_key.enc; \
		mv "$$work/ca_key.pub" ./ca_key.pub; \
	else \
		echo "Securely deleting the unencrypted CA private key..."; \
		shred -u "$$work/ca_key" 2>/dev/null || rm -f "$$work/ca_key"; \
	fi; \
	echo "Encrypted CA key saved to ca_key.enc"; \
	echo "Public key saved to ca_key.pub — keep this: it is distributed to SSH servers"; \
	echo "  for certificate validation AND baked into the EIF as the CA_PUBLIC_KEY_PATH pin."

# Clean build artifacts. CA key material (ca_key, ca_key.pub, ca_key.enc) is
# deliberately PRESERVED — losing it would force re-distributing a new public CA
# key to every SSH server. Use `make clean-ca-key` to remove it explicitly.
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME).amd64 $(BINARY_NAME).arm64 $(EIF_NAME_AMD64) $(EIF_NAME_ARM64) coverage.out coverage.html pcr-manifest-amd64.json pcr-manifest-arm64.json
	@if [ -e ca_key ] || [ -e ca_key.pub ] || [ -e ca_key.enc ]; then \
		echo "Note: preserving CA key material (ca_key / ca_key.pub / ca_key.enc)."; \
		echo "      'make clean' never deletes these. Run 'make clean-ca-key' to remove"; \
		echo "      them for a deliberate CA rotation (this invalidates the current CA)."; \
	fi
	$(GOCLEAN)

# Deliberately and DESTRUCTIVELY remove CA key material. A CA generated after
# this will not be trusted by any SSH server until you re-distribute the new
# ca_key.pub. `make clean` never removes these files — removal must be explicit.
clean-ca-key:
	@echo "WARNING: removing CA key material (ca_key ca_key.pub ca_key.enc)."
	@echo "         A newly generated CA will require re-distributing ca_key.pub to all SSH servers."
	@shred -u ca_key 2>/dev/null || rm -f ca_key
	rm -f ca_key.pub ca_key.enc
	@echo "CA key material removed. You may now run 'make encrypt-ca-key KMS_KEY_ARN=...'."

# Ensure targets are always run
.PHONY: all build eif eif-amd64 eif-arm64 require-ca-files test test-coverage clean clean-ca-key encrypt-ca-key

