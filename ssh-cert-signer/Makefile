# Makefile for the ssh-cert-signer enclave service

# Go build parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test

# Nitro Enclave CLI tool
# This Makefile assumes 'nitro-cli' is installed and in the system's PATH.
NITRO_CLI=nitro-cli

# Output names for the binary and the final Enclave Image File
BINARY_NAME=ssh-cert-signer
EIF_NAME_AMD64=ssh-cert-signer-amd64.eif
EIF_NAME_ARM64=ssh-cert-signer-arm64.eif

# Build flags for stripped release binary
LDFLAGS_STRIP = -ldflags="-s -w"

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

eif-amd64: build
	@echo "Building AMD64 Enclave Image File ($(EIF_NAME_AMD64))..."
	docker buildx build --platform linux/amd64 --build-arg TARGETARCH=amd64 -t ssh-cert-signer:amd64 .
	$(NITRO_CLI) build-enclave --docker-uri ssh-cert-signer:amd64 --output-file $(EIF_NAME_AMD64) | tee /dev/stderr | \
		python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('Measurements',{}); \
		json.dump({'Architecture':'amd64','EIF':'$(EIF_NAME_AMD64)','PCR0':m.get('PCR0',''),'PCR1':m.get('PCR1',''),'PCR2':m.get('PCR2','')}, \
		open('pcr-manifest-amd64.json','w'),indent=2)" || true
	@echo "Successfully created $(EIF_NAME_AMD64)."
	@if [ -f pcr-manifest-amd64.json ]; then echo "PCR manifest: pcr-manifest-amd64.json"; cat pcr-manifest-amd64.json; fi

eif-arm64: build
	@echo "Building ARM64 Enclave Image File ($(EIF_NAME_ARM64))..."
	docker buildx build --platform linux/arm64 --build-arg TARGETARCH=arm64 -t ssh-cert-signer:arm64 .
	$(NITRO_CLI) build-enclave --docker-uri ssh-cert-signer:arm64 --output-file $(EIF_NAME_ARM64) | tee /dev/stderr | \
		python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('Measurements',{}); \
		json.dump({'Architecture':'arm64','EIF':'$(EIF_NAME_ARM64)','PCR0':m.get('PCR0',''),'PCR1':m.get('PCR1',''),'PCR2':m.get('PCR2','')}, \
		open('pcr-manifest-arm64.json','w'),indent=2)" || true
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

# Create and encrypt SSH CA key with KMS
# Usage: make encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:region:account:key/key-id
# This will:
# 1. Generate a new SSH CA private key
# 2. Encrypt it with the specified KMS key
# 3. Save the encrypted key to ca_key.enc
# 4. Remove the original unencrypted key
encrypt-ca-key:
	@if [ -z "$(KMS_KEY_ARN)" ]; then \
		echo "Error: KMS_KEY_ARN parameter is required"; \
		echo "Usage: make encrypt-ca-key KMS_KEY_ARN=arn:aws:kms:region:account:key/key-id"; \
		exit 1; \
	fi
	@echo "Generating SSH CA private key..."
	ssh-keygen -t rsa -b 4096 -f ca_key -N "" -C "SSH CA Key for Nitro Enclave"
	@echo "Encrypting CA private key with KMS..."
	aws kms encrypt --key-id $(KMS_KEY_ARN) --plaintext fileb://ca_key --output text --query CiphertextBlob | base64 -d > ca_key.enc
	@echo "Removing unencrypted CA private key..."
	rm -f ca_key
	@echo "Encrypted CA key saved to ca_key.enc"
	@echo "Public key saved to ca_key.pub (keep this for SSH certificate validation)"

# Clean all build artifacts and generated keys
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME).amd64 $(BINARY_NAME).arm64 $(EIF_NAME_AMD64) $(EIF_NAME_ARM64) coverage.out coverage.html ca_key ca_key.pub ca_key.enc pcr-manifest-amd64.json pcr-manifest-arm64.json
	$(GOCLEAN)

# Ensure targets are always run
.PHONY: all build eif eif-amd64 eif-arm64 test test-coverage clean encrypt-ca-key

