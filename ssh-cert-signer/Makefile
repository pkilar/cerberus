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
EIF_NAME=ssh-cert-signer.eif

# Default target executed when you just run `make`
all: eif

# Target to build the Go binary specifically for the enclave environment.
# Nitro Enclaves run on linux/amd64.
build:
	@echo "Building Go binary for enclave environment (GOOS=linux, GOARCH=amd64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) -v -o $(BINARY_NAME) .

# Target to package the compiled binary into a deployable Enclave Image File (.eif).
# This uses Docker to create a root filesystem with the binary and its dependencies.
# The --docker-uri specifies the base image for the enclave's filesystem.
# The --docker-dir specifies the context for the Docker build.
eif: build
	@echo "Building Enclave Image File ($(EIF_NAME))..."
	$(NITRO_CLI) build-enclave --docker-uri amazonlinux:latest --docker-dir . --output-file $(EIF_NAME)
	@echo "Successfully created $(EIF_NAME). This is the artifact to deploy to the enclave."

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

# Clean all build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME) $(EIF_NAME) coverage.out coverage.html
	$(GOCLEAN)

# Ensure targets are always run
.PHONY: all build eif test test-coverage clean

