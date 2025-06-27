# Root Makefile for Cerberus SSH Certificate Authority

# Default target
all: build

# Build both services
build:
	@echo "Building ssh-cert-api..."
	$(MAKE) -C ssh-cert-api build
	@echo "Building ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer build

# Run all tests
test:
	@echo "Running tests for ssh-cert-api..."
	$(MAKE) -C ssh-cert-api test
	@echo "Running tests for ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer test
	@echo "Running integration tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage for ssh-cert-api..."
	$(MAKE) -C ssh-cert-api test-coverage
	@echo "Running tests with coverage for ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer test-coverage
	@echo "Running integration tests with coverage..."
	go test -v -coverprofile=integration-coverage.out ./...
	go tool cover -html=integration-coverage.out -o integration-coverage.html
	@echo "Integration coverage report generated: integration-coverage.html"

# Clean all build artifacts
clean:
	@echo "Cleaning ssh-cert-api..."
	$(MAKE) -C ssh-cert-api clean
	@echo "Cleaning ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer clean
	@echo "Cleaning integration test artifacts..."
	rm -f integration-coverage.out integration-coverage.html

# Build the enclave image file
eif:
	@echo "Building Enclave Image File..."
	$(MAKE) -C ssh-cert-signer eif

# Run the API service locally
run-api:
	@echo "Running ssh-cert-api locally..."
	$(MAKE) -C ssh-cert-api run

.PHONY: all build test test-coverage clean eif run-api