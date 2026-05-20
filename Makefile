# Root Makefile for Cerberus SSH Certificate Authority

# Modules to iterate over for cross-cutting commands (upgrade-deps, etc.).
# This list mirrors the matrix in .github/workflows/go.yml — keep it in sync
# when adding a new go.mod.
GO_MODULES := . ssh-cert-api ssh-cert-signer

# Default target
all: build

# Build both services
build:
	@echo "Building ssh-cert-api..."
	$(MAKE) -C ssh-cert-api build
	@echo "Building ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer build

# Build the stress-testing CLI (cerberus-stress)
stress:
	@echo "Building cerberus-stress..."
	@mkdir -p bin
	go build -o bin/cerberus-stress ./cmd/cerberus-stress
	@echo "  -> bin/cerberus-stress"

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

# Upgrade direct Go dependencies in every module to their latest minor/patch
# release, then tidy. Runs per-module because there is no go.work file and
# each go.mod pins its own dependency set. This is a deliberately manual
# operation — Dependabot already handles routine bumps PR-by-PR; use this
# for periodic sweeps or after a security advisory.
#
# After running:
#   1. Review the go.mod/go.sum diff in each module.
#   2. Run `make test` (and ideally `go test -race ./...` per module).
#   3. Commit per-module to keep the bump reviewable.
#
# Use `make upgrade-deps-patch` for patch-only bumps (safer; never crosses
# a minor version boundary).
upgrade-deps:
	@for mod in $(GO_MODULES); do \
		echo "==> Upgrading dependencies in $$mod"; \
		(cd $$mod && go get -u ./... && go mod tidy) || exit 1; \
	done
	@echo
	@echo "Done. Review the diff, run 'make test', then commit per module."

upgrade-deps-patch:
	@for mod in $(GO_MODULES); do \
		echo "==> Upgrading dependencies (patch only) in $$mod"; \
		(cd $$mod && go get -u=patch ./... && go mod tidy) || exit 1; \
	done
	@echo
	@echo "Done. Review the diff, run 'make test', then commit per module."

# Clean all build artifacts
clean:
	@echo "Cleaning ssh-cert-api..."
	$(MAKE) -C ssh-cert-api clean
	@echo "Cleaning ssh-cert-signer..."
	$(MAKE) -C ssh-cert-signer clean
	@echo "Cleaning integration test artifacts..."
	rm -f integration-coverage.out integration-coverage.html

# Build the enclave image files for both architectures
eif:
	@echo "Building Enclave Image Files for both architectures..."
	$(MAKE) -C ssh-cert-signer eif

# Build EIF for specific architectures
eif-amd64:
	@echo "Building AMD64 Enclave Image File..."
	$(MAKE) -C ssh-cert-signer eif-amd64

eif-arm64:
	@echo "Building ARM64 Enclave Image File..."
	$(MAKE) -C ssh-cert-signer eif-arm64

# Run the API service locally
run-api:
	@echo "Running ssh-cert-api locally..."
	$(MAKE) -C ssh-cert-api run

# Run the signer service in a Nitro enclave with debug mode
# Usage: make run-enclave-debug [ARCH=amd64|arm64]
run-enclave-debug:
	@echo "Running ssh-cert-signer in Nitro enclave (debug mode)..."
	@ARCH=$${ARCH:-amd64}; \
	EIF_FILE="ssh-cert-signer/ssh-cert-signer-$$ARCH.eif"; \
	if [ ! -f "$$EIF_FILE" ]; then \
		echo "Enclave Image File ($$EIF_FILE) not found. Building it first..."; \
		$(MAKE) eif-$$ARCH; \
	fi; \
	echo "Using EIF file: $$EIF_FILE"
	@# Check AWS environment variables
	@if [ -z "$(AWS_REGION)" ]; then \
		echo "AWS_REGION not set, will use default: us-east-1"; \
	else \
		echo "Using AWS region: $(AWS_REGION)"; \
	fi
	@echo "Checking AWS credentials..."
	@aws sts get-caller-identity || { \
		echo "ERROR: AWS credentials not configured correctly"; \
		echo "Please run 'aws configure' or set up credentials for the enclave"; \
		exit 1; \
	}
	@# Run the enclave with debug mode enabled
	@ARCH=$${ARCH:-amd64}; \
	EIF_FILE="ssh-cert-signer/ssh-cert-signer-$$ARCH.eif"; \
	nitro-cli run-enclave \
		--cpu-count 1 \
		--memory 1024 \
		--eif-path "$$EIF_FILE" \
		--enclave-cid 16 \
		--debug-mode \
		--attach-console

.PHONY: all build stress test test-coverage upgrade-deps upgrade-deps-patch clean eif eif-amd64 eif-arm64 run-api run-enclave-debug