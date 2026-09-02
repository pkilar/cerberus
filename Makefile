# Root Makefile for Cerberus SSH Certificate Authority

# Modules to iterate over for cross-cutting commands (upgrade-deps, etc.).
# This list mirrors the matrix in .github/workflows/go.yml — keep it in sync
# when adding a new go.mod.
GO_MODULES := . ssh-cert-api ssh-cert-signer

# Version stamped into each binary's -V flag output; single source of truth is
# the top-level VERSION file.
VERSION := $(shell cat VERSION)
LDFLAGS_VERSION = -ldflags="-X github.com/pkilar/cerberus/version.Version=$(VERSION)"

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
	go build $(LDFLAGS_VERSION) -o bin/cerberus-stress ./cmd/cerberus-stress
	@echo "  -> bin/cerberus-stress"

# Build the vsock-connect detective control (docs/vsock-connect-detection.md).
# CGO_ENABLED=0: the eBPF object is a prebuilt, architecture-portable blob
# embedded via go:embed (vsockwatch/ebpf/src/vsock_connect.bpf.o) — see
# vsock-watch-bpf below to regenerate it from source.
vsock-watch:
	@echo "Building cerberus-vsock-watch..."
	@mkdir -p bin
	CGO_ENABLED=0 go build $(LDFLAGS_VERSION) -o bin/cerberus-vsock-watch ./cmd/cerberus-vsock-watch
	@echo "  -> bin/cerberus-vsock-watch"

# Regenerate vsockwatch/ebpf/src/vsock_connect.bpf.o from source. Requires
# clang with a BPF target (any recent clang) and the host's C library UAPI
# headers (linux/bpf.h, linux/types.h, linux/vm_sockets.h) — no libbpf-dev,
# no kernel BTF/vmlinux.h, no bpftool: see vsock_connect.c's header comment
# for why this program deliberately avoids CO-RE. The resulting object is
# eBPF bytecode (a virtual ISA), so it is portable across host architectures
# (x86_64/aarch64) without a separate build per arch — but it has NOT been
# load-tested against a live kernel as part of this change; see
# docs/vsock-connect-detection.md §6 before deploying a regenerated object.
vsock-watch-bpf:
	@echo "Regenerating vsockwatch/ebpf/src/vsock_connect.bpf.o..."
	cd vsockwatch/ebpf/src && clang -target bpf -O2 -g -Wall -Wextra \
		$$(test -d /usr/include/$$(uname -m)-linux-gnu && echo -I/usr/include/$$(uname -m)-linux-gnu) \
		-c vsock_connect.c -o vsock_connect.bpf.o
	@echo "  -> vsockwatch/ebpf/src/vsock_connect.bpf.o (verify with: go test ./vsockwatch/ebpf/...)"

# Regenerate vsockwatch/ebpf/src/vsock_lsm.bpf.o from source — the opt-in
# preventive LSM gate (docs/vsock-connect-detection.md §4.6), a SEPARATE
# object from vsock_connect.bpf.o above (different program type, different
# attach mechanism, independent failure domain). Same minimal-header build as
# vsock-watch-bpf; see vsock_lsm.c's header comment for what's genuinely
# unconfirmed against a live kernel (BTF attach-point naming, parameter type
# compatibility) and MUST be verified on real hardware before enabling
# --lsm-monitor/--lsm-enforce.
vsock-watch-lsm-bpf:
	@echo "Regenerating vsockwatch/ebpf/src/vsock_lsm.bpf.o..."
	cd vsockwatch/ebpf/src && clang -target bpf -O2 -g -Wall -Wextra \
		$$(test -d /usr/include/$$(uname -m)-linux-gnu && echo -I/usr/include/$$(uname -m)-linux-gnu) \
		-c vsock_lsm.c -o vsock_lsm.bpf.o
	@echo "  -> vsockwatch/ebpf/src/vsock_lsm.bpf.o (verify with: go test ./vsockwatch/ebpf/...)"

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

# Build the Enclave Image File for THIS host's architecture. An EIF can only be
# built on hardware of the architecture it targets -- nitro-cli assembles it
# around blobs that exist only for the host arch -- so this no longer attempts
# both and fails on the foreign half.
eif:
	@echo "Building the Enclave Image File for this host's architecture..."
	$(MAKE) -C ssh-cert-signer eif

# Force a specific architecture. Off-native these refuse with an explanation
# rather than failing inside nitro-cli.
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

# --- Multi-distribution package builds -------------------------------------
# Build packages for a distribution you are not running, in a clean container.
# `make package-targets` lists what is available; packaging/targets.tsv is the
# manifest. The container supplies the distribution, this machine supplies the
# architecture -- nothing is cross-compiled or emulated.
#
# Builds COMMITTED state (git archive HEAD), so commit before running.

package-targets:
	@./packaging/targets.sh list

# make package-fedora / package-rhel9 / package-debian-bookworm / ...
package-%:
	./packaging/build-in-container.sh $*

# make lint-package-fedora / ...  builds and lints in one pass
lint-package-%:
	./packaging/build-in-container.sh $* --lint

# Every target in the manifest, sequentially. Stops at the first failure.
packages-all:
	@for t in $$(./packaging/targets.sh list); do \
		echo "==> $$t"; ./packaging/build-in-container.sh $$t --lint || exit 1; \
	done

.PHONY: all build stress test test-coverage upgrade-deps upgrade-deps-patch clean eif eif-amd64 eif-arm64 run-api run-enclave-debug package-targets packages-all