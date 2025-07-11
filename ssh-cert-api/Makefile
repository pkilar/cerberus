# Makefile for the ssh-cert-api service

# Go build parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOTIDY=$(GOCMD) mod tidy

# Output binary name
BINARY_NAME=ssh-cert-api
BINARY_PATH=./$(BINARY_NAME)

# Build flags for stripped release binary
LDFLAGS_STRIP = -ldflags="-s -w"

# Default target executed when you just run `make`
all: build

# Build the application binary
build:
	@echo "Building $(BINARY_NAME)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS_STRIP) -v -o $(BINARY_PATH).amd64 ./cmd/ssh-cert-api
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS_STRIP) -v -o $(BINARY_PATH).arm64 ./cmd/ssh-cert-api

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_PATH) cert.pem key.pem
	$(GOCLEAN)

# Run the application for local development.
# Automatically generates TLS certs if they are missing.
run: build
	@if [ ! -f cert.pem ] || [ ! -f key.pem ]; then \
		echo "TLS certificates not found. Generating new ones..."; \
		$(MAKE) tls-certs; \
	fi
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_PATH)

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

# Convenience target to generate self-signed TLS certs for local development
tls-certs:
	@echo "Generating self-signed TLS certificates (cert.pem, key.pem)..."
	@go run $$(go env GOROOT)/src/crypto/tls/generate_cert.go --host localhost

# Ensure targets are always run, even if a file with the same name exists
.PHONY: all build clean run test test-coverage tls-certs
