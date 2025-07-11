#!/bin/bash

# test_runner.sh - Test runner script for Cerberus SSH Certificate Authority

set -e

echo "🔐 Cerberus SSH Certificate Authority - Test Suite"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run tests for a specific component
run_component_tests() {
    local component=$1
    local path=$2
    
    print_status "Running tests for $component..."
    
    if [ -d "$path" ]; then
        cd "$path"
        
        # Check if there are any test files
        if ls *_test.go 1> /dev/null 2>&1; then
            echo "  Found test files:"
            ls -la *_test.go | awk '{print "    " $9}'
            
            # Run unit tests
            echo "  Running unit tests..."
            if go test -v -race -cover ./...; then
                print_status "✅ Unit tests passed for $component"
            else
                print_error "❌ Unit tests failed for $component"
                return 1
            fi
            
            # Run benchmarks
            echo "  Running benchmarks..."
            if go test -bench=. -benchmem ./...; then
                print_status "✅ Benchmarks completed for $component"
            else
                print_warning "⚠️  Benchmarks had issues for $component"
            fi
            
        else
            print_warning "No test files found for $component"
        fi
        
        cd - > /dev/null
    else
        print_error "Directory $path does not exist"
        return 1
    fi
}

# Function to check test coverage
check_coverage() {
    local component=$1
    local path=$2
    
    print_status "Checking test coverage for $component..."
    
    if [ -d "$path" ]; then
        cd "$path"
        
        if ls *_test.go 1> /dev/null 2>&1; then
            # Generate coverage report
            go test -coverprofile=coverage.out ./...
            
            # Display coverage summary
            if [ -f coverage.out ]; then
                coverage=$(go tool cover -func=coverage.out | grep "total:" | awk '{print $3}')
                echo "  Coverage: $coverage"
                
                # Generate HTML coverage report
                go tool cover -html=coverage.out -o coverage.html
                print_status "HTML coverage report generated: $path/coverage.html"
                
                # Clean up
                rm -f coverage.out
            fi
        fi
        
        cd - > /dev/null
    fi
}

# Function to run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    
    # Set environment variables for testing
    export ENCLAVE_VSOCK_PORT=5000
    export KERBEROS_KEYTAB_PATH="/tmp/test.keytab"
    export CA_KEY_FILE_PATH="/test/ca-key"
    
    # Run integration tests from root directory
    if [ -f "integration_test.go" ]; then
        echo "  Running integration test suite..."
        if go test -v -tags=integration ./integration_test.go; then
            print_status "✅ Integration tests passed"
        else
            print_warning "⚠️  Integration tests had issues (may require special environment)"
        fi
    else
        print_warning "No integration tests found"
    fi
}

# Function to run security tests
run_security_tests() {
    print_status "Running security analysis..."
    
    # Check for common security issues
    if command -v gosec &> /dev/null; then
        echo "  Running gosec security scanner..."
        gosec ./...
    else
        print_warning "gosec not installed, skipping security scan"
        echo "  Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
    
    # Check for vulnerable dependencies
    if command -v govulncheck &> /dev/null; then
        echo "  Running vulnerability check..."
        govulncheck ./...
    else
        print_warning "govulncheck not installed, skipping vulnerability check"
        echo "  Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
    fi
}

# Function to run linting
run_linting() {
    print_status "Running code linting..."
    
    if command -v golangci-lint &> /dev/null; then
        echo "  Running golangci-lint..."
        golangci-lint run ./...
    else
        print_warning "golangci-lint not installed, skipping linting"
        echo "  Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    fi
}

# Function to validate Go modules
validate_modules() {
    print_status "Validating Go modules..."
    
    for dir in "ssh-cert-api" "ssh-cert-signer"; do
        if [ -d "$dir" ]; then
            cd "$dir"
            echo "  Validating $dir module..."
            
            # Check if go.mod exists
            if [ -f "go.mod" ]; then
                # Verify dependencies
                go mod verify
                
                # Check for unused dependencies
                go mod tidy -diff
                
                print_status "✅ Module validation passed for $dir"
            else
                print_warning "No go.mod found in $dir"
            fi
            
            cd - > /dev/null
        fi
    done
}

# Main test execution
main() {
    print_status "Starting Cerberus test suite..."
    
    # Store original directory
    ORIGINAL_DIR=$(pwd)
    
    # Validate modules first
    validate_modules
    
    echo ""
    print_status "=== UNIT TESTS ==="
    
    # Run tests for each component
    run_component_tests "SSH Certificate API" "ssh-cert-api"
    echo ""
    
    run_component_tests "SSH Certificate Signer" "ssh-cert-signer"
    echo ""
    
    # Check test coverage
    print_status "=== COVERAGE ANALYSIS ==="
    check_coverage "SSH Certificate API" "ssh-cert-api"
    echo ""
    
    check_coverage "SSH Certificate Signer" "ssh-cert-signer"
    echo ""
    
    # Run integration tests
    print_status "=== INTEGRATION TESTS ==="
    run_integration_tests
    echo ""
    
    # Run security tests
    print_status "=== SECURITY ANALYSIS ==="
    run_security_tests
    echo ""
    
    # Run linting
    print_status "=== CODE LINTING ==="
    run_linting
    echo ""
    
    print_status "=== TEST SUMMARY ==="
    echo "Test suite completed!"
    echo ""
    echo "📋 Test Reports Generated:"
    find . -name "coverage.html" -type f | while read -r file; do
        echo "  • $file"
    done
    echo ""
    echo "🔍 To run specific tests:"
    echo "  • API tests:         cd ssh-cert-api && go test -v ./..."
    echo "  • Signer tests:      cd ssh-cert-signer && go test -v ./..."
    echo "  • Integration tests: go test -v ./integration_test.go"
    echo "  • Benchmarks:        go test -bench=. ./..."
    echo ""
    echo "🛡️  Security tools recommended:"
    echo "  • gosec:       go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    echo "  • govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest"
    echo "  • golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    
    # Return to original directory
    cd "$ORIGINAL_DIR"
}

# Handle command line arguments
case "${1:-all}" in
    "api")
        run_component_tests "SSH Certificate API" "ssh-cert-api"
        ;;
    "signer")
        run_component_tests "SSH Certificate Signer" "ssh-cert-signer"
        ;;
    "integration")
        run_integration_tests
        ;;
    "security")
        run_security_tests
        ;;
    "coverage")
        check_coverage "SSH Certificate API" "ssh-cert-api"
        check_coverage "SSH Certificate Signer" "ssh-cert-signer"
        ;;
    "lint")
        run_linting
        ;;
    "all"|*)
        main
        ;;
esac