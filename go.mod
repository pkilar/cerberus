module cerberus

go 1.26.0

toolchain go1.26.2

require golang.org/x/crypto v0.50.0

replace ssh-cert-api => ./ssh-cert-api

require golang.org/x/sys v0.43.0 // indirect

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2

// Dev tools (gosec, govulncheck, golangci-lint) are intentionally NOT tracked
// via Go 1.24+ tool directives here. Their transitive deps balloon go.sum
// by 40+ entries, widening the supply-chain surface of a signing service.
// CI installs pinned versions via `go install X@vY.Z` instead — see
// .github/workflows/go.yml.
