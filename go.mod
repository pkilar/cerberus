module cerberus

go 1.26.0

toolchain go1.26.3

require (
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mdlayher/vsock v1.2.1
	golang.org/x/crypto v0.51.0
)

replace ssh-cert-api => ./ssh-cert-api

require (
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2

// Dev tools (gosec, govulncheck, golangci-lint) are intentionally NOT tracked
// via Go 1.24+ tool directives here. Their transitive deps balloon go.sum
// by 40+ entries, widening the supply-chain surface of a signing service.
// CI installs pinned versions via `go install X@vY.Z` instead — see
// .github/workflows/go.yml.
