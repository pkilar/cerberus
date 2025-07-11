module cerberus

go 1.23.0

toolchain go1.23.3

require (
	github.com/jcmturner/gokrb5/v8 v8.4.4
	golang.org/x/crypto v0.39.0
	ssh-cert-api v0.0.0-00010101000000-000000000000
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
	github.com/mdlayher/vsock v1.2.1 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2
