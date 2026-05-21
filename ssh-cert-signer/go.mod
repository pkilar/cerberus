module ssh-cert-signer

go 1.26.0

toolchain go1.26.3

require (
	cerberus v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go-v2 v1.41.7
	github.com/aws/aws-sdk-go-v2/config v1.32.17
	github.com/aws/aws-sdk-go-v2/credentials v1.19.16
	github.com/aws/aws-sdk-go-v2/service/kms v1.51.1
	github.com/edgebitio/nitro-enclaves-sdk-go v1.0.0
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9
	github.com/mdlayher/vsock v1.2.1
	golang.org/x/crypto v0.51.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.1 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace cerberus => ../

replace github.com/edgebitio/nitro-enclaves-sdk-go => github.com/pkilar/nitro-enclaves-sdk-go v1.0.1-0.20260521032308-6819b7df8e4d
