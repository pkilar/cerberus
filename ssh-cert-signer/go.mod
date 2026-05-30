module github.com/pkilar/cerberus/ssh-cert-signer

go 1.26.0

toolchain go1.26.3

require (
	github.com/aws/aws-sdk-go-v2 v1.41.9
	github.com/aws/aws-sdk-go-v2/config v1.32.20
	github.com/aws/aws-sdk-go-v2/credentials v1.19.19
	github.com/aws/aws-sdk-go-v2/service/kms v1.52.2
	github.com/hf/nsm v0.0.0-20220930140112-cd181bd646b9
	github.com/mdlayher/vsock v1.3.0
	github.com/pkilar/cerberus v0.0.0-20260528230348-7a565fc38d87
	github.com/pkilar/nitro-enclaves-sdk-go v1.1.0
	golang.org/x/crypto v0.52.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.3 // indirect
	github.com/aws/smithy-go v1.26.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/mdlayher/socket v0.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/pkilar/cerberus => ../
