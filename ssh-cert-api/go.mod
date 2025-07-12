module ssh-cert-api

go 1.23.0

toolchain go1.23.10

require (
	cerberus v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go-v2/config v1.29.17
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.32
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mdlayher/vsock v1.2.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.36.5 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.70 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.34.0 // indirect
	github.com/aws/smithy-go v1.22.4 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
)

replace cerberus => ../
