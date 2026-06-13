module github.com/pkilar/cerberus/ssh-cert-api

go 1.26.0

toolchain go1.26.4

require (
	github.com/aws/aws-sdk-go-v2/config v1.32.23
	github.com/aws/aws-sdk-go-v2/credentials v1.19.22
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.28
	github.com/casbin/casbin/v2 v2.135.0
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/jcmturner/gokrb5/v8 v8.4.4
	github.com/mdlayher/vsock v1.3.0
	github.com/pkilar/cerberus v0.0.0-20260528230348-7a565fc38d87
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	go.uber.org/goleak v1.3.0
	golang.org/x/sync v0.21.0
	golang.org/x/time v0.15.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.28 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.28 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.31.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.43.2 // indirect
	github.com/aws/smithy-go v1.27.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/casbin/govaluate v1.10.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/socket v0.6.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/pkilar/cerberus => ../
