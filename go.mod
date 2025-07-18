module cerberus

go 1.23.0

toolchain go1.23.3

require golang.org/x/crypto v0.39.0

replace ssh-cert-api => ./ssh-cert-api

require golang.org/x/sys v0.33.0 // indirect

replace github.com/aws/aws-sdk-go-v2/service/kms => github.com/edgebitio/nitro-enclaves-sdk-go/kms v0.0.0-20221110205443-8a5476ff3cc2
