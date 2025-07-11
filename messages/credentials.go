package messages

// Credentials struct as returned by
// http://169.254.169.254/latest/meta-data/iam/security-credentials/<iam role>
//
// This struct should probably exist in the AWS SDK.
type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}
