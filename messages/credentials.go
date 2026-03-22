package messages

import "fmt"

// Credentials struct as returned by
// http://169.254.169.254/latest/meta-data/iam/security-credentials/<iam role>
//
// This struct should probably exist in the AWS SDK.
type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// truncate returns the first n characters of s followed by "***" if s is longer
// than n, or "***" if s is shorter than or equal to n.
func truncate(s string, n int) string {
	if len(s) <= n {
		return "***"
	}
	return s[:n] + "***"
}

// Redacted returns a copy of Credentials with SecretAccessKey and Token
// truncated to prevent accidental exposure in logs.
func (c Credentials) Redacted() Credentials {
	return Credentials{
		AccessKeyId:     c.AccessKeyId,
		SecretAccessKey: truncate(c.SecretAccessKey, 4),
		Token:           truncate(c.Token, 4),
	}
}

// String implements fmt.Stringer to prevent accidental logging of secrets.
func (c Credentials) String() string {
	return fmt.Sprintf("{AccessKeyId: %s, SecretAccessKey: %s, Token: %s}",
		c.AccessKeyId, truncate(c.SecretAccessKey, 4), truncate(c.Token, 4))
}
