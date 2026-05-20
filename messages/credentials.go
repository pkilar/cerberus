package messages

import (
	"encoding/json"
	"fmt"
)

// Credentials struct as returned by
// http://169.254.169.254/latest/meta-data/iam/security-credentials/<iam role>
//
// This struct should probably exist in the AWS SDK.
type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// redact returns a fixed placeholder for any non-empty secret, leaking no
// material. Empty strings remain empty so callers can distinguish "unset"
// from "set but redacted".
func redact(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

// Redacted returns a copy of Credentials with SecretAccessKey and Token
// replaced by a fixed placeholder to prevent accidental exposure in logs.
// AccessKeyId is left as-is — it identifies the role, not the secret.
func (c Credentials) Redacted() Credentials {
	return Credentials{
		AccessKeyId:     c.AccessKeyId,
		SecretAccessKey: redact(c.SecretAccessKey),
		Token:           redact(c.Token),
	}
}

// String implements fmt.Stringer to prevent accidental logging of secrets.
func (c Credentials) String() string {
	return fmt.Sprintf("{AccessKeyId: %s, SecretAccessKey: %s, Token: %s}",
		c.AccessKeyId, redact(c.SecretAccessKey), redact(c.Token))
}

// RedactedJSON returns r marshalled to JSON with sensitive fields replaced by
// placeholders. Use this — never bare json.Marshal — when logging request
// bodies that may cross the LoadKeySigner path, which carries AWS credentials.
func RedactedJSON(r Request) string {
	if r.LoadKeySigner != nil {
		red := *r.LoadKeySigner
		red.Credentials = red.Credentials.Redacted()
		r.LoadKeySigner = &red
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf("<marshal error: %v>", err)
	}
	return string(b)
}
