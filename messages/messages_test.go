package messages

import (
	"encoding/json"
	"testing"
)

func TestSshSigningRequest_JSON(t *testing.T) {
	req := EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "test-key-id",
		Principals: []string{"user1", "user2"},
		Validity:   "24h",
		Permissions: map[string]string{
			"permit-pty":     "",
			"permit-user-rc": "",
		},
		CustomAttributes: map[string]string{
			"environment":     "production",
			"requesting_user": "admin@example.com",
		},
	}

	// Test marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Test unmarshaling
	var decoded EnclaveSigningRequest
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	// Verify all fields
	if decoded.SSHKey != req.SSHKey {
		t.Errorf("expected SSHKey %s, got %s", req.SSHKey, decoded.SSHKey)
	}
	if decoded.KeyID != req.KeyID {
		t.Errorf("expected KeyID %s, got %s", req.KeyID, decoded.KeyID)
	}
	if len(decoded.Principals) != len(req.Principals) {
		t.Errorf("expected %d principals, got %d", len(req.Principals), len(decoded.Principals))
	}
	if decoded.Validity != req.Validity {
		t.Errorf("expected Validity %s, got %s", req.Validity, decoded.Validity)
	}

	// Check maps
	for k, v := range req.Permissions {
		if decoded.Permissions[k] != v {
			t.Errorf("expected permission %s=%s, got %s", k, v, decoded.Permissions[k])
		}
	}
	for k, v := range req.CustomAttributes {
		if decoded.CustomAttributes[k] != v {
			t.Errorf("expected attribute %s=%s, got %s", k, v, decoded.CustomAttributes[k])
		}
	}
}

func TestSshSigningResponse_JSON(t *testing.T) {
	resp := SigningResponse{
		SignedKey: "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAB...",
	}

	// Test marshaling
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	// Test unmarshaling
	var decoded SigningResponse
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decoded.SignedKey != resp.SignedKey {
		t.Errorf("expected SignedKey %s, got %s", resp.SignedKey, decoded.SignedKey)
	}
}

func TestRequest_JSON(t *testing.T) {
	sshReq := EnclaveSigningRequest{
		SSHKey:   "ssh-rsa AAAAB3...",
		KeyID:    "test",
		Validity: "1h",
	}

	req := Request{
		SignSshKey: &sshReq,
	}

	// Test marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Test unmarshaling
	var decoded Request
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	if decoded.SignSshKey == nil {
		t.Error("expected SignSshKey to be non-nil")
	}
	if decoded.SignSshKey.KeyID != sshReq.KeyID {
		t.Errorf("expected KeyID %s, got %s", sshReq.KeyID, decoded.SignSshKey.KeyID)
	}

	// Verify other fields are nil
	if decoded.LoadKeySigner != nil {
		t.Error("expected LoadKeySigner to be nil")
	}
}

func TestResponse_JSON(t *testing.T) {
	sshResp := SigningResponse{
		SignedKey: "ssh-rsa-cert-v01@openssh.com...",
	}

	resp := Response{
		SignSshKey: &sshResp,
	}

	// Test marshaling
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	// Test unmarshaling
	var decoded Response
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decoded.SignSshKey == nil {
		t.Error("expected SignSshKey to be non-nil")
	}
	if decoded.SignSshKey.SignedKey != sshResp.SignedKey {
		t.Errorf("expected SignedKey %s, got %s", sshResp.SignedKey, decoded.SignSshKey.SignedKey)
	}
}

func TestResponse_WithError(t *testing.T) {
	errorMsg := "test error message"
	resp := Response{
		Error: &errorMsg,
	}

	// Test marshaling
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	// Test unmarshaling
	var decoded Response
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if decoded.Error == nil {
		t.Error("expected Error to be non-nil")
	}
	if *decoded.Error != errorMsg {
		t.Errorf("expected Error %s, got %s", errorMsg, *decoded.Error)
	}
}

func TestCredentials_JSON(t *testing.T) {
	creds := Credentials{
		AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Token:           "token123",
	}

	// Test marshaling
	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("failed to marshal credentials: %v", err)
	}

	// Test unmarshaling
	var decoded Credentials
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal credentials: %v", err)
	}

	if decoded.AccessKeyId != creds.AccessKeyId {
		t.Errorf("expected AccessKeyId %s, got %s", creds.AccessKeyId, decoded.AccessKeyId)
	}
	if decoded.SecretAccessKey != creds.SecretAccessKey {
		t.Errorf("expected SecretAccessKey %s, got %s", creds.SecretAccessKey, decoded.SecretAccessKey)
	}
	if decoded.Token != creds.Token {
		t.Errorf("expected Token %s, got %s", creds.Token, decoded.Token)
	}
}

// Benchmark JSON operations
func BenchmarkSshSigningRequest_Marshal(b *testing.B) {
	req := EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "benchmark-key",
		Principals: []string{"user1", "user2"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(req)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}
	}
}

func BenchmarkSshSigningRequest_Unmarshal(b *testing.B) {
	req := EnclaveSigningRequest{
		SSHKey:     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
		KeyID:      "benchmark-key",
		Principals: []string{"user1", "user2"},
		Validity:   "1h",
		Permissions: map[string]string{
			"permit-pty": "",
		},
		CustomAttributes: map[string]string{
			"environment": "test",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		b.Fatalf("failed to marshal request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var decoded EnclaveSigningRequest
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}
