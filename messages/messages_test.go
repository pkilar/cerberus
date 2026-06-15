package messages

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestSshSigningRequest_JSON(t *testing.T) {
	t.Parallel()
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
			"environment@example.com":     "production",
			"requesting_user@example.com": "admin@example.com",
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
	if !slices.Equal(decoded.Principals, req.Principals) {
		t.Errorf("Principals = %v, want %v", decoded.Principals, req.Principals)
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
	t.Parallel()
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
	t.Parallel()
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
	if decoded.BeginKeyLoad != nil {
		t.Error("expected BeginKeyLoad to be nil")
	}
}

func TestResponse_JSON(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestBeginKeyLoad_JSON(t *testing.T) {
	t.Parallel()
	req := Request{BeginKeyLoad: &BeginKeyLoadRequest{}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if decodedReq.BeginKeyLoad == nil {
		t.Fatal("expected BeginKeyLoad to be non-nil")
	}

	resp := Response{BeginKeyLoad: &BeginKeyLoadResponse{
		AttestationDocument: []byte("doc-bytes"),
		CiphertextBlob:      []byte("ciphertext"),
	}}
	rdata, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decodedResp Response
	if err := json.Unmarshal(rdata, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decodedResp.BeginKeyLoad == nil {
		t.Fatal("expected BeginKeyLoad response to be non-nil")
	}
	if string(decodedResp.BeginKeyLoad.AttestationDocument) != "doc-bytes" {
		t.Errorf("AttestationDocument round-trip mismatch: %q", decodedResp.BeginKeyLoad.AttestationDocument)
	}
	if string(decodedResp.BeginKeyLoad.CiphertextBlob) != "ciphertext" {
		t.Errorf("CiphertextBlob round-trip mismatch: %q", decodedResp.BeginKeyLoad.CiphertextBlob)
	}
	if decodedResp.BeginKeyLoad.Loaded {
		t.Error("Loaded should be false")
	}

	// Loaded-only (development) shape must omit the byte fields.
	loaded, err := json.Marshal(Response{BeginKeyLoad: &BeginKeyLoadResponse{Loaded: true}})
	if err != nil {
		t.Fatalf("marshal loaded: %v", err)
	}
	if strings.Contains(string(loaded), "attestationDocument") || strings.Contains(string(loaded), "ciphertextBlob") {
		t.Errorf("loaded response should omit empty byte fields, got %s", loaded)
	}
}

func TestCompleteKeyLoad_JSON(t *testing.T) {
	t.Parallel()
	req := Request{CompleteKeyLoad: &CompleteKeyLoadRequest{CiphertextForRecipient: []byte("cms-envelope")}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decodedReq Request
	if err := json.Unmarshal(data, &decodedReq); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if decodedReq.CompleteKeyLoad == nil || string(decodedReq.CompleteKeyLoad.CiphertextForRecipient) != "cms-envelope" {
		t.Fatalf("CompleteKeyLoad round-trip mismatch: %+v", decodedReq.CompleteKeyLoad)
	}

	resp := Response{CompleteKeyLoad: &CompleteKeyLoadResponse{Success: true}}
	rdata, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var decodedResp Response
	if err := json.Unmarshal(rdata, &decodedResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if decodedResp.CompleteKeyLoad == nil || !decodedResp.CompleteKeyLoad.Success {
		t.Fatalf("CompleteKeyLoad response round-trip mismatch: %+v", decodedResp.CompleteKeyLoad)
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
			"environment@example.com": "test",
		},
	}

	for b.Loop() {
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
			"environment@example.com": "test",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		b.Fatalf("failed to marshal request: %v", err)
	}

	for b.Loop() {
		var decoded EnclaveSigningRequest
		err = json.Unmarshal(data, &decoded)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}
