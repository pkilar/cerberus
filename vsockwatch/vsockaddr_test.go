package vsockwatch

import (
	"encoding/binary"
	"testing"
)

func encodeSockaddrVM(family uint16, port, cid uint32) []byte {
	b := make([]byte, sockaddrVMSize)
	binary.NativeEndian.PutUint16(b[0:2], family)
	binary.NativeEndian.PutUint32(b[4:8], port)
	binary.NativeEndian.PutUint32(b[8:12], cid)
	return b
}

func TestDecodeSockaddrVM(t *testing.T) {
	b := encodeSockaddrVM(40, 5000, 16)
	addr, err := DecodeSockaddrVM(b)
	if err != nil {
		t.Fatalf("DecodeSockaddrVM: %v", err)
	}
	if addr.Family != 40 || addr.Port != 5000 || addr.CID != 16 {
		t.Errorf("got %+v, want family=40 port=5000 cid=16", addr)
	}
}

func TestDecodeSockaddrVM_TooShort(t *testing.T) {
	if _, err := DecodeSockaddrVM(make([]byte, sockaddrVMSize-1)); err == nil {
		t.Fatal("expected an error for a too-short buffer")
	}
}

func TestIsEnclaveTarget(t *testing.T) {
	tests := []struct {
		name string
		addr VMAddr
		want bool
	}{
		{"exact match", VMAddr{Family: 40, CID: 16, Port: 5000}, true},
		{"wrong family (AF_INET)", VMAddr{Family: 2, CID: 16, Port: 5000}, false},
		{"wrong cid", VMAddr{Family: 40, CID: 17, Port: 5000}, false},
		{"wrong port", VMAddr{Family: 40, CID: 16, Port: 5001}, false},
		{"loopback cid (host, not enclave)", VMAddr{Family: 40, CID: 1, Port: 5000}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.IsEnclaveTarget(); got != tt.want {
				t.Errorf("IsEnclaveTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnclaveVMAddr_IsEnclaveTarget(t *testing.T) {
	if !EnclaveVMAddr().IsEnclaveTarget() {
		t.Error("EnclaveVMAddr() must always satisfy IsEnclaveTarget()")
	}
}
