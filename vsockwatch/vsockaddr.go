// Package vsockwatch implements the detective control described in
// docs/vsock-connect-detection.md: alerting on any AF_VSOCK connect() to the
// enclave from a process other than the known-good ssh-cert-api. It does not
// close the underlying gap (SIGN-1 in docs/THREAT-MODEL.md) — a compromised
// host can still disable this watcher — it makes exploitation observable.
package vsockwatch

import (
	"encoding/binary"
	"fmt"

	"github.com/pkilar/cerberus/constants"
)

// afVSock is the Linux socket address family for VSOCK (AF_VSOCK). It is not
// exposed via the linux/vm_sockets.h UAPI header (family constants live in
// glibc's sys/socket.h instead), but the value is a stable kernel UAPI
// constant unchanged since VSOCK was introduced.
const afVSock = 40

// sockaddrVMSize is sizeof(struct sockaddr_vm) on Linux: 2-byte svm_family +
// 2-byte svm_reserved1 + 4-byte svm_port + 4-byte svm_cid + 1-byte svm_flags +
// padding to sizeof(struct sockaddr) (16 bytes). See
// /usr/include/linux/vm_sockets.h. The struct is copied from the connecting
// process's own userspace argument to connect(2), so decoding it needs no
// kernel-internal (BTF/CO-RE) knowledge — only this fixed, stable UAPI layout.
const sockaddrVMSize = 16

// VMAddr is the decoded form of a struct sockaddr_vm.
type VMAddr struct {
	Family uint16
	Port   uint32
	CID    uint32
}

// DecodeSockaddrVM parses the first sockaddrVMSize bytes of b as a struct
// sockaddr_vm (native byte order — this only ever runs on the same
// architecture that captured the bytes, whether via eBPF ring buffer or an
// auditd SOCKADDR hex field). It returns an error if b is too short.
func DecodeSockaddrVM(b []byte) (VMAddr, error) {
	if len(b) < sockaddrVMSize {
		return VMAddr{}, fmt.Errorf("vsockwatch: sockaddr_vm needs %d bytes, got %d", sockaddrVMSize, len(b))
	}
	return VMAddr{
		Family: binary.NativeEndian.Uint16(b[0:2]),
		// bytes 2:4 are svm_reserved1, skipped
		Port: binary.NativeEndian.Uint32(b[4:8]),
		CID:  binary.NativeEndian.Uint32(b[8:12]),
		// svm_flags + padding, unused
	}, nil
}

// EnclaveVMAddr returns the VMAddr representing "a connection to the
// Cerberus enclave" — used by detectors (like the eBPF path) that have
// already confirmed the (CID, port) match by construction and just need a
// VMAddr value for Event.Addr / IsEnclaveTarget's defensive check.
func EnclaveVMAddr() VMAddr {
	return VMAddr{Family: afVSock, CID: uint32(constants.EnclaveCID), Port: uint32(constants.EnclaveListeningPort)}
}

// IsEnclaveTarget reports whether addr is a connection to the Cerberus
// enclave's VSOCK listener: AF_VSOCK, the enclave's CID, and its signing
// port. These are the same constants ssh-cert-api itself dials
// (constants.EnclaveCID, constants.EnclaveListeningPort) — kept as the single
// source of truth so the watcher and the API can never silently drift apart
// on what "the enclave" means.
func (a VMAddr) IsEnclaveTarget() bool {
	return a.Family == afVSock &&
		a.CID == uint32(constants.EnclaveCID) &&
		a.Port == uint32(constants.EnclaveListeningPort)
}
