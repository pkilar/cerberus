// Package constants defines the VSOCK CIDs and port numbers used for
// communication between the ssh-cert-api host service and the ssh-cert-signer
// enclave. These values are fixed by the deployment topology; changing them
// requires a coordinated update on both sides.
package constants

// Context identifier for the enclave. This value must match the value used with `nitro-cli run-enclave`.
const EnclaveCID = 16

// Port the enclave listens on.
// Port 5000 is used here; any unused port above 1024 is fine.
const EnclaveListeningPort = 5000
