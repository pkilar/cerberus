package constants

// Context identifier for the parent instance. This is always 3.
const INSTANCE_CID = 3

// Port the parent instance listens on and forward data to KMS.
const INSTANCE_LISTENING_PORT = 8000

// Context identifier for the enclave. This value must match the value used with `nitro-cli run-enclave`.
const ENCLAVE_CID = 16

// Port the enclave listens on.
// Port 5000 is used here; any unused port above 1024 is fine.
const ENCLAVE_LISTENING_PORT = 5000
