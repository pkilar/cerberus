#!/usr/bin/env bash
# Wrapper script to manage the Cerberus signer Nitro Enclave.
# Used by the cerberus-signer systemd service.
set -euo pipefail

# Source configuration defaults.
ARCH="${ARCH:-amd64}"
EIF_PATH="${EIF_PATH:-/usr/share/cerberus/ssh-cert-signer-${ARCH}.eif}"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
ENCLAVE_CPU_COUNT="${ENCLAVE_CPU_COUNT:-1}"
ENCLAVE_MEMORY_MIB="${ENCLAVE_MEMORY_MIB:-1024}"
ENCLAVE_DEBUG="${ENCLAVE_DEBUG:-false}"

get_enclave_id() {
    nitro-cli describe-enclaves \
        | grep -o '"EnclaveID"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | head -1 \
        | sed 's/.*"EnclaveID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

start() {
    if [ ! -f "${EIF_PATH}" ]; then
        echo "ERROR: EIF file not found: ${EIF_PATH}" >&2
        exit 1
    fi

    # Check if an enclave is already running.
    local existing_id
    existing_id=$(get_enclave_id)
    if [ -n "${existing_id}" ]; then
        echo "Enclave already running: ${existing_id}"
        return 0
    fi

    local debug_flags=""
    if [ "${ENCLAVE_DEBUG}" = "true" ]; then
        debug_flags="--debug-mode"
    fi

    echo "Starting enclave from ${EIF_PATH}..."
    nitro-cli run-enclave \
        --cpu-count "${ENCLAVE_CPU_COUNT}" \
        --memory "${ENCLAVE_MEMORY_MIB}" \
        --eif-path "${EIF_PATH}" \
        --enclave-cid "${ENCLAVE_CID}" \
        ${debug_flags}

    echo "Enclave started successfully."
}

stop() {
    local enclave_id
    enclave_id=$(get_enclave_id)
    if [ -z "${enclave_id}" ]; then
        echo "No enclave running."
        return 0
    fi

    echo "Terminating enclave ${enclave_id}..."
    nitro-cli terminate-enclave --enclave-id "${enclave_id}"
    echo "Enclave terminated."
}

restart() {
    stop
    start
}

status() {
    nitro-cli describe-enclaves
}

case "${1:-}" in
    start)   start   ;;
    stop)    stop    ;;
    restart) restart ;;
    status)  status  ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}" >&2
        exit 1
        ;;
esac
