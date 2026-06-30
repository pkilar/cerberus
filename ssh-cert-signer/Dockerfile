# Use a minimal base image for the enclave's root filesystem.
# amazonlinux is a good choice as it's lightweight and standard for AWS.
FROM amazonlinux:latest

# Set the working directory inside the container.
WORKDIR /app

# Copy the compiled Go binary from the build context (the local directory
# where the 'nitro-cli build-enclave' command is run) into the image.
# The architecture-specific binary is determined by the build argument.
ARG TARGETARCH
COPY ssh-cert-signer.${TARGETARCH} ssh-cert-signer
COPY ca_key.enc ca_key.enc

# Bake the CA public key into the image and point the signer at it. Both the
# file and CA_PUBLIC_KEY_PATH become part of the EIF, so they are covered by
# PCR0 — a host cannot tamper with the pin without changing the measurement. On
# startup the enclave verifies the decrypted CA key's public half against this
# pin and refuses to load on mismatch, closing first-load ciphertext
# substitution (see ssh-cert-signer/internal/handlers parseCASigner and
# docs/kms-attestation-policy.md). The pin is active by default in packaged
# builds; the enclave code itself still treats it as opt-in (an EIF built
# without ca_key.pub and without this ENV logs loadkey.ca_pubkey.unpinned and
# proceeds), so to opt out, remove the COPY + ENV below.
COPY ca_key.pub ca_key.pub
ENV CA_PUBLIC_KEY_PATH=/app/ca_key.pub

# Make the binary executable
RUN chmod +x ssh-cert-signer

# Define the command that the enclave will execute upon startup.
# This runs our signing service.
CMD ["/app/ssh-cert-signer"]
