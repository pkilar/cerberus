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

# Make the binary executable
RUN chmod +x ssh-cert-signer

# Define the command that the enclave will execute upon startup.
# This runs our signing service.
CMD ["/app/ssh-cert-signer"]
