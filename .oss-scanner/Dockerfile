# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this with the repository as the build context and network access, then analyses the
# finished image offline. Everything the build and the tests need is fetched here.
#
# Cerberus is three Go modules with no go.work: / (shared packages + CLIs), ssh-cert-api/ (host HTTPS
# gateway) and ssh-cert-signer/ (Nitro Enclave signer). Each is built and tested from its own directory.
FROM golang:1.27-trixie
ENV DEBIAN_FRONTEND=noninteractive
# zsh: the cssh client tests run under bash, zsh and sh. jq/curl/ssh/ssh-keygen: called by cssh.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git make zsh jq curl openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Offline after this image is built: never try to download a newer Go toolchain.
ENV GOTOOLCHAIN=local

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module needed to build and test each Go module, and compile the test binaries (with and
# without the race detector) so the build cache is warm for offline use.
RUN set -e; for m in . ssh-cert-api ssh-cert-signer; do \
      (cd "$m" && go mod download && go test -count=1 -run '^$' ./... >/dev/null \
        && go test -race -count=1 -run '^$' ./... >/dev/null); \
    done

# Unstripped binaries (DWARF and frame pointers are Go defaults) in /src/bin. The Makefile strips them, so
# build directly instead.
RUN set -e; mkdir -p /src/bin; \
    ldflags="-X github.com/pkilar/cerberus/version.Version=$(cat VERSION)"; \
    (cd ssh-cert-api && go build -ldflags="$ldflags" -o /src/bin/ssh-cert-api ./cmd/ssh-cert-api); \
    (cd ssh-cert-signer && go build -ldflags="$ldflags" -o /src/bin/ssh-cert-signer ./cmd/ssh-cert-signer); \
    go build -ldflags="$ldflags" -o /src/bin/ ./cmd/...; \
    ls -l /src/bin

# Run the test suites as CI does. A failing test is reported but does not abort the build.
RUN for m in . ssh-cert-api ssh-cert-signer; do \
      (cd "$m" && go test -race -count=1 -timeout 10m ./...) || echo "WARNING: go test reported failures in $m"; \
    done; \
    (make test-cssh && bash tests/cssh_login_as_test.sh && zsh tests/cssh_login_as_test.sh) \
      || echo "WARNING: cssh shell tests reported failures"

# Fail fast instead of hanging if anything offline tries to reach the module proxy.
ENV GOPROXY=off
