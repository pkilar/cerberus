# Contributing to Cerberus

Thanks for your interest! This project is an SSH Certificate Authority that
runs partly inside an AWS Nitro Enclave. Most of the codebase is
straightforward Go; the enclave-specific bits are isolated to
`ssh-cert-signer/` and do not require Nitro hardware for unit testing.

## Prerequisites

- Go 1.26 or newer
- `make`
- `git`

Optional (for enclave-level work):
- AWS CLI + AWS Nitro Enclaves CLI
- An EC2 instance with Nitro Enclaves enabled

## Repository layout

This is a **multi-module Go project** with three `go.mod` files, not a Go
workspace. See [CLAUDE.md](./CLAUDE.md) for the full architecture.

- `/` — shared packages (`constants`, `logging`, `messages`) + integration tests
- `/ssh-cert-api/` — HTTPS API service
- `/ssh-cert-signer/` — Nitro Enclave signing service

You must `cd` into the correct module directory before running `go test`,
`go build`, or `go mod tidy`.

## Build & test

```bash
# Everything
make build
make test

# One service
make -C ssh-cert-api build
make -C ssh-cert-api test

# A single test
cd ssh-cert-api && go test -run TestHandleSignRequest ./internal/api/...

# Race detector + full suite (what CI runs)
go test -race ./...
cd ssh-cert-api && go test -race ./...
cd ssh-cert-signer && go test -race ./...

# Fuzz the CMS parser briefly
cd ssh-cert-signer && go test -fuzz=FuzzDecryptCMSEnvelope -fuzztime=10s ./internal/attestation/
```

## Linting

CI runs `golangci-lint v2.6+` with the config in `.golangci.yml` (modernize,
gosec, errorlint, bodyclose, misspell, etc.). Run it locally before pushing:

```bash
golangci-lint run ./...
(cd ssh-cert-api && golangci-lint run ./...)
(cd ssh-cert-signer && golangci-lint run ./...)
```

## Security checks

CI also runs `govulncheck` and `gosec`. You can run them locally via:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest

govulncheck ./...   # and in each submodule
gosec ./...         # and in each submodule
```

## Pull request checklist

Before opening a PR:

- [ ] `make build` passes in all three modules.
- [ ] `go test -race ./...` passes in all three modules.
- [ ] `golangci-lint run ./...` is clean.
- [ ] Security-affecting changes include a test that would fail without the fix.
- [ ] Public types and functions have doc comments.
- [ ] If you add an env var, a config field, or an HTTP endpoint, update
      [README.md](./README.md).

Commits on feature branches should be focused and reviewable — prefer a
sequence of small logical commits over one mega-diff.

## What needs help

- Expanding integration coverage that exercises real VSOCK (currently mocked
  over TCP).
- Signer-side Prometheus metrics surfaced out of the enclave.
- Documentation: runbooks for common operational scenarios in
  [docs/RUNBOOK.md](./docs/RUNBOOK.md).

## Reporting vulnerabilities

For suspected security issues, please avoid filing a public issue. Contact
the maintainer directly; see the repository metadata on GitHub for the
current contact.
