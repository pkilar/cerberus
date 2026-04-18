# Profile-Guided Optimization (PGO) for ssh-cert-signer

Go 1.21+ supports PGO: the compiler uses runtime CPU profiles to make
better inlining and devirtualization decisions on the hot path. For the
signer — which spends most of its wall time in RSA/ECDSA signing and
JSON marshaling — PGO typically buys 2–7% throughput without changing
any code.

## When to bother

Capture a fresh profile if any of the following is true:
- The signer handles > 50 requests/second sustained.
- You changed the hot path (cert builder, RSA signer, JSON codec).
- You upgraded the Go toolchain.

A stale profile is worse than no profile — recapture after refactors.

## How to capture

The signer does not currently expose `net/http/pprof`. Add it behind a
debug flag if you need to collect profiles in the enclave (or on a
staging host).

```go
import _ "net/http/pprof"

// In main, guarded:
if os.Getenv("PPROF_ADDR") != "" {
    go http.ListenAndServe(os.Getenv("PPROF_ADDR"), nil)
}
```

Then capture 30 s of CPU profile under realistic load:

```bash
curl -o default.pgo http://<host>:<pprof-port>/debug/pprof/profile?seconds=30
```

Move the resulting file to `ssh-cert-signer/cmd/ssh-cert-signer/default.pgo`.
`go build` discovers `default.pgo` next to `main.go` automatically and
uses it for PGO (see `go help build -pgo`).

## Verifying PGO is enabled

```bash
go build -pgo=auto -o /tmp/signer ./ssh-cert-signer/cmd/ssh-cert-signer
go version -m /tmp/signer | grep -i pgo
```

You should see a `build -pgo=/...default.pgo` line.

## CI

CI builds do not need PGO. Commit `default.pgo` (binary file) only when
you have a representative production profile. Treat it like any other
build artifact: review diffs when the profile changes, rotate when the
hot path moves.

## References

- <https://go.dev/doc/pgo>
- <https://go.dev/blog/pgo>
