// Package version holds the Cerberus release version, stamped at build time
// via -ldflags "-X github.com/pkilar/cerberus/version.Version=x.y.z" from the
// top-level VERSION file. See each binary's Makefile/packaging build step.
package version

// Version defaults to "dev" for `go build`/`go run` invocations that don't
// inject a value (e.g. plain `go test`, local debugging).
var Version = "dev"
