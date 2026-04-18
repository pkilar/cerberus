package api

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak after all api-package tests to catch goroutine leaks.
// The rate limiter, HTTP handlers, and middleware all run in-process here;
// any test that spawns a goroutine and fails to shut it down will surface as
// a leak and fail this package's test run.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
