package ebpf

import (
	"fmt"
	"os"
)

// defaultResolveExe resolves /proc/<pid>/exe to an absolute path. It is
// deliberately best-effort: a process that has already exited by the time we
// read this (the connect() happened, then the process exited before our
// userspace consumer got to it) returns an error, and decodeEvent treats
// that as an empty Exe — which Allowlist.Classify treats as Indeterminate
// (alert-worthy), not silently Expected. See event.go's Event.Exe doc.
func defaultResolveExe(pid uint32) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}
