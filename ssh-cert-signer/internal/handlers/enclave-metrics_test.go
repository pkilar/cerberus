package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleProcStat = `cpu  100 20 30 5000 40 5 10 0 0 0
cpu0 50 10 15 2500 20 3 5 0 0 0
cpu1 50 10 15 2500 20 2 5 0 0 0
intr 1234567 0 0 0
ctxt 9876543
btime 1700000000
processes 12345
procs_running 1
procs_blocked 0
softirq 99999 0 1 2 3 4 5 6 7 8
`

func TestParseProcStat(t *testing.T) {
	t.Parallel()
	cpu, err := parseProcStat([]byte(sampleProcStat), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// jiffies / 100 → seconds
	checks := []struct {
		name string
		got  float64
		want float64
	}{
		{"user", cpu.User, 1.0},
		{"nice", cpu.Nice, 0.2},
		{"system", cpu.System, 0.3},
		{"idle", cpu.Idle, 50.0},
		{"iowait", cpu.IOWait, 0.4},
		{"irq", cpu.IRQ, 0.05},
		{"softirq", cpu.SoftIRQ, 0.1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestParseProcStat_Errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		data      string
		errSubstr string
	}{
		{
			name:      "no aggregate cpu line",
			data:      "cpu0 50 10 15 2500 20 3 5\nintr 1234\n",
			errSubstr: "no aggregate cpu line found",
		},
		{
			name:      "too few fields",
			data:      "cpu 100 20 30\n",
			errSubstr: "need >= 8",
		},
		{
			name:      "non-numeric field",
			data:      "cpu  100 abc 30 5000 40 5 10\n",
			errSubstr: "abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseProcStat([]byte(tt.data), 100)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("error %v does not contain %q", err, tt.errSubstr)
			}
		})
	}
}

const sampleProcMeminfo = `MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:          524288 kB
Cached:          2097152 kB
SwapCached:            0 kB
Active:          3000000 kB
Inactive:        1000000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
`

func TestParseProcMeminfo(t *testing.T) {
	t.Parallel()
	mem, err := parseProcMeminfo([]byte(sampleProcMeminfo))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// kB * 1024 → bytes
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"total", mem.TotalBytes, 16384000 * 1024},
		{"free", mem.FreeBytes, 8192000 * 1024},
		{"available", mem.AvailableBytes, 12288000 * 1024},
		{"buffers", mem.BuffersBytes, 524288 * 1024},
		{"cached", mem.CachedBytes, 2097152 * 1024},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestParseProcMeminfo_MissingMemTotalIsError(t *testing.T) {
	t.Parallel()
	data := "MemFree: 100 kB\nMemAvailable: 200 kB\n"
	_, err := parseProcMeminfo([]byte(data))
	if err == nil || !strings.Contains(err.Error(), "MemTotal") {
		t.Fatalf("expected MemTotal error, got: %v", err)
	}
}

func TestParseProcMeminfo_NonNumericValueIsError(t *testing.T) {
	t.Parallel()
	data := "MemTotal: abc kB\n"
	_, err := parseProcMeminfo([]byte(data))
	if err == nil {
		t.Fatal("expected error for non-numeric MemTotal value")
	}
}

// withProcPaths swaps the package-level /proc path vars to the given fixtures
// and returns a cleanup. Cannot run in parallel with anything else that
// touches the same vars.
func withProcPaths(t *testing.T, statPath, meminfoPath string) {
	t.Helper()
	origStat, origMem := procStatPath, procMeminfoPath
	procStatPath, procMeminfoPath = statPath, meminfoPath
	t.Cleanup(func() {
		procStatPath, procMeminfoPath = origStat, origMem
	})
}

func TestReadEnclaveMetrics_HappyPath(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "stat")
	meminfoPath := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(statPath, []byte(sampleProcStat), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	if err := os.WriteFile(meminfoPath, []byte(sampleProcMeminfo), 0o600); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	withProcPaths(t, statPath, meminfoPath)

	resp, err := ReadEnclaveMetrics()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CPU.User != 1.0 {
		t.Errorf("CPU,User = %v, want 1.0", resp.CPU.User)
	}
	if resp.CPU.Idle != 50.0 {
		t.Errorf("CPU.Idle = %v, want 50.0", resp.CPU.Idle)
	}
	if resp.Memory.TotalBytes != 16384000*1024 {
		t.Errorf("Memory.TotalBytes = %d, want %d", resp.Memory.TotalBytes, 16384000*1024)
	}
	if resp.Memory.AvailableBytes != 12288000*1024 {
		t.Errorf("Memory.AvailableBytes = %d", resp.Memory.AvailableBytes)
	}
}

func TestReadEnclaveMetrics_StatReadError(t *testing.T) {
	dir := t.TempDir()
	meminfoPath := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(meminfoPath, []byte(sampleProcMeminfo), 0o600); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	withProcPaths(t, filepath.Join(dir, "does-not-exist"), meminfoPath)

	_, err := ReadEnclaveMetrics()
	if err == nil {
		t.Fatal("expected error when /proc/stat is missing")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error %v does not contain expected substring 'read'", err)
	}
}

func TestReadEnclaveMetrics_MeminfoReadError(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "stat")
	if err := os.WriteFile(statPath, []byte(sampleProcStat), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	withProcPaths(t, statPath, filepath.Join(dir, "does-not-exist"))

	_, err := ReadEnclaveMetrics()
	if err == nil {
		t.Fatal("expected error when /proc/meminfo is missing")
	}
}

func TestReadEnclaveMetrics_StatParseError(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "stat")
	meminfoPath := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(statPath, []byte("garbage with no cpu line\n"), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	if err := os.WriteFile(meminfoPath, []byte(sampleProcMeminfo), 0o600); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	withProcPaths(t, statPath, meminfoPath)

	_, err := ReadEnclaveMetrics()
	if err == nil {
		t.Fatal("expected parse error from malformed /proc/stat")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error %v should be wrapped as a parse error", err)
	}
}
