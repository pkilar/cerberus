package handlers

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkilar/cerberus/messages"
)

// procStatPath and procMeminfoPath are vars (not consts) so tests can point
// them at fixture files. Production callers always read from the real /proc.
var (
	procStatPath    = "/proc/stat"
	procMeminfoPath = "/proc/meminfo"
)

// userHZ is the kernel clock-tick rate used to convert /proc/stat jiffies to
// seconds. It's hard-coded to 100 because Linux x86_64 has fixed CLK_TCK at
// 100 since well before x86_64 existed, and is what the prometheus/procfs and
// node_exporter projects also assume. The enclave runs on x86_64; if that
// ever changes, sample the value at startup via cgo sysconf(_SC_CLK_TCK) or
// reading the (uncommitted) /proc/self/auxv AT_CLKTCK entry.
const userHZ = 100

// ReadEnclaveMetrics samples one snapshot of CPU usage from /proc/stat and
// memory usage from /proc/meminfo. CPU values are converted from kernel
// jiffies to seconds using the enclave's CLK_TCK; memory values are converted
// from kB to bytes so the wire format matches node_exporter conventions.
func ReadEnclaveMetrics() (messages.EnclaveMetricsResponse, error) {
	statData, err := os.ReadFile(procStatPath)
	if err != nil {
		return messages.EnclaveMetricsResponse{}, fmt.Errorf("read %s: %w", procStatPath, err)
	}
	cpu, err := parseProcStat(statData, userHZ)
	if err != nil {
		return messages.EnclaveMetricsResponse{}, fmt.Errorf("parse %s: %w", procStatPath, err)
	}

	memData, err := os.ReadFile(procMeminfoPath)
	if err != nil {
		return messages.EnclaveMetricsResponse{}, fmt.Errorf("read %s: %w", procMeminfoPath, err)
	}
	mem, err := parseProcMeminfo(memData)
	if err != nil {
		return messages.EnclaveMetricsResponse{}, fmt.Errorf("parse %s: %w", procMeminfoPath, err)
	}

	return messages.EnclaveMetricsResponse{CPU: cpu, Memory: mem}, nil
}

// parseProcStat parses the first "cpu " aggregate line of /proc/stat and
// converts the seven canonical fields from jiffies to seconds. Trailing
// fields (steal, guest, guest_nice) are ignored — they're irrelevant inside
// an enclave that owns its CPU allocation outright.
//
// Format (Linux kernel >= 2.6.33):
//
//	cpu  <user> <nice> <system> <idle> <iowait> <irq> <softirq> <steal> ...
func parseProcStat(data []byte, clkTck float64) (messages.EnclaveCPUTimes, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields[0] == "cpu"; need at least 8 entries to read through softirq.
		if len(fields) < 8 {
			return messages.EnclaveCPUTimes{}, fmt.Errorf("aggregate cpu line has %d fields, need >= 8", len(fields))
		}
		var jiffies [7]uint64
		for i := 0; i < 7; i++ {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return messages.EnclaveCPUTimes{}, fmt.Errorf("field %q at index %d: %w", fields[i+1], i+1, err)
			}
			jiffies[i] = v
		}
		toSec := func(j uint64) float64 { return float64(j) / clkTck }
		return messages.EnclaveCPUTimes{
			User:    toSec(jiffies[0]),
			Nice:    toSec(jiffies[1]),
			System:  toSec(jiffies[2]),
			Idle:    toSec(jiffies[3]),
			IOWait:  toSec(jiffies[4]),
			IRQ:     toSec(jiffies[5]),
			SoftIRQ: toSec(jiffies[6]),
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return messages.EnclaveCPUTimes{}, err
	}
	return messages.EnclaveCPUTimes{}, fmt.Errorf("no aggregate cpu line found")
}

// parseProcMeminfo extracts MemTotal, MemAvailable, MemFree, Buffers, and
// Cached from /proc/meminfo. Each line in /proc/meminfo has the shape
// "Key:    <value> kB" — the unit suffix is always kB on Linux even on
// systems where pages are not 4 kB. Returns bytes.
func parseProcMeminfo(data []byte) (messages.EnclaveMemoryStats, error) {
	wanted := map[string]*uint64{}
	var stats messages.EnclaveMemoryStats
	wanted["MemTotal"] = &stats.TotalBytes
	wanted["MemAvailable"] = &stats.AvailableBytes
	wanted["MemFree"] = &stats.FreeBytes
	wanted["Buffers"] = &stats.BuffersBytes
	wanted["Cached"] = &stats.CachedBytes

	seen := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		dst, ok := wanted[key]
		if !ok {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) == 0 {
			return messages.EnclaveMemoryStats{}, fmt.Errorf("%s has no value", key)
		}
		kB, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return messages.EnclaveMemoryStats{}, fmt.Errorf("%s value %q: %w", key, fields[0], err)
		}
		*dst = kB * 1024
		seen++
	}
	if err := scanner.Err(); err != nil {
		return messages.EnclaveMemoryStats{}, err
	}
	if stats.TotalBytes == 0 {
		return messages.EnclaveMemoryStats{}, fmt.Errorf("MemTotal missing or zero")
	}
	return stats, nil
}
