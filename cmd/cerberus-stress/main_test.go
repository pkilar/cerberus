package main

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHistogram_Empty(t *testing.T) {
	t.Parallel()
	h := newHistogram()
	if h.count != 0 {
		t.Errorf("count = %d, want 0", h.count)
	}
	// percentile on an empty histogram must not panic and must return 0.
	for _, p := range []float64{0, 50, 99, 99.9, 100} {
		if got := h.percentile(p); got != 0 {
			t.Errorf("percentile(%v) = %v, want 0", p, got)
		}
	}
}

func TestHistogram_RecordTracksMinMaxCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		samples []time.Duration
		wantMin time.Duration
		wantMax time.Duration
	}{
		{
			name:    "single sample",
			samples: []time.Duration{100 * time.Microsecond},
			wantMin: 100 * time.Microsecond,
			wantMax: 100 * time.Microsecond,
		},
		{
			name:    "ascending",
			samples: []time.Duration{1 * time.Microsecond, 10 * time.Microsecond, 100 * time.Microsecond, 1 * time.Millisecond},
			wantMin: 1 * time.Microsecond,
			wantMax: 1 * time.Millisecond,
		},
		{
			name:    "descending",
			samples: []time.Duration{1 * time.Millisecond, 100 * time.Microsecond, 10 * time.Microsecond, 1 * time.Microsecond},
			wantMin: 1 * time.Microsecond,
			wantMax: 1 * time.Millisecond,
		},
		{
			name:    "below smallest bucket bound",
			samples: []time.Duration{50 * time.Nanosecond},
			wantMin: 50 * time.Nanosecond,
			wantMax: 50 * time.Nanosecond,
		},
		{
			name:    "above largest numbered bucket — lands in catchall",
			samples: []time.Duration{1000 * time.Second},
			wantMin: 1000 * time.Second,
			wantMax: 1000 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHistogram()
			for _, s := range tt.samples {
				h.record(s)
			}
			if h.count != uint64(len(tt.samples)) {
				t.Errorf("count = %d, want %d", h.count, len(tt.samples))
			}
			if h.min != tt.wantMin {
				t.Errorf("min = %v, want %v", h.min, tt.wantMin)
			}
			if h.max != tt.wantMax {
				t.Errorf("max = %v, want %v", h.max, tt.wantMax)
			}
		})
	}
}

func TestHistogram_PercentileMonotonic(t *testing.T) {
	t.Parallel()
	// Recording a spread of samples, percentile(p) must be non-decreasing
	// in p and always lie within [observed-min, observed-max].
	h := newHistogram()
	for _, d := range []time.Duration{
		100 * time.Nanosecond,
		500 * time.Nanosecond,
		1 * time.Microsecond,
		5 * time.Microsecond,
		10 * time.Microsecond,
		50 * time.Microsecond,
	} {
		h.record(d)
	}
	var last time.Duration
	for _, p := range []float64{0, 25, 50, 75, 95, 99, 99.9, 100} {
		got := h.percentile(p)
		if got < h.min || got > h.max {
			t.Errorf("percentile(%v) = %v outside [min=%v, max=%v]", p, got, h.min, h.max)
		}
		if got < last {
			t.Errorf("percentile(%v) = %v < previous = %v (must be monotonic)", p, got, last)
		}
		last = got
	}
}

func TestHistogram_PercentileClampsToObservedMax(t *testing.T) {
	t.Parallel()
	// All 10 samples land in the same bucket (200ns bucket, upper bound 200ns).
	// Without the clamp, percentile(50) would report 200ns; with the clamp it
	// returns the observed max of 105ns. This guards sparse runs from
	// inflated tail reports.
	h := newHistogram()
	for range 10 {
		h.record(105 * time.Nanosecond)
	}
	if got := h.percentile(50); got != 105*time.Nanosecond {
		t.Errorf("percentile(50) = %v, want 105ns (observed max, not bucket bound)", got)
	}
	if got := h.percentile(99); got != 105*time.Nanosecond {
		t.Errorf("percentile(99) = %v, want 105ns", got)
	}
}

func TestHistogram_BoundedMemory(t *testing.T) {
	t.Parallel()
	// Regression test for the medium-severity issue (unbounded latency slice):
	// recording many samples must NOT grow the bucket/bounds arrays.
	h := newHistogram()
	bucketsLen := len(h.buckets)
	boundsLen := len(h.bounds)
	for range 100_000 {
		h.record(time.Microsecond)
	}
	if len(h.buckets) != bucketsLen {
		t.Errorf("buckets grew from %d to %d under 100k samples", bucketsLen, len(h.buckets))
	}
	if len(h.bounds) != boundsLen {
		t.Errorf("bounds grew from %d to %d under 100k samples", boundsLen, len(h.bounds))
	}
	if h.count != 100_000 {
		t.Errorf("count = %d, want 100000", h.count)
	}
}

func TestFormatStopCondition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		c    commonFlags
		want string
	}{
		{"requests only", commonFlags{requests: 100, duration: 0}, "until 100 requests"},
		{"duration only", commonFlags{requests: 0, duration: 30 * time.Second}, "for 30s"},
		{"both", commonFlags{requests: 100, duration: 30 * time.Second}, "until 100 requests OR 30s"},
		{"neither", commonFlags{}, "until interrupted (Ctrl-C)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatStopCondition(tt.c); got != tt.want {
				t.Errorf("formatStopCondition(%+v) = %q, want %q", tt.c, got, tt.want)
			}
		})
	}
}

func TestMakeTestSSHKey(t *testing.T) {
	t.Parallel()
	key, err := makeTestSSHKey()
	if err != nil {
		t.Fatalf("makeTestSSHKey: %v", err)
	}
	if !strings.HasPrefix(key, "ssh-ed25519 ") {
		t.Errorf("key prefix wrong: %q", key)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
		t.Errorf("generated key not parseable as authorized_keys: %v", err)
	}
}
