package ldap

import (
	"math/rand/v2"
	"net"
	"testing"
)

func TestRFC2782Order_PriorityAscending(t *testing.T) {
	recs := []*net.SRV{
		{Target: "hi.", Port: 389, Priority: 10, Weight: 0},
		{Target: "lo.", Port: 389, Priority: 0, Weight: 0},
		{Target: "mid.", Port: 636, Priority: 5, Weight: 0},
	}
	got := rfc2782OrderWith(recs, func(int) int { return 0 })
	want := []target{{"lo", 389}, {"mid", 636}, {"hi", 389}}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pos %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRFC2782Order_SingleDotIsEmpty(t *testing.T) {
	if got := rfc2782Order([]*net.SRV{{Target: ".", Port: 0}}); got != nil {
		t.Fatalf("single-dot should be empty, got %+v", got)
	}
}

func TestRFC2782Order_EmptyInput(t *testing.T) {
	if got := rfc2782Order(nil); got != nil {
		t.Fatalf("nil input should be empty, got %+v", got)
	}
}

func TestRFC2782Order_WeightedWithinTier(t *testing.T) {
	recs := []*net.SRV{
		{Target: "a.", Port: 389, Priority: 0, Weight: 90},
		{Target: "b.", Port: 389, Priority: 0, Weight: 10},
	}
	r := rand.New(rand.NewPCG(1, 2)) // seeded -> reproducible
	const N = 20000
	firstA := 0
	for i := 0; i < N; i++ {
		if rfc2782OrderWith(recs, r.IntN)[0].host == "a" {
			firstA++
		}
	}
	if frac := float64(firstA) / N; frac < 0.85 || frac > 0.95 {
		t.Fatalf("a-first fraction = %.3f, want ~0.90", frac)
	}
}

func TestRFC2782Order_WeightZeroAmongPositive(t *testing.T) {
	// Weight-0 record listed AFTER a positive-weight one. RFC 2782 places
	// weight-0 records at the front of the tier, so with threshold 0 the
	// weight-0 record is selected first.
	recs := []*net.SRV{
		{Target: "big.", Port: 389, Priority: 0, Weight: 100},
		{Target: "zero.", Port: 389, Priority: 0, Weight: 0},
	}
	got := rfc2782OrderWith(recs, func(int) int { return 0 })
	if len(got) != 2 {
		t.Fatalf("want 2 targets, got %+v", got)
	}
	if got[0].host != "zero" {
		t.Fatalf("weight-0 record should be orderable first, got %+v", got)
	}
}

func TestRFC2782Order_AllZeroTierKeepsDNSOrder(t *testing.T) {
	recs := []*net.SRV{
		{Target: "x.", Port: 389, Priority: 0, Weight: 0},
		{Target: "y.", Port: 389, Priority: 0, Weight: 0},
		{Target: "z.", Port: 389, Priority: 0, Weight: 0},
	}
	got := rfc2782OrderWith(recs, func(int) int { return 0 })
	want := []string{"x", "y", "z"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%+v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].host != w {
			t.Fatalf("all-zero tier should keep DNS order; pos %d = %q want %q (%+v)", i, got[i].host, w, got)
		}
	}
}

func TestRFC2782Order_DotAmongReals(t *testing.T) {
	recs := []*net.SRV{
		{Target: "a.", Port: 389, Priority: 0, Weight: 0},
		{Target: ".", Port: 0, Priority: 0, Weight: 0},
		{Target: "b.", Port: 389, Priority: 0, Weight: 0},
	}
	got := rfc2782OrderWith(recs, func(int) int { return 0 })
	if len(got) != 2 {
		t.Fatalf("expected 2 targets (. dropped), got %+v", got)
	}
	for _, g := range got {
		if g.host == "." || g.host == "" {
			t.Fatalf("dot target leaked: %+v", got)
		}
	}
}

func TestRFC2782Order_CrossTier(t *testing.T) {
	recs := []*net.SRV{
		{Target: "hi1.", Port: 389, Priority: 10, Weight: 50},
		{Target: "lo1.", Port: 389, Priority: 0, Weight: 50},
		{Target: "hi2.", Port: 389, Priority: 10, Weight: 50},
		{Target: "lo2.", Port: 389, Priority: 0, Weight: 50},
	}
	got := rfc2782OrderWith(recs, func(int) int { return 0 })
	if len(got) != 4 {
		t.Fatalf("want 4, got %+v", got)
	}
	for i := 0; i < 2; i++ {
		if got[i].host != "lo1" && got[i].host != "lo2" {
			t.Fatalf("position %d should be a priority-0 target, got %+v", i, got)
		}
	}
	for i := 2; i < 4; i++ {
		if got[i].host != "hi1" && got[i].host != "hi2" {
			t.Fatalf("position %d should be a priority-10 target, got %+v", i, got)
		}
	}
}
