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
