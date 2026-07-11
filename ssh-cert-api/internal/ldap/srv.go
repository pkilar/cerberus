package ldap

import (
	"context"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
)

// srvResolver is the subset of *net.Resolver used for SRV discovery. It is an
// interface so tests can inject canned answers without real DNS.
// net.DefaultResolver satisfies it.
type srvResolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// target is one resolved LDAP endpoint: a hostname (trailing dot trimmed) and
// its port.
type target struct {
	host string
	port int
}

// rfc2782Order orders SRV records per RFC 2782 using the default PRNG.
func rfc2782Order(recs []*net.SRV) []target {
	return rfc2782OrderWith(recs, rand.IntN)
}

// rfc2782OrderWith orders SRV records per RFC 2782: ascending Priority, and
// within each equal-Priority tier a weighted-random shuffle whose selection
// probability is proportional to Weight (Weight-0 records keep a small chance).
// A lone record whose Target is "." means the service is decidedly unavailable
// and yields no targets. Trailing dots are trimmed from each Target. intn must
// behave like math/rand/v2.IntN (returns [0, n)); it is a parameter so the
// weighting is deterministically testable.
func rfc2782OrderWith(recs []*net.SRV, intn func(int) int) []target {
	if len(recs) == 1 && recs[0].Target == "." {
		return nil
	}
	byPrio := map[uint16][]*net.SRV{}
	var prios []uint16
	for _, r := range recs {
		if r.Target == "." {
			continue
		}
		if _, ok := byPrio[r.Priority]; !ok {
			prios = append(prios, r.Priority)
		}
		byPrio[r.Priority] = append(byPrio[r.Priority], r)
	}
	slices.Sort(prios)

	var out []target
	for _, p := range prios {
		for _, r := range weightedShuffle(byPrio[p], intn) {
			out = append(out, target{host: strings.TrimSuffix(r.Target, "."), port: int(r.Port)})
		}
	}
	return out
}

// weightedShuffle returns recs reordered by RFC 2782 weighted selection.
func weightedShuffle(recs []*net.SRV, intn func(int) int) []*net.SRV {
	remaining := slices.Clone(recs)
	out := make([]*net.SRV, 0, len(remaining))
	for len(remaining) > 0 {
		total := 0
		for _, r := range remaining {
			total += int(r.Weight)
		}
		threshold := intn(total + 1) // [0, total]
		pick := len(remaining) - 1
		run := 0
		for i, r := range remaining {
			run += int(r.Weight)
			if run >= threshold {
				pick = i
				break
			}
		}
		out = append(out, remaining[pick])
		remaining = slices.Delete(remaining, pick, pick+1)
	}
	return out
}
