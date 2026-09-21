package prefixes

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
)

// addrInterval is an inclusive address range, used as an independent oracle for
// Collapse union equivalence (not the CIDR stack algorithm).
//
// The endpoints are big.Int rather than a fixed width because an IPv6 /0 spans
// 2^128 addresses and unionAddressCount must be able to report it. That is the
// same reason the IPv4-only version used uint64 for 32-bit values: the count of
// a full prefix does not fit in the width of its addresses.
type addrInterval struct {
	start, end *big.Int // inclusive
}

func (iv addrInterval) String() string {
	return fmt.Sprintf("[%s,%s]", iv.start, iv.end)
}

func (iv addrInterval) equal(o addrInterval) bool {
	return iv.start.Cmp(o.start) == 0 && iv.end.Cmp(o.end) == 0
}

func prefixToInterval(p netip.Prefix) addrInterval {
	p = p.Masked()
	start := new(big.Int).SetBytes(p.Addr().AsSlice())
	size := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
	end := new(big.Int).Add(start, size)
	end.Sub(end, big.NewInt(1))
	return addrInterval{start: start, end: end}
}

type fataler interface {
	Helper()
	Fatalf(string, ...any)
}

// prefixesToMergedIntervals canonicalizes prefs into a minimal ascending
// interval list.
//
// It fails on a mixed-family list rather than skipping one family. The earlier
// version silently dropped every non-IPv4 prefix, so a mixed input compared
// only its IPv4 half and passed -- which is precisely the defect class the
// mixed-family fuzz target exists to find, hidden inside the thing meant to
// find it. Callers with mixed input split first.
func prefixesToMergedIntervals(t fataler, prefs []netip.Prefix) []addrInterval {
	t.Helper()
	if len(prefs) == 0 {
		return nil
	}
	intervals := make([]addrInterval, 0, len(prefs))
	bits := prefs[0].Addr().BitLen()
	for _, p := range prefs {
		if p.Addr().BitLen() != bits {
			t.Fatalf("prefixesToMergedIntervals: mixed families in %v; split by family first", prefs)
		}
		intervals = append(intervals, prefixToInterval(p))
	}
	sort.Slice(intervals, func(i, j int) bool {
		if c := intervals[i].start.Cmp(intervals[j].start); c != 0 {
			return c < 0
		}
		return intervals[i].end.Cmp(intervals[j].end) < 0
	})

	merged := []addrInterval{intervals[0]}
	for _, iv := range intervals[1:] {
		last := &merged[len(merged)-1]
		// Overlapping or adjacent → merge.
		if iv.start.Cmp(new(big.Int).Add(last.end, big.NewInt(1))) <= 0 {
			if iv.end.Cmp(last.end) > 0 {
				last.end = iv.end
			}
			continue
		}
		merged = append(merged, iv)
	}
	return merged
}

func intervalsEqual(a, b []addrInterval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].equal(b[i]) {
			return false
		}
	}
	return true
}

func unionAddressCount(intervals []addrInterval) *big.Int {
	n := new(big.Int)
	for _, iv := range intervals {
		n.Add(n, new(big.Int).Sub(iv.end, iv.start))
		n.Add(n, big.NewInt(1))
	}
	return n
}

// assertSameUnion checks that collapsing preserved the exact address union.
// Both families are allowed; each is compared independently.
func assertSameUnion(t fataler, input, output []netip.Prefix) {
	t.Helper()
	in4, in6 := splitByFamily(input)
	out4, out6 := splitByFamily(output)
	assertSameFamilyUnion(t, in4, out4)
	assertSameFamilyUnion(t, in6, out6)
}

func assertSameFamilyUnion(t fataler, input, output []netip.Prefix) {
	t.Helper()
	in := prefixesToMergedIntervals(t, input)
	out := prefixesToMergedIntervals(t, output)
	if !intervalsEqual(in, out) {
		t.Fatalf("union mismatch:\n  input intervals=%v\n  output intervals=%v", in, out)
	}
	if a, b := unionAddressCount(in), unionAddressCount(out); a.Cmp(b) != 0 {
		t.Fatalf("address count mismatch: in=%s out=%s", a, b)
	}
}

// assertSameIPv4Union is the IPv4-only spelling the existing table tests use.
func assertSameIPv4Union(t fataler, input, output []netip.Prefix) {
	t.Helper()
	assertSameUnion(t, input, output)
}

// splitByFamily partitions prefixes into IPv4 and IPv6. A 4-in-6 prefix counts
// as IPv6, because that is how netip classifies it and how an nftables set
// would treat it -- the oracle must not paper over a family mistake.
func splitByFamily(prefs []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefs {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func isMaximallyCollapsed(prefs []netip.Prefix) bool {
	if len(prefs) == 0 {
		return true
	}
	// Canonical order: (addr, bits).
	for i := 1; i < len(prefs); i++ {
		a, b := prefs[i-1], prefs[i]
		if a.Addr() == b.Addr() && a.Bits() == b.Bits() {
			return false // duplicate
		}
		if b.Addr().Less(a.Addr()) || (a.Addr() == b.Addr() && b.Bits() < a.Bits()) {
			return false // unsorted
		}
	}
	for i := 0; i < len(prefs); i++ {
		for j := 0; j < len(prefs); j++ {
			if i == j {
				continue
			}
			if prefixContains(prefs[i], prefs[j]) {
				return false
			}
		}
		if i+1 < len(prefs) {
			if _, ok := mergeSiblings(prefs[i], prefs[i+1]); ok {
				return false
			}
		}
	}
	// Also check any non-adjacent sibling pair that somehow remained (should not).
	for i := 0; i < len(prefs); i++ {
		for j := i + 1; j < len(prefs); j++ {
			if _, ok := mergeSiblings(prefs[i], prefs[j]); ok {
				return false
			}
		}
	}
	return true
}
