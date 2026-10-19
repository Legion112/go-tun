package prefixes

import (
	"net/netip"
)

// Range is an inclusive address range.
//
// It exists because an IKEv2 traffic selector is a range rather than a prefix,
// and the difference is not cosmetic. "Everything except private space" is
// about 35 prefixes and only 7 ranges, and iOS has no documented limit on how
// many selectors it will accept -- so the shorter proposal is the one that does
// not depend on finding that limit in production.
type Range struct {
	From netip.Addr
	To   netip.Addr
}

// String renders the range the way swanctl's local_ts/remote_ts expect it.
func (r Range) String() string {
	if !r.IsValid() {
		return "<invalid>"
	}
	return r.From.String() + "-" + r.To.String()
}

// IsValid reports whether the range is a usable non-empty same-family range.
func (r Range) IsValid() bool {
	if !r.From.IsValid() || !r.To.IsValid() {
		return false
	}
	if r.From.Is4() != r.To.Is4() {
		return false
	}
	return !r.To.Less(r.From)
}

// Prefixes decomposes the range into the minimal set of CIDRs covering exactly
// it.
//
// Needed because the range is only the wire form. Everything that consumes the
// same decision in kernel terms -- an XFRM policy, a route, an nftables set --
// is prefix-shaped, so the two representations have to come from one function
// or they will eventually disagree.
func (r Range) Prefixes() []netip.Prefix {
	if !r.IsValid() {
		return nil
	}
	bits := r.From.BitLen()
	var out []netip.Prefix
	cur := r.From
	for {
		// Grow the block as long as it stays aligned on its own length and
		// does not overshoot the end of the range.
		n := bits
		for n > 0 {
			cand := netip.PrefixFrom(cur, n-1)
			if cand.Masked().Addr() != cur || r.To.Less(lastAddr(cand)) {
				break
			}
			n--
		}
		p := netip.PrefixFrom(cur, n)
		out = append(out, p)
		end := lastAddr(p)
		if !end.Less(r.To) {
			return out
		}
		cur = end.Next()
		if !cur.IsValid() {
			return out
		}
	}
}

// Complement returns the ranges of the selected families' address space that
// cut does not cover.
//
// This is the only way to express "tunnel everything except these" to an iOS
// IKEv2 client: Apple's VPN payload has no excluded-routes key, and iOS ignores
// split-exclude attributes, so the exclusion has to be sent as the positive
// selectors that remain.
func Complement(cut []netip.Prefix, f Families) []Range {
	var base []netip.Prefix
	if f.V4 {
		base = append(base, netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))
	}
	if f.V6 {
		base = append(base, netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0))
	}
	return Subtract(base, cut)
}

// Subtract returns the ranges covered by base but not by cut, per family.
//
// It is the primitive rather than Complement because punching an exception back
// into an excluded block is the common case, not a special one: the gateway's
// own tunnel-side address lives inside RFC1918, so it is cut by the very list
// that keeps the client's local LAN off the tunnel, and it has to be subtracted
// out of the cut before the complement is taken. Composing two range lists
// afterwards would leave adjacent ranges unmerged; doing it here cannot.
func Subtract(base, cut []netip.Prefix) []Range {
	cut = canonicalAll(cut)
	base = canonicalAll(base)

	var out []Range
	for _, f := range []Families{{V4: true}, {V6: true}} {
		b := rangesOf(Collapse(FilterFamilies(base, f)))
		c := rangesOf(Collapse(FilterFamilies(cut, f)))
		out = append(out, subtractRanges(b, c)...)
	}
	return out
}

// RangePrefixes flattens the prefix decomposition of every range, for callers
// that need the kernel form rather than the wire form.
func RangePrefixes(rs []Range) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range rs {
		out = append(out, r.Prefixes()...)
	}
	return out
}

// canonicalAll normalizes before the family split, not after.
//
// FilterFamilies reads Addr.Is4, which is false for a 4-in-6 prefix, so an
// unnormalized ::ffff:10.0.0.0/104 would be filed under IPv6 and silently fail
// to cut the IPv4 block it actually describes.
func canonicalAll(prefs []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if !p.IsValid() {
			continue
		}
		out = append(out, canonical(p))
	}
	return out
}

// subtractRanges sweeps two ascending, non-overlapping range lists.
//
// Collapse guarantees both properties, which is what lets the cut pointer
// advance monotonically across the whole base list rather than being rescanned
// per base range.
func subtractRanges(base, cut []Range) []Range {
	out := make([]Range, 0, len(base))
	j := 0
	for _, b := range base {
		for j < len(cut) && cut[j].To.Less(b.From) {
			j++
		}
		cur := b.From
		// A single cut range can span several base ranges, so k walks ahead
		// from j without consuming it.
		for k := j; k < len(cut) && !b.To.Less(cut[k].From); k++ {
			c := cut[k]
			if cur.Less(c.From) {
				out = append(out, Range{From: cur, To: c.From.Prev()})
			}
			next := c.To.Next()
			if !next.IsValid() {
				// The cut runs to the top of the address space; nothing of
				// this base range survives past it.
				cur = netip.Addr{}
				break
			}
			if cur.Less(next) {
				cur = next
			}
		}
		if cur.IsValid() && !b.To.Less(cur) {
			out = append(out, Range{From: cur, To: b.To})
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func rangesOf(prefs []netip.Prefix) []Range {
	out := make([]Range, 0, len(prefs))
	for _, p := range prefs {
		out = append(out, Range{From: p.Masked().Addr(), To: lastAddr(p)})
	}
	return out
}

// lastAddr returns the highest address in p by setting every host bit.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8
		switch {
		case lo >= bits:
			b[i] = 0xff
		case lo+8 > bits:
			b[i] |= byte(0xff) >> (bits - lo)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
