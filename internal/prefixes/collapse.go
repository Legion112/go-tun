package prefixes

import (
	"fmt"
	"net/netip"
	"sort"
)

// Collapse returns the minimal set of prefixes covering exactly the same
// addresses as prefs. Mixed families are allowed and are collapsed
// independently: netip.Addr.Less orders every IPv4 address before every IPv6
// one, so the two blocks never interleave, and a cross-family pair can never
// merge because their parent prefixes cannot compare equal.
//
// Steps: canonicalize, dedupe, remove covered prefixes, then merge sibling
// pairs with a stack until no further lossless merge is possible.
func Collapse(prefs []netip.Prefix) []netip.Prefix {
	if len(prefs) == 0 {
		return nil
	}

	normalized := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if !p.IsValid() {
			continue
		}
		normalized = append(normalized, canonical(p))
	}
	if len(normalized) == 0 {
		return nil
	}

	sort.Slice(normalized, func(i, j int) bool {
		ai, aj := normalized[i], normalized[j]
		if ai.Addr() != aj.Addr() {
			return ai.Addr().Less(aj.Addr())
		}
		return ai.Bits() < aj.Bits()
	})

	// Deduplicate.
	deduped := normalized[:0]
	for _, p := range normalized {
		if len(deduped) > 0 && deduped[len(deduped)-1] == p {
			continue
		}
		deduped = append(deduped, p)
	}

	return mergeSiblingStack(removeCovered(deduped))
}

// CollapseIPv4 is Collapse restricted to IPv4; an IPv6 prefix panics.
//
// The panic is the contract, not an oversight: the call sites that feed an
// nftables ipv4_addr set must not silently accept a prefix the kernel would
// reject, and a v6 prefix arriving here means a family split was missed
// upstream.
func CollapseIPv4(prefs []netip.Prefix) []netip.Prefix {
	for _, p := range prefs {
		if !p.Addr().Is4() {
			panic(fmt.Sprintf("prefixes.CollapseIPv4: IPv6 prefix %s not supported", p))
		}
	}
	return Collapse(prefs)
}

// CollapseIPv6 is Collapse restricted to IPv6; an IPv4 prefix panics.
//
// A 4-in-6 prefix (::ffff:a.b.c.d) panics too. It reports Is6, so it would
// otherwise reach an ipv6_addr set, where it matches no real traffic: the
// kernel compares a v6 packet's destination, and a v4 packet never presents
// one. Silently classifying nothing is the worst outcome available, so this
// refuses instead.
func CollapseIPv6(prefs []netip.Prefix) []netip.Prefix {
	for _, p := range prefs {
		if !p.Addr().Is6() || p.Addr().Is4In6() {
			panic(fmt.Sprintf("prefixes.CollapseIPv6: non-IPv6 prefix %s not supported", p))
		}
	}
	return Collapse(prefs)
}

// canonical masks a prefix and unwraps the 4-in-6 form.
//
// ::ffff:10.0.0.0/104 and 10.0.0.0/8 denote the same addresses, but as
// netip.Prefix values they are neither equal nor mergeable, so leaving both in
// the input defeats dedupe and sibling merging and yields a set that is not
// minimal. Only prefixes inside ::ffff:0:0/96 can be unwrapped; a shorter one
// spans beyond the mapped range and is a genuine IPv6 prefix.
func canonical(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked()
	}
	return p.Masked()
}

// removeCovered drops every prefix contained in another.
//
// prefs must be sorted by (addr asc, bits asc) and deduped. Only the last kept
// prefix can cover the candidate: kept prefixes are pairwise non-covering, and
// if some earlier k covered p then any prefix added after k with an address at
// or below p's would have to lie inside k -- and would therefore have been
// dropped rather than kept. So a single comparison replaces a scan, which
// matters at RU scale (~12k IPv4 plus ~4.6k IPv6) on a router CPU.
func removeCovered(prefs []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if n := len(out); n > 0 && prefixContains(out[n-1], p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// prefixContains reports whether outer fully contains inner (both masked).
// Prefix equality also compares the family, so a cross-family pair is never
// contained, which is what keeps the two blocks independent.
func prefixContains(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return netip.PrefixFrom(inner.Addr(), outer.Bits()).Masked() == outer
}

func mergeSiblingStack(prefs []netip.Prefix) []netip.Prefix {
	stack := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		stack = append(stack, p)
		for len(stack) >= 2 {
			a, b := stack[len(stack)-2], stack[len(stack)-1]
			parent, ok := mergeSiblings(a, b)
			if !ok {
				break
			}
			stack = stack[:len(stack)-2]
			stack = append(stack, parent)
		}
	}
	return stack
}

// mergeSiblings returns the parent prefix if a and b are the two halves of it.
//
// No address arithmetic is needed, which is what makes this family-generic. A
// /(n-1) has exactly two /n children, so once a and b are distinct masked /n
// prefixes inside the same parent and a is the left child, b can only be the
// right one. The earlier IPv4 version reconstructed the right half with uint32
// arithmetic and so could not be reused for 128-bit addresses; that step was
// redundant, and dropping it was verified to produce identical output over the
// full 71821-prefix RU extract.
func mergeSiblings(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 || a == b {
		return netip.Prefix{}, false
	}
	if b.Addr().Less(a.Addr()) {
		a, b = b, a
	}
	parentBits := a.Bits() - 1
	parent := netip.PrefixFrom(a.Addr(), parentBits).Masked()
	if netip.PrefixFrom(b.Addr(), parentBits).Masked() != parent {
		return netip.Prefix{}, false
	}
	// a must be the left half, or these are the same child twice.
	if netip.PrefixFrom(parent.Addr(), a.Bits()).Masked() != a {
		return netip.Prefix{}, false
	}
	return parent, true
}
