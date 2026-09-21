package policy

import "net/netip"

// Family is the address family a kernel object belongs to.
//
// It is an explicit field rather than something derived on demand because at
// the kernel layer family is a real property of the object, not of the values
// inside it: an nftables set has one type, an ip rule belongs to one RPDB, and
// table 100 for IPv4 and table 100 for IPv6 are two different tables. Making it
// explicit also means every switch over it has a default arm, so a family added
// later cannot be silently skipped.
type Family string

const (
	FamilyV4 Family = "ipv4"
	FamilyV6 Family = "ipv6"
	// FamilyAny is for rules with no layer-3 dependency, such as an ingress
	// interface guard. Such a rule is emitted once and covers both families;
	// emitting it twice would double it in the chain.
	FamilyAny Family = "any"
)

func (f Family) Valid() bool {
	return f == FamilyV4 || f == FamilyV6 || f == FamilyAny
}

// IsV6 reports whether f is the IPv6 family. The zero Family is empty rather
// than FamilyV4, so callers that never set it are caught by Valid, not
// silently treated as IPv4.
func (f Family) IsV6() bool { return f == FamilyV6 }

// FamilyOf and FamilyOfAddr classify a value. A 4-in-6 address counts as IPv6,
// matching netip and matching what an nftables set would do with it; callers
// that must not see one reject it before asking.
func FamilyOf(p netip.Prefix) Family {
	if p.Addr().Is4() {
		return FamilyV4
	}
	return FamilyV6
}

func FamilyOfAddr(a netip.Addr) Family {
	if a.Is4() {
		return FamilyV4
	}
	return FamilyV6
}

// SplitPrefixes partitions prefixes by family, preserving order within each.
func SplitPrefixes(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// SplitAddrs partitions addresses by family, preserving order within each.
func SplitAddrs(as []netip.Addr) (v4, v6 []netip.Addr) {
	for _, a := range as {
		if !a.IsValid() {
			continue
		}
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// SetTypeFor is the nftables set type for a family. Compile derives Type from
// Family rather than letting a caller set them independently, so the two can
// never disagree.
func SetTypeFor(f Family) string {
	if f == FamilyV6 {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

// DefaultRouteFor is the default-route destination for a family.
func DefaultRouteFor(f Family) netip.Prefix {
	if f == FamilyV6 {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

// SetNameForFamily suffixes a set name for IPv6, so ru_nets and ru_nets6 can
// live side by side in the one inet table.
func SetNameForFamily(base string, f Family) string {
	if f == FamilyV6 {
		return base + "6"
	}
	return base
}
