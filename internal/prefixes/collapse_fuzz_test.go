package prefixes

import (
	"net/netip"
	"testing"
)

func FuzzCollapseIPv4(f *testing.F) {
	f.Add([]byte{
		10, 0, 0, 0, 8,
		10, 1, 0, 0, 16,
	})
	f.Add([]byte{
		2, 60, 4, 0, 23,
		2, 60, 6, 0, 23,
	})
	f.Add([]byte{
		0, 0, 0, 0, 1,
		128, 0, 0, 0, 1,
	})
	f.Add([]byte{
		10, 0, 0, 0, 26,
		10, 0, 0, 64, 26,
		10, 0, 0, 128, 26,
		10, 0, 0, 192, 26,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		prefs := decodeFuzzPrefixes(data)
		if len(prefs) == 0 {
			return
		}
		got := CollapseIPv4(prefs)
		assertSameIPv4Union(t, prefs, got)
		twice := CollapseIPv4(got)
		assertPrefixesEqual(t, got, twice)
		if !isMaximallyCollapsed(got) {
			t.Fatalf("not maximally collapsed: %v", got)
		}
	})
}

// decodeFuzzPrefixes reads groups of 5 bytes: a.b.c.d /bits (bits clamped to 0..32).
func decodeFuzzPrefixes(data []byte) []netip.Prefix {
	const rec = 5
	n := len(data) / rec
	if n > 64 {
		n = 64 // keep fuzz cases small
	}
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		off := i * rec
		addr := netip.AddrFrom4([4]byte{data[off], data[off+1], data[off+2], data[off+3]})
		bits := int(data[off+4] % 33)
		out = append(out, netip.PrefixFrom(addr, bits).Masked())
	}
	return out
}

func FuzzCollapseIPv6(f *testing.F) {
	seed := func(recs ...[]byte) {
		var b []byte
		for _, r := range recs {
			b = append(b, r...)
		}
		f.Add(b)
	}
	v6 := func(cidr string) []byte {
		p := netip.MustParsePrefix(cidr)
		a := p.Addr().As16()
		return append(a[:], byte(p.Bits()))
	}
	// Covered prefix, sibling merge, merge all the way to ::/0 (the 2^128 case),
	// and a four-way cascade -- the IPv6 twins of the IPv4 corpus above.
	seed(v6("fd00::/8"), v6("fd00:1::/32"))
	seed(v6("2001:db8::/33"), v6("2001:db8:8000::/33"))
	seed(v6("::/1"), v6("8000::/1"))
	seed(v6("2001:db8::/50"), v6("2001:db8:0:4000::/50"),
		v6("2001:db8:0:8000::/50"), v6("2001:db8:0:c000::/50"))
	seed(v6("2001:db8::1/128"))

	f.Fuzz(func(t *testing.T, data []byte) {
		prefs := decodeFuzzPrefixes6(data)
		if len(prefs) == 0 {
			return
		}
		got := CollapseIPv6(prefs)
		assertSameUnion(t, prefs, got)
		twice := CollapseIPv6(got)
		assertPrefixesEqual(t, got, twice)
		if !isMaximallyCollapsed(got) {
			t.Fatalf("not maximally collapsed: %v", got)
		}
	})
}

// FuzzCollapseMixed checks that neither family can disturb the other. A shared
// address space would let 0.0.0.0/0 and ::/0 fuse, and a family-blind oracle
// would not notice -- which is why the seeds pair them explicitly.
func FuzzCollapseMixed(f *testing.F) {
	f.Add([]byte{
		0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
		1, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
	})
	f.Add([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		prefs := decodeFuzzPrefixesMixed(data)
		if len(prefs) == 0 {
			return
		}
		got := Collapse(prefs)
		assertSameUnion(t, prefs, got)
		if twice := Collapse(got); !prefixSlicesEqual(got, twice) {
			t.Fatalf("not idempotent:\ngot=%v\ntwice=%v", got, twice)
		}

		in4, in6 := splitByFamily(prefs)
		got4, got6 := splitByFamily(got)
		// Each family must collapse exactly as it would have alone.
		if want := Collapse(in4); !prefixSlicesEqual(got4, want) {
			t.Fatalf("IPv4 half differs when mixed:\ngot=%v\nwant=%v", got4, want)
		}
		if want := Collapse(in6); !prefixSlicesEqual(got6, want) {
			t.Fatalf("IPv6 half differs when mixed:\ngot=%v\nwant=%v", got6, want)
		}
		for _, p := range got {
			if p.Addr().Is4In6() {
				t.Fatalf("4-in-6 prefix %s survived collapse", p)
			}
		}
		if !isMaximallyCollapsed(got4) || !isMaximallyCollapsed(got6) {
			t.Fatalf("not maximally collapsed: %v", got)
		}
	})
}

// decodeFuzzPrefixes6 reads groups of 17 bytes: 16 address bytes then /bits
// (clamped to 0..128), mirroring the 5-byte IPv4 encoding. The modulo means no
// input is ever rejected, so every byte string is a usable case.
func decodeFuzzPrefixes6(data []byte) []netip.Prefix {
	const rec = 17
	n := len(data) / rec
	if n > 64 {
		n = 64
	}
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		off := i * rec
		var a [16]byte
		copy(a[:], data[off:off+16])
		addr := netip.AddrFrom16(a)
		if addr.Is4In6() {
			// Not representable in an ipv6_addr set; nudge it out of the
			// mapped range rather than discarding the case.
			a[0] = 0x20
			addr = netip.AddrFrom16(a)
		}
		out = append(out, netip.PrefixFrom(addr, int(data[off+16]%129)).Masked())
	}
	return out
}

// decodeFuzzPrefixesMixed reads groups of 18 bytes: a family selector, 16
// address bytes, then /bits. IPv4 uses the first 4 address bytes.
func decodeFuzzPrefixesMixed(data []byte) []netip.Prefix {
	const rec = 18
	n := len(data) / rec
	if n > 64 {
		n = 64
	}
	out := make([]netip.Prefix, 0, n)
	for i := 0; i < n; i++ {
		off := i * rec
		if data[off]%2 == 0 {
			addr := netip.AddrFrom4([4]byte{data[off+1], data[off+2], data[off+3], data[off+4]})
			out = append(out, netip.PrefixFrom(addr, int(data[off+17]%33)).Masked())
			continue
		}
		var a [16]byte
		copy(a[:], data[off+1:off+17])
		addr := netip.AddrFrom16(a)
		if addr.Is4In6() {
			a[0] = 0x20
			addr = netip.AddrFrom16(a)
		}
		out = append(out, netip.PrefixFrom(addr, int(data[off+17]%129)).Masked())
	}
	return out
}
