package prefixes

import (
	"math/big"
	"math/rand"
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCollapseIPv6_MergesSiblings(t *testing.T) {
	in := mustPrefs(t, "2001:db8::/33", "2001:db8:8000::/33")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "2001:db8::/32"))
	assertSameUnion(t, in, got)
}

func TestCollapseIPv6_DoesNotMergeAcrossGap(t *testing.T) {
	in := mustPrefs(t, "2001:db8::/33", "2001:dba:8000::/33")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, in)
	assertSameUnion(t, in, got)
}

func TestCollapseIPv6_RemovesCovered(t *testing.T) {
	in := mustPrefs(t, "fd00::/8", "fd00:1::/32", "fd00:2::/48")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "fd00::/8"))
	assertSameUnion(t, in, got)
}

func TestCollapseIPv6_CascadesToParent(t *testing.T) {
	in := mustPrefs(t,
		"2001:db8::/50", "2001:db8:0:4000::/50",
		"2001:db8:0:8000::/50", "2001:db8:0:c000::/50")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "2001:db8::/48"))
	assertSameUnion(t, in, got)
}

// TestCollapseIPv6_MergesToDefault is the case the big.Int oracle exists for:
// the union is 2^128 addresses, which no fixed-width counter can express.
func TestCollapseIPv6_MergesToDefault(t *testing.T) {
	in := mustPrefs(t, "::/1", "8000::/1")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "::/0"))

	want := new(big.Int).Lsh(big.NewInt(1), 128)
	if n := unionAddressCount(prefixesToMergedIntervals(t, got)); n.Cmp(want) != 0 {
		t.Fatalf("want 2^128 addresses, got %s", n)
	}
}

func TestCollapseIPv6_CanonicalizesUnmaskedInput(t *testing.T) {
	in := mustPrefs(t, "2001:db8::1/32", "2001:db8::2/32")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "2001:db8::/32"))
}

func TestCollapseIPv6_HostPrefix(t *testing.T) {
	in := mustPrefs(t, "2001:db8::1/128", "2001:db8::1/128")
	got := CollapseIPv6(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "2001:db8::1/128"))
}

func TestCollapseIPv6_PanicsOnIPv4(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on IPv4")
		}
	}()
	CollapseIPv6(mustPrefs(t, "10.0.0.0/8"))
}

// TestCollapseIPv6_PanicsOn4In6 pins the hazard that a ::ffff:a.b.c.d prefix
// reports Is6 and would otherwise reach an ipv6_addr set, where it matches no
// real traffic at all.
func TestCollapseIPv6_PanicsOn4In6(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on 4-in-6 prefix")
		}
	}()
	CollapseIPv6([]netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")})
}

// TestCollapse_Unmaps4In6 proves the two spellings of the same addresses
// collapse together instead of surviving as two unmergeable prefixes.
func TestCollapse_Unmaps4In6(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("::ffff:10.0.0.0/104"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	got := Collapse(in)
	assertPrefixesEqual(t, got, mustPrefs(t, "10.0.0.0/8"))
}

func TestCollapse_MixedFamiliesStayIndependent(t *testing.T) {
	in := mustPrefs(t,
		"10.0.0.0/9", "10.128.0.0/9",
		"2001:db8::/33", "2001:db8:8000::/33")
	got := Collapse(in)
	// IPv4 sorts before IPv6, and neither family may absorb the other.
	assertPrefixesEqual(t, got, mustPrefs(t, "10.0.0.0/8", "2001:db8::/32"))
	assertSameUnion(t, in, got)
}

// TestCollapse_MixedDefaultsDoNotMerge is the adversarial case for a shared
// interval space: 0.0.0.0/0 and ::/0 both start at zero, so an oracle or an
// algorithm that ignored family would happily fuse them.
func TestCollapse_MixedDefaultsDoNotMerge(t *testing.T) {
	in := mustPrefs(t, "0.0.0.0/0", "::/0")
	got := Collapse(in)
	assertPrefixesEqual(t, got, in)
	assertSameUnion(t, in, got)
}

// TestCollapse_DifferentialAgainstIPv4Path locks in the generalization: the
// family-generic merge, with the uint32 right-half reconstruction deleted, must
// produce byte-identical output to the IPv4 path it replaced. The address space
// is deliberately narrow so siblings and covered prefixes actually occur.
func TestCollapse_DifferentialAgainstIPv4Path(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 20000; iter++ {
		in := make([]netip.Prefix, 0, 24)
		for i, k := 0, 1+rng.Intn(24); i < k; i++ {
			addr := netip.AddrFrom4([4]byte{
				10, byte(rng.Intn(2)), byte(rng.Intn(4)), byte(rng.Intn(256)),
			})
			in = append(in, netip.PrefixFrom(addr, 8+rng.Intn(25)).Masked())
		}
		got := Collapse(in)
		assertSameIPv4Union(t, in, got)
		if !isMaximallyCollapsed(got) {
			t.Fatalf("iter %d not maximally collapsed:\n in=%v\ngot=%v", iter, in, got)
		}
		if twice := Collapse(got); !prefixSlicesEqual(got, twice) {
			t.Fatalf("iter %d not idempotent:\ngot=%v\ntwice=%v", iter, got, twice)
		}
	}
}

// TestCollapse_RUFixture6 runs the real pipeline over a v6 fixture.
func TestCollapse_RUFixture6(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "prefixes", "ru6-fixture.txt")
	in, err := ParseCIDRFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(in) == 0 {
		t.Fatal("fixture parsed to nothing; ParseCIDRList is still dropping IPv6")
	}
	got := Collapse(in)
	assertSameUnion(t, in, got)
	if len(got) > len(in) {
		t.Fatalf("collapse grew the set: %d -> %d", len(in), len(got))
	}
	if !isMaximallyCollapsed(got) {
		t.Fatalf("not maximally collapsed: %v", got)
	}
}

func prefixSlicesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
