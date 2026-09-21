package prefixes

import (
	"math/big"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestCollapseIPv4_MergeSiblings(t *testing.T) {
	in := mustPrefs(t, "2.60.4.0/23", "2.60.6.0/23")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "2.60.4.0/22")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_NoMergeAcrossGap(t *testing.T) {
	in := mustPrefs(t, "2.60.4.0/23", "2.60.8.0/23")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "2.60.4.0/23", "2.60.8.0/23")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_RemoveCovered(t *testing.T) {
	in := mustPrefs(t, "10.0.0.0/8", "10.1.2.0/24")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "10.0.0.0/8")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_CascadingMerge(t *testing.T) {
	in := mustPrefs(t,
		"10.0.0.0/26",
		"10.0.0.64/26",
		"10.0.0.128/26",
		"10.0.0.192/26",
	)
	got := CollapseIPv4(in)
	want := mustPrefs(t, "10.0.0.0/24")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_OctetBoundary(t *testing.T) {
	in := mustPrefs(t, "10.0.0.0/9", "10.128.0.0/9")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "10.0.0.0/8")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_MergeToDefault(t *testing.T) {
	in := mustPrefs(t, "0.0.0.0/1", "128.0.0.0/1")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "0.0.0.0/0")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_DedupeCanonicalize(t *testing.T) {
	in := mustPrefs(t, "10.0.0.1/24", "10.0.0.0/24", "10.0.0.50/24")
	got := CollapseIPv4(in)
	want := mustPrefs(t, "10.0.0.0/24")
	assertPrefixesEqual(t, got, want)
	assertSameIPv4Union(t, in, got)
}

func TestCollapseIPv4_Idempotent(t *testing.T) {
	in := mustPrefs(t, "2.60.4.0/23", "2.60.6.0/23", "10.0.0.0/8", "10.1.0.0/16")
	once := CollapseIPv4(in)
	twice := CollapseIPv4(once)
	assertPrefixesEqual(t, once, twice)
	if !isMaximallyCollapsed(once) {
		t.Fatalf("not maximally collapsed: %v", once)
	}
}

func TestCollapseIPv4_OverlappingUnionOracle(t *testing.T) {
	// Naïve size sum would be 2^24+2^16; union is 2^24.
	in := mustPrefs(t, "10.0.0.0/8", "10.1.0.0/16")
	got := CollapseIPv4(in)
	assertSameIPv4Union(t, in, got)
	if n := unionAddressCount(prefixesToMergedIntervals(t, got)); n.Cmp(big.NewInt(1<<24)) != 0 {
		t.Fatalf("want 2^24 addresses, got %s", n)
	}
}

func TestCollapseIPv4_PanicOnIPv6(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on IPv6")
		}
	}()
	_ = CollapseIPv4(mustPrefs(t, "2001:db8::/32"))
}

func TestCollapseIPv4_Empty(t *testing.T) {
	if got := CollapseIPv4(nil); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestCollapseIPv4_RUFixture(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "prefixes", "ru-fixture.txt")
	in, err := ParseCIDRFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := CollapseIPv4(in)
	assertSameIPv4Union(t, in, got)
	if len(got) > len(in) {
		t.Fatalf("collapsed grew: %d → %d", len(in), len(got))
	}
	if !isMaximallyCollapsed(got) {
		t.Fatalf("not maximally collapsed")
	}
	twice := CollapseIPv4(got)
	assertPrefixesEqual(t, got, twice)
}

func mustPrefs(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func assertPrefixesEqual(t *testing.T, got, want []netip.Prefix) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
