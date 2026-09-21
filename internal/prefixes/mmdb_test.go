package prefixes_test

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/legion/go-tun/internal/prefixes"
	"github.com/legion/go-tun/internal/testutil"
)

func TestExtractCountryFromMMDB_MissingFile(t *testing.T) {
	_, err := prefixes.ExtractCountryFromMMDB("/nonexistent/GeoIP2-City.mmdb", "RU")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestExtractCountryFromMMDB_InvalidFile(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller failed")
	}
	// Use a non-MMDB file
	bad := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "prefixes", "ru-fixture.txt")
	_, err := prefixes.ExtractCountryFromMMDB(bad, "RU")
	if err == nil {
		t.Fatal("expected error for invalid mmdb")
	}
}

func TestExtractCountryFromMMDB_LiveOptional(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller failed")
	}
	mmdb := filepath.Join(filepath.Dir(thisFile), "..", "..", "data", "geo", "GeoIP2-City.mmdb")
	prefs, err := prefixes.ExtractCountryFromMMDB(mmdb, "RU")
	if err != nil {
		t.Skipf("local MMDB not available at data/geo/GeoIP2-City.mmdb: %v", err)
	}
	var n4, n6 int
	// The aliased copies of the IPv4 tree that SkipAliasedNetworks suppresses.
	// If one ever reaches the direct set it matches no traffic, while looking
	// like the IPv4 entry it duplicates is accounted for.
	aliases := []netip.Prefix{
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/32"),
	}
	for _, p := range prefs {
		if !p.IsValid() {
			t.Fatalf("invalid prefix %s", p)
		}
		if p.Addr().Is4In6() {
			t.Fatalf("4-in-6 prefix %s leaked into the direct set", p)
		}
		if p.Addr().Is4() {
			n4++
			continue
		}
		n6++
		for _, a := range aliases {
			if a.Overlaps(p) {
				t.Fatalf("aliased IPv4 space %s leaked in as IPv6 %s", a, p)
			}
		}
	}
	if n4 < 1000 {
		t.Fatalf("expected many RU IPv4 prefixes from City MMDB, got %d", n4)
	}
	if n6 < 100 {
		t.Fatalf("expected RU IPv6 prefixes from City MMDB, got %d", n6)
	}
	t.Logf("extracted %d RU IPv4 and %d RU IPv6 prefixes", n4, n6)
}

// ruFixtureMMDB is a synthetic dual-stack database. It exists because the MMDB
// path is the primary production path -- make fetch-prefixes prefers it, and
// LoadCountryPrefixesRaw prefers it -- yet all of its positive coverage used to
// depend on a licensed file that is gitignored and usually absent.
func ruFixtureMMDB(t *testing.T) string {
	t.Helper()
	return testutil.BuildCountryMMDB(t, map[string][]netip.Prefix{
		"RU": {
			netip.MustParsePrefix("10.200.0.0/24"),
			netip.MustParsePrefix("10.200.1.0/24"),
			netip.MustParsePrefix("5.45.192.0/18"),
			netip.MustParsePrefix("2a02:6b8::/32"),
			netip.MustParsePrefix("2a00:1148::/32"),
		},
		"US": {
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	})
}

func TestExtractCountryFromMMDB_ReturnsBothFamilies(t *testing.T) {
	got, err := prefixes.ExtractCountryFromMMDB(ruFixtureMMDB(t), "RU")
	if err != nil {
		t.Fatal(err)
	}
	// 10.200.0.0/24 and 10.200.1.0/24 come back merged as a /23. That is the
	// MMDB tree, not the extractor: adjacent nodes carrying the same record
	// are one node, so the reader reports the shortest prefix covering them.
	// Worth knowing, because it means the extractor's output is already
	// partly aggregated before Collapse ever sees it.
	want := map[string]bool{
		"10.200.0.0/23":  true,
		"5.45.192.0/18":  true,
		"2a02:6b8::/32":  true,
		"2a00:1148::/32": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Fatalf("unexpected prefix %s in %v", p, got)
		}
	}
}

// TestExtractCountryFromMMDB_NoAliasedIPv4LeaksAsIPv6 is the reason this
// fixture is generated rather than hand-written.
//
// MaxMind aliases the whole IPv4 tree into the IPv6 tree, so without
// SkipAliasedNetworks every IPv4 network is also reported as a ::ffff: prefix.
// Those copies match no traffic, and the real IPv4 entries they duplicate look
// accounted for -- RU traffic would quietly stop going direct and nothing would
// error. A CSV fixture cannot reproduce that tree shape.
func TestExtractCountryFromMMDB_NoAliasedIPv4LeaksAsIPv6(t *testing.T) {
	got, err := prefixes.ExtractCountryFromMMDB(ruFixtureMMDB(t), "RU")
	if err != nil {
		t.Fatal(err)
	}
	aliases := []netip.Prefix{
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/32"),
	}
	for _, p := range got {
		if p.Addr().Is4In6() {
			t.Fatalf("4-in-6 prefix %s: the aliased IPv4 tree leaked into the IPv6 half", p)
		}
		if p.Addr().Is4() {
			continue
		}
		for _, a := range aliases {
			if a.Overlaps(p) {
				t.Fatalf("aliased IPv4 space %s leaked in as IPv6 %s", a, p)
			}
		}
	}
}

func TestExtractCountryFromMMDB_OtherCountriesExcluded(t *testing.T) {
	got, err := prefixes.ExtractCountryFromMMDB(ruFixtureMMDB(t), "US")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the two US prefixes, got %v", got)
	}
	for _, p := range got {
		if p.String() != "198.51.100.0/24" && p.String() != "2001:db8::/32" {
			t.Fatalf("unexpected US prefix %s", p)
		}
	}
}

func TestExtractCountryFromMMDB_UnknownCountryIsEmpty(t *testing.T) {
	got, err := prefixes.ExtractCountryFromMMDB(ruFixtureMMDB(t), "ZZ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want nothing, got %v", got)
	}
}

// TestLoadCountryPrefixes_CollapsesBothFamilies covers the whole configuration
// path: extract, then collapse, with the two 10.200.x /24s merging into a /23.
func TestLoadCountryPrefixes_CollapsesBothFamilies(t *testing.T) {
	got, err := prefixes.LoadCountryPrefixes("", "RU", ruFixtureMMDB(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"10.200.0.0/23":  true,
		"5.45.192.0/18":  true,
		"2a02:6b8::/32":  true,
		"2a00:1148::/32": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d prefixes", got, len(want))
	}
	for _, p := range got {
		if !want[p.String()] {
			t.Fatalf("unexpected prefix %s in %v", p, got)
		}
	}
}
