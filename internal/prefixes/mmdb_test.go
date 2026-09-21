package prefixes_test

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/legion/go-tun/internal/prefixes"
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
