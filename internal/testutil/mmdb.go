package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"net/netip"

	"github.com/legion/go-tun/internal/prefixes"
)

// ModuleRoot returns the go-tun module root directory.
func ModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/testutil -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// MMDBPath returns the path to the local City MMDB if it exists. GOTUN_MMDB
// overrides the default location, so a dev box need not copy licensed data into
// the tree.
func MMDBPath(t *testing.T) (string, bool) {
	t.Helper()
	p := os.Getenv("GOTUN_MMDB")
	if p == "" {
		p = filepath.Join(ModuleRoot(t), "data", "geo", "GeoIP2-City.mmdb")
	}
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return p, true
}

// LoadAllRUfromMMDB extracts every RU prefix, both families, from the local
// City MMDB. Skips the test if the MMDB is missing.
//
// The per-family minimums exist because a single total would not notice one
// family vanishing: a v4-only extract still clears any threshold a mixed one
// would. The IPv6 floor is kept well under the real count (~12k) so ordinary
// MaxMind data churn does not turn it into a tripwire.
func LoadAllRUfromMMDB(t *testing.T) []netip.Prefix {
	t.Helper()
	path, ok := MMDBPath(t)
	if !ok {
		t.Skip("local MMDB not available at data/geo/GeoIP2-City.mmdb")
	}
	prefs, err := prefixes.ExtractCountryFromMMDB(path, "RU")
	if err != nil {
		t.Fatalf("extract RU from MMDB: %v", err)
	}
	var n4, n6 int
	for _, p := range prefs {
		if !p.IsValid() {
			t.Fatalf("invalid prefix: %v", p)
		}
		if p.Addr().Is4In6() {
			t.Fatalf("4-in-6 prefix %v: aliased IPv4 space leaked into the IPv6 half", p)
		}
		if p.Addr().Is4() {
			n4++
		} else {
			n6++
		}
	}
	if n4 < 1000 {
		t.Fatalf("expected >= 1000 RU IPv4 prefixes from City MMDB, got %d", n4)
	}
	if n6 < 100 {
		t.Fatalf("expected >= 100 RU IPv6 prefixes from City MMDB, got %d", n6)
	}
	return prefs
}

// LoadRUv4FromMMDB and LoadRUv6FromMMDB are the single-family views, for tests
// that build a family-specific nftables set.
func LoadRUv4FromMMDB(t *testing.T) []netip.Prefix {
	t.Helper()
	return filterFamily(LoadAllRUfromMMDB(t), true)
}

func LoadRUv6FromMMDB(t *testing.T) []netip.Prefix {
	t.Helper()
	return filterFamily(LoadAllRUfromMMDB(t), false)
}

func filterFamily(prefs []netip.Prefix, v4 bool) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if p.Addr().Is4() == v4 {
			out = append(out, p)
		}
	}
	return out
}
