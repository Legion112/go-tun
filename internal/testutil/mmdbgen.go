package testutil

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// BuildCountryMMDB writes a small MMDB mapping prefixes to country ISO codes,
// and returns its path.
//
// IPv4 aliasing is left ENABLED, which is the whole point of synthesising one
// rather than hand-rolling a fixture. MaxMind's own builds alias the entire
// IPv4 tree into the IPv6 tree under ::ffff:0:0/96, 2002::/16 and 2001::/32, so
// a reader that does not skip those sees every IPv4 network a second time as a
// ::ffff: prefix. Those copies would land in the IPv6 direct set, where they
// match no traffic, while looking like the IPv4 entries they duplicate were
// accounted for -- a country's traffic would quietly stop going direct with
// nothing erroring. That tree shape cannot be reproduced with a CSV fixture,
// and this is the only way to test for it without the licensed database.
//
// This is a test-only dependency: it is imported from this file alone, so it
// never reaches the router binary. `go list -deps ./cmd/gotun` confirms.
func BuildCountryMMDB(t *testing.T, byCountry map[string][]netip.Prefix) string {
	t.Helper()

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoIP2-Country",
		RecordSize:   24,
		IPVersion:    6,
		// The lab and the existing fixtures use RFC1918 and documentation
		// space, which the writer excludes by default. Allowing it here keeps
		// the synthetic database addressed like everything else in the tree;
		// what is being tested is the extractor, not MaxMind's own policy
		// about which networks it publishes.
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatalf("new mmdb writer: %v", err)
	}

	for iso, prefs := range byCountry {
		rec := mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)},
			"registered_country": mmdbtype.Map{
				"iso_code": mmdbtype.String(iso),
			},
		}
		for _, p := range prefs {
			_, ipnet, err := net.ParseCIDR(p.String())
			if err != nil {
				t.Fatalf("prefix %s: %v", p, err)
			}
			if err := w.Insert(ipnet, rec); err != nil {
				t.Fatalf("insert %s: %v", p, err)
			}
		}
	}

	path := filepath.Join(t.TempDir(), "test.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatalf("write mmdb: %v", err)
	}
	return path
}
