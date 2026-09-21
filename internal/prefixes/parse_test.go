package prefixes_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/prefixes"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "prefixes")
}

func TestParseCIDRList(t *testing.T) {
	prefs, err := prefixes.ParseCIDRFile(filepath.Join(testdataDir(t), "ru-fixture.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefs))
	}
	if prefs[0].String() != "10.200.0.0/24" {
		t.Fatalf("got %s", prefs[0])
	}
}

func TestParseMaxMindCountryDir_RU(t *testing.T) {
	dir := testdataDir(t)
	prefs, err := prefixes.ParseMaxMindCountryDir(dir, "RU")
	if err != nil {
		t.Fatal(err)
	}
	// Both blocks files are read. The IPv4 assertions stay explicit: a change
	// that swapped Blocks-IPv4 for Blocks-IPv6 rather than reading both would
	// still return four prefixes and pass a bare count check.
	want := map[string]bool{
		"10.200.0.0/24":  true,
		"10.200.1.0/24":  true,
		"2a02:6b8::/32":  true,
		"2a00:1148::/32": true,
		"2a03:d000::/32": true, // empty geoname_id, falls back to registered_country
	}
	if len(prefs) != len(want) {
		t.Fatalf("got %d RU prefixes, want %d: %v", len(prefs), len(want), prefs)
	}
	for _, p := range prefs {
		if !want[p.String()] {
			t.Fatalf("unexpected RU prefix %s in %v", p, prefs)
		}
	}
	us, err := prefixes.ParseMaxMindCountryDir(dir, "US")
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 2 || us[0].String() != "198.51.100.0/24" || us[1].String() != "2001:db8::/32" {
		t.Fatalf("US prefixes: %v", us)
	}
}

// TestParseMaxMindCountryDir_IPv6BlocksOptional pins that a directory carrying
// only the IPv4 blocks file still works. Older extracts and hand-made fixtures
// look like this, and turning them into an error would break them for no gain.
func TestParseMaxMindCountryDir_IPv6BlocksOptional(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"GeoLite2-Country-Locations-en.csv", "GeoLite2-Country-Blocks-IPv4.csv"} {
		data, err := os.ReadFile(filepath.Join(testdataDir(t), name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prefs, err := prefixes.ParseMaxMindCountryDir(dir, "RU")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 2 {
		t.Fatalf("want the 2 IPv4 RU prefixes, got %v", prefs)
	}
}

func TestParseMaxMindCountryDir_NoBlocksFilesErrors(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join(testdataDir(t), "GeoLite2-Country-Locations-en.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GeoLite2-Country-Locations-en.csv"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prefixes.ParseMaxMindCountryDir(dir, "RU"); err == nil {
		t.Fatal("expected an error when no blocks file is present")
	}
}

func TestParseMaxMindCountryDir_Unknown(t *testing.T) {
	prefs, err := prefixes.ParseMaxMindCountryDir(testdataDir(t), "ZZ")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefs) != 0 {
		t.Fatalf("want empty, got %v", prefs)
	}
}

func TestWriteAndParseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src, err := prefixes.ParseMaxMindCountryDir(testdataDir(t), "RU")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	if err := prefixes.WriteCIDRList(out, src); err != nil {
		t.Fatal(err)
	}
	got, err := prefixes.ParseCIDRFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(src) {
		t.Fatalf("roundtrip len %d != %d", len(got), len(src))
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
}

func TestParseCIDRList_KeepsIPv6(t *testing.T) {
	in := "# comment\n10.0.0.0/8\n2001:db8::/32\n\nfd00::/8\n"
	prefs, err := prefixes.ParseCIDRList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "2001:db8::/32", "fd00::/8"}
	if len(prefs) != len(want) {
		t.Fatalf("got %d prefixes, want %d: %v", len(prefs), len(want), prefs)
	}
	for i, w := range want {
		if prefs[i].String() != w {
			t.Fatalf("prefix %d: got %s want %s", i, prefs[i], w)
		}
	}
}

// TestParseCIDRList_Rejects4In6 pins that ::ffff:a.b.c.d is refused rather than
// accepted into the IPv6 half, where it would match no traffic at all.
func TestParseCIDRList_Rejects4In6(t *testing.T) {
	_, err := prefixes.ParseCIDRList(strings.NewReader("::ffff:10.0.0.0/104\n"))
	if err == nil {
		t.Fatal("expected an error for a 4-in-6 prefix")
	}
	if !strings.Contains(err.Error(), "4-in-6") {
		t.Fatalf("error should name the problem, got %v", err)
	}
}

func TestWriteCIDRList_RoundTripsIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.txt")
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2a02:6b8::/32"),
	}
	if err := prefixes.WriteCIDRList(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := prefixes.ParseCIDRFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("round trip lost data: %v", got)
	}
}
