package prefixes

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ParseCIDRList reads one CIDR per line (comments and blanks ignored).
func ParseCIDRList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", line, err)
		}
		if p.Addr().Is4In6() {
			// ::ffff:a.b.c.d reports Is6, so it would be classified into the
			// IPv6 set, where it can never match: the kernel matches a v6
			// packet's destination and a v4 packet never presents one. Refuse
			// rather than silently classify nothing.
			return nil, fmt.Errorf("parse cidr %q: 4-in-6 prefix; write it as plain IPv4", line)
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// ParseCIDRFile loads a CIDR list from disk.
func ParseCIDRFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseCIDRList(f)
}

// ParseMaxMindCountryDir parses GeoLite2-Country-CSV style directories.
// Expects Locations-en.csv plus Blocks-IPv4.csv and/or Blocks-IPv6.csv.
//
// The IPv6 blocks file is optional: the MaxMind zip has always contained it and
// extractZip has always unpacked it, but older fixture directories carry only
// the IPv4 one, and a v4-only directory must keep working rather than become an
// error. At least one blocks file is required.
func ParseMaxMindCountryDir(dir, countryISO string) ([]netip.Prefix, error) {
	locPath := findFile(dir, "Locations-en.csv", "GeoLite2-Country-Locations-en.csv")
	if locPath == "" {
		return nil, fmt.Errorf("maxmind: missing Locations-en.csv in %s", dir)
	}
	blocks4 := findFile(dir, "Blocks-IPv4.csv", "GeoLite2-Country-Blocks-IPv4.csv")
	blocks6 := findFile(dir, "Blocks-IPv6.csv", "GeoLite2-Country-Blocks-IPv6.csv")
	if blocks4 == "" && blocks6 == "" {
		return nil, fmt.Errorf("maxmind: missing Blocks-IPv4.csv and Blocks-IPv6.csv in %s", dir)
	}

	geonames, err := loadCountryGeonames(locPath, countryISO)
	if err != nil {
		return nil, err
	}

	var out []netip.Prefix
	for _, path := range []string{blocks4, blocks6} {
		if path == "" {
			continue
		}
		prefs, err := loadBlocksForGeonames(path, geonames)
		if err != nil {
			return nil, err
		}
		out = append(out, prefs...)
	}
	return out, nil
}

func findFile(dir string, names ...string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, n := range names {
			if e.Name() == n || strings.HasSuffix(e.Name(), n) {
				return filepath.Join(dir, e.Name())
			}
		}
	}
	// also try exact paths
	for _, n := range names {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func loadCountryGeonames(path, iso string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idxID := indexOf(header, "geoname_id")
	idxISO := indexOf(header, "country_iso_code")
	if idxID < 0 || idxISO < 0 {
		return nil, fmt.Errorf("maxmind locations: missing geoname_id or country_iso_code columns")
	}
	want := strings.ToUpper(iso)
	out := map[string]struct{}{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) <= idxID || len(rec) <= idxISO {
			continue
		}
		if strings.ToUpper(rec[idxISO]) == want {
			out[rec[idxID]] = struct{}{}
		}
	}
	return out, nil
}

func loadBlocksForGeonames(path string, geonames map[string]struct{}) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	idxNet := indexOf(header, "network")
	idxGeo := indexOf(header, "geoname_id")
	idxReg := indexOf(header, "registered_country_geoname_id")
	if idxNet < 0 {
		return nil, fmt.Errorf("maxmind blocks: missing network column")
	}
	var out []netip.Prefix
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) <= idxNet {
			continue
		}
		gid := ""
		if idxGeo >= 0 && idxGeo < len(rec) && rec[idxGeo] != "" {
			gid = rec[idxGeo]
		} else if idxReg >= 0 && idxReg < len(rec) {
			gid = rec[idxReg]
		}
		if _, ok := geonames[gid]; !ok {
			continue
		}
		p, err := netip.ParsePrefix(rec[idxNet])
		if err != nil {
			return nil, fmt.Errorf("maxmind network %q: %w", rec[idxNet], err)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("maxmind network %q: 4-in-6 prefix", rec[idxNet])
		}
		out = append(out, p)
	}
	return out, nil
}

func indexOf(header []string, name string) int {
	for i, h := range header {
		if h == name {
			return i
		}
	}
	return -1
}

// WriteCIDRList writes prefixes one per line.
func WriteCIDRList(path string, prefixes []netip.Prefix) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, p := range prefixes {
		if _, err := fmt.Fprintln(f, p.String()); err != nil {
			return err
		}
	}
	return nil
}

// Families selects which address families a command emits.
type Families struct{ V4, V6 bool }

// ParseFamilies parses a -families flag value such as "v4", "v6" or "v4,v6".
func ParseFamilies(s string) (Families, error) {
	f := Families{}
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "":
			continue
		case "v4", "ipv4", "4":
			f.V4 = true
		case "v6", "ipv6", "6":
			f.V6 = true
		case "all", "both":
			f.V4, f.V6 = true, true
		default:
			return Families{}, fmt.Errorf("unknown address family %q (want v4, v6 or v4,v6)", part)
		}
	}
	if !f.V4 && !f.V6 {
		return Families{}, fmt.Errorf("no address family selected")
	}
	return f, nil
}

func (f Families) String() string {
	switch {
	case f.V4 && f.V6:
		return "v4,v6"
	case f.V6:
		return "v6"
	default:
		return "v4"
	}
}

// FilterFamilies keeps only the prefixes whose family is selected.
func FilterFamilies(prefs []netip.Prefix, f Families) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefs))
	for _, p := range prefs {
		if p.Addr().Is4() {
			if f.V4 {
				out = append(out, p)
			}
			continue
		}
		if f.V6 {
			out = append(out, p)
		}
	}
	return out
}

// CountFamilies reports how many prefixes of each family are present, for the
// per-family summaries the CLI prints.
func CountFamilies(prefs []netip.Prefix) (v4, v6 int) {
	for _, p := range prefs {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	return v4, v6
}
