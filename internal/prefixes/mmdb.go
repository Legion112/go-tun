package prefixes

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

type mmdbCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// ExtractCountryFromMMDB walks all networks in a MaxMind City/Country MMDB and
// returns the IPv4 and IPv6 prefixes whose country ISO code matches countryISO.
//
// SkipAliasedNetworks is load-bearing, not a tuning knob. MaxMind aliases the
// whole IPv4 tree into the IPv6 tree under ::ffff:0:0/96, 2002::/16 and
// 2001::/32, so without it every IPv4 network is also reported a second time as
// a ::ffff:a.b.c.d prefix. Those copies would land in the IPv6 direct set,
// where they match no traffic, and the real IPv4 entries they duplicate would
// look accounted for -- a country's traffic would quietly stop going direct
// with nothing erroring. The cost of keeping the flag is that genuine
// 6to4/Teredo space is not classified, which is the right trade.
func ExtractCountryFromMMDB(mmdbPath, countryISO string) ([]netip.Prefix, error) {
	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("open mmdb: %w", err)
	}
	defer db.Close()

	want := strings.ToUpper(countryISO)
	var out []netip.Prefix

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec mmdbCountryRecord
		subnet, err := networks.Network(&rec)
		if err != nil {
			return nil, fmt.Errorf("mmdb network: %w", err)
		}
		iso := rec.Country.ISOCode
		if iso == "" {
			iso = rec.RegisteredCountry.ISOCode
		}
		if strings.ToUpper(iso) != want {
			continue
		}
		p, ok := ipNetToPrefix(subnet)
		if !ok {
			continue
		}
		out = append(out, p)
	}
	if err := networks.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// FetchFromMMDB extracts country prefixes from a local MMDB and writes a CIDR list.
func FetchFromMMDB(mmdbPath, countryISO, outPath string) error {
	prefs, err := ExtractCountryFromMMDB(mmdbPath, countryISO)
	if err != nil {
		return err
	}
	return WriteCIDRList(outPath, Collapse(prefs))
}

// LoadCountryPrefixesRaw returns country prefixes of both families, uncollapsed.
// Prefer LoadCountryPrefixes for configuration paths.
func LoadCountryPrefixesRaw(licenseKey, countryISO, mmdbPath string) ([]netip.Prefix, error) {
	if mmdbPath != "" {
		return ExtractCountryFromMMDB(mmdbPath, countryISO)
	}
	return DownloadGeoLite2CountryPrefixes(licenseKey, countryISO)
}

// LoadCountryPrefixes returns country prefixes (both families) from a local MMDB or MaxMind CSV download,
// collapsed with Collapse for configuration use.
// When mmdbPath is non-empty, the MMDB is used; otherwise licenseKey is required for CSV download.
func LoadCountryPrefixes(licenseKey, countryISO, mmdbPath string) ([]netip.Prefix, error) {
	prefs, err := LoadCountryPrefixesRaw(licenseKey, countryISO, mmdbPath)
	if err != nil {
		return nil, err
	}
	return Collapse(prefs), nil
}

// ipNetToPrefix converts a MaxMind network to a netip.Prefix.
//
// maxminddb hands back a 4-byte IP with a /32-based mask for IPv4 networks and
// a 16-byte one with a /128-based mask for IPv6, so the two cases are told
// apart by mask width rather than by inspecting the address. A 4-in-6 address
// is unmapped to its IPv4 form: it denotes IPv4 addresses, and leaving it in
// the v6 half would put it in an ipv6_addr set where it matches nothing.
func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	switch bits {
	case 32:
		ip4 := n.IP.To4()
		if ip4 == nil {
			return netip.Prefix{}, false
		}
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(addr, ones), true
	case 128:
		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			return netip.Prefix{}, false
		}
		if addr.Is4In6() && ones >= 96 {
			return netip.PrefixFrom(addr.Unmap(), ones-96), true
		}
		return netip.PrefixFrom(addr, ones), true
	default:
		return netip.Prefix{}, false
	}
}
