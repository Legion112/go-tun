package linux

import (
	"net"
	"net/netip"
	"sort"
)

// InterfacesForPrefixes returns the names of UP non-loopback interfaces holding
// an IPv4 address inside one of the given prefixes, sorted for stable output.
//
// It exists so per-device sysctls can be applied to the client-facing NICs
// without the caller having to name them.
func InterfacesForPrefixes(prefixes []netip.Prefix) ([]string, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			// Unmap matters: net.IPNet hands back a 16-byte slice for IPv4
			// addresses too, and a 4-in-6 Addr is not Contains-ed by an IPv4
			// prefix, so without this every IPv4 LAN would stop matching.
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			for _, p := range prefixes {
				if p.Contains(addr) {
					seen[iface.Name] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
