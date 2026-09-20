package gotunclient

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/legion/go-tun/internal/linux"
)

// DetectOnLinkPrefixes returns IPv4 prefixes configured on UP non-loopback interfaces.
func DetectOnLinkPrefixes() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := map[netip.Prefix]struct{}{}
	var out []netip.Prefix
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
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 || ones < 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP.To4())
			if !ok {
				continue
			}
			p := netip.PrefixFrom(addr, ones).Masked()
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

// MergePrefixes unions extras into base (masked, deduped).
func MergePrefixes(base []netip.Prefix, extras ...netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]struct{}{}
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		if !p.IsValid() || !p.Addr().Is4() {
			return
		}
		p = p.Masked()
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range base {
		add(p)
	}
	for _, p := range extras {
		add(p)
	}
	return out
}

// ProbeHost returns a usable host address inside p for route probes (network+1 when possible).
func ProbeHost(p netip.Prefix) (netip.Addr, error) {
	hosts, err := ProbeHosts(p)
	if err != nil {
		return netip.Addr{}, err
	}
	return hosts[0], nil
}

// ProbeHosts returns up to two host addresses inside p: the first and last
// usable ones. Probing two matters because a stale per-host route exception
// (an ICMP redirect NM did not install) can make a single probe read on-link
// when the prefix as a whole is not.
func ProbeHosts(p netip.Prefix) ([]netip.Addr, error) {
	if !p.IsValid() || !p.Addr().Is4() {
		return nil, fmt.Errorf("invalid prefix %s", p)
	}
	if p.IsSingleIP() {
		return []netip.Addr{p.Addr()}, nil
	}
	first := nextAddr(p.Addr())
	if !p.Contains(first) {
		return []netip.Addr{p.Addr()}, nil
	}
	last := lastUsable(p)
	if last == first || !p.Contains(last) {
		return []netip.Addr{first}, nil
	}
	return []netip.Addr{first, last}, nil
}

func nextAddr(a netip.Addr) netip.Addr {
	b := a.As4()
	for i := 3; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return netip.AddrFrom4(b)
}

func prevAddr(a netip.Addr) netip.Addr {
	b := a.As4()
	for i := 3; i >= 0; i-- {
		if b[i] != 0 {
			b[i]--
			break
		}
		b[i] = 0xff
	}
	return netip.AddrFrom4(b)
}

// lastUsable returns the broadcast address minus one for prefixes that have a
// broadcast address, else the last address in the prefix.
func lastUsable(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	hostBits := 32 - p.Bits()
	// Set all host bits to 1 -> broadcast, then step back one.
	for i := 0; i < hostBits; i++ {
		byteIdx := 3 - i/8
		bitIdx := uint(i % 8)
		b[byteIdx] |= 1 << bitIdx
	}
	bcast := netip.AddrFrom4(b)
	if p.Bits() >= 31 {
		return bcast
	}
	return prevAddr(bcast)
}

// RouteResult is a parsed `ip route get` answer.
type RouteResult struct {
	Via   netip.Addr // zero when the destination is on-link
	Dev   string
	Local bool
	Line  string
}

// parseRouteGet extracts the nexthop and device from `ip -4 route get` output.
// A route with no "via" keyword is on-link and leaves Via unset.
func parseRouteGet(out string) (RouteResult, error) {
	res := RouteResult{Line: strings.TrimSpace(strings.ReplaceAll(out, "\n", " "))}
	first := out
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		first = out[:i]
	}
	f := strings.Fields(first)
	if len(f) == 0 {
		return res, fmt.Errorf("empty ip route get output")
	}
	if f[0] == "local" {
		res.Local = true
	}
	if f[0] == "unreachable" || f[0] == "blackhole" || f[0] == "prohibit" {
		return res, fmt.Errorf("destination %s", f[0])
	}
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case "via":
			a, err := netip.ParseAddr(f[i+1])
			if err != nil {
				return res, fmt.Errorf("parse nexthop %q: %w", f[i+1], err)
			}
			res.Via = a
		case "dev":
			res.Dev = f[i+1]
		}
	}
	return res, nil
}

// RouteGet resolves how the kernel would reach dest.
func RouteGet(r linux.Runner, dest netip.Addr) (RouteResult, error) {
	out, err := r.Run("ip", "-4", "route", "get", dest.String())
	if err != nil {
		return RouteResult{}, fmt.Errorf("ip route get %s: %w", dest, err)
	}
	return parseRouteGet(out)
}

// RouteViaGateway reports whether `ip route get dest` would use via gateway.
//
// The nexthop is compared as an address, not by substring: gateway 192.168.8.16
// must not match a route line reading "via 192.168.8.162".
func RouteViaGateway(r linux.Runner, dest, gateway netip.Addr) (viaGateway bool, routeLine string, err error) {
	res, err := RouteGet(r, dest)
	if err != nil {
		return false, res.Line, err
	}
	return res.Via.IsValid() && res.Via == gateway, res.Line, nil
}

// AssertLANsOnLink fails if any protected prefix routes via gotunGateway.
func AssertLANsOnLink(r linux.Runner, protected []netip.Prefix, gotunGateway netip.Addr) error {
	var errs []string
	for _, p := range protected {
		hosts, err := ProbeHosts(p)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		for _, host := range hosts {
			if host == gotunGateway {
				// Probing the gateway address itself proves nothing either way.
				continue
			}
			via, line, err := RouteViaGateway(r, host, gotunGateway)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if via {
				errs = append(errs, fmt.Sprintf("LAN %s probe %s routes via gotun gateway: %s", p, host, line))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("LAN safety failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// AssertDefaultViaGateway fails unless off-LAN traffic to probe leaves via gw.
func AssertDefaultViaGateway(r linux.Runner, probe, gw netip.Addr) error {
	res, err := RouteGet(r, probe)
	if err != nil {
		return err
	}
	if !res.Via.IsValid() {
		return fmt.Errorf("off-LAN probe %s is on-link (dev %s), expected via %s: %s", probe, res.Dev, gw, res.Line)
	}
	if res.Via != gw {
		return fmt.Errorf("off-LAN probe %s routes via %s, expected %s: %s", probe, res.Via, gw, res.Line)
	}
	return nil
}

// AssertSingleDefaultRoute fails unless exactly one IPv4 default route exists.
// Two defaults mean a second uplink (or a duplicated static route from a double
// enable) is silently competing for off-LAN traffic.
func AssertSingleDefaultRoute(r linux.Runner) error {
	out, err := r.Run("ip", "-4", "route", "show", "default")
	if err != nil {
		return fmt.Errorf("read default routes: %w", err)
	}
	devs := defaultRouteDevices(out)
	switch len(devs) {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("no IPv4 default route")
	default:
		return fmt.Errorf("expected one IPv4 default route, found %d (%s):\n%s",
			len(devs), strings.Join(devs, ", "), strings.TrimSpace(out))
	}
}

// FlushRouteCache drops cached route exceptions (PMTU discoveries and accepted
// ICMP redirects) so a subsequent `ip route get` reflects the FIB rather than a
// stale per-destination exception. Best effort: it needs root.
func FlushRouteCache(r linux.Runner) error {
	_, err := r.Run("ip", "route", "flush", "cache")
	return err
}
