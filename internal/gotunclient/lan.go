package gotunclient

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/legion/go-tun/internal/linux"
)

// DetectOnLinkPrefixes returns the prefixes of both families configured on UP
// non-loopback interfaces.
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
			if !ok {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if (bits != 32 && bits != 128) || ones < 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			// fe80::/64 exists on every interface and is not a LAN worth
			// protecting; worse, "ip -6 route get" on a link-local address
			// fails without a dev, which would make the on-link assertion
			// permanently unsatisfiable.
			if addr.IsLinkLocalUnicast() || addr.IsLoopback() || addr.IsMulticast() {
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
		if !p.IsValid() {
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
// It works for IPv6 unchanged: the two addresses are only ever arguments to
// "ip route get", which is a FIB lookup, so nothing is sent to them and their
// reachability is irrelevant. A /64 costs exactly two lookups, not 2^64.
func ProbeHosts(p netip.Prefix) ([]netip.Addr, error) {
	if !p.IsValid() {
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

// nextAddr and prevAddr delegate to the standard library, which is already
// family-generic. Both can return an invalid Addr at the edges of the address
// space, so callers check.
func nextAddr(a netip.Addr) netip.Addr { return a.Next() }

func prevAddr(a netip.Addr) netip.Addr { return a.Prev() }

// lastUsable returns the highest address worth probing in p.
//
// For IPv4 that is the broadcast address minus one, where a broadcast address
// exists. IPv6 has no broadcast address, so the top of the prefix is returned
// as is -- it falls in the RFC 2526 subnet-anycast reserve, which does not
// matter here because the address is only ever handed to "ip route get".
func lastUsable(p netip.Prefix) netip.Addr {
	top := setHostBits(p)
	if p.Addr().Is4() && p.Bits() < 31 {
		return prevAddr(top)
	}
	return top
}

// setHostBits returns the address with every host bit set.
func setHostBits(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Addr().As4()
		for i := 0; i < 32-p.Bits(); i++ {
			b[3-i/8] |= 1 << uint(i%8)
		}
		return netip.AddrFrom4(b)
	}
	b := p.Addr().As16()
	for i := 0; i < 128-p.Bits(); i++ {
		b[15-i/8] |= 1 << uint(i%8)
	}
	return netip.AddrFrom16(b)
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

// famFlag is the iproute2 family selector for an address.
func famFlag(a netip.Addr) string {
	if a.Is4() {
		return "-4"
	}
	return "-6"
}

// RouteGet resolves how the kernel would reach dest. The family follows the
// destination, so the same call works for both.
func RouteGet(r linux.Runner, dest netip.Addr) (RouteResult, error) {
	out, err := r.Run("ip", famFlag(dest), "route", "get", dest.String())
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

// ErrNoDefaultRoute6 means this host has no IPv6 default route at all.
//
// It is a sentinel rather than a plain error because for IPv6 that is an
// ordinary state -- a v4-only network -- and callers treat it as "there is no
// IPv6 here to manage" rather than as a failure.
var ErrNoDefaultRoute6 = errors.New("no IPv6 default route")

// AssertSingleDefaultRoute fails unless exactly one IPv4 default route exists.
// Two defaults mean a second uplink (or a duplicated static route from a double
// enable) is silently competing for off-LAN traffic.
func AssertSingleDefaultRoute(r linux.Runner) error {
	return assertSingleDefaultRoute(r, "-4")
}

// AssertSingleDefaultRoute6 is the IPv6 counterpart. Zero default routes
// returns ErrNoDefaultRoute6 rather than a hard error.
func AssertSingleDefaultRoute6(r linux.Runner) error {
	return assertSingleDefaultRoute(r, "-6")
}

func assertSingleDefaultRoute(r linux.Runner, fam string) error {
	name := "IPv4"
	if fam == "-6" {
		name = "IPv6"
	}
	out, err := r.Run("ip", fam, "route", "show", "default")
	if err != nil {
		return fmt.Errorf("read %s default routes: %w", name, err)
	}
	devs := defaultRouteDevices(out)
	switch len(devs) {
	case 1:
		return nil
	case 0:
		if fam == "-6" {
			return ErrNoDefaultRoute6
		}
		return fmt.Errorf("no IPv4 default route")
	default:
		return fmt.Errorf("expected one %s default route, found %d (%s):\n%s",
			name, len(devs), strings.Join(devs, ", "), strings.TrimSpace(out))
	}
}

// HostFamilies reports which families currently have a default route.
//
// Empty output is read as absence, never as an error: a host may legitimately
// have only one family, and a fake Runner returns "" for anything it was not
// told about, so treating silence as failure would make every existing test
// that never mentions IPv6 start failing.
func HostFamilies(r linux.Runner) (v4, v6 bool) {
	if out, err := r.Run("ip", "-4", "route", "show", "default"); err == nil {
		v4 = len(defaultRouteDevices(out)) > 0
	}
	if out, err := r.Run("ip", "-6", "route", "show", "default"); err == nil {
		v6 = len(defaultRouteDevices(out)) > 0
	}
	return v4, v6
}

// DetectGateway6 finds the gotun box's IPv6 address by matching the link-layer
// address its IPv4 address answers with.
//
// Deriving it from the current IPv6 default route would be exactly backwards:
// before enable, that route points at the ISP router, not at gotun. The MAC is
// the only thing that ties the two addresses of the same box together.
//
// A global or ULA address is preferred over the link-local one, because a
// link-local nexthop constrains the route to a single device.
func DetectGateway6(r linux.Runner, dev string, gw4 netip.Addr) (netip.Addr, error) {
	if !gw4.IsValid() {
		return netip.Addr{}, fmt.Errorf("no IPv4 gateway to match against")
	}
	out, err := r.Run("ip", "-4", "neigh", "show", gw4.String(), "dev", dev)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read the gateway's neighbour entry: %w", err)
	}
	lladdr := neighLLAddr(out)
	if lladdr == "" {
		return netip.Addr{}, fmt.Errorf("gateway %s has no neighbour entry on %s"+
			" (ping it once so the kernel learns its address)", gw4, dev)
	}

	out6, err := r.Run("ip", "-6", "neigh", "show", "dev", dev)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read IPv6 neighbours: %w", err)
	}
	var linkLocal netip.Addr
	for _, line := range strings.Split(out6, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || neighLLAddr(line) != lladdr {
			continue
		}
		a, err := netip.ParseAddr(fields[0])
		if err != nil || !a.Is6() {
			continue
		}
		if a.IsLinkLocalUnicast() {
			if !linkLocal.IsValid() {
				linkLocal = a
			}
			continue
		}
		return a, nil
	}
	if linkLocal.IsValid() {
		return linkLocal, nil
	}
	return netip.Addr{}, fmt.Errorf("no IPv6 neighbour on %s shares the gateway's"+
		" link-layer address %s", dev, lladdr)
}

// neighLLAddr pulls the lladdr out of an "ip neigh" line.
func neighLLAddr(line string) string {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "lladdr" {
			return strings.ToLower(fields[i+1])
		}
	}
	return ""
}

// FlushRouteCache drops cached route exceptions (PMTU discoveries and accepted
// ICMP redirects) so a subsequent `ip route get` reflects the FIB rather than a
// stale per-destination exception. Best effort: it needs root.
func FlushRouteCache(r linux.Runner) error {
	_, err := r.Run("ip", "route", "flush", "cache")
	return err
}
