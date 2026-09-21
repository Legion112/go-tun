package wireguard

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile brings up a managed WireGuard interface from declarative spec.
func Reconcile(r linux.Runner, spec policy.WireGuardSpec) (int, error) {
	if !spec.Managed {
		return 0, nil
	}
	changes := 0
	iface := spec.Interface

	link, err := r.Run("ip", "link", "show", "dev", iface)
	missing := err != nil || link == "" || strings.Contains(link, "does not exist") || strings.Contains(link, "Cannot find")
	if missing {
		if _, err := r.Run("ip", "link", "add", "dev", iface, "type", "wireguard"); err != nil {
			return changes, err
		}
		changes++
	}

	if !spec.Up {
		// Fail-closed: remove AllowedIPs routes and bring interface down.
		for _, p := range spec.Peer.AllowedIPs {
			if p.IsValid() {
				_, _ = r.Run("ip", famFlag(p.Addr()), "route", "del", p.String(), "dev", iface)
			}
		}
		if _, err := r.Run("ip", "link", "set", "dev", iface, "down"); err != nil {
			return changes, err
		}
		changes++
		return changes, nil
	}

	if !missing && semanticMatch(r, iface, link, spec) {
		// Still ensure AllowedIPs routes (except defaults) exist; bounce/up can drop them
		// while the WG peer config remains unchanged.
		n, err := ensureAllowedIPRoutes(r, iface, spec.Peer.AllowedIPs)
		return changes + n, err
	}

	args := []string{"set", iface, "private-key", linux.StdinPath}
	if spec.ListenPort > 0 {
		args = append(args, "listen-port", fmt.Sprintf("%d", spec.ListenPort))
	}
	if _, err := r.RunWithInput("wg", spec.PrivateKey+"\n", args...); err != nil {
		return changes, err
	}
	changes++

	peer := spec.Peer
	if peer.PublicKey != "" {
		pargs := []string{"set", iface, "peer", peer.PublicKey}
		if peer.Endpoint != "" {
			pargs = append(pargs, "endpoint", peer.Endpoint)
		}
		if len(peer.AllowedIPs) > 0 {
			var ips []string
			for _, p := range peer.AllowedIPs {
				ips = append(ips, p.String())
			}
			pargs = append(pargs, "allowed-ips", strings.Join(ips, ","))
		}
		if peer.PersistentKeepalive > 0 {
			pargs = append(pargs, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKeepalive))
		}
		if _, err := r.Run("wg", pargs...); err != nil {
			return changes, err
		}
		changes++
	}

	for _, addr := range spec.Addresses {
		if !addr.IsValid() {
			continue
		}
		// No family flag: iproute2 infers it from the address itself.
		if _, err := r.Run("ip", "address", "replace", addr.String(), "dev", iface); err != nil {
			return changes, err
		}
		changes++
	}
	if _, err := r.Run("ip", "link", "set", "dev", iface, "up"); err != nil {
		return changes, err
	}
	changes++

	n, err := ensureAllowedIPRoutes(r, iface, spec.Peer.AllowedIPs)
	if err != nil {
		return changes, err
	}
	return changes + n, nil
}

// famFlag is the explicit iproute2 family selector.
//
// Passed on every ip route/rule invocation, including IPv4 ones. Relying on the
// default family is what made the read below IPv4-only while the write it
// guarded was not: an IPv6 AllowedIP was never found in "ip route show dev X",
// so it was reinstalled on every apply and counted as a change, and the gateway
// never reported convergence.
func famFlag(a netip.Addr) string {
	if a.Is4() {
		return "-4"
	}
	return "-6"
}

func ensureAllowedIPRoutes(r linux.Runner, iface string, allowed []netip.Prefix) (int, error) {
	// Ensure AllowedIPs appear as routes (some environments suppress WG auto-routes).
	// Skip default routes: policy routing (fwmark → table 100) owns the default via
	// the tunnel; installing 0.0.0.0/0 or ::/0 into main hijacks underlay/endpoint traffic.
	//
	// Read first, and only count a route that was actually missing. The check has
	// to keep running even when the peer config matches semantically, because a
	// bounce can drop these routes -- but reporting a change for a route that was
	// already correct makes every apply look non-convergent and hides real drift.
	//
	// The listing is cached per family, because "ip route show" answers for one
	// family only. One shared cache would compare IPv6 prefixes against the IPv4
	// table and never find them.
	changes := 0
	existing := map[string]string{}
	for _, p := range allowed {
		if !p.IsValid() || isDefaultRoute(p) {
			continue
		}
		fam := famFlag(p.Addr())
		if _, ok := existing[fam]; !ok {
			// Lazily, so a peer with only default AllowedIPs costs nothing.
			existing[fam], _ = r.Run("ip", fam, "route", "show", "dev", iface)
		}
		if routeExists(existing[fam], p) {
			continue
		}
		if _, err := r.Run("ip", fam, "route", "replace", p.String(), "dev", iface); err != nil {
			return changes, err
		}
		changes++
	}
	return changes, nil
}

// routeExists reports whether `ip route show dev X` output already carries a
// route for p.
//
// The destination is compared as a parsed prefix, not as a string: iproute2
// prints a host route without its prefix length ("10.0.0.5" for 10.0.0.5/32),
// so a textual match would miss it.
func routeExists(routeShowOutput string, p netip.Prefix) bool {
	want := p.Masked()
	for _, line := range strings.Split(routeShowOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		got, ok := parseRouteDest(fields[0])
		if ok && got == want {
			return true
		}
	}
	return false
}

// parseRouteDest parses the destination field of an `ip route show` line, which
// is either a CIDR, a bare address (a host route), or the word "default".
func parseRouteDest(field string) (netip.Prefix, bool) {
	if strings.Contains(field, "/") {
		pfx, err := netip.ParsePrefix(field)
		if err != nil {
			return netip.Prefix{}, false
		}
		return pfx.Masked(), true
	}
	addr, err := netip.ParseAddr(field)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func isDefaultRoute(p netip.Prefix) bool {
	return p.Bits() == 0
}

func semanticMatch(r linux.Runner, iface, link string, spec policy.WireGuardSpec) bool {
	if !strings.Contains(link, "UP") {
		return false
	}
	dump, err := r.Run("wg", "show", iface, "dump")
	if err != nil || dump == "" {
		return false
	}
	live, ok := parseWGDump(dump)
	if !ok {
		return false
	}
	if live.PrivateKey != spec.PrivateKey {
		return false
	}
	if spec.ListenPort > 0 && live.ListenPort != spec.ListenPort {
		return false
	}
	if live.PeerPublicKey != spec.Peer.PublicKey {
		return false
	}
	if live.Endpoint != spec.Peer.Endpoint {
		return false
	}
	if live.Keepalive != spec.Peer.PersistentKeepalive {
		return false
	}
	wantIPs := map[string]struct{}{}
	for _, p := range spec.Peer.AllowedIPs {
		wantIPs[p.String()] = struct{}{}
	}
	if len(wantIPs) != len(live.AllowedIPs) {
		return false
	}
	for ip := range wantIPs {
		if _, ok := live.AllowedIPs[ip]; !ok {
			return false
		}
	}
	if len(spec.Addresses) > 0 {
		// No -4: one listing covers both families, and a dual-stack tunnel
		// needs both checked. Only the desired addresses have to be present,
		// so the link-local address every IPv6 interface carries is ignored.
		addrOut, err := r.Run("ip", "addr", "show", "dev", iface)
		if err != nil {
			return false
		}
		for _, addr := range spec.Addresses {
			if !addr.IsValid() {
				continue
			}
			if strings.Contains(addrOut, addr.String()) {
				continue
			}
			// Also accept "inet 10.99.0.1/30" style without requiring exact Prefix.String()
			if !addrContainsPrefix(addrOut, addr) {
				return false
			}
		}
	}
	return true
}

type liveWG struct {
	PrivateKey    string
	ListenPort    int
	PeerPublicKey string
	Endpoint      string
	AllowedIPs    map[string]struct{}
	Keepalive     int
}

// parseWGDump parses `wg show <iface> dump` output.
// Line 1 (iface): private-key  public-key  listen-port  fwmark
// Peer lines:     public-key   psk         endpoint     allowed-ips  ...  persistent-keepalive
func parseWGDump(out string) (liveWG, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 1 {
		return liveWG{}, false
	}
	ifaceFields := strings.Split(lines[0], "\t")
	if len(ifaceFields) < 3 {
		return liveWG{}, false
	}
	port, _ := strconv.Atoi(ifaceFields[2])
	live := liveWG{
		PrivateKey: ifaceFields[0],
		ListenPort: port,
		AllowedIPs: map[string]struct{}{},
	}
	if len(lines) < 2 {
		return live, true
	}
	peerFields := strings.Split(lines[1], "\t")
	if len(peerFields) < 4 {
		return live, false
	}
	live.PeerPublicKey = peerFields[0]
	if peerFields[2] != "(none)" {
		live.Endpoint = peerFields[2]
	}
	for _, ip := range strings.Split(peerFields[3], ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" || ip == "(none)" {
			continue
		}
		live.AllowedIPs[ip] = struct{}{}
	}
	if len(peerFields) >= 8 {
		ka, _ := strconv.Atoi(peerFields[7])
		live.Keepalive = ka
	}
	return live, true
}

func addrContainsPrefix(addrOut string, want netip.Prefix) bool {
	needle := want.String()
	if strings.Contains(addrOut, needle) {
		return true
	}
	// "inet 10.99.0.1/30" without matching Prefix.String() quirks
	return strings.Contains(addrOut, want.Addr().String()+"/"+strconv.Itoa(want.Bits()))
}

// SetDown brings the interface down (for fail-closed tests).
func SetDown(r linux.Runner, iface string) error {
	_, err := r.Run("ip", "link", "set", "dev", iface, "down")
	return err
}

// Clear deletes the WireGuard interface.
func Clear(r linux.Runner, iface string) error {
	_, err := r.Run("ip", "link", "del", "dev", iface)
	if err != nil && strings.Contains(err.Error(), "Cannot find") {
		return nil
	}
	return err
}
