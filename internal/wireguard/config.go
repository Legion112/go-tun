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
				_, _ = r.Run("ip", "route", "del", p.String(), "dev", iface)
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

	args := []string{"set", iface, "private-key", "/dev/stdin"}
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

	if spec.Address.IsValid() {
		if _, err := r.Run("ip", "address", "replace", spec.Address.String(), "dev", iface); err != nil {
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

func ensureAllowedIPRoutes(r linux.Runner, iface string, allowed []netip.Prefix) (int, error) {
	// Ensure AllowedIPs appear as routes (some environments suppress WG auto-routes).
	// Skip default routes: policy routing (fwmark → table 100) owns the default via
	// the tunnel; installing 0.0.0.0/0 or ::/0 into main hijacks underlay/endpoint traffic.
	changes := 0
	for _, p := range allowed {
		if !p.IsValid() || isDefaultRoute(p) {
			continue
		}
		if _, err := r.Run("ip", "route", "replace", p.String(), "dev", iface); err != nil {
			return changes, err
		}
		changes++
	}
	return changes, nil
}

func isDefaultRoute(p netip.Prefix) bool {
	return (p.Addr().Is4() && p.Bits() == 0) || (p.Addr().Is6() && p.Bits() == 0)
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
	if spec.Address.IsValid() {
		addrOut, err := r.Run("ip", "-4", "addr", "show", "dev", iface)
		if err != nil || !strings.Contains(addrOut, spec.Address.String()) {
			// Also accept "inet 10.99.0.1/30" style without requiring exact Prefix.String()
			if err != nil || !addrContainsPrefix(addrOut, spec.Address) {
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
