package cli

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/amnezia"
	"github.com/legion/go-tun/internal/apply"
	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

// FetchPrefixes writes a country prefix list from a local MMDB or MaxMind CSV download.
func FetchPrefixes(license, country, out, mmdbPath string, fams prefixes.Families) error {
	raw, err := prefixes.LoadCountryPrefixesRaw(license, country, mmdbPath)
	if err != nil {
		return err
	}
	collapsed := prefixes.Collapse(prefixes.FilterFamilies(raw, fams))
	if err := prefixes.WriteCIDRList(out, collapsed); err != nil {
		return err
	}
	raw4, raw6 := prefixes.CountFamilies(raw)
	got4, got6 := prefixes.CountFamilies(collapsed)
	fmt.Printf("gotun fetch: collapsed %d → %d IPv4 and %d → %d IPv6 prefixes → %s\n",
		raw4, got4, raw6, got6, out)
	if got6 == 0 && fams.V6 {
		fmt.Fprintln(os.Stderr, "gotun fetch: no IPv6 prefixes found;"+
			" gotun apply will leave IPv6 unclassified unless you pass -ipv6 on")
	}
	return nil
}

// FetchMaxMind downloads and writes a country prefix list (CSV). Kept for callers.
func FetchMaxMind(license, country, out string) error {
	return FetchPrefixes(license, country, out, "", prefixes.Families{V4: true, V6: true})
}

// ExportAmnezia fetches country prefixes and writes Amnezia site-based split-tunnel JSON.
// Import into Amnezia with "listed sites bypass VPN" / except-listed mode so country
// CIDRs go direct and everything else uses the tunnel.
func ExportAmnezia(license, country, out, mmdbPath, format string, fams prefixes.Families) error {
	siteFormat, err := amnezia.ParseFormat(format)
	if err != nil {
		return err
	}
	raw, err := prefixes.LoadCountryPrefixesRaw(license, country, mmdbPath)
	if err != nil {
		return err
	}
	collapsed := prefixes.Collapse(prefixes.FilterFamilies(raw, fams))
	if err := amnezia.WriteSites(out, collapsed, siteFormat); err != nil {
		return err
	}
	fmt.Printf("gotun amnezia: collapsed %d → %d sites → %s (format=%s, families=%s)\n",
		len(raw), len(collapsed), out, siteFormat, fams)
	fmt.Println("gotun amnezia: in Amnezia, enable site-based split tunneling with listed sites bypassing the VPN")
	return nil
}

// Apply loads prefixes and reconciles kernel state.
// ApplyOptions carries the apply flags. A struct rather than a growing positional
// list, now that there are more than a couple of booleans.
type ApplyOptions struct {
	PrefixesPath    string
	Endpoint        string
	WGConfig        string
	WGClientsConfig string
	LANCSV          string
	TunnelUp        bool
	DirectSNAT      bool
	DirectSNAT6     bool
	FailMode        policy.FailMode
	IPv6            policy.IPv6Mode
	IPv6Fallback    policy.IPv6Fallback
	DropIPv6        bool
	MarkIfaceCSV    string
	NonRoutableCSV  string
	// TunnelIface overrides the routed interface name. Empty keeps the default.
	TunnelIface string
	// DryRun reads real state but prints every write instead of applying it.
	DryRun bool
}

// parsePrefixCSV parses a comma-separated CIDR list.
func parsePrefixCSV(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pref, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
		out = append(out, pref)
	}
	return out, nil
}

func splitCSV(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func Apply(o ApplyOptions) error {
	prefixesPath, endpoint := o.PrefixesPath, o.Endpoint
	wgConfig, wgClientsConfig, lanCSV := o.WGConfig, o.WGClientsConfig, o.LANCSV
	tunnelUp, directSNAT := o.TunnelUp, o.DirectSNAT
	if prefixesPath == "" {
		return fmt.Errorf("-prefixes is required")
	}
	if endpoint == "" {
		return fmt.Errorf("-endpoint is required")
	}
	var eps []netip.Addr
	for _, part := range splitCSV(endpoint) {
		a, err := netip.ParseAddr(part)
		if err != nil {
			return fmt.Errorf("endpoint %q: %w", part, err)
		}
		eps = append(eps, a)
	}
	if len(eps) == 0 {
		return fmt.Errorf("-endpoint is required")
	}

	var prefs []netip.Prefix
	st, err := os.Stat(prefixesPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		prefs, err = prefixes.ParseMaxMindCountryDir(prefixesPath, "RU")
	} else {
		prefs, err = prefixes.ParseCIDRFile(prefixesPath)
	}
	if err != nil {
		return err
	}
	prefs = prefixes.Collapse(prefs)

	var lans []netip.Prefix
	if lanCSV != "" {
		for _, p := range strings.Split(lanCSV, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			pref, err := netip.ParsePrefix(p)
			if err != nil {
				return err
			}
			lans = append(lans, pref)
		}
	}

	lanIfaces, err := linux.InterfacesForPrefixes(lans)
	if err != nil {
		return err
	}
	if directSNAT && len(lanIfaces) == 0 {
		fmt.Fprintln(os.Stderr, "gotun apply: -direct-snat requested but no interface matched -lan; direct traffic will NOT be masqueraded")
	}

	p := policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: policy.DefaultTunnelIface,
		TunnelEndpoints: eps,
		LANs:            lans,
		LANIfaces:       lanIfaces,
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		TunnelUp:        tunnelUp,
		DirectSNAT:      directSNAT,
		DirectSNAT6:     o.DirectSNAT6,
		FailMode:        o.FailMode,
		IPv6:            o.IPv6,
		IPv6Fallback:    o.IPv6Fallback,
		DropIPv6:        o.DropIPv6,
		MarkIIfNames:    splitCSV(o.MarkIfaceCSV),
	}

	if o.TunnelIface != "" {
		p.TunnelInterface = o.TunnelIface
	}

	if nr := strings.TrimSpace(o.NonRoutableCSV); nr != "" {
		extra, err := parsePrefixCSV(nr)
		if err != nil {
			return err
		}
		p.NonRoutablePrefixes = extra
	} else {
		p.NonRoutablePrefixes = policy.DefaultNonRoutable()
	}

	if len(p.MarkIIfNames) == 0 {
		fmt.Fprintln(os.Stderr, "gotun apply: -mark-iface is empty, so traffic arriving on ANY interface is classified;"+
			" on a router pass the client-facing interface(s)")
	}
	if p.FailMode == policy.FailOpen {
		fmt.Fprintln(os.Stderr, "gotun apply: fail-mode=open -- if the tunnel becomes unusable, marked traffic will"+
			" SILENTLY egress the uplink instead. Check egress identity to detect it.")
	}

	if wgConfig != "" {
		cfg, err := loadWGQuick(wgConfig)
		if err != nil {
			return err
		}
		p.WireGuard = cfg
		p.TunnelCarriesIPv6 = cfg.CarriesIPv6()
	} else {
		// No config to read, so ask the device. On OpenWrt the tunnel is
		// netifd's, not gotun's, and this is the only way to know. Both reads
		// are read-only, so they are honest under -dry-run.
		p.TunnelCarriesIPv6 = probeTunnelIPv6(p.TunnelInterface)
	}
	if wgClientsConfig != "" {
		cfg, err := loadWGQuick(wgClientsConfig)
		if err != nil {
			return err
		}
		p.InboundWireGuard = cfg
	}

	var runner linux.Runner = linux.ExecRunner{}
	dry := &linux.DryRunner{Inner: linux.ExecRunner{}, Out: os.Stdout}
	if o.DryRun {
		runner = dry
	}

	// Compile once up front purely to surface its warnings. Every path that
	// leaves IPv6 unclassified is a silent leak rather than a visible failure,
	// so it has to be said out loud before the apply, not discovered later.
	if st, err := policy.Compile(p); err == nil {
		for _, w := range st.Warnings {
			fmt.Fprintln(os.Stderr, "gotun apply: "+w)
		}
	}

	res, err := apply.Reconcile(runner, p)
	if err != nil {
		return err
	}
	if o.DryRun {
		fmt.Printf("gotun apply: DRY RUN, %d commands withheld (%d semantic changes)\n", dry.Writes, res.Changes)
		return nil
	}
	if sum := res.Summary(); sum != "" {
		fmt.Printf("gotun apply: %d changes (%s)\n", res.Changes, sum)
	} else {
		fmt.Printf("gotun apply: %d changes\n", res.Changes)
	}
	return nil
}

// probeTunnelIPv6 reports whether the live tunnel device can carry IPv6.
//
// Both halves are needed: a v6 route in AllowedIPs with no v6 address on the
// interface gives the kernel a route it cannot use, because source address
// selection finds nothing. A failed probe -- no device yet, no privileges --
// reads as "cannot", which is the connectivity-safe and privacy-unsafe answer,
// and is exactly the case planIPv6 warns about.
func probeTunnelIPv6(iface string) bool {
	r := linux.ExecRunner{}
	allowed, err := r.Run("wg", "show", iface, "allowed-ips")
	if err != nil {
		return false
	}
	var route bool
	for _, f := range strings.Fields(allowed) {
		if p, err := netip.ParsePrefix(f); err == nil && p.Addr().Is6() {
			route = true
			break
		}
	}
	if !route {
		return false
	}
	addrs, err := r.Run("ip", "-6", "addr", "show", "dev", iface, "scope", "global")
	return err == nil && strings.Contains(addrs, "inet6")
}

// Clear removes owned kernel objects.
func Clear() error {
	return apply.Clear(linux.ExecRunner{})
}

func loadWGQuick(path string) (policy.WireGuardConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policy.WireGuardConfig{}, err
	}
	var cfg policy.WireGuardConfig
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch {
		case section == "[interface]" && k == "PrivateKey":
			cfg.PrivateKey = v
		case section == "[interface]" && k == "Address":
			// Every address, not just the first. A dual-stack tunnel lists both
			// families here, and taking Split(v, ",")[0] silently dropped the
			// IPv6 half -- leaving a tunnel that advertises ::/0 in AllowedIPs
			// but has no IPv6 source address to send from.
			for _, addr := range strings.Split(v, ",") {
				addr = strings.TrimSpace(addr)
				if addr == "" {
					continue
				}
				if p, err := netip.ParsePrefix(addr); err == nil {
					cfg.Addresses = append(cfg.Addresses, p)
				} else if a, err := netip.ParseAddr(addr); err == nil {
					// wg-quick treats a bare address as a host address, which
					// is /32 for IPv4 and /128 for IPv6 -- not /32 for both.
					cfg.Addresses = append(cfg.Addresses, netip.PrefixFrom(a, a.BitLen()))
				}
			}
		case section == "[interface]" && k == "ListenPort":
			fmt.Sscanf(v, "%d", &cfg.ListenPort)
		case section == "[peer]" && k == "PublicKey":
			cfg.Peer.PublicKey = v
		case section == "[peer]" && k == "Endpoint":
			cfg.Peer.Endpoint = v
		case section == "[peer]" && k == "AllowedIPs":
			for _, p := range strings.Split(v, ",") {
				p = strings.TrimSpace(p)
				if pref, err := netip.ParsePrefix(p); err == nil {
					cfg.Peer.AllowedIPs = append(cfg.Peer.AllowedIPs, pref)
				}
			}
		case section == "[peer]" && k == "PersistentKeepalive":
			fmt.Sscanf(v, "%d", &cfg.Peer.PersistentKeepalive)
		}
	}
	return cfg, nil
}
