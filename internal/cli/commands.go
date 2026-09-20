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
func FetchPrefixes(license, country, out, mmdbPath string) error {
	raw, err := prefixes.LoadCountryPrefixesRaw(license, country, mmdbPath)
	if err != nil {
		return err
	}
	collapsed := prefixes.CollapseIPv4(raw)
	if err := prefixes.WriteCIDRList(out, collapsed); err != nil {
		return err
	}
	fmt.Printf("gotun fetch: collapsed %d → %d prefixes → %s\n", len(raw), len(collapsed), out)
	return nil
}

// FetchMaxMind downloads and writes a country prefix list (CSV). Kept for callers.
func FetchMaxMind(license, country, out string) error {
	return FetchPrefixes(license, country, out, "")
}

// ExportAmnezia fetches country prefixes and writes Amnezia site-based split-tunnel JSON.
// Import into Amnezia with "listed sites bypass VPN" / except-listed mode so country
// CIDRs go direct and everything else uses the tunnel.
func ExportAmnezia(license, country, out, mmdbPath, format string) error {
	siteFormat, err := amnezia.ParseFormat(format)
	if err != nil {
		return err
	}
	raw, err := prefixes.LoadCountryPrefixesRaw(license, country, mmdbPath)
	if err != nil {
		return err
	}
	collapsed := prefixes.CollapseIPv4(raw)
	if err := amnezia.WriteSites(out, collapsed, siteFormat); err != nil {
		return err
	}
	fmt.Printf("gotun amnezia: collapsed %d → %d sites → %s (format=%s)\n", len(raw), len(collapsed), out, siteFormat)
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
	FailMode        policy.FailMode
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
	ep, err := netip.ParseAddr(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
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
	prefs = prefixes.CollapseIPv4(prefs)

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
		TunnelEndpoint:  ep,
		LANs:            lans,
		LANIfaces:       lanIfaces,
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		TunnelUp:        tunnelUp,
		DirectSNAT:      directSNAT,
		FailMode:        o.FailMode,
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
			// take first address
			addr := strings.Split(v, ",")[0]
			addr = strings.TrimSpace(addr)
			if p, err := netip.ParsePrefix(addr); err == nil {
				cfg.Address = p
			} else if a, err := netip.ParseAddr(addr); err == nil {
				cfg.Address = netip.PrefixFrom(a, 32)
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
