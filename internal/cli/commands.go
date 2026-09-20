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
func Apply(prefixesPath, endpoint, wgConfig, wgClientsConfig, lanCSV string, tunnelUp bool) error {
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

	p := policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: policy.DefaultTunnelIface,
		TunnelEndpoint:  ep,
		LANs:            lans,
		LANIfaces:       lanIfaces,
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		FailMode:        policy.FailClosed,
		TunnelUp:        tunnelUp,
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

	res, err := apply.Reconcile(linux.ExecRunner{}, p)
	if err != nil {
		return err
	}
	fmt.Printf("gotun apply: %d changes\n", res.Changes)
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
