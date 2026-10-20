package cli

import (
	"flag"
	"strings"

	"github.com/legion/go-tun/internal/policy"
)

// applyFlags is the flag set shared by `apply` and `watch`. They must stay
// identical: watch re-applies the very same policy with only TunnelUp differing,
// so any flag that exists for one and not the other would silently change the
// policy at the moment of a failover.
type applyFlags struct {
	prefixesPath, endpoint          *string
	wgConf, wgClients               *string
	tunnelUp, lan, directSNAT       *string
	failMode, dropIPv6              *string
	ipv6, ipv6Fallback, directSNAT6 *string
	markIface, dryRun               *string
	tunnelIface, nonRoutable        *string
	directSrc, clientsIface         *string
	configPath                      *string
}

func registerApplyFlags(fs *flag.FlagSet) *applyFlags {
	return &applyFlags{
		prefixesPath: fs.String("prefixes", "", "path to CIDR list (one per line) or MaxMind-shaped fixture dir"),
		endpoint: fs.String("endpoint", "",
			"WireGuard peer endpoint IP(s) (underlay), comma-separated. A dual-stack peer"+
				" reachable over both families needs both, or the IPv6 classifier marks the"+
				" tunnel's own encapsulated packets"),
		wgConf:     fs.String("wg-config", "", "optional path to wg-quick style config (exit hop)"),
		wgClients:  fs.String("wg-clients-config", "", "optional path to wg-quick style config (inbound clients iface)"),
		tunnelUp:   fs.String("tunnel-up", "true", "whether tunnel should carry traffic (true|false)"),
		lan:        fs.String("lan", "", "LAN CIDR to exclude from marking, for home isolation, and to skip SNAT (comma-separated)"),
		directSNAT: fs.String("direct-snat", "false", "masquerade direct-class traffic out the LAN interface(s) (true|false)"),
		failMode: fs.String("fail-mode", "open",
			"what happens to marked traffic when the tunnel is unusable: open (fall back to the uplink) or closed (blackhole)"),
		dropIPv6: fs.String("drop-ipv6", "false",
			"deprecated: prefer -ipv6 off. Drop IPv6 and disable it via sysctl (true|false);"+
				" note clear cannot undo the sysctls"),
		ipv6: fs.String("ipv6", "auto",
			"how to treat IPv6: auto (classify when the tunnel can carry it and IPv6 direct"+
				" prefixes are loaded), on (always classify), off (leave IPv6 alone)"),
		ipv6Fallback: fs.String("ipv6-fallback", "direct",
			"what non-direct IPv6 does when the tunnel cannot carry it: direct (egress the"+
				" uplink -- LEAKS your real IPv6 address), blackhole (drop it in the routing"+
				" table), drop (drop it in prerouting)"),
		directSNAT6: fs.String("direct-snat6", "false",
			"masquerade the direct class on IPv6 too (true|false); only useful on a ULA-only LAN,"+
				" since a routed IPv6 prefix wants no NAT66"),
		markIface: fs.String("mark-iface", "",
			"only mark traffic arriving on these interfaces (comma-separated); empty means any, which is unsafe on a router"),
		dryRun: fs.String("dry-run", "false",
			"read real state but print every write instead of applying it (true|false)"),
		tunnelIface: fs.String("tunnel-iface", policy.DefaultTunnelIface,
			"name of the tunnel interface to route through; must match the device that exists on the box"+
				" (netifd names it after the UCI section, and UCI section names cannot contain hyphens)"),
		directSrc: fs.String("direct-src", "",
			"hosts whose own traffic is never marked, by source address (comma-separated IPs or CIDRs);"+
				" needed for a port-forwarded server, whose replies would otherwise leave via the exit hop"+
				" and reach the peer from an address it never dialled"),
		clientsIface: fs.String("clients-iface", "",
			"inbound clients-facing devices gotun does not manage (comma-separated): netifd's"+
				" WireGuard interface, the xfrm interface an IKEv2 CHILD_SA surfaces on, or both"+
				" at once. gotun holds no credential for them; each must also appear in"+
				" -mark-iface, or clients on it get no split routing at all"),
		configPath: fs.String("config", "",
			"read settings from this /etc/gotun/gotun.conf-style file. A flag passed explicitly"+
				" wins over the file, and a setting the file omits keeps its default here rather"+
				" than being overridden with an empty value"),
		nonRoutable: fs.String("non-routable", "",
			"extra destinations never to mark (comma-separated CIDRs); defaults to private, CGNAT, link-local, loopback and multicast space"),
	}
}

func (f *applyFlags) options() (ApplyOptions, error) {
	fm, err := policy.ParseFailMode(strings.TrimSpace(*f.failMode))
	if err != nil {
		return ApplyOptions{}, err
	}
	v6, err := policy.ParseIPv6Mode(strings.TrimSpace(*f.ipv6))
	if err != nil {
		return ApplyOptions{}, err
	}
	v6fb, err := policy.ParseIPv6Fallback(strings.TrimSpace(*f.ipv6Fallback))
	if err != nil {
		return ApplyOptions{}, err
	}
	return ApplyOptions{
		PrefixesPath:    *f.prefixesPath,
		Endpoint:        *f.endpoint,
		WGConfig:        *f.wgConf,
		WGClientsConfig: *f.wgClients,
		LANCSV:          *f.lan,
		TunnelUp:        truthy(*f.tunnelUp),
		DirectSNAT:      truthy(*f.directSNAT),
		DirectSNAT6:     truthy(*f.directSNAT6),
		FailMode:        fm,
		IPv6:            v6,
		IPv6Fallback:    v6fb,
		DropIPv6:        truthy(*f.dropIPv6),
		MarkIfaceCSV:    *f.markIface,
		NonRoutableCSV:  *f.nonRoutable,
		DirectSrcCSV:    *f.directSrc,
		TunnelIface:     strings.TrimSpace(*f.tunnelIface),
		ClientsIfaceCSV: *f.clientsIface,
		DryRun:          truthy(*f.dryRun),
	}, nil
}
