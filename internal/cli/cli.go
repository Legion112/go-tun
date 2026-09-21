package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

// Run dispatches gotun subcommands.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun <fetch|amnezia|apply|clear>")
	}
	switch args[0] {
	case "fetch":
		return runFetch(args[1:])
	case "amnezia":
		return runAmnezia(args[1:])
	case "apply":
		return runApply(args[1:])
	case "clear":
		return runClear(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	out := fs.String("out", "prefixes.txt", "output prefix list path")
	country := fs.String("country", "RU", "ISO country code to extract")
	license := fs.String("license", os.Getenv("MAXMIND_LICENSE_KEY"), "MaxMind license key (CSV download)")
	mmdb := fs.String("mmdb", "", "path to local GeoIP2/GeoLite2 City or Country MMDB")
	families := fs.String("families", "v4,v6", "address families to emit: v4, v6 or v4,v6")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fams, err := prefixes.ParseFamilies(*families)
	if err != nil {
		return err
	}
	return FetchPrefixes(*license, *country, *out, *mmdb, fams)
}

func runAmnezia(args []string) error {
	fs := flag.NewFlagSet("amnezia", flag.ContinueOnError)
	out := fs.String("out", "amnezia-sites.json", "output Amnezia sites JSON path")
	country := fs.String("country", "RU", "ISO country code to extract")
	license := fs.String("license", os.Getenv("MAXMIND_LICENSE_KEY"), "MaxMind license key (CSV download)")
	mmdb := fs.String("mmdb", "", "path to local GeoIP2/GeoLite2 City or Country MMDB")
	format := fs.String("format", "official", "JSON shape: official (CIDR in hostname) or ios (CIDR in ip)")
	// Defaults to IPv4 alone, unlike fetch. The consumer here is a third-party
	// client whose handling of an IPv6 CIDR in these fields is unverified, and
	// an import it rejects outright is worse than one that is merely
	// incomplete. Opt in with -families v4,v6 once you have checked.
	families := fs.String("families", "v4", "address families to emit: v4, v6 or v4,v6")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fams, err := prefixes.ParseFamilies(*families)
	if err != nil {
		return err
	}
	return ExportAmnezia(*license, *country, *out, *mmdb, *format, fams)
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	prefixesPath := fs.String("prefixes", "", "path to CIDR list (one per line) or MaxMind-shaped fixture dir")
	endpoint := fs.String("endpoint", "",
		"WireGuard peer endpoint IP(s) (underlay), comma-separated. A dual-stack peer"+
			" reachable over both families needs both, or the IPv6 classifier marks the"+
			" tunnel's own encapsulated packets")
	wgConf := fs.String("wg-config", "", "optional path to wg-quick style config (exit hop)")
	wgClients := fs.String("wg-clients-config", "", "optional path to wg-quick style config (inbound clients iface)")
	tunnelUp := fs.String("tunnel-up", "true", "whether tunnel should carry traffic (true|false)")
	lan := fs.String("lan", "", "LAN CIDR to exclude from marking, for home isolation, and to skip SNAT (comma-separated)")
	directSNAT := fs.String("direct-snat", "false", "masquerade direct-class traffic out the LAN interface(s) (true|false)")
	failMode := fs.String("fail-mode", "open",
		"what happens to marked traffic when the tunnel is unusable: open (fall back to the uplink) or closed (blackhole)")
	dropIPv6 := fs.String("drop-ipv6", "false",
		"deprecated: prefer -ipv6 off. Drop IPv6 and disable it via sysctl (true|false);"+
			" note clear cannot undo the sysctls")
	ipv6 := fs.String("ipv6", "auto",
		"how to treat IPv6: auto (classify when the tunnel can carry it and IPv6 direct"+
			" prefixes are loaded), on (always classify), off (leave IPv6 alone)")
	ipv6Fallback := fs.String("ipv6-fallback", "direct",
		"what non-direct IPv6 does when the tunnel cannot carry it: direct (egress the"+
			" uplink -- LEAKS your real IPv6 address), blackhole (drop it in the routing"+
			" table), drop (drop it in prerouting)")
	directSNAT6 := fs.String("direct-snat6", "false",
		"masquerade the direct class on IPv6 too (true|false); only useful on a ULA-only LAN,"+
			" since a routed IPv6 prefix wants no NAT66")
	markIface := fs.String("mark-iface", "",
		"only mark traffic arriving on these interfaces (comma-separated); empty means any, which is unsafe on a router")
	dryRun := fs.String("dry-run", "false",
		"read real state but print every write instead of applying it (true|false)")
	tunnelIface := fs.String("tunnel-iface", policy.DefaultTunnelIface,
		"name of the tunnel interface to route through; must match the device that exists on the box"+
			" (netifd names it after the UCI section, and UCI section names cannot contain hyphens)")
	nonRoutable := fs.String("non-routable", "",
		"extra destinations never to mark (comma-separated CIDRs); defaults to private, CGNAT, link-local, loopback and multicast space")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fm, err := policy.ParseFailMode(strings.TrimSpace(*failMode))
	if err != nil {
		return err
	}
	v6, err := policy.ParseIPv6Mode(strings.TrimSpace(*ipv6))
	if err != nil {
		return err
	}
	v6fb, err := policy.ParseIPv6Fallback(strings.TrimSpace(*ipv6Fallback))
	if err != nil {
		return err
	}
	return Apply(ApplyOptions{
		PrefixesPath:    *prefixesPath,
		Endpoint:        *endpoint,
		WGConfig:        *wgConf,
		WGClientsConfig: *wgClients,
		LANCSV:          *lan,
		TunnelUp:        truthy(*tunnelUp),
		DirectSNAT:      truthy(*directSNAT),
		DirectSNAT6:     truthy(*directSNAT6),
		FailMode:        fm,
		IPv6:            v6,
		IPv6Fallback:    v6fb,
		DropIPv6:        truthy(*dropIPv6),
		MarkIfaceCSV:    *markIface,
		NonRoutableCSV:  *nonRoutable,
		TunnelIface:     strings.TrimSpace(*tunnelIface),
		DryRun:          truthy(*dryRun),
	})
}

// truthy parses the string-valued booleans this CLI uses. They are strings
// rather than fs.Bool because Go's flag package rejects the "-flag value" form
// for bool flags, and the integration labs invoke gotun that way.
func truthy(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true") || strings.TrimSpace(s) == "1"
}

func runClear(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Clear()
}
