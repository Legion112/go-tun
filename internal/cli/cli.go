package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/policy"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return FetchPrefixes(*license, *country, *out, *mmdb)
}

func runAmnezia(args []string) error {
	fs := flag.NewFlagSet("amnezia", flag.ContinueOnError)
	out := fs.String("out", "amnezia-sites.json", "output Amnezia sites JSON path")
	country := fs.String("country", "RU", "ISO country code to extract")
	license := fs.String("license", os.Getenv("MAXMIND_LICENSE_KEY"), "MaxMind license key (CSV download)")
	mmdb := fs.String("mmdb", "", "path to local GeoIP2/GeoLite2 City or Country MMDB")
	format := fs.String("format", "official", "JSON shape: official (CIDR in hostname) or ios (CIDR in ip)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return ExportAmnezia(*license, *country, *out, *mmdb, *format)
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	prefixesPath := fs.String("prefixes", "", "path to CIDR list (one per line) or MaxMind-shaped fixture dir")
	endpoint := fs.String("endpoint", "", "WireGuard peer endpoint IP (underlay)")
	wgConf := fs.String("wg-config", "", "optional path to wg-quick style config (exit hop)")
	wgClients := fs.String("wg-clients-config", "", "optional path to wg-quick style config (inbound clients iface)")
	tunnelUp := fs.String("tunnel-up", "true", "whether tunnel should carry traffic (true|false)")
	lan := fs.String("lan", "", "LAN CIDR to exclude from marking, for home isolation, and to skip SNAT (comma-separated)")
	directSNAT := fs.String("direct-snat", "false", "masquerade direct-class traffic out the LAN interface(s) (true|false)")
	failMode := fs.String("fail-mode", "open",
		"what happens to marked traffic when the tunnel is unusable: open (fall back to the uplink) or closed (blackhole)")
	dropIPv6 := fs.String("drop-ipv6", "false",
		"drop IPv6 and disable it via sysctl (true|false); note clear cannot undo the sysctls")
	markIface := fs.String("mark-iface", "",
		"only mark traffic arriving on these interfaces (comma-separated); empty means any, which is unsafe on a router")
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
	return Apply(ApplyOptions{
		PrefixesPath:    *prefixesPath,
		Endpoint:        *endpoint,
		WGConfig:        *wgConf,
		WGClientsConfig: *wgClients,
		LANCSV:          *lan,
		TunnelUp:        truthy(*tunnelUp),
		DirectSNAT:      truthy(*directSNAT),
		FailMode:        fm,
		DropIPv6:        truthy(*dropIPv6),
		MarkIfaceCSV:    *markIface,
		NonRoutableCSV:  *nonRoutable,
		TunnelIface:     strings.TrimSpace(*tunnelIface),
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
