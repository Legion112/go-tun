package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/prefixes"
)

// Run dispatches gotun subcommands.
func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun <fetch|amnezia|ikev2|apply|check|watch|clear>")
	}
	switch args[0] {
	case "fetch":
		return runFetch(args[1:])
	case "amnezia":
		return runAmnezia(args[1:])
	case "ikev2":
		return runIKEv2(args[1:])
	case "apply":
		return runApply(args[1:])
	case "check":
		return runCheck(args[1:])
	case "watch":
		return runWatch(args[1:])
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
	f := registerApplyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := loadConfigInto(fs, *f.configPath, deployconf.WatchFlags); err != nil {
		return err
	}
	o, err := f.options()
	if err != nil {
		return err
	}
	return Apply(o)
}

// truthy parses the string-valued booleans this CLI uses. They are strings
// rather than fs.Bool because Go's flag package rejects the "-flag value" form
// for bool flags, and the integration labs invoke gotun that way.
func truthy(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true") || strings.TrimSpace(s) == "1"
}

func runClear(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	devices := fs.String("devices", "",
		"interfaces to delete as well as withdrawing the policy (comma-separated)."+
			" Name only devices gotun created: on OpenWrt the tunnel belongs to netifd or"+
			" sing-box, and deleting it would take the transport down as a side effect of"+
			" rolling back a routing policy. Empty, the default, touches no interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Positional arguments would otherwise be accepted and ignored, so
	// `gotun clear wg-exit` would look like it had done something.
	if fs.NArg() > 0 {
		return fmt.Errorf("clear takes no positional arguments, got %q;"+
			" did you mean -devices %s", fs.Args(), fs.Arg(0))
	}
	return Clear(splitCSV(*devices)...)
}
