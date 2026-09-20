package gotunclient

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

// Run dispatches gotun-client subcommands.
func Run(args []string, w io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun-client <enable|disable|confirm|status|verify>")
	}
	switch args[0] {
	case "enable":
		return runEnable(args[1:], w)
	case "disable":
		return runDisable(args[1:], w)
	case "confirm":
		return runConfirm(args[1:], w)
	case "status":
		return runStatus(args[1:], w)
	case "verify":
		return runVerify(args[1:], w)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// flagPrefixes collects repeatable -lan CIDR flags. Parsing eagerly in Set
// rejects a bad CIDR at flag-parse time, before anything touches the network.
type flagPrefixes []netip.Prefix

func (f *flagPrefixes) String() string {
	var parts []string
	for _, p := range *f {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

func (f *flagPrefixes) Set(v string) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("invalid -lan %q: %w", v, err)
	}
	if !p.Addr().Is4() {
		return fmt.Errorf("invalid -lan %q: IPv4 only", v)
	}
	*f = append(*f, p.Masked())
	return nil
}

func parseAddrFlag(name, v string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid -%s %q: %w", name, v, err)
	}
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("invalid -%s %q: IPv4 only", name, v)
	}
	return a, nil
}

// runner returns the real runner, wrapped for dry runs.
func runner(dryRun bool, w io.Writer) linux.Runner {
	if dryRun {
		return DryRunner{Inner: linux.ExecRunner{}, Out: w}
	}
	return linux.ExecRunner{}
}

func runEnable(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	gateway := fs.String("gateway", DefaultGateway, "gotun gateway to send off-LAN traffic to")
	dns := fs.String("dns", DefaultDNS, "DNS server to pin")
	probe := fs.String("probe", DefaultProbe, "off-LAN address used to assert the default route moved")
	statePath := fs.String("state", DefaultStatePath, "path to the saved-settings state file")
	connection := fs.String("connection", "", "NM connection to modify (default: the one carrying the default route)")
	applyMode := fs.String("apply-mode", string(ApplyDevice), "how far to write the change: device|temporary|persistent")
	confirm := fs.Duration("confirm-timeout", 120*time.Second, "revert automatically unless 'confirm' runs within this time (0 disables)")
	settle := fs.Duration("settle-timeout", 20*time.Second, "how long to wait for NetworkManager to reactivate")
	force := fs.Bool("force", false, "re-apply over an existing state file, reusing its snapshot")
	dryRun := fs.Bool("dry-run", false, "print the mutating commands instead of running them")
	detachFlag := fs.Bool("detach", true, "for link-bouncing apply modes, re-run under a transient systemd unit so an SSH drop cannot kill the apply")
	var lans flagPrefixes
	fs.Var(&lans, "lan", "extra prefix that must stay on-link (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	gw, err := parseAddrFlag("gateway", *gateway)
	if err != nil {
		return err
	}
	dnsAddr, err := parseAddrFlag("dns", *dns)
	if err != nil {
		return err
	}
	probeAddr, err := parseAddrFlag("probe", *probe)
	if err != nil {
		return err
	}
	mode, err := ParseApplyMode(*applyMode)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own path (needed to arm the rollback): %w", err)
	}

	return Enable(runner(*dryRun, w), w, EnableOptions{
		Gateway:        gw,
		DNS:            dnsAddr,
		Probe:          probeAddr,
		ExtraLANs:      lans,
		StatePath:      *statePath,
		ConnectionID:   *connection,
		Mode:           mode,
		Force:          *force,
		DryRun:         *dryRun,
		ConfirmTimeout: *confirm,
		SettleTimeout:  *settle,
		SelfPath:       self,
		Detach:         *detachFlag,
		Args:           args,
	})
}

func runDisable(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("disable", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath, "path to the saved-settings state file")
	dryRun := fs.Bool("dry-run", false, "print the mutating commands instead of running them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Disable(runner(*dryRun, w), w, *statePath)
}

func runConfirm(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("confirm", flag.ContinueOnError)
	statePath := fs.String("state", DefaultStatePath, "path to the saved-settings state file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return Confirm(linux.ExecRunner{}, w, *statePath)
}

func runStatus(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	gateway := fs.String("gateway", DefaultGateway, "gotun gateway (used when no state file exists)")
	statePath := fs.String("state", DefaultStatePath, "path to the saved-settings state file")
	var lans flagPrefixes
	fs.Var(&lans, "lan", "extra prefix that must stay on-link (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	gw, err := parseAddrFlag("gateway", *gateway)
	if err != nil {
		return err
	}
	rep, err := Status(linux.ExecRunner{}, *statePath, gw, lans)
	if err != nil {
		return err
	}
	PrintStatus(w, rep)
	return nil
}

func runVerify(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	gateway := fs.String("gateway", DefaultGateway, "gotun gateway off-LAN traffic should use")
	probe := fs.String("probe", DefaultProbe, "off-LAN address used to assert the default route")
	ruURL := fs.String("ru-url", DefaultRUEchoURL, "RU-hosted IP echo endpoint (\"\" to skip)")
	fgnURL := fs.String("foreign-url", DefaultForeignEchoURL, "foreign IP echo endpoint (\"\" to skip)")
	ruIP := fs.String("ru-ip", "", "pin the RU endpoint to this IP (recommended; must be inside ru_nets)")
	fgnIP := fs.String("foreign-ip", "", "pin the foreign endpoint to this IP (recommended; must be outside ru_nets)")
	wantRU := fs.String("expect-ru-egress", "", "public IP RU traffic must appear from (e.g. the ISP WAN address)")
	wantFgn := fs.String("expect-foreign-egress", "", "public IP foreign traffic must appear from (the exit hop)")
	largeURL := fs.String("large-url", DefaultLargeURL, "large object fetched to catch an MTU/MSS black hole (\"\" to skip)")
	largeBytes := fs.Int64("large-bytes", DefaultLargeBytes, "expected size of -large-url")
	directURL := fs.String("large-direct-url", DefaultDirectURL, "RU-hosted object fetched to measure the DIRECT class (\"\" to skip)")
	directIP := fs.String("large-direct-ip", "", "pin -large-direct-url to this IP (recommended; must be inside ru_nets)")
	minDirect := fs.Int64("min-direct-speed", DefaultMinDirectSpeed, "fail if the direct class is slower than this many B/s")
	dnsNames := fs.String("dns-names", "yandex.ru,example.com", "comma-separated names to resolve")
	skipEgress := fs.Bool("skip-egress", false, "skip the egress-identity checks")
	timeout := fs.Duration("timeout", 25*time.Second, "per-request timeout")
	var lans flagPrefixes
	fs.Var(&lans, "lan", "extra prefix that must stay on-link (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	gw, err := parseAddrFlag("gateway", *gateway)
	if err != nil {
		return err
	}
	probeAddr, err := parseAddrFlag("probe", *probe)
	if err != nil {
		return err
	}
	o := VerifyOptions{
		Gateway:        gw,
		Probe:          probeAddr,
		ExtraLANs:      lans,
		RUEchoURL:      *ruURL,
		ForeignEchoURL: *fgnURL,
		ExpectRUEgress: strings.TrimSpace(*wantRU),
		ExpectFgnEgres: strings.TrimSpace(*wantFgn),
		LargeURL:       *largeURL,
		LargeBytes:     *largeBytes,
		DirectURL:      *directURL,
		MinDirectSpeed: *minDirect,
		SkipEgress:     *skipEgress,
		SkipLarge:      *largeURL == "",
		SkipDirect:     *directURL == "",
		Timeout:        *timeout,
	}
	if *ruIP != "" {
		if o.RUIP, err = parseAddrFlag("ru-ip", *ruIP); err != nil {
			return err
		}
	}
	if *fgnIP != "" {
		if o.ForeignIP, err = parseAddrFlag("foreign-ip", *fgnIP); err != nil {
			return err
		}
	}
	if *directIP != "" {
		if o.DirectIP, err = parseAddrFlag("large-direct-ip", *directIP); err != nil {
			return err
		}
	}
	for _, n := range strings.Split(*dnsNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			o.DNSNames = append(o.DNSNames, n)
		}
	}
	return Verify(linux.ExecRunner{}, w, o)
}
