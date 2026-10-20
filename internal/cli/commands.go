package cli

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/amnezia"
	"github.com/legion/go-tun/internal/apply"
	"github.com/legion/go-tun/internal/deployconf"
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
	// DirectSrcCSV lists hosts to bypass classification by source address.
	// Accepts bare addresses as well as CIDRs, because the thing being named
	// is a host, not a subnet.
	DirectSrcCSV string
	// TunnelIface overrides the routed interface name. Empty keeps the default.
	TunnelIface string
	// ClientsIfaceCSV names the inbound clients-facing devices gotun does not
	// manage. Separate from WGClientsConfig because a device may not be
	// WireGuard at all -- an IKEv2 CHILD_SA surfaces on an xfrm interface --
	// and because on OpenWrt netifd owns it and gotun deliberately holds no
	// private key, so there is no config to infer a name from.
	//
	// Comma-separated, because a gateway carries several inbound transports at
	// once and each needs its own isolation rule.
	ClientsIfaceCSV string
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

// parseHostCSV parses a comma-separated list of hosts, accepting both a bare
// address and a CIDR. A bare address becomes a single-host prefix: operators
// name a server by its address, and requiring "/32" on it is the kind of
// friction that ends in the flag being left off.
func parseHostCSV(csv string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range splitCSV(csv) {
		if pref, err := netip.ParsePrefix(part); err == nil {
			out = append(out, pref)
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid host %q: not an address or CIDR", part)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
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

// loadConfigInto fills in, from the configuration file, every flag in m that
// the operator did not pass explicitly. An empty path is not an error: the file
// is optional and every flag has a default.
//
// This replaces the mapping the init scripts used to do in shell, where each
// parameter was named a third time -- once as documentation, once as a flag,
// once in Go -- with nothing checking the three agreed.
func loadConfigInto(fs *flag.FlagSet, path string, m deployconf.Mapping) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	conf, err := deployconf.Load(path, deployconf.GotunConf)
	if err != nil {
		return ConfigError{Err: err}
	}
	if err := conf.Into(fs, m); err != nil {
		return ConfigError{Err: err}
	}
	return nil
}

// ConfigError is a configuration that cannot work: a file that is not there, a
// value that does not parse, a policy that does not compile.
//
// The distinction earns its keep in `watch`. A failed apply at boot is usually
// the transport not being up yet, which the watchdog recovers from on its own --
// so watch logs it and carries on. A failed apply because the configuration is
// wrong will fail identically forever, and carrying on would mean procd
// restarting the service every five seconds for as long as nobody looks.
type ConfigError struct{ Err error }

func (e ConfigError) Error() string { return e.Err.Error() }
func (e ConfigError) Unwrap() error { return e.Err }

func cfgErrf(format string, a ...any) error {
	return ConfigError{Err: fmt.Errorf(format, a...)}
}

// Validate turns ApplyOptions into a policy, or says why it cannot.
//
// It is everything apply does before it writes anything, split out so `check`
// can run exactly the same checks without touching the system -- which is what
// makes `gotun check -config` a command an operator can trust, unlike
// `/etc/init.d/gotun start`, whose exit status rc.common discards.
//
// Not every error here is a ConfigError, deliberately.
// linux.InterfacesForPrefixes and probeTunnelIPv6 read live kernel state, and a
// LAN bridge or a tunnel device that is not up yet at boot is transient. Calling
// that a configuration error would put the gateway back in the respawn loop
// this split exists to end.
func Validate(o ApplyOptions) (policy.Policy, error) {
	prefixesPath, endpoint := o.PrefixesPath, o.Endpoint
	wgConfig, wgClientsConfig, lanCSV := o.WGConfig, o.WGClientsConfig, o.LANCSV
	tunnelUp, directSNAT := o.TunnelUp, o.DirectSNAT
	if prefixesPath == "" {
		return policy.Policy{}, cfgErrf("-prefixes is required")
	}
	if endpoint == "" {
		return policy.Policy{}, cfgErrf("-endpoint is required")
	}
	var eps []netip.Addr
	for _, part := range splitCSV(endpoint) {
		a, err := netip.ParseAddr(part)
		if err != nil {
			return policy.Policy{}, cfgErrf("endpoint %q: %w", part, err)
		}
		eps = append(eps, a)
	}
	if len(eps) == 0 {
		return policy.Policy{}, cfgErrf("-endpoint is required")
	}

	var prefs []netip.Prefix
	st, err := os.Stat(prefixesPath)
	if err != nil {
		// Named, because the bare stat error says a path is missing without
		// saying which setting put it there.
		return policy.Policy{}, cfgErrf("-prefixes %s: %w", prefixesPath, err)
	}
	if st.IsDir() {
		prefs, err = prefixes.ParseMaxMindCountryDir(prefixesPath, "RU")
	} else {
		prefs, err = prefixes.ParseCIDRFile(prefixesPath)
	}
	if err != nil {
		return policy.Policy{}, cfgErrf("-prefixes %s: %w", prefixesPath, err)
	}
	prefs = prefixes.Collapse(prefs)

	var lans []netip.Prefix
	if lanCSV != "" {
		for _, q := range strings.Split(lanCSV, ",") {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			pref, err := netip.ParsePrefix(q)
			if err != nil {
				return policy.Policy{}, ConfigError{Err: err}
			}
			lans = append(lans, pref)
		}
	}

	// Live state, so not a ConfigError: see the doc comment.
	lanIfaces, err := linux.InterfacesForPrefixes(lans)
	if err != nil {
		return policy.Policy{}, err
	}
	if directSNAT && len(lanIfaces) == 0 {
		fmt.Fprintln(os.Stderr, "gotun: -direct-snat requested but no interface matched -lan; direct traffic will NOT be masqueraded")
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

	if ds := strings.TrimSpace(o.DirectSrcCSV); ds != "" {
		srcs, err := parseHostCSV(ds)
		if err != nil {
			return policy.Policy{}, ConfigError{Err: err}
		}
		p.DirectSources = srcs
	}

	if o.TunnelIface != "" {
		p.TunnelInterface = o.TunnelIface
	}
	if ifaces := splitCSV(o.ClientsIfaceCSV); len(ifaces) > 0 {
		p.ClientsInterfaces = ifaces
	}

	if nr := strings.TrimSpace(o.NonRoutableCSV); nr != "" {
		extra, err := parsePrefixCSV(nr)
		if err != nil {
			return policy.Policy{}, ConfigError{Err: err}
		}
		p.NonRoutablePrefixes = extra
	} else {
		p.NonRoutablePrefixes = policy.DefaultNonRoutable()
	}

	if len(p.MarkIIfNames) == 0 {
		fmt.Fprintln(os.Stderr, "gotun: -mark-iface is empty, so traffic arriving on ANY interface is classified;"+
			" on a router pass the client-facing interface(s)")
	}
	if p.FailMode == policy.FailOpen {
		fmt.Fprintln(os.Stderr, "gotun: fail-mode=open -- if the tunnel becomes unusable, marked traffic will"+
			" SILENTLY egress the uplink instead. Check egress identity to detect it.")
	}

	if wgConfig != "" {
		cfg, err := loadWGQuick(wgConfig)
		if err != nil {
			return policy.Policy{}, ConfigError{Err: err}
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
			return policy.Policy{}, ConfigError{Err: err}
		}
		p.InboundWireGuard = cfg
	}

	// Compiled here to validate, and to surface the warnings. Every path that
	// leaves IPv6 unclassified is a silent leak rather than a visible failure,
	// so it has to be said out loud before the apply, not discovered later.
	//
	// Reconcile compiles again. That is a few milliseconds of duplicated work
	// in exchange for one definition of "valid" shared by apply, watch and
	// check, which is the trade this split is for.
	cst, err := policy.Compile(p)
	if err != nil {
		return policy.Policy{}, ConfigError{Err: err}
	}
	for _, w := range cst.Warnings {
		fmt.Fprintln(os.Stderr, "gotun: "+w)
	}
	return p, nil
}

func Apply(o ApplyOptions) error {
	p, err := Validate(o)
	if err != nil {
		return err
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
// Clear withdraws the routing policy. It deletes an interface only when named
// one, because gotun must not destroy a device it did not create -- see
// apply.Clear.
func Clear(devices ...string) error {
	return apply.Clear(linux.ExecRunner{}, devices...)
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
