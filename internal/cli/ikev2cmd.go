package cli

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/legion/go-tun/internal/ikev2"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

func runIKEv2(args []string) error {
	if len(args) > 0 && args[0] == "user" {
		return runIKEv2User(args[1:])
	}
	fs := flag.NewFlagSet("ikev2", flag.ContinueOnError)
	f := registerIKEv2Flags(fs)
	outSwanctl := fs.String("out-swanctl", "swanctl-phone.conf", "output path for the gateway configuration")
	outProfile := fs.String("out-profile", "phone.mobileconfig", "output path for the iOS profile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Refused rather than ignored: "gotun ikev2 -server x user add alice" is a
	// plausible thing to type, and silently generating a single-user
	// configuration instead of adding a user is the kind of near-miss that
	// gets discovered much later.
	if fs.NArg() > 0 {
		return fmt.Errorf("gotun ikev2: unexpected argument %q;"+
			" subcommands come first, as in `gotun ikev2 user add <name> [flags]`", fs.Arg(0))
	}
	cfg, err := f.config()
	if err != nil {
		return err
	}
	return ExportIKEv2(cfg, *outSwanctl, *outProfile)
}

// ikev2Flags is the shared description of a gateway, used by both `ikev2` and
// `ikev2 user add`. One registrar rather than two, because a -vip-subnet that
// meant something different in each would orphan every user already issued.
type ikev2Flags struct {
	server, gatewayID, clientID *string
	vipSubnet, vipGateway, pool *string
	nonRoutable, families       *string
	probeURL, homeSSID          *string
	ifID, serverCert, dpd       *string
	caFile, onDemand            *string
	keepalive                   *int
	name, identifier            *string
}

func registerIKEv2Flags(fs *flag.FlagSet) *ikev2Flags {
	f := &ikev2Flags{}
	f.server = fs.String("server", "",
		"the address the phone dials: a DDNS name or public IP, reachable from outside")
	f.gatewayID = fs.String("gateway-id", "",
		"the gateway's IKE identity; must be a subjectAltName on its certificate."+
			" Empty means -server")
	f.clientID = fs.String("client-id", "phone", "the phone's identity, and its EAP username")
	f.vipSubnet = fs.String("vip-subnet", "", "tunnel-side subnet (CIDR); pick an unusual one,"+
		" because it is routed into the tunnel and would shadow a network the phone sits on")
	f.vipGateway = fs.String("vip-gateway", "",
		"the gateway's tunnel-side address, where gotun-dns listens; pushed to the phone as DNS")
	f.pool = fs.String("pool", "", "range virtual IPs are handed out from (CIDR, inside -vip-subnet)")
	f.nonRoutable = fs.String("non-routable", "",
		"space the phone keeps on-link (comma-separated CIDRs); defaults to private, CGNAT,"+
			" link-local, loopback and multicast")
	f.families = fs.String("families", "v4,v6", "address families to emit selectors for: v4, v6 or v4,v6")
	f.probeURL = fs.String("probe-url", "",
		"URL the phone fetches over its physical interface to decide whether to connect."+
			" Point it at `gotun watch -health-listen` on the gateway's PUBLIC address;"+
			" without it the profile connects unconditionally and can sit in 'connecting'")
	f.homeSSID = fs.String("home-ssid", "",
		"Wi-Fi networks on which not to connect (comma-separated); the tunnel would otherwise"+
			" hairpin out and back through the same uplink")
	f.ifID = fs.String("if-id", ikev2.DefaultIfID,
		"xfrm interface id tying the CHILD_SA to a netdev; must match the `ip link add type xfrm if_id`")
	f.serverCert = fs.String("server-cert", "",
		"gateway certificate filename under /etc/swanctl/x509")
	f.onDemand = fs.String("on-demand", "true",
		"let iOS bring the tunnel up by itself (true|false). false ships a profile connected by"+
			" hand, which is what a first test against a gateway that is not reachable from"+
			" everywhere wants: on-demand with no probe makes the phone hold traffic wherever"+
			" it cannot reach the gateway")
	f.caFile = fs.String("ca", "",
		"PEM file of the CA that signed the gateway certificate, embedded in the profile as a"+
			" root payload. Required unless the gateway certificate is publicly trusted:"+
			" without it the phone has nothing to validate the server against and fails with"+
			" a generic connect error")
	f.dpd = fs.String("dpd", ikev2.DPDHigh,
		"DeadPeerDetectionRate: None, Low (30m), Medium (10m) or High (1m)."+
			" This is also the fail-open latency, so it trades battery against availability")
	f.keepalive = fs.Int("keepalive", ikev2.DefaultKeepAliveInterval,
		"NAT keepalive seconds (Apple's minimum is 20); offloaded to hardware, so it costs no wakeup")
	f.name = fs.String("name", "gotun", "what the VPN entry is called on the phone")
	f.identifier = fs.String("identifier", "", "reverse-DNS payload identifier prefix")
	return f
}

func (f *ikev2Flags) config() (ikev2.Config, error) {
	fams, err := prefixes.ParseFamilies(*f.families)
	if err != nil {
		return ikev2.Config{}, err
	}

	cfg := ikev2.Config{
		Server:            strings.TrimSpace(*f.server),
		GatewayID:         strings.TrimSpace(*f.gatewayID),
		ClientID:          strings.TrimSpace(*f.clientID),
		Families:          fams,
		IfID:              strings.TrimSpace(*f.ifID),
		ServerCert:        strings.TrimSpace(*f.serverCert),
		ProbeURL:          strings.TrimSpace(*f.probeURL),
		HomeSSIDs:         splitCSV(*f.homeSSID),
		DPDRate:           strings.TrimSpace(*f.dpd),
		KeepAliveInterval: *f.keepalive,
		OnDemandDisabled:  !truthy(*f.onDemand),
		ProfileName:       strings.TrimSpace(*f.name),
		Identifier:        strings.TrimSpace(*f.identifier),
	}

	if cfg.VIPSubnet, err = parsePrefixFlag("vip-subnet", *f.vipSubnet); err != nil {
		return ikev2.Config{}, err
	}
	if cfg.Pool, err = parsePrefixFlag("pool", *f.pool); err != nil {
		return ikev2.Config{}, err
	}
	if v := strings.TrimSpace(*f.vipGateway); v != "" {
		if cfg.VIPGateway, err = netip.ParseAddr(v); err != nil {
			return ikev2.Config{}, fmt.Errorf("-vip-gateway %q: %w", v, err)
		}
	}
	if ca := strings.TrimSpace(*f.caFile); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return ikev2.Config{}, fmt.Errorf("-ca %q: %w", ca, err)
		}
		cfg.CAPEM = pem
	}
	if nr := strings.TrimSpace(*f.nonRoutable); nr != "" {
		if cfg.NonRoutable, err = parsePrefixCSV(nr); err != nil {
			return ikev2.Config{}, err
		}
	} else {
		cfg.NonRoutable = policy.DefaultNonRoutable()
	}
	return cfg, nil
}

func parsePrefixFlag(name, v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("-%s %q: %w", name, v, err)
	}
	return p, nil
}

// ExportIKEv2 writes the gateway configuration and the phone profile from one
// description.
//
// Both halves come out of one call because the invariants that tie them
// together have no other home: the identity the phone expects must be the one
// the gateway presents, and the resolver the gateway pushes must be inside the
// selectors it offers. Each is a mismatch whose symptom is nowhere near its
// cause -- authentication failing after a successful handshake, or every GeoDNS
// answer being quietly wrong on a tunnel that looks healthy.
func ExportIKEv2(cfg ikev2.Config, outSwanctl, outProfile string) error {
	conf, err := ikev2.RenderSwanctl(cfg)
	if err != nil {
		return err
	}
	profile, err := ikev2.EncodeProfile(cfg)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outSwanctl, []byte(conf), 0o644); err != nil {
		return err
	}
	// 0600: not a credential, but it names the gateway, its identity and the
	// EAP username, and it is the file that gets copied to a phone.
	if err := os.WriteFile(outProfile, profile, 0o600); err != nil {
		return err
	}

	sel := ikev2.SelectorStrings(cfg)
	v4, v6 := prefixes.CountFamilies(cfg.Selectors())
	fmt.Printf("gotun ikev2: %d traffic selectors (%d IPv4, %d IPv6) → %s\n",
		len(sel), v4, v6, outSwanctl)
	fmt.Printf("gotun ikev2: iOS profile → %s\n", outProfile)

	// Three things the operator has to do that no generated file can do for
	// them, each of which fails silently if skipped.
	fmt.Fprintln(os.Stderr, "gotun ikev2: still to do by hand —")
	fmt.Fprintln(os.Stderr, "  1. the EAP secret: see the commented stanza at the end of the swanctl file")
	fmt.Fprintf(os.Stderr, "  2. the xfrm interface: ip link add <name> type xfrm dev <wan> if_id %s,"+
		" then address it inside %s with a /%d — a /32 leaves the pool off-link and every"+
		" reply to the phone fails source lookup while the SA still reads ESTABLISHED\n",
		orDefault(cfg.IfID, ikev2.DefaultIfID), cfg.VIPSubnet, cfg.VIPSubnet.Bits())
	fmt.Fprintf(os.Stderr, "  3. gotun apply -clients-iface <name> -mark-iface <lan>,<name>"+
		" — leaving the xfrm interface out of -mark-iface gives the phone no split routing"+
		" and reports nothing\n")
	if hp, ok := cfg.ProbeHostPort(); ok {
		fmt.Fprintf(os.Stderr, "  4. forward UDP 500, UDP 4500 and %s to the gateway on every NAT in front of it\n", hp)
	} else {
		fmt.Fprintln(os.Stderr, "  4. no -probe-url given: the profile connects unconditionally,"+
			" so an unreachable gateway holds traffic instead of releasing it")
	}
	if len(cfg.CAPEM) == 0 {
		fmt.Fprintln(os.Stderr, "gotun ikev2: no -ca given, so the profile trusts nothing of its"+
			" own. The gateway certificate must be signed by a publicly trusted CA, or the"+
			" phone rejects it with a generic connect error that says nothing about trust.")
	}
	if !cfg.Families.V6 {
		fmt.Fprintln(os.Stderr, "gotun ikev2: IPv6 selectors are OFF. iOS proposes both families, so the"+
			" phone keeps its IPv6 on the carrier and every IPv6-capable destination sees its real"+
			" address. On an IPv6-only mobile network that is most of the traffic.")
	}
	return nil
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
