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
	fs := flag.NewFlagSet("ikev2", flag.ContinueOnError)
	server := fs.String("server", "",
		"the address the phone dials: a DDNS name or public IP, reachable from outside")
	gatewayID := fs.String("gateway-id", "",
		"the gateway's IKE identity; must be a subjectAltName on its certificate."+
			" Empty means -server")
	clientID := fs.String("client-id", "phone", "the phone's identity, and its EAP username")
	vipSubnet := fs.String("vip-subnet", "", "tunnel-side subnet (CIDR); pick an unusual one,"+
		" because it is routed into the tunnel and would shadow a network the phone sits on")
	vipGateway := fs.String("vip-gateway", "",
		"the gateway's tunnel-side address, where gotun-dns listens; pushed to the phone as DNS")
	pool := fs.String("pool", "", "range virtual IPs are handed out from (CIDR, inside -vip-subnet)")
	nonRoutable := fs.String("non-routable", "",
		"space the phone keeps on-link (comma-separated CIDRs); defaults to private, CGNAT,"+
			" link-local, loopback and multicast")
	families := fs.String("families", "v4,v6", "address families to emit selectors for: v4, v6 or v4,v6")
	probeURL := fs.String("probe-url", "",
		"URL the phone fetches over its physical interface to decide whether to connect."+
			" Point it at `gotun watch -health-listen` on the gateway's PUBLIC address;"+
			" without it the profile connects unconditionally and can sit in 'connecting'")
	homeSSID := fs.String("home-ssid", "",
		"Wi-Fi networks on which not to connect (comma-separated); the tunnel would otherwise"+
			" hairpin out and back through the same uplink")
	ifID := fs.String("if-id", ikev2.DefaultIfID,
		"xfrm interface id tying the CHILD_SA to a netdev; must match the `ip link add type xfrm if_id`")
	serverCert := fs.String("server-cert", "",
		"gateway certificate filename under /etc/swanctl/x509")
	dpd := fs.String("dpd", ikev2.DPDHigh,
		"DeadPeerDetectionRate: None, Low (30m), Medium (10m) or High (1m)."+
			" This is also the fail-open latency, so it trades battery against availability")
	keepalive := fs.Int("keepalive", ikev2.DefaultKeepAliveInterval,
		"NAT keepalive seconds (Apple's minimum is 20); offloaded to hardware, so it costs no wakeup")
	name := fs.String("name", "gotun", "what the VPN entry is called on the phone")
	identifier := fs.String("identifier", "", "reverse-DNS payload identifier prefix")
	outSwanctl := fs.String("out-swanctl", "swanctl-phone.conf", "output path for the gateway configuration")
	outProfile := fs.String("out-profile", "phone.mobileconfig", "output path for the iOS profile")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fams, err := prefixes.ParseFamilies(*families)
	if err != nil {
		return err
	}

	cfg := ikev2.Config{
		Server:            strings.TrimSpace(*server),
		GatewayID:         strings.TrimSpace(*gatewayID),
		ClientID:          strings.TrimSpace(*clientID),
		Families:          fams,
		IfID:              strings.TrimSpace(*ifID),
		ServerCert:        strings.TrimSpace(*serverCert),
		ProbeURL:          strings.TrimSpace(*probeURL),
		HomeSSIDs:         splitCSV(*homeSSID),
		DPDRate:           strings.TrimSpace(*dpd),
		KeepAliveInterval: *keepalive,
		ProfileName:       strings.TrimSpace(*name),
		Identifier:        strings.TrimSpace(*identifier),
	}

	if cfg.VIPSubnet, err = parsePrefixFlag("vip-subnet", *vipSubnet); err != nil {
		return err
	}
	if cfg.Pool, err = parsePrefixFlag("pool", *pool); err != nil {
		return err
	}
	if v := strings.TrimSpace(*vipGateway); v != "" {
		if cfg.VIPGateway, err = netip.ParseAddr(v); err != nil {
			return fmt.Errorf("-vip-gateway %q: %w", v, err)
		}
	}
	if nr := strings.TrimSpace(*nonRoutable); nr != "" {
		if cfg.NonRoutable, err = parsePrefixCSV(nr); err != nil {
			return err
		}
	} else {
		cfg.NonRoutable = policy.DefaultNonRoutable()
	}

	return ExportIKEv2(cfg, *outSwanctl, *outProfile)
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
