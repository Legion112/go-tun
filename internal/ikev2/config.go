// Package ikev2 emits the gateway and phone halves of an IKEv2/IPsec road-warrior
// configuration from one description, so the two cannot disagree.
//
// The split that matters is not symmetric. Apple's IKEv2 payload carries no
// routes at all -- there is no excluded-routes key and iOS ignores
// split-exclude attributes -- so what the phone tunnels is decided entirely by
// the traffic selectors the gateway narrows to. The profile and the swanctl
// configuration therefore describe different things, and the invariants that
// tie them together are the ones worth enforcing in one place: the identity the
// phone expects must be the identity the gateway presents, and the resolver the
// gateway pushes must be inside the selectors it offers.
//
// See docs/ikev2-phone.md.
package ikev2

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/legion/go-tun/internal/prefixes"
)

// Apple's documented DeadPeerDetectionRate values, with the intervals they
// mean. The rate is also the fail-open latency: nothing re-evaluates an
// On-Demand rule while the SA is alive, so a tunnel that dies mid-session is
// noticed by DPD and traffic is held until then. High costs the most radio
// wakeups and is the right default for a phone that must degrade quickly.
const (
	DPDNone   = "None"   // disabled
	DPDLow    = "Low"    // 30 minutes
	DPDMedium = "Medium" // 10 minutes
	DPDHigh   = "High"   // 1 minute
)

// DefaultKeepAliveInterval sits just under the 120-second UDP mapping most NATs
// use. Apple's minimum is 20. Offloaded to hardware via
// NATKeepAliveOffloadEnable it costs no application-processor wakeup, which is
// the actual reason a native IKEv2 profile beats a WireGuard app on battery.
const DefaultKeepAliveInterval = 110

// DefaultIfID is the xfrm interface id tying the CHILD_SA to a netdev. charon
// only ever learns the number; the interface name belongs to whoever created
// it.
const DefaultIfID = "0x61"

// Config describes one phone and the gateway it dials.
type Config struct {
	// Server is the address the phone dials: a DDNS name or a public IP. It
	// must be reachable from outside, which is also why ProbeURL has to point
	// at it rather than at the tunnel-side address.
	Server string
	// GatewayID is the gateway's IKE identity. It is the profile's
	// RemoteIdentifier and swanctl's local id, and a mismatch between the two
	// fails authentication with no hint that the names are the problem --
	// which is the first reason this package exists.
	GatewayID string
	// ClientID is the phone's identity: the profile's LocalIdentifier, and its
	// EAP username when ExtendedAuth is used.
	ClientID string

	// VIPSubnet is the tunnel-side subnet. Deliberately an operator choice and
	// deliberately unusual: it is routed into the tunnel by an explicit
	// selector, so a phone sitting on a network that used the same prefix
	// would lose that network.
	VIPSubnet netip.Prefix
	// VIPGateway is the gateway's own tunnel-side address, which is where
	// gotun-dns listens and what the pool pushes as INTERNAL_IP4_DNS.
	VIPGateway netip.Addr
	// Pool is the range virtual IPs are handed out from.
	Pool netip.Prefix

	// NonRoutable is the space the phone keeps on-link. Empty means
	// policy.DefaultNonRoutable, passed in rather than imported to keep this
	// package free of the policy types.
	NonRoutable []netip.Prefix
	// Families selects which address families get selectors. Leaving IPv6 out
	// is a decision with a cost: iOS proposes both, so a v4-only tunnel leaves
	// the phone's IPv6 on the carrier and every IPv6-capable destination sees
	// its real address. On an IPv6-only mobile network that is most of the
	// traffic, not an edge case.
	Families prefixes.Families

	// IfID is the xfrm interface id. Empty means DefaultIfID.
	IfID string
	// ServerCert is the gateway certificate's filename under
	// /etc/swanctl/x509. Its subjectAltName must contain Server, and
	// GatewayID must match that SAN, or iOS rejects the server it just
	// authenticated.
	ServerCert string

	// ProbeURL is fetched by the phone over its physical interface to decide
	// whether to bring the tunnel up at all. It must be served by something
	// that knows whether the exit hop works -- `gotun watch -health-listen` --
	// or the phone connects into a tunnel whose exit is dead and gotun's
	// fail-open then sends it out the local uplink, silently.
	ProbeURL string
	// HomeSSIDs are networks on which the phone should not connect, because
	// the tunnel would hairpin back through the same uplink it exits from.
	HomeSSIDs []string

	// DPDRate is one of the DPD* constants. Empty means DPDHigh.
	DPDRate string
	// KeepAliveInterval is the NAT keepalive in seconds. 0 means the default.
	KeepAliveInterval int

	// IKEProposals and ESPProposals are the gateway's accepted algorithms.
	//
	// They are configurable because the one value this project has actually
	// measured is charon-to-charon in the lab, and what an iPhone proposes is
	// a deploy-time observation rather than something to assert here. The
	// defaults are a broad road-warrior set for exactly that reason: a
	// too-narrow list fails as "no proposal chosen", which says nothing about
	// which side was fussy.
	IKEProposals string
	ESPProposals string

	// ProfileName is what the VPN entry is called on the phone. Empty means
	// "gotun".
	ProfileName string
	// Identifier is the reverse-DNS payload identifier prefix. Empty means
	// "com.github.legion.gotun".
	Identifier string
}

func (c *Config) withDefaults() {
	if c.IfID == "" {
		c.IfID = DefaultIfID
	}
	if c.DPDRate == "" {
		c.DPDRate = DPDHigh
	}
	if c.KeepAliveInterval == 0 {
		c.KeepAliveInterval = DefaultKeepAliveInterval
	}
	if c.ProfileName == "" {
		c.ProfileName = "gotun"
	}
	if c.Identifier == "" {
		c.Identifier = "com.github.legion.gotun"
	}
	if c.GatewayID == "" {
		c.GatewayID = c.Server
	}
	if c.ClientID == "" {
		c.ClientID = "phone"
	}
	if c.ServerCert == "" {
		c.ServerCert = "gotun-gw.pem"
	}
	if c.IKEProposals == "" {
		c.IKEProposals = "aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256," +
			"aes256-sha256-ecp256,aes256-sha256-modp2048"
	}
	if c.ESPProposals == "" {
		c.ESPProposals = "aes256gcm16-ecp384,aes256gcm16,aes256-sha256"
	}
}

// ReservedV4 is address space that is neither private nor routable.
//
// It is deliberately absent from policy.DefaultNonRoutable -- nothing on a LAN
// is addressed there, so the classifier never needed it -- but leaving it in
// the selector cut makes the complement advertise 240.0.0.0-255.255.255.255,
// a selector no packet will ever use.
func ReservedV4() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
}

// MustStayLocal is the hard floor for traffic selectors: space the phone has to
// keep on its own interface no matter what the operator passes as NonRoutable.
//
// It is the same idea as policy.MandatoryNonRoutable and exists for the same
// reason -- an override that forgot a block would break something whose cause
// is nowhere near its symptom -- but the consequence here is different. On the
// gateway, forgetting RFC1918 marks LAN traffic. On the phone, it means the
// selectors cover the network the phone is attached to, so the printer, the
// Chromecast and the hotel portal all disappear into a tunnel that drops them,
// and the only symptom is that local things stop working while the internet is
// fine.
//
// Deliberately restated rather than taken from the caller's list: a floor that
// came from the value being checked would check nothing.
func MustStayLocal() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

// GlobalUnicastV6 is the IPv6 base, and it is a base rather than a complement
// on purpose.
//
// 2000::/3 is the only globally routable IPv6 range, so offering it directly is
// both exactly right and one selector. Complementing the non-routable list
// instead produces around twenty prefixes describing space no packet is
// addressed to, and gets longer every time a reserved block is remembered.
func GlobalUnicastV6() netip.Prefix {
	return netip.MustParsePrefix("2000::/3")
}

// Selectors is the single source of truth for what the phone tunnels.
//
// Prefixes rather than ranges, which is measured rather than aesthetic: a
// traffic selector is a range on the wire and the range form is far shorter,
// but charon's own client rounds each received range up to its smallest
// covering prefix when it installs routes, so a range spanning across 10/8
// becomes a 0.0.0.0/1 route that swallows the client's own LAN. See
// docs/ikev2-phone.md; the behaviour is pinned in the integration lab.
func (c Config) Selectors() []netip.Prefix {
	c.withDefaults()

	cut := slices.Clone(c.NonRoutable)
	if c.Families.V4 {
		cut = append(cut, ReservedV4()...)
	}
	// The gateway's own tunnel-side address is inside the cut -- it is RFC1918
	// -- so without this the selectors exclude the resolver the gateway pushes
	// and the phone quietly resolves through whatever network it is sitting on.
	// Subtracting here rather than appending the subnet afterwards is what
	// keeps the result seamless.
	if c.VIPSubnet.IsValid() {
		cut = prefixes.RangePrefixes(prefixes.Subtract(cut, []netip.Prefix{c.VIPSubnet}))
	}

	var base []netip.Prefix
	if c.Families.V4 {
		base = append(base, netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))
	}
	if c.Families.V6 {
		base = append(base, GlobalUnicastV6())
	}
	// A VIP subnet outside every base -- a ULA one, with IPv6 selected --
	// would otherwise be silently dropped here rather than in Validate.
	if c.VIPSubnet.IsValid() {
		base = append(base, c.VIPSubnet)
	}
	return prefixes.RangePrefixes(prefixes.Subtract(base, cut))
}

// Validate rejects the configurations whose failure mode is silence.
func (c Config) Validate() error {
	c.withDefaults()

	if strings.TrimSpace(c.Server) == "" {
		return fmt.Errorf("ikev2: Server is required")
	}
	if !c.Families.V4 && !c.Families.V6 {
		return fmt.Errorf("ikev2: no address family selected")
	}
	if !c.VIPSubnet.IsValid() {
		return fmt.Errorf("ikev2: VIPSubnet is required")
	}
	if c.VIPSubnet.Bits() == 0 {
		return fmt.Errorf("ikev2: VIPSubnet %v covers everything", c.VIPSubnet)
	}
	if !c.VIPGateway.IsValid() {
		return fmt.Errorf("ikev2: VIPGateway is required (it is what the pool pushes as DNS)")
	}
	if !c.VIPSubnet.Contains(c.VIPGateway) {
		return fmt.Errorf("ikev2: VIPGateway %v is outside VIPSubnet %v, so the resolver the"+
			" phone is handed is not reachable through the tunnel", c.VIPGateway, c.VIPSubnet)
	}
	if !c.Pool.IsValid() {
		return fmt.Errorf("ikev2: Pool is required")
	}
	if !prefixContains(c.VIPSubnet, c.Pool) {
		return fmt.Errorf("ikev2: Pool %v is not inside VIPSubnet %v, so a client's own address"+
			" would fall outside the selector that routes the tunnel subnet", c.Pool, c.VIPSubnet)
	}
	switch c.DPDRate {
	case DPDNone, DPDLow, DPDMedium, DPDHigh:
	default:
		return fmt.Errorf("ikev2: unknown DeadPeerDetectionRate %q (want None, Low, Medium or High)", c.DPDRate)
	}
	// Apple's documented minimum. A smaller value is not clamped, it is
	// ignored, so the keepalive silently reverts to the system default.
	if c.KeepAliveInterval < 20 {
		return fmt.Errorf("ikev2: NATKeepAliveInterval %d is below Apple's minimum of 20",
			c.KeepAliveInterval)
	}

	sel := c.Selectors()
	if len(sel) == 0 {
		return fmt.Errorf("ikev2: the non-routable list leaves no address space to tunnel")
	}
	if !selectorsCover(sel, c.VIPSubnet) {
		return fmt.Errorf("ikev2: no selector covers VIPSubnet %v, so the phone cannot reach"+
			" the resolver on %v", c.VIPSubnet, c.VIPGateway)
	}
	// The tunnel subnet is the one piece of private space that is supposed to
	// be in the selectors, so it comes out of the floor before the comparison.
	//
	// This also subsumes the full-tunnel case: a 0.0.0.0/0 selector necessarily
	// overlaps 10.0.0.0/8, and an error naming the block that would stop
	// working is more use than one saying "full tunnel".
	floor := prefixes.RangePrefixes(prefixes.Subtract(MustStayLocal(), []netip.Prefix{c.VIPSubnet}))
	for _, s := range sel {
		for _, f := range floor {
			if prefixesOverlap(s, f) {
				return fmt.Errorf("ikev2: selector %v covers private space %v, which the phone"+
					" must keep on its own interface; the NonRoutable list is missing it", s, f)
			}
		}
	}

	if err := validateProbeURL(c.ProbeURL); err != nil {
		return err
	}
	return nil
}

// validateProbeURL rejects a probe the phone cannot use as a discriminator.
//
// The probe is fetched over the physical interface, while the tunnel is down,
// to decide whether to bring it up. Pointing it at a private address makes it
// fail exactly when the tunnel is down, the Connect rule never matches, and the
// phone never connects at all -- a configuration that reads as "fail-open
// working perfectly" because traffic does flow, just never through the tunnel.
func validateProbeURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		// Optional: without it the profile falls back to an unconditional
		// Connect rule, which is a worse but legitimate choice.
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("ikev2: ProbeURL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("ikev2: ProbeURL %q must be http or https", raw)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("ikev2: ProbeURL %q has no host", raw)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
			return fmt.Errorf("ikev2: ProbeURL host %s is not a public address; the probe runs"+
				" over the physical interface and would fail precisely when the tunnel is down", host)
		}
	}
	return nil
}

func selectorsCover(sel []netip.Prefix, want netip.Prefix) bool {
	for _, p := range sel {
		if prefixContains(p, want) {
			return true
		}
	}
	return false
}

// prefixesOverlap reports whether two prefixes share any address. Prefixes are
// either disjoint or nested, so one containing the other's base address is the
// whole test.
func prefixesOverlap(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Contains(b.Masked().Addr()) || b.Contains(a.Masked().Addr())
}

func prefixContains(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() || outer.Bits() > inner.Bits() {
		return false
	}
	return netip.PrefixFrom(inner.Addr(), outer.Bits()).Masked() == outer.Masked()
}

// ProbeHostPort is a convenience for the operator: the host and port the probe
// URL implies, which is the port forward that has to exist on the upstream NAT.
func (c Config) ProbeHostPort() (string, bool) {
	u, err := url.Parse(strings.TrimSpace(c.ProbeURL))
	if err != nil || u.Host == "" {
		return "", false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port), true
}
