package policy

import (
	"fmt"
	"net/netip"
)

// FailMode controls non-RU behavior when the tunnel is unavailable.
type FailMode int

const (
	// FailOpen withdraws the tunnel route and installs nothing in its place, so
	// the policy-routing lookup misses and the RPDB continues to the main table,
	// i.e. marked traffic falls back to the ordinary uplink.
	//
	// This is the zero value and the default: on a household gateway, losing the
	// tunnel should degrade to plain internet rather than to no internet.
	//
	// The cost is that the fallback is SILENT. Traffic intended for the exit hop
	// egresses the local ISP with nothing logged, so a dead tunnel looks like a
	// working network that has quietly stopped hiding where you are. Detecting it
	// requires an egress-identity check, not an error.
	FailOpen FailMode = iota
	// FailClosed blackholes marked (non-RU) traffic when the tunnel is down, so
	// it cannot leak to the uplink. Prefer this when a silent fallback would be
	// worse than an outage.
	FailClosed
)

func (m FailMode) String() string {
	if m == FailClosed {
		return "closed"
	}
	return "open"
}

// DefaultNonRoutable are destinations that can never sensibly be reached through
// an exit hop: private space, CGNAT, link-local, loopback and multicast.
//
// Multicast matters more than it looks: mDNS and SSDP are LAN-sourced and are not
// in a country prefix set, so without this they get marked and routed off the
// segment, which breaks Chromecast and AirPlay discovery.
//
// The IPv6 half matters more still. Neighbour discovery is ICMPv6 to link-local
// and multicast addresses, so marking those does not merely break service
// discovery -- it breaks address resolution, and with it every IPv6 flow on the
// segment. fc00::/7 is the IPv6 counterpart of the RFC1918 entries.
func DefaultNonRoutable() []netip.Prefix {
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

// MandatoryNonRoutable are destinations excluded from marking even when the
// operator replaces the default list with -non-routable.
//
// They are not a matter of taste. Marking IPv6 link-local or multicast breaks
// neighbour discovery, so a gateway configured with a v4-only override would
// lose IPv6 on the segment entirely -- an error whose cause is nowhere near its
// symptom. Loopback and IPv4 multicast are here for the same reason: nothing
// reachable through an exit hop lives there.
func MandatoryNonRoutable() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

// IPv6Mode selects how IPv6 destinations are treated.
type IPv6Mode int

const (
	// IPv6Auto classifies IPv6 exactly like IPv4 whenever that can actually
	// work: the tunnel must be able to carry IPv6 and the direct set must be
	// non-empty. This is the zero value and the default.
	//
	// The empty-set condition is not a nicety. The classifier rule reads
	// "ip6 daddr != @ru_nets6 meta mark set 0x1", so against an empty set it
	// matches everything -- a gateway upgrading with a legacy IPv4-only
	// prefixes.txt would push all of its IPv6 into the tunnel the moment it
	// reapplied. Refusing to classify is the safe reading of "I have no data".
	IPv6Auto IPv6Mode = iota
	// IPv6On classifies IPv6 regardless of what the peer advertises. For a
	// tunnel whose IPv6 capability gotun cannot see, such as one managed by
	// netifd rather than from a wg-quick config.
	IPv6On
	// IPv6Off emits no IPv6 objects at all. IPv6 is left entirely alone, which
	// means it is not classified -- see IPv6Fallback for what that costs.
	IPv6Off
)

func ParseIPv6Mode(s string) (IPv6Mode, error) {
	switch s {
	case "auto", "":
		return IPv6Auto, nil
	case "on", "true":
		return IPv6On, nil
	case "off", "false":
		return IPv6Off, nil
	}
	return IPv6Auto, fmt.Errorf("unknown ipv6 mode %q (want auto, on or off)", s)
}

func (m IPv6Mode) String() string {
	switch m {
	case IPv6On:
		return "on"
	case IPv6Off:
		return "off"
	}
	return "auto"
}

// IPv6Fallback decides what happens to non-direct IPv6 when the tunnel cannot
// carry it.
type IPv6Fallback int

const (
	// FallbackDirect emits no IPv6 objects, so non-direct IPv6 egresses the
	// ordinary uplink. This is the default, and it LEAKS BY DESIGN: a
	// dual-stack destination sees the real IPv6 address, and clients prefer
	// IPv6 over IPv4 when both resolve, so the leak is the common path rather
	// than a corner. It is the default because on a household gateway a
	// half-broken internet is worse than a known leak -- but it is silent, and
	// apply says so out loud every time it engages.
	FallbackDirect IPv6Fallback = iota
	// FallbackBlackhole marks non-direct IPv6 and terminates it in the owned
	// table, so it cannot reach the uplink. Choose this when being seen
	// matters more than IPv6 working.
	FallbackBlackhole
	// FallbackDrop drops non-direct IPv6 in prerouting.
	FallbackDrop
)

func ParseIPv6Fallback(s string) (IPv6Fallback, error) {
	switch s {
	case "direct", "":
		return FallbackDirect, nil
	case "blackhole":
		return FallbackBlackhole, nil
	case "drop":
		return FallbackDrop, nil
	}
	return FallbackDirect, fmt.Errorf("unknown ipv6 fallback %q (want direct, blackhole or drop)", s)
}

func (f IPv6Fallback) String() string {
	switch f {
	case FallbackBlackhole:
		return "blackhole"
	case FallbackDrop:
		return "drop"
	}
	return "direct"
}

// ParseFailMode parses the -fail-mode flag value.
func ParseFailMode(s string) (FailMode, error) {
	switch s {
	case "open", "":
		return FailOpen, nil
	case "closed":
		return FailClosed, nil
	}
	return FailOpen, fmt.Errorf("unknown fail mode %q (want open or closed)", s)
}

const (
	// OwnedNftTable is the nftables table owned exclusively by gotun.
	OwnedNftTable  = "gotun"
	OwnedNftFamily = "inet"

	DefaultMark         uint32 = 0x1
	DefaultTableID             = 100
	DefaultRulePriority        = 100
	DefaultTunnelIface         = "wg-exit"
	DefaultClientsIface        = "wg-clients"
	RuNetsSetName              = "ru_nets"
	HomeNetsSetName            = "home_nets"
	RuNetsSetNameV6            = RuNetsSetName + "6"
	HomeNetsSetNameV6          = HomeNetsSetName + "6"

	// SrcNatPriority is nft's "srcnat" hook priority, where source NAT belongs.
	SrcNatPriority = 100

	// MarkChainPriority is where the classifier sits in the prerouting hook.
	//
	// One past mangle (-150) rather than on it. iptables' mangle PREROUTING
	// registers at exactly -150, and the order between two hook functions at the
	// same priority is not defined -- it falls out of registration order, so it
	// would depend on boot timing. -149 is deterministically after anything in
	// mangle and still far ahead of nat prerouting at -100, so the mark is set
	// before any NAT decision is made.
	//
	// nft renders this back as "mangle + 1", which is why comparing chain
	// priorities as text does not work.
	MarkChainPriority = -149

	// TunnelRouteMetric is preferred while wg-exit is usable.
	TunnelRouteMetric = 10
	// FailClosedRouteMetric is the permanent terminal fallback in table 100.
	// Marked packets must never fall through to main if the tunnel route disappears.
	FailClosedRouteMetric = 100
)

// Policy is the high-level desired routing policy for the gotun gateway.
type Policy struct {
	DirectPrefixes  []netip.Prefix // RU (or other "direct") CIDRs, either family
	TunnelInterface string
	// TunnelEndpoints are the peer's underlay addresses, excluded from marking
	// so handshake traffic cannot recurse into the tunnel. A dual-stack peer
	// can be reached over either family, and an unexcluded IPv6 endpoint means
	// the IPv6 classifier marks the tunnel's own encapsulated packets -- the
	// tunnel then eats itself.
	TunnelEndpoints []netip.Addr
	LANs            []netip.Prefix
	// LANIfaces are the client-facing interface names. They exist so
	// send_redirects can be disabled per device: the kernel ORs the "all" and
	// per-device values, so clearing "all" alone leaves redirects enabled on
	// any interface whose own value is 1.
	LANIfaces    []string
	Mark         uint32
	Table        int
	RulePriority int
	FailMode     FailMode
	// TunnelUp indicates whether the WireGuard interface should carry traffic.
	// When true, table 100 prefers default via the tunnel device; a higher-metric
	// blackhole always remains so an unexpected wg-exit loss cannot fall through to main.
	// When false, only the blackhole is installed.
	TunnelUp bool
	// WireGuard holds keys/peers when apply manages the exit interface.
	WireGuard WireGuardConfig
	// InboundWireGuard is the clients-facing listen interface (WAN peers via port-forward).
	// When set (PrivateKey non-empty), compile installs home_nets forward isolation.
	InboundWireGuard WireGuardConfig
	// MarkIIfNames restricts marking to these ingress interfaces. Empty means
	// mark traffic arriving on any interface, which is safe on a dedicated
	// gateway box but not on a router: the prerouting hook also sees WAN-inbound
	// traffic, so an unscoped rule marks reply packets whose destination is the
	// router's own address. Only the local table sitting at rule priority 0 then
	// stands between that and a lost management path.
	MarkIIfNames []string
	// NonRoutablePrefixes are destinations that must never be marked, on top of
	// LANs. Distinct from LANs because LANs also drives home_nets isolation and
	// the SNAT skip list, whereas this is purely "traffic that cannot sensibly
	// leave via an exit hop": RFC1918, CGNAT, link-local, loopback, multicast.
	NonRoutablePrefixes []netip.Prefix
	// IPv6 selects how IPv6 destinations are treated. The zero value,
	// IPv6Auto, classifies them like IPv4 whenever that can work.
	IPv6 IPv6Mode
	// IPv6Fallback decides what non-direct IPv6 does when the tunnel cannot
	// carry it. The zero value sends it out the uplink, which leaks.
	IPv6Fallback IPv6Fallback
	// TunnelCarriesIPv6 reports whether the exit peer can actually carry IPv6:
	// a v6 route in AllowedIPs AND a v6 address on the interface. AllowedIPs
	// alone is not evidence -- routing ::/0 out a device with no IPv6 source
	// address fails source selection rather than reaching the peer. Filled by
	// the caller from the wg config or a live probe.
	TunnelCarriesIPv6 bool
	// DropIPv6 installs an IPv6 drop rule and disables IPv6 via sysctl.
	//
	// Deprecated: superseded by IPv6Off, which leaves no sysctls behind. Off by
	// default. It is the right call on a box that only routes a split-tunnel
	// policy, and the wrong call on a household router: it takes IPv6 away from
	// every device, and Clear does not put it back.
	DropIPv6 bool
	// DirectSNAT6 masquerades the direct class on IPv6 as well.
	//
	// Separate from DirectSNAT and off by default, because the argument for
	// the IPv4 version does not carry over: it is about NAT and hairpinning on
	// a v4 LAN, whereas a routed IPv6 prefix wants no NAT66 at all. Only useful
	// when the LAN is ULA-only.
	DirectSNAT6 bool
	// DirectSNAT masquerades the direct class as it leaves LANIfaces.
	//
	// Required whenever clients reach the gateway over the same L2 segment the
	// gateway uses as its own uplink. Direct-class traffic then hairpins: in and
	// out the same interface, keeping the client's source address, with the reply
	// returning from the upstream router straight to the client. Some routers
	// handle that badly -- a MediaTek hardware flow-offload engine was measured
	// destroying such flows (~700x throughput loss, heavy TCP retransmission,
	// while ICMP stayed pristine because it is not offloaded). Masquerading makes
	// the flow ordinary and symmetric from the router's point of view, exactly as
	// the tunnel class already appears.
	DirectSNAT bool
}

// WireGuardConfig is declarative WG desired state attached to Policy.
type WireGuardConfig struct {
	PrivateKey string
	ListenPort int
	// Addresses are the tunnel addresses on the interface. A slice rather than
	// one prefix because a dual-stack tunnel needs one per family.
	Addresses []netip.Prefix
	Peer      WireGuardPeer
}

// CarriesIPv6 reports whether this peer can actually carry IPv6 traffic.
//
// Both halves are required. A v6 route in AllowedIPs with no v6 address on the
// interface gives a route the kernel cannot use: source address selection finds
// nothing and the send fails, rather than the packet reaching the peer.
func (c WireGuardConfig) CarriesIPv6() bool {
	var route, addr bool
	for _, p := range c.Peer.AllowedIPs {
		if p.IsValid() && p.Addr().Is6() {
			route = true
			break
		}
	}
	for _, p := range c.Addresses {
		if p.IsValid() && p.Addr().Is6() {
			addr = true
			break
		}
	}
	return route && addr
}

// WireGuardPeer describes the exit hop.
type WireGuardPeer struct {
	PublicKey           string
	Endpoint            string // host:port
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// DesiredKernelState is fully declarative: what should exist, not how to apply it.
type DesiredKernelState struct {
	// Warnings are operator-facing notes from Compile -- above all, every way
	// IPv6 can end up unclassified, since that is a silent leak rather than a
	// visible failure.
	Warnings []string
	// IPv6 records what Compile decided about IPv6, for apply and status to
	// report.
	IPv6             IPv6Plan
	Sysctls          []SysctlSpec
	Nft              NftSpec
	IPRules          []IPRuleSpec
	Routes           []RouteSpec
	WireGuard        WireGuardSpec // exit hop (wg-exit)
	WireGuardClients WireGuardSpec // inbound clients (wg-clients); Managed=false if unused
}

// SysctlSpec is a desired sysctl key/value.
type SysctlSpec struct {
	Key   string
	Value string
}

// NftSpec describes owned nftables objects under inet gotun.
type NftSpec struct {
	Family string
	Table  string
	Sets   []NftSetSpec
	Chains []NftChainSpec
}

// NftSetSpec is a named set of prefixes (interval).
type NftSetSpec struct {
	Name   string
	Family Family
	// Type is the nft set type. Compile derives it from Family via SetTypeFor
	// so the two cannot disagree.
	Type     string
	Flags    []string
	Elements []netip.Prefix
}

// NftChainSpec is a chain with declarative rules.
type NftChainSpec struct {
	Name     string
	Type     string // "filter"
	Hook     string // "prerouting", "forward", ...
	Priority int
	Policy   string // "accept"
	Rules    []NftRuleSpec
}

// NftRuleSpec is a semantic rule (not nft handle numbers).
type NftRuleSpec struct {
	// Description is a stable id for semantic comparison. It carries no family:
	// the emitted comment does, via nftables.RuleComment, so that the two
	// families land in separate comment buckets on readback.
	Description string
	// Family picks ip vs ip6 for the destination match, and ipv4 vs ipv6 for
	// the nfproto guard. FamilyAny means the rule has no layer-3 dependency.
	Family Family
	// ExcludePrefixes/ExcludeAddrs: if dst is in any of these prefixes or equals
	// one of these addrs, return before this rule's action -- skipping the mark
	// in prerouting, or skipping SNAT in postrouting.
	ExcludePrefixes []netip.Prefix
	ExcludeAddrs    []netip.Addr
	// DirectSet: if dst is in this set, do not mark (go direct).
	DirectSet string
	// Mark value to set when dst is not in DirectSet and not excluded.
	Mark uint32
	// DropIPv6 when true adds an ip6 drop rule in this chain context.
	DropIPv6 bool
	// DropNonDirect makes the verdict "drop" rather than "set mark", for the
	// IPv6 fallback that refuses to let untunnelable traffic out.
	DropNonDirect bool
	// IIfName + DropDstSet: drop forwarded packets from iface to destinations in set.
	IIfName    string
	DropDstSet string
	// IIfNames: restrict to these ingress interfaces (rendered as a guard that
	// returns for anything else).
	IIfNames []string
	// OIfNames: output interfaces this rule applies to; one nft rule per entry.
	OIfNames []string
	// SNATMasquerade emits a masquerade statement.
	SNATMasquerade bool
}

// IPRuleSpec is a policy routing rule owned by gotun.
type IPRuleSpec struct {
	Family   Family
	Priority int
	Mark     uint32
	Table    int
}

// RouteSpec is a route in a specific table.
type RouteSpec struct {
	Family      Family
	Table       int
	Destination netip.Prefix // default route for the family
	// Blackhole when true installs an unreachable/blackhole default (fail-closed).
	Blackhole bool
	Device    string // e.g. wg-exit when tunnel is up
	Metric    int    // lower wins; 0 means kernel default
}

// WireGuardSpec is declarative WG interface state.
type WireGuardSpec struct {
	Interface  string
	PrivateKey string
	ListenPort int
	Addresses  []netip.Prefix
	Peer       WireGuardPeer
	Managed    bool // if false, apply only assumes iface exists for routing
	Up         bool // desired admin state; false => fail-closed (iface down, no AllowedIPs routes)
}
