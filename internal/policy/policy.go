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
func DefaultNonRoutable() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
	}
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

	// SrcNatPriority is nft's "srcnat" hook priority, where source NAT belongs.
	SrcNatPriority = 100

	// TunnelRouteMetric is preferred while wg-exit is usable.
	TunnelRouteMetric = 10
	// FailClosedRouteMetric is the permanent terminal fallback in table 100.
	// Marked packets must never fall through to main if the tunnel route disappears.
	FailClosedRouteMetric = 100
)

// Policy is the high-level desired routing policy for the gotun gateway.
type Policy struct {
	DirectPrefixes  []netip.Prefix // RU (or other "direct") CIDRs
	TunnelInterface string
	TunnelEndpoint  netip.Addr
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
	// DropIPv6 installs an IPv6 drop rule and disables IPv6 via sysctl.
	//
	// Off by default. It is the right call on a box that only routes a
	// split-tunnel policy, and the wrong call on a household router: it takes
	// IPv6 away from every device, and Clear does not put it back. Leaving it off
	// means IPv6 is not classified at all, so it must not be reachable -- verify
	// that separately rather than assuming it.
	DropIPv6 bool
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
	Address    netip.Prefix // tunnel address on wg-exit
	Peer       WireGuardPeer
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

// NftSetSpec is a named set of IPv4 prefixes (interval).
type NftSetSpec struct {
	Name     string
	Type     string // "ipv4_addr"
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
	// Description is a stable id for semantic comparison.
	Description string
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
	Priority int
	Mark     uint32
	Table    int
}

// RouteSpec is a route in a specific table.
type RouteSpec struct {
	Table       int
	Destination netip.Prefix // default = 0.0.0.0/0
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
	Address    netip.Prefix
	Peer       WireGuardPeer
	Managed    bool // if false, apply only assumes iface exists for routing
	Up         bool // desired admin state; false => fail-closed (iface down, no AllowedIPs routes)
}
