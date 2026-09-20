package policy

import "net/netip"

// FailMode controls non-RU behavior when the tunnel is unavailable.
type FailMode int

const (
	// FailClosed blackholes marked (non-RU) traffic when the tunnel is down.
	FailClosed FailMode = iota
)

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
	// MatchExcludes: if dst is in any of these prefixes or equals Endpoint, skip mark.
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
