package policy

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"
)

// Compile turns a Policy into a declarative DesiredKernelState.
func Compile(p Policy) (DesiredKernelState, error) {
	if err := validate(p); err != nil {
		return DesiredKernelState{}, err
	}

	mark := p.Mark
	if mark == 0 {
		mark = DefaultMark
	}
	table := p.Table
	if table == 0 {
		table = DefaultTableID
	}
	prio := p.RulePriority
	if prio == 0 {
		prio = DefaultRulePriority
	}
	iface := p.TunnelInterface
	if iface == "" {
		iface = DefaultTunnelIface
	}
	clientsIface := DefaultClientsIface

	excludes := append([]netip.Prefix(nil), p.LANs...)
	excludeAddrs := []netip.Addr{}
	if p.TunnelEndpoint.IsValid() {
		excludeAddrs = append(excludeAddrs, p.TunnelEndpoint)
	}

	sets := []NftSetSpec{
		{
			Name:     RuNetsSetName,
			Type:     "ipv4_addr",
			Flags:    []string{"interval"},
			Elements: append([]netip.Prefix(nil), p.DirectPrefixes...),
		},
	}
	chains := []NftChainSpec{
		{
			Name:     "prerouting",
			Type:     "filter",
			Hook:     "prerouting",
			Priority: -150, // mangle-like
			Policy:   "accept",
			Rules: []NftRuleSpec{
				{
					Description: "drop-ipv6",
					DropIPv6:    true,
				},
				{
					Description:     "mark-non-direct",
					ExcludePrefixes: excludes,
					ExcludeAddrs:    excludeAddrs,
					DirectSet:       RuNetsSetName,
					Mark:            mark,
				},
			},
		},
	}

	inboundManaged := p.InboundWireGuard.PrivateKey != ""
	if inboundManaged {
		sets = append(sets, NftSetSpec{
			Name:     HomeNetsSetName,
			Type:     "ipv4_addr",
			Flags:    []string{"interval"},
			Elements: append([]netip.Prefix(nil), p.LANs...),
		})
		chains = append(chains, NftChainSpec{
			Name:     "forward",
			Type:     "filter",
			Hook:     "forward",
			Priority: 0,
			Policy:   "accept",
			Rules: []NftRuleSpec{
				{
					Description: "isolate-inbound-from-home",
					IIfName:     clientsIface,
					DropDstSet:  HomeNetsSetName,
				},
			},
		})
	}

	// A policy-routing gateway must not emit ICMP redirects. When a client
	// sends direct-destined traffic here, the next hop is on the same interface
	// the packet arrived on, so the kernel would tell the client "go to the ISP
	// router yourself" -- the client then caches a route that bypasses this box
	// entirely. Today that only affects the direct class, where the egress is
	// the same either way, but it means a client's own route table stops
	// reflecting the policy, and any future per-destination decision here would
	// be silently ignored.
	//
	// The kernel ORs the "all" and per-device values for send_redirects, so
	// both have to be zero: "all" alone is not enough.
	sysctls := []SysctlSpec{
		{Key: "net.ipv4.ip_forward", Value: "1"},
		{Key: "net.ipv6.conf.all.disable_ipv6", Value: "1"},
		{Key: "net.ipv6.conf.default.disable_ipv6", Value: "1"},
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
		{Key: "net.ipv4.conf.default.send_redirects", Value: "0"},
	}
	for _, dev := range p.LANIfaces {
		sysctls = append(sysctls, SysctlSpec{
			Key:   "net.ipv4.conf." + dev + ".send_redirects",
			Value: "0",
		})
	}

	state := DesiredKernelState{
		Sysctls: sysctls,
		Nft: NftSpec{
			Family: OwnedNftFamily,
			Table:  OwnedNftTable,
			Sets:   sets,
			Chains: chains,
		},
		IPRules: []IPRuleSpec{
			{Priority: prio, Mark: mark, Table: table},
		},
		Routes: routesForTunnel(table, iface, p.TunnelUp, p.FailMode),
		WireGuard: WireGuardSpec{
			Interface:  iface,
			PrivateKey: p.WireGuard.PrivateKey,
			ListenPort: p.WireGuard.ListenPort,
			Address:    p.WireGuard.Address,
			Peer:       p.WireGuard.Peer,
			Managed:    p.WireGuard.PrivateKey != "",
			Up:         p.TunnelUp,
		},
		WireGuardClients: WireGuardSpec{
			Interface:  clientsIface,
			PrivateKey: p.InboundWireGuard.PrivateKey,
			ListenPort: p.InboundWireGuard.ListenPort,
			Address:    p.InboundWireGuard.Address,
			Peer:       p.InboundWireGuard.Peer,
			Managed:    inboundManaged,
			Up:         inboundManaged, // listen iface stays up whenever managed
		},
	}

	return state, nil
}

// routesForTunnel always installs a terminal blackhole in the owned table.
// When the tunnel is up, a lower-metric device route is preferred; if wg-exit
// disappears without a control-plane reapply, the blackhole remains and
// marked packets cannot fall through RPDB into main.
func routesForTunnel(table int, iface string, tunnelUp bool, mode FailMode) []RouteSpec {
	dst := netip.MustParsePrefix("0.0.0.0/0")
	_ = mode // v1: FailClosed only
	bh := RouteSpec{
		Table:       table,
		Destination: dst,
		Blackhole:   true,
		Metric:      FailClosedRouteMetric,
	}
	if !tunnelUp {
		return []RouteSpec{bh}
	}
	return []RouteSpec{
		{Table: table, Destination: dst, Device: iface, Metric: TunnelRouteMetric},
		bh,
	}
}

func validate(p Policy) error {
	if !p.TunnelEndpoint.IsValid() {
		return fmt.Errorf("policy: TunnelEndpoint is required")
	}
	for _, pref := range p.DirectPrefixes {
		if !pref.IsValid() || pref.Addr().Is6() {
			return fmt.Errorf("policy: invalid or IPv6 DirectPrefix %v", pref)
		}
	}
	if p.InboundWireGuard.PrivateKey != "" && len(p.LANs) == 0 {
		return fmt.Errorf("policy: LANs required when InboundWireGuard is set (home isolation)")
	}
	return nil
}

// SemanticEqual reports whether two desired states are semantically equivalent
// after canonicalizing incidental ordering.
func SemanticEqual(a, b DesiredKernelState) bool {
	return reflect.DeepEqual(normalize(a), normalize(b))
}

func normalize(s DesiredKernelState) DesiredKernelState {
	out := DesiredKernelState{
		Sysctls:          slices.Clone(s.Sysctls),
		IPRules:          slices.Clone(s.IPRules),
		Routes:           slices.Clone(s.Routes),
		WireGuard:        s.WireGuard,
		WireGuardClients: s.WireGuardClients,
		Nft: NftSpec{
			Family: s.Nft.Family,
			Table:  s.Nft.Table,
			Sets:   make([]NftSetSpec, len(s.Nft.Sets)),
			Chains: make([]NftChainSpec, len(s.Nft.Chains)),
		},
	}
	sort.Slice(out.Sysctls, func(i, j int) bool { return out.Sysctls[i].Key < out.Sysctls[j].Key })
	sort.Slice(out.IPRules, func(i, j int) bool {
		if out.IPRules[i].Priority != out.IPRules[j].Priority {
			return out.IPRules[i].Priority < out.IPRules[j].Priority
		}
		return out.IPRules[i].Mark < out.IPRules[j].Mark
	})
	sort.Slice(out.Routes, func(i, j int) bool {
		a, b := out.Routes[i], out.Routes[j]
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Metric != b.Metric {
			return a.Metric < b.Metric
		}
		if a.Blackhole != b.Blackhole {
			return a.Blackhole
		}
		return a.Device < b.Device
	})
	normalizeWGPeer(&out.WireGuard)
	normalizeWGPeer(&out.WireGuardClients)
	for i, set := range s.Nft.Sets {
		el := slices.Clone(set.Elements)
		sort.Slice(el, func(a, b int) bool { return el[a].String() < el[b].String() })
		flags := slices.Clone(set.Flags)
		sort.Strings(flags)
		out.Nft.Sets[i] = NftSetSpec{Name: set.Name, Type: set.Type, Flags: flags, Elements: el}
	}
	sort.Slice(out.Nft.Sets, func(i, j int) bool { return out.Nft.Sets[i].Name < out.Nft.Sets[j].Name })
	for i, ch := range s.Nft.Chains {
		rules := make([]NftRuleSpec, len(ch.Rules))
		for j, rule := range ch.Rules {
			rules[j] = NftRuleSpec{
				Description:     rule.Description,
				ExcludePrefixes: slices.Clone(rule.ExcludePrefixes),
				ExcludeAddrs:    slices.Clone(rule.ExcludeAddrs),
				DirectSet:       rule.DirectSet,
				Mark:            rule.Mark,
				DropIPv6:        rule.DropIPv6,
				IIfName:         rule.IIfName,
				DropDstSet:      rule.DropDstSet,
			}
			sort.Slice(rules[j].ExcludePrefixes, func(a, b int) bool {
				return rules[j].ExcludePrefixes[a].String() < rules[j].ExcludePrefixes[b].String()
			})
			sort.Slice(rules[j].ExcludeAddrs, func(a, b int) bool {
				return rules[j].ExcludeAddrs[a].String() < rules[j].ExcludeAddrs[b].String()
			})
		}
		sort.Slice(rules, func(a, b int) bool { return rules[a].Description < rules[b].Description })
		out.Nft.Chains[i] = NftChainSpec{
			Name: ch.Name, Type: ch.Type, Hook: ch.Hook, Priority: ch.Priority, Policy: ch.Policy, Rules: rules,
		}
	}
	sort.Slice(out.Nft.Chains, func(i, j int) bool { return out.Nft.Chains[i].Name < out.Nft.Chains[j].Name })
	return out
}

func normalizeWGPeer(wg *WireGuardSpec) {
	if wg.Peer.AllowedIPs == nil {
		return
	}
	wg.Peer.AllowedIPs = slices.Clone(wg.Peer.AllowedIPs)
	sort.Slice(wg.Peer.AllowedIPs, func(i, j int) bool {
		return wg.Peer.AllowedIPs[i].String() < wg.Peer.AllowedIPs[j].String()
	})
}
