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

	// MandatoryNonRoutable is unioned in rather than replaced by the operator's
	// list: an override that forgot IPv6 link-local and multicast would mark
	// neighbour discovery and take IPv6 off the segment entirely.
	excludes := append([]netip.Prefix(nil), p.LANs...)
	excludes = append(excludes, MandatoryNonRoutable()...)
	excludes = append(excludes, p.NonRoutablePrefixes...)
	// Deduped, because the mandatory list and the default one deliberately
	// overlap -- loopback, link-local and multicast appear in both -- and each
	// duplicate would otherwise become a second identical nft rule sitting in
	// the prerouting hot path.
	excludes = dedupePrefixes(excludes)

	dir4, dir6 := SplitPrefixes(p.DirectPrefixes)
	ex4, ex6 := SplitPrefixes(excludes)
	lan4, lan6 := SplitPrefixes(p.LANs)
	ep4, ep6 := SplitAddrs(p.TunnelEndpoints)

	plan, warnings := planIPv6(p, len(dir6))

	sets := []NftSetSpec{
		{
			Name:     RuNetsSetName,
			Family:   FamilyV4,
			Type:     SetTypeFor(FamilyV4),
			Flags:    []string{"interval"},
			Elements: slices.Clone(dir4),
		},
	}
	if plan.Classify {
		sets = append(sets, NftSetSpec{
			Name:     RuNetsSetNameV6,
			Family:   FamilyV6,
			Type:     SetTypeFor(FamilyV6),
			Flags:    []string{"interval"},
			Elements: slices.Clone(dir6),
		})
	}
	chains := []NftChainSpec{
		{
			Name:     "prerouting",
			Type:     "filter",
			Hook:     "prerouting",
			Priority: MarkChainPriority,
			Policy:   "accept",
			Rules:    markRules(p, plan, mark, ex4, ex6, ep4, ep6),
		},
	}

	inboundManaged := p.InboundWireGuard.PrivateKey != ""
	if inboundManaged {
		sets = append(sets, NftSetSpec{
			Name:     HomeNetsSetName,
			Family:   FamilyV4,
			Type:     SetTypeFor(FamilyV4),
			Flags:    []string{"interval"},
			Elements: slices.Clone(lan4),
		})
		forwardRules := []NftRuleSpec{
			{
				Description: "isolate-inbound-from-home",
				Family:      FamilyV4,
				IIfName:     clientsIface,
				DropDstSet:  HomeNetsSetName,
			},
		}
		// The IPv6 half only exists when there is a v6 home net to isolate.
		// An empty home_nets6 would drop nothing, which is fine, but an
		// always-emitted set is one more object to keep converged for no gain.
		if plan.Classify && len(lan6) > 0 {
			sets = append(sets, NftSetSpec{
				Name:     HomeNetsSetNameV6,
				Family:   FamilyV6,
				Type:     SetTypeFor(FamilyV6),
				Flags:    []string{"interval"},
				Elements: slices.Clone(lan6),
			})
			forwardRules = append(forwardRules, NftRuleSpec{
				Description: "isolate-inbound-from-home",
				Family:      FamilyV6,
				IIfName:     clientsIface,
				DropDstSet:  HomeNetsSetNameV6,
			})
		}
		chains = append(chains, NftChainSpec{
			Name:     "forward",
			Type:     "filter",
			Hook:     "forward",
			Priority: 0,
			Policy:   "accept",
			Rules:    forwardRules,
		})
	}

	// Masquerade the direct class on the way out, when asked.
	//
	// The tunnel class egresses wg-exit, so matching on the LAN output
	// interfaces already selects only direct-class traffic. Two guards matter:
	//
	//   fib saddr type != local  -- WireGuard's own encapsulated packets are
	//     locally generated, carry the gateway's LAN address and leave via a LAN
	//     interface, so they match oifname too. Masquerading them can remap the
	//     source port and make the peer see a roaming endpoint. A mark match
	//     cannot substitute: encap packets never traverse prerouting, so they
	//     carry mark 0 exactly like the direct class.
	//
	//   ip daddr <LAN> return   -- traffic the gateway forwards between two LAN
	//     hosts also arrives and leaves on a LAN interface. It never transits the
	//     upstream router and must keep the client's source address.
	//
	// DirectSNAT6 is a separate opt-in rather than following DirectSNAT,
	// because the reasoning above is about IPv4 NAT: a routed IPv6 prefix
	// wants no NAT66 at all, and masquerading it would hide the very addresses
	// that make IPv6 worth having. It is only useful on a ULA-only LAN.
	if len(p.LANIfaces) > 0 && (p.DirectSNAT || (p.DirectSNAT6 && plan.Classify)) {
		var natRules []NftRuleSpec
		if p.DirectSNAT {
			natRules = append(natRules, NftRuleSpec{
				Description:     "snat-direct",
				Family:          FamilyV4,
				OIfNames:        slices.Clone(p.LANIfaces),
				ExcludePrefixes: slices.Clone(lan4),
				SNATMasquerade:  true,
			})
		}
		if p.DirectSNAT6 && plan.Classify {
			natRules = append(natRules, NftRuleSpec{
				Description:     "snat-direct",
				Family:          FamilyV6,
				OIfNames:        slices.Clone(p.LANIfaces),
				ExcludePrefixes: slices.Clone(lan6),
				SNATMasquerade:  true,
			})
		}
		chains = append(chains, NftChainSpec{
			Name:     "postrouting",
			Type:     "nat",
			Hook:     "postrouting",
			Priority: SrcNatPriority,
			Policy:   "accept",
			Rules:    natRules,
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
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
		{Key: "net.ipv4.conf.default.send_redirects", Value: "0"},
	}
	for _, dev := range p.LANIfaces {
		sysctls = append(sysctls, SysctlSpec{
			Key:   "net.ipv4.conf." + dev + ".send_redirects",
			Value: "0",
		})
	}
	if plan.Classify {
		// Forwarding is off by default for IPv6 on a plain Linux box, and
		// without it the gateway silently drops every forwarded v6 packet.
		//
		// Enabling it has a side effect worth knowing: the kernel stops
		// honouring Router Advertisements on interfaces left at accept_ra=1,
		// so a WAN whose address comes from SLAAC can lose its v6 default
		// route. That interface needs accept_ra=2. gotun does not write it --
		// the WAN is netifd's to configure, not the classifier's.
		sysctls = append(sysctls, SysctlSpec{Key: "net.ipv6.conf.all.forwarding", Value: "1"})
	}
	if p.DropIPv6 {
		// Only when explicitly asked: Clear cannot undo these, so on a shared
		// gateway they outlive the deployment that set them.
		sysctls = append(sysctls,
			SysctlSpec{Key: "net.ipv6.conf.all.disable_ipv6", Value: "1"},
			SysctlSpec{Key: "net.ipv6.conf.default.disable_ipv6", Value: "1"},
		)
	}

	state := DesiredKernelState{
		Sysctls: sysctls,
		Nft: NftSpec{
			Family: OwnedNftFamily,
			Table:  OwnedNftTable,
			Sets:   sets,
			Chains: chains,
		},
		IPRules:  ipRules(prio, mark, table, plan),
		Routes:   routes(table, iface, p.TunnelUp, p.FailMode, plan),
		Warnings: warnings,
		IPv6:     plan,
		WireGuard: WireGuardSpec{
			Interface:  iface,
			PrivateKey: p.WireGuard.PrivateKey,
			ListenPort: p.WireGuard.ListenPort,
			Addresses:  slices.Clone(p.WireGuard.Addresses),
			Peer:       p.WireGuard.Peer,
			Managed:    p.WireGuard.PrivateKey != "",
			Up:         p.TunnelUp,
		},
		WireGuardClients: WireGuardSpec{
			Interface:  clientsIface,
			PrivateKey: p.InboundWireGuard.PrivateKey,
			ListenPort: p.InboundWireGuard.ListenPort,
			Addresses:  slices.Clone(p.InboundWireGuard.Addresses),
			Peer:       p.InboundWireGuard.Peer,
			Managed:    inboundManaged,
			Up:         inboundManaged, // listen iface stays up whenever managed
		},
	}

	if err := checkInvariants(state); err != nil {
		return DesiredKernelState{}, err
	}
	return state, nil
}

// IPv6Plan records what Compile decided to do about IPv6, so apply and status
// can report it rather than leaving the operator to infer it from nft output.
type IPv6Plan struct {
	// Classify emits ru_nets6, the IPv6 exclude rules and an IPv6 verdict rule.
	Classify bool
	// Mark makes the verdict "set mark"; false means "drop".
	Mark bool
	// RouteVia installs ::/0 via the tunnel device in the owned table.
	RouteVia bool
	// Blackhole installs a terminal blackhole ::/0 in the owned table.
	Blackhole bool
}

// planIPv6 decides how IPv6 is treated, and returns any warnings the operator
// needs to see. Every path that leaves IPv6 unclassified warns, because the
// result is a silent leak rather than a visible failure.
func planIPv6(p Policy, directCount int) (IPv6Plan, []string) {
	var warn []string

	if p.DropIPv6 {
		return IPv6Plan{}, append(warn,
			"-drop-ipv6 is set, so IPv6 is dropped rather than classified;"+
				" prefer -ipv6 off, which leaves no sysctls behind that clear cannot undo")
	}
	if p.IPv6 == IPv6Off {
		return IPv6Plan{}, warn
	}

	classify := func() (IPv6Plan, []string) {
		if directCount == 0 {
			warn = append(warn, "IPv6 classification is on with an empty IPv6 direct set,"+
				" so ALL IPv6 is treated as non-direct")
		}
		return IPv6Plan{
			Classify:  true,
			Mark:      true,
			RouteVia:  p.TunnelUp,
			Blackhole: p.FailMode == FailClosed,
		}, warn
	}

	if p.IPv6 == IPv6On {
		return classify()
	}

	// Auto.
	if !p.TunnelCarriesIPv6 {
		switch p.IPv6Fallback {
		case FallbackBlackhole:
			warn = append(warn, "the tunnel does not carry IPv6; non-direct IPv6 will be blackholed")
			return IPv6Plan{Classify: true, Mark: true, Blackhole: true}, warn
		case FallbackDrop:
			warn = append(warn, "the tunnel does not carry IPv6; non-direct IPv6 will be dropped")
			return IPv6Plan{Classify: true}, warn
		default:
			return IPv6Plan{}, append(warn,
				"the tunnel does not carry IPv6, so non-direct IPv6 will egress the uplink"+
					" DIRECTLY, exposing the real IPv6 address to every IPv6-capable destination."+
					" Clients prefer IPv6 when both families resolve, so this is the common path,"+
					" not a corner case. Use -ipv6-fallback blackhole to prevent it")
		}
	}
	if directCount == 0 {
		return IPv6Plan{}, append(warn,
			"no IPv6 direct prefixes were loaded, so IPv6 is left unclassified and egresses"+
				" the uplink directly. Re-run gotun fetch to pick up IPv6 prefixes, or pass"+
				" -ipv6 on to tunnel all IPv6")
	}
	return classify()
}

// markRules builds the prerouting rule list. The ingress guard comes first so
// traffic from interfaces gotun does not steer never even walks the direct set,
// and it is emitted once with FamilyAny: it matches on the input interface, has
// no layer-3 dependency, and a second copy would just double it in the chain.
func markRules(p Policy, plan IPv6Plan, mark uint32,
	ex4, ex6 []netip.Prefix, ep4, ep6 []netip.Addr) []NftRuleSpec {

	var rules []NftRuleSpec
	if p.DropIPv6 {
		rules = append(rules, NftRuleSpec{Description: "drop-ipv6", Family: FamilyAny, DropIPv6: true})
	}
	if len(p.MarkIIfNames) > 0 {
		rules = append(rules, NftRuleSpec{
			Description: "only-marked-ingress",
			Family:      FamilyAny,
			IIfNames:    slices.Clone(p.MarkIIfNames),
		})
	}
	rules = append(rules, NftRuleSpec{
		Description:     "mark-non-direct",
		Family:          FamilyV4,
		ExcludePrefixes: ex4,
		ExcludeAddrs:    ep4,
		DirectSet:       RuNetsSetName,
		Mark:            mark,
	})
	if plan.Classify {
		v6 := NftRuleSpec{
			Description:     "mark-non-direct",
			Family:          FamilyV6,
			ExcludePrefixes: ex6,
			ExcludeAddrs:    ep6,
			DirectSet:       RuNetsSetNameV6,
		}
		if plan.Mark {
			v6.Mark = mark
		} else {
			v6.DropNonDirect = true
		}
		rules = append(rules, v6)
	}
	return rules
}

// dedupePrefixes removes exact duplicates, preserving first-seen order so the
// emitted rule list stays stable across applies.
func dedupePrefixes(ps []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(ps))
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		m := p.Masked()
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

func ipRules(prio int, mark uint32, table int, plan IPv6Plan) []IPRuleSpec {
	out := []IPRuleSpec{{Family: FamilyV4, Priority: prio, Mark: mark, Table: table}}
	// Only when something actually sets the mark on IPv6. Under the drop
	// fallback nothing is marked, so a rule would steer an empty table.
	if plan.Classify && plan.Mark {
		out = append(out, IPRuleSpec{Family: FamilyV6, Priority: prio, Mark: mark, Table: table})
	}
	return out
}

func routes(table int, iface string, tunnelUp bool, mode FailMode, plan IPv6Plan) []RouteSpec {
	out := routesForTunnel(FamilyV4, table, iface, tunnelUp, mode)
	if plan.Classify && plan.Mark {
		// The IPv6 half is driven by the plan rather than by tunnelUp and the
		// fail mode alone: under the blackhole fallback the tunnel is up but
		// cannot carry IPv6, so there must be no route via it.
		out = append(out, routesForPlan(table, iface, plan)...)
	}
	return out
}

func routesForPlan(table int, iface string, plan IPv6Plan) []RouteSpec {
	dst := DefaultRouteFor(FamilyV6)
	var out []RouteSpec
	if plan.RouteVia {
		out = append(out, RouteSpec{
			Family: FamilyV6, Table: table, Destination: dst,
			Device: iface, Metric: TunnelRouteMetric,
		})
	}
	if plan.Blackhole {
		out = append(out, RouteSpec{
			Family: FamilyV6, Table: table, Destination: dst,
			Blackhole: true, Metric: FailClosedRouteMetric,
		})
	}
	return out
}

// routesForTunnel always installs a terminal blackhole in the owned table.
// When the tunnel is up, a lower-metric device route is preferred; if wg-exit
// disappears without a control-plane reapply, the blackhole remains and
// marked packets cannot fall through RPDB into main.
func routesForTunnel(fam Family, table int, iface string, tunnelUp bool, mode FailMode) []RouteSpec {
	dst := DefaultRouteFor(fam)
	tunnel := RouteSpec{Family: fam, Table: table, Destination: dst, Device: iface, Metric: TunnelRouteMetric}

	if mode == FailOpen {
		// Nothing but the tunnel route. When it is absent -- withdrawn here, or
		// dropped by the kernel when the link goes down -- the lookup in this
		// table misses and the RPDB continues to main. Verified to hold for
		// IPv6 as well as IPv4.
		//
		// Returning an empty slice is only safe because routing.Reconcile treats
		// every table named by an ip rule as owned, and so still flushes a table
		// with no desired routes. Without that, a stale blackhole would survive.
		if !tunnelUp {
			return nil
		}
		return []RouteSpec{tunnel}
	}

	// Fail-closed: a terminal blackhole always remains, so losing wg-exit without
	// a control-plane reapply cannot fall through the RPDB into main.
	bh := RouteSpec{
		Family:      fam,
		Table:       table,
		Destination: dst,
		Blackhole:   true,
		Metric:      FailClosedRouteMetric,
	}
	if !tunnelUp {
		return []RouteSpec{bh}
	}
	return []RouteSpec{tunnel, bh}
}

func validate(p Policy) error {
	if len(p.TunnelEndpoints) == 0 {
		return fmt.Errorf("policy: at least one TunnelEndpoint is required")
	}
	for _, a := range p.TunnelEndpoints {
		if !a.IsValid() {
			return fmt.Errorf("policy: invalid TunnelEndpoint %v", a)
		}
	}
	for _, pref := range p.DirectPrefixes {
		if !pref.IsValid() {
			return fmt.Errorf("policy: invalid DirectPrefix %v", pref)
		}
		if pref.Addr().Is4In6() {
			// It reports Is6, so it would be routed into the ipv6_addr set,
			// where it matches nothing: the kernel compares a v6 packet's
			// destination and a v4 packet never presents one.
			return fmt.Errorf("policy: 4-in-6 DirectPrefix %v; write it as plain IPv4", pref)
		}
	}
	if p.DropIPv6 && p.IPv6 == IPv6On {
		return fmt.Errorf("policy: -drop-ipv6 and -ipv6 on are mutually exclusive" +
			" (one drops all IPv6, the other classifies it)")
	}
	if p.InboundWireGuard.PrivateKey != "" && len(p.LANs) == 0 {
		return fmt.Errorf("policy: LANs required when InboundWireGuard is set (home isolation)")
	}
	return nil
}

// checkInvariants rejects a state whose halves disagree.
//
// The failure it exists to prevent is not a crash but a leak: a rule that marks
// a family with no matching ip rule to steer it sends that traffic straight
// back to the main table, so the classifier appears to work while every packet
// takes the uplink. Catching it here turns a future refactor slip into a
// compile error instead of a silent policy hole.
func checkInvariants(st DesiredKernelState) error {
	setFamily := map[string]Family{}
	for _, set := range st.Nft.Sets {
		if !set.Family.Valid() || set.Family == FamilyAny {
			return fmt.Errorf("policy: set %q has invalid family %q", set.Name, set.Family)
		}
		if set.Type != SetTypeFor(set.Family) {
			return fmt.Errorf("policy: set %q is family %s but type %q", set.Name, set.Family, set.Type)
		}
		for _, el := range set.Elements {
			if FamilyOf(el) != set.Family {
				return fmt.Errorf("policy: set %q (%s) contains %v", set.Name, set.Family, el)
			}
		}
		setFamily[set.Name] = set.Family
	}

	marked := map[Family]bool{}
	for _, ch := range st.Nft.Chains {
		for _, rule := range ch.Rules {
			if !rule.Family.Valid() {
				return fmt.Errorf("policy: rule %q in chain %q has invalid family %q",
					rule.Description, ch.Name, rule.Family)
			}
			if rule.Family == FamilyAny &&
				(len(rule.ExcludePrefixes) > 0 || len(rule.ExcludeAddrs) > 0 ||
					rule.DirectSet != "" || rule.DropDstSet != "") {
				return fmt.Errorf("policy: rule %q is FamilyAny but matches on layer 3", rule.Description)
			}
			for _, name := range []string{rule.DirectSet, rule.DropDstSet} {
				if name == "" {
					continue
				}
				fam, ok := setFamily[name]
				if !ok {
					return fmt.Errorf("policy: rule %q references unknown set %q", rule.Description, name)
				}
				if fam != rule.Family {
					return fmt.Errorf("policy: rule %q (%s) references set %q (%s)",
						rule.Description, rule.Family, name, fam)
				}
			}
			for _, pref := range rule.ExcludePrefixes {
				if FamilyOf(pref) != rule.Family {
					return fmt.Errorf("policy: rule %q (%s) excludes %v",
						rule.Description, rule.Family, pref)
				}
			}
			for _, a := range rule.ExcludeAddrs {
				if FamilyOfAddr(a) != rule.Family {
					return fmt.Errorf("policy: rule %q (%s) excludes address %v",
						rule.Description, rule.Family, a)
				}
			}
			if rule.Mark != 0 {
				marked[rule.Family] = true
			}
		}
	}

	steered := map[Family]bool{}
	for _, r := range st.IPRules {
		steered[r.Family] = true
	}
	for fam := range marked {
		if !steered[fam] {
			return fmt.Errorf("policy: %s traffic is marked but no %s ip rule steers it;"+
				" it would fall through to the main table", fam, fam)
		}
	}
	for _, rt := range st.Routes {
		if !steered[rt.Family] {
			return fmt.Errorf("policy: %s route in table %d with no %s ip rule to reach it",
				rt.Family, rt.Table, rt.Family)
		}
		if rt.Destination.IsValid() && FamilyOf(rt.Destination) != rt.Family {
			return fmt.Errorf("policy: %s route with destination %v", rt.Family, rt.Destination)
		}
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
		a, b := out.IPRules[i], out.IPRules[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.Mark < b.Mark
	})
	sort.Slice(out.Routes, func(i, j int) bool {
		a, b := out.Routes[i], out.Routes[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
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
		out.Nft.Sets[i] = NftSetSpec{
			Name: set.Name, Family: set.Family, Type: set.Type, Flags: flags, Elements: el,
		}
	}
	sort.Slice(out.Nft.Sets, func(i, j int) bool { return out.Nft.Sets[i].Name < out.Nft.Sets[j].Name })
	for i, ch := range s.Nft.Chains {
		rules := make([]NftRuleSpec, len(ch.Rules))
		for j, rule := range ch.Rules {
			rules[j] = NftRuleSpec{
				Description:     rule.Description,
				Family:          rule.Family,
				ExcludePrefixes: slices.Clone(rule.ExcludePrefixes),
				ExcludeAddrs:    slices.Clone(rule.ExcludeAddrs),
				DirectSet:       rule.DirectSet,
				Mark:            rule.Mark,
				DropIPv6:        rule.DropIPv6,
				DropNonDirect:   rule.DropNonDirect,
				IIfName:         rule.IIfName,
				DropDstSet:      rule.DropDstSet,
				IIfNames:        slices.Clone(rule.IIfNames),
				OIfNames:        slices.Clone(rule.OIfNames),
				SNATMasquerade:  rule.SNATMasquerade,
			}
			sort.Strings(rules[j].IIfNames)
			sort.Strings(rules[j].OIfNames)
			sort.Slice(rules[j].ExcludePrefixes, func(a, b int) bool {
				return rules[j].ExcludePrefixes[a].String() < rules[j].ExcludePrefixes[b].String()
			})
			sort.Slice(rules[j].ExcludeAddrs, func(a, b int) bool {
				return rules[j].ExcludeAddrs[a].String() < rules[j].ExcludeAddrs[b].String()
			})
		}
		// Family is part of the key: mark-non-direct now exists once per family,
		// and sorting by Description alone would leave their order dependent on
		// how Compile happened to append them.
		sort.Slice(rules, func(a, b int) bool {
			if rules[a].Description != rules[b].Description {
				return rules[a].Description < rules[b].Description
			}
			return rules[a].Family < rules[b].Family
		})
		out.Nft.Chains[i] = NftChainSpec{
			Name: ch.Name, Type: ch.Type, Hook: ch.Hook, Priority: ch.Priority, Policy: ch.Policy, Rules: rules,
		}
	}
	sort.Slice(out.Nft.Chains, func(i, j int) bool { return out.Nft.Chains[i].Name < out.Nft.Chains[j].Name })
	return out
}

func normalizeWGPeer(wg *WireGuardSpec) {
	if wg.Addresses != nil {
		wg.Addresses = slices.Clone(wg.Addresses)
		sort.Slice(wg.Addresses, func(i, j int) bool {
			return wg.Addresses[i].String() < wg.Addresses[j].String()
		})
	}
	if wg.Peer.AllowedIPs == nil {
		return
	}
	wg.Peer.AllowedIPs = slices.Clone(wg.Peer.AllowedIPs)
	sort.Slice(wg.Peer.AllowedIPs, func(i, j int) bool {
		return wg.Peer.AllowedIPs[i].String() < wg.Peer.AllowedIPs[j].String()
	})
}
