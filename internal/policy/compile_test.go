package policy_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func testPolicy(tunnelUp bool) policy.Policy {
	return policy.Policy{
		DirectPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.0/24"),
		},
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		FailMode:        policy.FailClosed,
		TunnelUp:        tunnelUp,
	}
}

func TestCompile_OwnedTableAndSet(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if st.Nft.Family != policy.OwnedNftFamily || st.Nft.Table != policy.OwnedNftTable {
		t.Fatalf("owned table: %s %s", st.Nft.Family, st.Nft.Table)
	}
	if len(st.Nft.Sets) != 1 || st.Nft.Sets[0].Name != policy.RuNetsSetName {
		t.Fatalf("sets: %+v", st.Nft.Sets)
	}
	if len(st.Nft.Sets[0].Elements) != 1 {
		t.Fatalf("elements: %v", st.Nft.Sets[0].Elements)
	}
}

func TestCompile_EndpointExcluded(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	var markRule *policy.NftRuleSpec
	for i := range st.Nft.Chains {
		for j := range st.Nft.Chains[i].Rules {
			if st.Nft.Chains[i].Rules[j].Description == "mark-non-direct" {
				markRule = &st.Nft.Chains[i].Rules[j]
			}
		}
	}
	if markRule == nil {
		t.Fatal("missing mark-non-direct rule")
	}
	if len(markRule.ExcludeAddrs) != 1 || markRule.ExcludeAddrs[0].String() != "10.10.0.2" {
		t.Fatalf("exclude addrs: %v", markRule.ExcludeAddrs)
	}
	if len(markRule.ExcludePrefixes) != 1 {
		t.Fatalf("exclude prefixes: %v", markRule.ExcludePrefixes)
	}
}

func TestCompile_FailClosedBlackhole(t *testing.T) {
	st, err := policy.Compile(testPolicy(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 1 || !st.Routes[0].Blackhole || st.Routes[0].Metric != policy.FailClosedRouteMetric {
		t.Fatalf("want lone blackhole metric %d, got %+v", policy.FailClosedRouteMetric, st.Routes)
	}
}

func TestCompile_TunnelUpKeepsFailClosedFallback(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Routes) != 2 {
		t.Fatalf("want device + blackhole routes, got %+v", st.Routes)
	}
	var haveDev, haveBH bool
	for _, rt := range st.Routes {
		if rt.Device == "wg-exit" && rt.Metric == policy.TunnelRouteMetric && !rt.Blackhole {
			haveDev = true
		}
		if rt.Blackhole && rt.Metric == policy.FailClosedRouteMetric {
			haveBH = true
		}
	}
	if !haveDev || !haveBH {
		t.Fatalf("want wg-exit metric %d + blackhole metric %d, got %+v",
			policy.TunnelRouteMetric, policy.FailClosedRouteMetric, st.Routes)
	}
}

func TestSemanticEqual_IgnoresPrefixOrder(t *testing.T) {
	a := testPolicy(true)
	b := testPolicy(true)
	b.DirectPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.200.1.0/24"),
		netip.MustParsePrefix("10.200.0.0/24"),
	}
	a.DirectPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.200.0.0/24"),
		netip.MustParsePrefix("10.200.1.0/24"),
	}
	sa, err := policy.Compile(a)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := policy.Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.SemanticEqual(sa, sb) {
		t.Fatal("expected equal after normalize despite prefix order")
	}
}

func TestCompile_RequiresEndpoint(t *testing.T) {
	p := testPolicy(true)
	p.TunnelEndpoint = netip.Addr{}
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("expected error")
	}
}

func TestSemanticEqual_SamePolicy(t *testing.T) {
	a, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.SemanticEqual(a, b) {
		t.Fatal("expected semantic equal")
	}
}

func TestCompile_InboundIsolatesHomeNets(t *testing.T) {
	p := testPolicy(true)
	p.InboundWireGuard = policy.WireGuardConfig{
		PrivateKey: "CLIENTPRIV",
		ListenPort: 51821,
		Address:    netip.MustParsePrefix("10.98.0.1/30"),
		Peer: policy.WireGuardPeer{
			PublicKey:  "WANPEER",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.0.2/32")},
		},
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.WireGuardClients.Managed || st.WireGuardClients.Interface != policy.DefaultClientsIface {
		t.Fatalf("clients wg: %+v", st.WireGuardClients)
	}
	var haveHome, haveIsolate bool
	for _, set := range st.Nft.Sets {
		if set.Name == policy.HomeNetsSetName && len(set.Elements) == 1 {
			haveHome = true
		}
	}
	for _, ch := range st.Nft.Chains {
		if ch.Hook != "forward" {
			continue
		}
		for _, r := range ch.Rules {
			if r.Description == "isolate-inbound-from-home" &&
				r.IIfName == policy.DefaultClientsIface &&
				r.DropDstSet == policy.HomeNetsSetName {
				haveIsolate = true
			}
		}
	}
	if !haveHome || !haveIsolate {
		t.Fatalf("want home_nets + isolate rule, sets=%+v chains=%+v", st.Nft.Sets, st.Nft.Chains)
	}
}

func TestCompile_InboundRequiresLANs(t *testing.T) {
	p := testPolicy(true)
	p.LANs = nil
	p.InboundWireGuard = policy.WireGuardConfig{PrivateKey: "x"}
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("expected error when inbound WG without LANs")
	}
}

func TestCompile_DisablesSendRedirectsIncludingPerDevice(t *testing.T) {
	p := policy.Policy{
		DirectPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")},
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("192.168.8.0/24")},
		LANIfaces:       []string{"enp1s0"},
		Mark:            0x1,
		Table:           100,
		RulePriority:    100,
		FailMode:        policy.FailClosed,
		TunnelUp:        true,
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	got := map[string]string{}
	for _, s := range st.Sysctls {
		got[s.Key] = s.Value
	}
	// The kernel ORs "all" with the per-device value, so both must be zero:
	// clearing "all" alone leaves redirects enabled on a device set to 1.
	for _, key := range []string{
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.conf.default.send_redirects",
		"net.ipv4.conf.enp1s0.send_redirects",
	} {
		if got[key] != "0" {
			t.Errorf("%s = %q, want 0", key, got[key])
		}
	}
	if got["net.ipv4.ip_forward"] != "1" {
		t.Errorf("ip_forward should still be 1, got %q", got["net.ipv4.ip_forward"])
	}
}

func TestCompile_NoLANIfacesStillClearsAll(t *testing.T) {
	st, err := policy.Compile(policy.Policy{
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		Mark:            0x1, Table: 100, RulePriority: 100,
		FailMode: policy.FailClosed, TunnelUp: true,
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	found := false
	for _, s := range st.Sysctls {
		if s.Key == "net.ipv4.conf.all.send_redirects" && s.Value == "0" {
			found = true
		}
		if strings.Contains(s.Key, "conf..send_redirects") {
			t.Fatalf("empty interface name leaked into a sysctl key: %q", s.Key)
		}
	}
	if !found {
		t.Fatal("all.send_redirects should be cleared even with no LAN interfaces")
	}
}

func directSNATPolicy(ifaces ...string) policy.Policy {
	p := testPolicy(true)
	p.DirectSNAT = true
	p.LANIfaces = ifaces
	return p
}

func postroutingChain(t *testing.T, st policy.DesiredKernelState) *policy.NftChainSpec {
	t.Helper()
	for i, ch := range st.Nft.Chains {
		if ch.Hook == "postrouting" {
			return &st.Nft.Chains[i]
		}
	}
	return nil
}

func TestCompile_DirectSNATAddsPostroutingChain(t *testing.T) {
	st, err := policy.Compile(directSNATPolicy("enp1s0"))
	if err != nil {
		t.Fatal(err)
	}
	ch := postroutingChain(t, st)
	if ch == nil {
		t.Fatal("expected a postrouting chain")
	}
	if ch.Type != "nat" || ch.Priority != policy.SrcNatPriority || ch.Policy != "accept" {
		t.Fatalf("chain = %+v", *ch)
	}
	if len(ch.Rules) != 1 {
		t.Fatalf("want one rule, got %d", len(ch.Rules))
	}
	r := ch.Rules[0]
	if r.Description != "snat-direct" || !r.SNATMasquerade {
		t.Fatalf("rule = %+v", r)
	}
	if len(r.OIfNames) != 1 || r.OIfNames[0] != "enp1s0" {
		t.Fatalf("OIfNames = %v", r.OIfNames)
	}
	// The LAN skip guard must be present, or client-to-client traffic gets NATed.
	if len(r.ExcludePrefixes) != 1 || r.ExcludePrefixes[0].String() != "10.10.0.0/24" {
		t.Fatalf("ExcludePrefixes = %v", r.ExcludePrefixes)
	}
}

func TestCompile_NoDirectSNATByDefault(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if ch := postroutingChain(t, st); ch != nil {
		t.Fatalf("no postrouting chain expected by default, got %+v", *ch)
	}
}

// Compile must stay total: LANIfaces comes from live interface discovery, so a
// host that matches nothing must not make Compile fail.
func TestCompile_DirectSNATWithoutLANIfacesSkipsChain(t *testing.T) {
	st, err := policy.Compile(directSNATPolicy())
	if err != nil {
		t.Fatalf("Compile should not fail: %v", err)
	}
	if ch := postroutingChain(t, st); ch != nil {
		t.Fatal("no interfaces means no chain")
	}
}

// snatOnlyState is a minimal state differing ONLY in the SNAT rule fields.
//
// Compiling two policies with different LANIfaces would also change the
// per-device send_redirects sysctls, so SemanticEqual would differ for the wrong
// reason and the test would pass even with normalize() broken. Build the states
// directly to isolate the field under test.
func snatOnlyState(oif string, masq bool) policy.DesiredKernelState {
	return policy.DesiredKernelState{
		Nft: policy.NftSpec{
			Family: policy.OwnedNftFamily,
			Table:  policy.OwnedNftTable,
			Chains: []policy.NftChainSpec{{
				Name: "postrouting", Type: "nat", Hook: "postrouting",
				Priority: policy.SrcNatPriority, Policy: "accept",
				Rules: []policy.NftRuleSpec{{
					Description:    "snat-direct",
					OIfNames:       []string{oif},
					SNATMasquerade: masq,
				}},
			}},
		},
	}
}

// Guards normalize(): if OIfNames is not copied there, both sides normalise to
// nil and two genuinely different states compare equal -- drift goes undetected.
func TestSemanticEqual_DirectSNATOIfNameChangeDiffers(t *testing.T) {
	if policy.SemanticEqual(snatOnlyState("enp1s0", true), snatOnlyState("enp2s0", true)) {
		t.Fatal("a different output interface must not compare equal")
	}
}

// Same guard for the masquerade flag.
func TestSemanticEqual_DirectSNATMasqueradeFlagDiffers(t *testing.T) {
	if policy.SemanticEqual(snatOnlyState("enp1s0", true), snatOnlyState("enp1s0", false)) {
		t.Fatal("dropping the masquerade statement must not compare equal")
	}
}

func TestSemanticEqual_DirectSNATToggleDiffers(t *testing.T) {
	on, err := policy.Compile(directSNATPolicy("enp1s0"))
	if err != nil {
		t.Fatal(err)
	}
	off, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	if policy.SemanticEqual(on, off) {
		t.Fatal("enabling direct SNAT must not compare equal to leaving it off")
	}
}
