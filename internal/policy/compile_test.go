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
