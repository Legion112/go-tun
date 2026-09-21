package nftables_test

import (
	"strings"
	"testing"
	"time"

	"net/netip"

	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/testutil"
)

func TestRenderFullTable_BatchesElements(t *testing.T) {
	els := make([]netip.Prefix, nftables.ElementBatchSize+10)
	for i := range els {
		els[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32)
	}
	script := nftables.RenderFullTable(policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{{
			Name:     "ru_nets",
			Type:     "ipv4_addr",
			Flags:    []string{"interval"},
			Elements: els,
		}},
	})
	if c := strings.Count(script, "add element"); c < 2 {
		t.Fatalf("expected multiple add element batches, got %d", c)
	}
}

// TestLargeRUSet_CompileAndRender runs the real RU extract, both families, at
// full size. The IPv6 half roughly doubles the element count on the wire, and
// its prefixes are about three times longer as text, so the batching maths and
// the script size are worth measuring rather than assuming.
func TestLargeRUSet_CompileAndRender(t *testing.T) {
	prefs := testutil.LoadAllRUfromMMDB(t)
	var v4, v6 []netip.Prefix
	for _, p := range prefs {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}

	start := time.Now()
	st, err := policy.Compile(policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: "wg-exit",
		TunnelEndpoints: []netip.Addr{netip.MustParseAddr("10.20.0.3")},
		LANs: []netip.Prefix{
			netip.MustParsePrefix("10.10.0.0/24"),
			netip.MustParsePrefix("fd00:10::/64"),
		},
		FailMode:          policy.FailClosed,
		TunnelUp:          false,
		TunnelCarriesIPv6: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Nft.Sets) != 2 {
		t.Fatalf("want one set per family, got %d", len(st.Nft.Sets))
	}
	bySet := map[string]policy.NftSetSpec{}
	for _, set := range st.Nft.Sets {
		bySet[set.Name] = set
	}
	if got := bySet[policy.RuNetsSetName]; len(got.Elements) != len(v4) || got.Type != "ipv4_addr" {
		t.Fatalf("ru_nets: %d elements type %q, want %d ipv4_addr", len(got.Elements), got.Type, len(v4))
	}
	if got := bySet[policy.RuNetsSetNameV6]; len(got.Elements) != len(v6) || got.Type != "ipv6_addr" {
		t.Fatalf("ru_nets6: %d elements type %q, want %d ipv6_addr", len(got.Elements), got.Type, len(v6))
	}

	renderStart := time.Now()
	script := nftables.RenderFullTable(st.Nft)
	renderDur := time.Since(renderStart)

	for _, want := range []string{"ru_nets", "ru_nets6", "type ipv6_addr", "ip6 daddr"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	batches := strings.Count(script, "add element")
	batchesFor := func(n int) int {
		return (n + nftables.ElementBatchSize - 1) / nftables.ElementBatchSize
	}
	if want := batchesFor(len(v4)) + batchesFor(len(v6)); batches != want {
		t.Fatalf("add element batches: got %d want %d", batches, want)
	}
	if len(script) < 1000 {
		t.Fatalf("script unexpectedly small: %d bytes", len(script))
	}
	t.Logf("RU prefixes=%d (v4=%d v6=%d) compile+checks=%s render=%s script=%d bytes batches=%d",
		len(prefs), len(v4), len(v6), time.Since(start), renderDur, len(script), batches)
}

func snatSpec(lans []string, oifs []string) policy.NftSpec {
	var pfx []netip.Prefix
	for _, l := range lans {
		pfx = append(pfx, netip.MustParsePrefix(l))
	}
	return policy.NftSpec{
		Family: "inet", Table: "gotun",
		Chains: []policy.NftChainSpec{{
			Name: "postrouting", Type: "nat", Hook: "postrouting",
			Priority: policy.SrcNatPriority, Policy: "accept",
			Rules: []policy.NftRuleSpec{{
				Description:     "snat-direct",
				OIfNames:        oifs,
				ExcludePrefixes: pfx,
				SNATMasquerade:  true,
			}},
		}},
	}
}

func TestRenderFullTable_DirectSNATChainAndRule(t *testing.T) {
	script := nftables.RenderFullTable(snatSpec([]string{"192.168.8.0/24"}, []string{"enp1s0"}))
	wantChain := "add chain inet gotun postrouting { type nat hook postrouting priority 100; policy accept; }"
	wantSkip := `ip daddr 192.168.8.0/24 return comment "snat-skip-lan"`
	wantMasq := `meta nfproto ipv4 oifname "enp1s0" fib saddr type != local counter masquerade comment "snat-direct"`
	for _, want := range []string{wantChain, wantSkip, wantMasq} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	// Guards must precede the masquerade: emission order is evaluation order.
	if strings.Index(script, wantSkip) > strings.Index(script, wantMasq) {
		t.Fatalf("skip guard must come before the masquerade:\n%s", script)
	}
}

func TestRenderFullTable_DirectSNATFansOutPerInterface(t *testing.T) {
	script := nftables.RenderFullTable(snatSpec(
		[]string{"192.168.8.0/24", "192.168.9.0/24"},
		[]string{"enp1s0", "enp2s0"}))
	if n := strings.Count(script, `comment "snat-direct"`); n != 2 {
		t.Fatalf("want one masquerade rule per interface, got %d:\n%s", n, script)
	}
	if n := strings.Count(script, `comment "snat-skip-lan"`); n != 2 {
		t.Fatalf("want one skip rule per LAN, got %d:\n%s", n, script)
	}
}

// renderRuleLines has no default branch, so an unrecognised Description renders
// nothing at all, silently. Assert every compiled rule produces output.
func TestRenderFullTable_EveryCompiledRuleRenders(t *testing.T) {
	p := policy.Policy{
		DirectPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")},
		TunnelInterface: "wg-exit",
		TunnelEndpoints: []netip.Addr{netip.MustParseAddr("10.10.0.2")},
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		LANIfaces:       []string{"eth0"},
		Mark:            policy.DefaultMark,
		Table:           policy.DefaultTableID,
		RulePriority:    policy.DefaultRulePriority,
		FailMode:        policy.FailClosed,
		TunnelUp:        true,
		DirectSNAT:      true,
		InboundWireGuard: policy.WireGuardConfig{
			PrivateKey: "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=",
			ListenPort: 51821,
		},
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	script := nftables.RenderFullTable(st.Nft)
	for _, ch := range st.Nft.Chains {
		for _, r := range ch.Rules {
			if !strings.Contains(script, "add rule inet gotun "+ch.Name) {
				t.Fatalf("chain %q produced no rules at all:\n%s", ch.Name, script)
			}
			if r.Description != "" && !strings.Contains(script, r.Description) {
				t.Fatalf("rule %q in chain %q rendered nothing:\n%s", r.Description, ch.Name, script)
			}
		}
	}
}

func ingressSpec(ifaces ...string) policy.NftSpec {
	return policy.NftSpec{
		Family: "inet", Table: "gotun",
		Chains: []policy.NftChainSpec{{
			Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -150, Policy: "accept",
			Rules: []policy.NftRuleSpec{
				{Description: "only-marked-ingress", IIfNames: ifaces},
				{Description: "mark-non-direct", DirectSet: "ru_nets", Mark: 1,
					ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}},
			},
		}},
	}
}

func TestRenderFullTable_IngressGuardPrecedesMark(t *testing.T) {
	script := nftables.RenderFullTable(ingressSpec("br-lan"))
	guard := `iifname != { "br-lan" } return comment "only-marked-ingress"`
	if !strings.Contains(script, guard) {
		t.Fatalf("missing guard:\n%s", script)
	}
	if strings.Index(script, guard) > strings.Index(script, `comment "mark-non-direct"`) {
		t.Fatalf("guard must render before the mark rule:\n%s", script)
	}
	// And the multicast exclusion must be there, or mDNS gets routed off-segment.
	if !strings.Contains(script, `ip daddr 224.0.0.0/4 return comment "exclude-lan"`) {
		t.Fatalf("missing multicast exclusion:\n%s", script)
	}
}

func TestRenderFullTable_IngressGuardListsEveryInterface(t *testing.T) {
	script := nftables.RenderFullTable(ingressSpec("br-lan", "br-guest"))
	if !strings.Contains(script, `iifname != { "br-lan", "br-guest" } return`) {
		t.Fatalf("both interfaces expected in one set:\n%s", script)
	}
}
