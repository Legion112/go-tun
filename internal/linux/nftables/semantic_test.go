package nftables

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func baseMarkSpec(lan, endpoint string) policy.NftSpec {
	return policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{{
			Name: "ru_nets",
			Type: "ipv4_addr",
			Elements: []netip.Prefix{
				netip.MustParsePrefix("10.200.0.0/24"),
				netip.MustParsePrefix("10.200.1.0/24"),
			},
		}},
		Chains: []policy.NftChainSpec{{
			Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -150, Policy: "accept",
			Rules: []policy.NftRuleSpec{
				{Description: "drop-ipv6", DropIPv6: true},
				{
					Description:     "mark-non-direct",
					ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix(lan)},
					ExcludeAddrs:    []netip.Addr{netip.MustParseAddr(endpoint)},
					DirectSet:       "ru_nets",
					Mark:            1,
				},
			},
		}},
	}
}

func nftJSONWithExclusions(lanPrefix, endpoint string) string {
	// lanPrefix like "10.10.0.0/24" — split for JSON prefix object
	p := netip.MustParsePrefix(lanPrefix)
	return fmt.Sprintf(`{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"%s","len":%d}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"%s"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`, p.Addr().String(), p.Bits(), endpoint)
}

func TestSemanticMatchJSON_ExactElements(t *testing.T) {
	spec := baseMarkSpec("10.10.0.0/24", "10.10.0.2")
	good := nftJSONWithExclusions("10.10.0.0/24", "10.10.0.2")
	if !semanticMatchJSON(good, spec) {
		t.Fatal("expected match")
	}

	extra := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24","10.200.2.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(extra, spec) {
		t.Fatal("extra prefix must not match")
	}

	sameCountDiff := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.9.9.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if semanticMatchJSON(sameCountDiff, spec) {
		t.Fatal("same count different contents must not match")
	}

	wrongMark := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":2}}]}}
]}`
	if semanticMatchJSON(wrongMark, spec) {
		t.Fatal("wrong mark must not match")
	}
}

func TestSemanticMatchJSON_DifferentEndpointDoesNotMatch(t *testing.T) {
	spec := baseMarkSpec("10.10.0.0/24", "5.6.7.8")
	live := nftJSONWithExclusions("10.10.0.0/24", "1.2.3.4")
	if semanticMatchJSON(live, spec) {
		t.Fatal("different exclude-endpoint daddr must not match")
	}
}

func TestSemanticMatchJSON_DifferentLANDoesNotMatch(t *testing.T) {
	spec := baseMarkSpec("192.168.50.0/24", "10.10.0.2")
	live := nftJSONWithExclusions("192.168.1.0/24", "10.10.0.2")
	if semanticMatchJSON(live, spec) {
		t.Fatal("different exclude-lan prefix must not match")
	}
}

func TestSemanticMatchJSON_IsolateHome(t *testing.T) {
	spec := policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{
			{Name: "ru_nets", Type: "ipv4_addr", Elements: []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")}},
			{Name: "home_nets", Type: "ipv4_addr", Elements: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}},
		},
		Chains: []policy.NftChainSpec{
			{
				Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -150, Policy: "accept",
				Rules: []policy.NftRuleSpec{
					{Description: "drop-ipv6", DropIPv6: true},
					{
						Description:     "mark-non-direct",
						ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
						ExcludeAddrs:    []netip.Addr{netip.MustParseAddr("10.10.0.2")},
						DirectSet:       "ru_nets",
						Mark:            1,
					},
				},
			},
			{
				Name: "forward", Type: "filter", Hook: "forward", Priority: 0, Policy: "accept",
				Rules: []policy.NftRuleSpec{{
					Description: "isolate-inbound-from-home",
					IIfName:     "wg-clients",
					DropDstSet:  "home_nets",
				}},
			},
		},
	}
	good := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24"]}},
{"set":{"name":"home_nets","elem":["10.10.0.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"chain":{"name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}},
{"rule":{"chain":"forward","comment":"isolate-inbound-from-home","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-clients"}},
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"set":"home_nets"}}}
]}}
]}`
	if !semanticMatchJSON(good, spec) {
		t.Fatal("expected isolate rule to match")
	}

	wrongHome := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24"]}},
{"set":{"name":"home_nets","elem":["10.11.0.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"chain":{"name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}},
{"rule":{"chain":"forward","comment":"isolate-inbound-from-home","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-clients"}},
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"set":"home_nets"}}}
]}}
]}`
	if semanticMatchJSON(wrongHome, spec) {
		t.Fatal("wrong home_nets elements must not match")
	}
}

func snatMatchSpec(lan string, oifs ...string) policy.NftSpec {
	return policy.NftSpec{
		Family: "inet", Table: "gotun",
		Chains: []policy.NftChainSpec{{
			Name: "postrouting", Type: "nat", Hook: "postrouting",
			Priority: policy.SrcNatPriority, Policy: "accept",
			Rules: []policy.NftRuleSpec{{
				Description:     "snat-direct",
				OIfNames:        oifs,
				ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix(lan)},
				SNATMasquerade:  true,
			}},
		}},
	}
}

// snatRuleJSON builds one live snat-direct rule. natStmt is injected verbatim so
// a test can omit it entirely.
func snatRuleJSON(oif, natStmt string) string {
	return fmt.Sprintf(`{"rule":{"chain":"postrouting","comment":"snat-direct","expr":[`+
		`{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"%s"}},`+
		`{"match":{"op":"!=","left":{"fib":{"result":"type","flags":["saddr"]}},"right":"local"}},`+
		`{"counter":{"packets":0,"bytes":0}}%s]}}`, oif, natStmt)
}

func nftJSONWithSNAT(lan string, natStmt string, oifs ...string) string {
	p := netip.MustParsePrefix(lan)
	out := `{"nftables":[
{"chain":{"name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
` + fmt.Sprintf(`{"rule":{"chain":"postrouting","comment":"snat-skip-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"%s","len":%d}}}}]}}`,
		p.Addr().String(), p.Bits())
	for _, o := range oifs {
		out += ",\n" + snatRuleJSON(o, natStmt)
	}
	return out + "\n]}"
}

// A bare masquerade serialises as {"masquerade": null}. This is the single most
// likely place for a hand-written fixture to diverge from real nft output.
func TestSemanticMatchJSON_DirectSNATMasqueradeNullValue(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	good := nftJSONWithSNAT("192.168.8.0/24", `,{"masquerade":null}`, "enp1s0")
	if !semanticMatchJSON(good, spec) {
		t.Fatalf("expected match for a null-valued masquerade statement:\n%s", good)
	}
}

func TestSemanticMatchJSON_DirectSNAT(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	if !semanticMatchJSON(nftJSONWithSNAT("192.168.8.0/24", `,{"masquerade":{}}`, "enp1s0"), spec) {
		t.Fatal("expected match")
	}
}

func TestSemanticMatchJSON_DirectSNATWrongOIfName(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	live := nftJSONWithSNAT("192.168.8.0/24", `,{"masquerade":null}`, "enp2s0")
	if semanticMatchJSON(live, spec) {
		t.Fatal("a rule on the wrong interface must not match: the masquerade would catch nothing")
	}
}

func TestSemanticMatchJSON_DirectSNATStaleExtraInterface(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	live := nftJSONWithSNAT("192.168.8.0/24", `,{"masquerade":null}`, "enp1s0", "enp2s0")
	if semanticMatchJSON(live, spec) {
		t.Fatal("a leftover rule for a removed interface must read as drift")
	}
}

func TestSemanticMatchJSON_DirectSNATMissingMasquerade(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	live := nftJSONWithSNAT("192.168.8.0/24", ``, "enp1s0")
	if semanticMatchJSON(live, spec) {
		t.Fatal("right interface but no NAT statement must not match")
	}
}

func TestSemanticMatchJSON_DirectSNATWrongSkipPrefix(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	live := nftJSONWithSNAT("192.168.1.0/24", `,{"masquerade":null}`, "enp1s0")
	if semanticMatchJSON(live, spec) {
		t.Fatal("a stale LAN skip guard must read as drift")
	}
}

func TestSemanticMatchJSON_DirectSNATMissingChain(t *testing.T) {
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	if semanticMatchJSON(`{"nftables":[]}`, spec) {
		t.Fatal("a missing postrouting chain must not match")
	}
}

func TestSemanticMatchJSON_DirectSNATAcceptsSnatToAddr(t *testing.T) {
	// hasNATStmtInExpr also recognises an explicit snat, not just masquerade.
	spec := snatMatchSpec("192.168.8.0/24", "enp1s0")
	live := nftJSONWithSNAT("192.168.8.0/24", `,{"snat":{"addr":"192.168.8.162"}}`, "enp1s0")
	if !semanticMatchJSON(live, spec) {
		t.Fatal("an explicit snat statement should satisfy the NAT requirement")
	}
}

// nft renders a single address as a bare string with no prefix length. Dropping
// such an element made the live set compare unequal to the desired one, so every
// apply deleted and rebuilt the whole table -- reloading the entire prefix set
// and resetting the counters that live verification depends on.
func TestElemToCIDR_BareAddressGetsHostPrefix(t *testing.T) {
	got, ok := elemToCIDR([]byte(`"2.16.10.221"`))
	if !ok {
		t.Fatal("a bare address must be accepted, not dropped")
	}
	if got != "2.16.10.221/32" {
		t.Fatalf("got %q, want 2.16.10.221/32", got)
	}
}

func TestElemToCIDR_BareIPv6AddressGetsHostPrefix(t *testing.T) {
	got, ok := elemToCIDR([]byte(`"2001:db8::1"`))
	if !ok {
		t.Fatal("a bare v6 address must be accepted")
	}
	if got != "2001:db8::1/128" {
		t.Fatalf("got %q, want 2001:db8::1/128", got)
	}
}

func TestElemToCIDR_CIDRStringUnchanged(t *testing.T) {
	got, ok := elemToCIDR([]byte(`"10.0.0.0/24"`))
	if !ok || got != "10.0.0.0/24" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestElemToCIDR_PrefixObject(t *testing.T) {
	got, ok := elemToCIDR([]byte(`{"prefix":{"addr":"10.0.0.0","len":24}}`))
	if !ok || got != "10.0.0.0/24" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

// A non-address string must still be rejected rather than turned into garbage.
func TestElemToCIDR_NonAddressStringRejected(t *testing.T) {
	if got, ok := elemToCIDR([]byte(`"local"`)); ok {
		t.Fatalf("expected rejection, got %q", got)
	}
}

// The regression as it actually appeared: a set mixing prefixes and bare hosts
// must compare equal to the spec that produced it.
func TestSemanticMatchJSON_SetWithBareHostElements(t *testing.T) {
	spec := policy.NftSpec{
		Family: "inet", Table: "gotun",
		Sets: []policy.NftSetSpec{{
			Name: "ru_nets", Type: "ipv4_addr",
			Elements: []netip.Prefix{
				netip.MustParsePrefix("10.200.0.0/24"),
				netip.MustParsePrefix("2.16.10.221/32"),
				netip.MustParsePrefix("5.178.2.128/32"),
			},
		}},
	}
	// nft returns the /32s bare, exactly as observed on a live gateway.
	live := `{"nftables":[
{"set":{"name":"ru_nets","elem":[{"prefix":{"addr":"10.200.0.0","len":24}},"2.16.10.221","5.178.2.128"]}}
]}`
	if !semanticMatchJSON(live, spec) {
		t.Fatal("a set containing bare host addresses must match; otherwise every apply rebuilds the table")
	}
}

func ingressMatchSpec(ifaces ...string) policy.NftSpec {
	return policy.NftSpec{
		Family: "inet", Table: "gotun",
		Chains: []policy.NftChainSpec{{
			Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -150, Policy: "accept",
			Rules: []policy.NftRuleSpec{{Description: "only-marked-ingress", IIfNames: ifaces}},
		}},
	}
}

func nftJSONWithIngress(ifaces ...string) string {
	var rights []string
	for _, i := range ifaces {
		rights = append(rights, fmt.Sprintf(`{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"%s"}}`, i))
	}
	return `{"nftables":[
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"only-marked-ingress","expr":[` + strings.Join(rights, ",") + `]}}
]}`
}

func TestSemanticMatchJSON_IngressGuardMatches(t *testing.T) {
	if !semanticMatchJSON(nftJSONWithIngress("br-lan"), ingressMatchSpec("br-lan")) {
		t.Fatal("expected match")
	}
}

// Without a real matcher, a renamed interface reads as converged while the guard
// protects nothing and marking applies to no traffic at all.
func TestSemanticMatchJSON_IngressGuardStaleInterfaceIsDrift(t *testing.T) {
	if semanticMatchJSON(nftJSONWithIngress("br-guest"), ingressMatchSpec("br-lan")) {
		t.Fatal("a guard naming the wrong interface must read as drift")
	}
}

func TestSemanticMatchJSON_IngressGuardMissingInterfaceIsDrift(t *testing.T) {
	if semanticMatchJSON(nftJSONWithIngress("br-lan"), ingressMatchSpec("br-lan", "br-guest")) {
		t.Fatal("a guard missing one desired interface must read as drift")
	}
}

func TestSemanticMatchJSON_IngressGuardAbsentIsDrift(t *testing.T) {
	if semanticMatchJSON(`{"nftables":[{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}}]}`,
		ingressMatchSpec("br-lan")) {
		t.Fatal("a missing guard must read as drift")
	}
}

// TestParseRuleJSON_SetReferenceIsNotADAddr pins a defect the dual-stack
// round-trip test uncovered: nft renders "ip daddr @home_nets" as a daddr match
// whose right-hand side is the string "@home_nets". The JSON parser filed that
// under DAddrs while liveHasRule looks for it in SetNames, so
// isolate-inbound-from-home never matched on a box with JSON support -- for
// either family -- and the forward chain was rebuilt on every apply. The text
// parser has always made this distinction; this keeps the two in step.
func TestParseRuleJSON_SetReferenceIsNotADAddr(t *testing.T) {
	const out = `{"nftables":[
{"table":{"family":"inet","name":"gotun"}},
{"chain":{"family":"inet","table":"gotun","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"rule":{"family":"inet","table":"gotun","chain":"forward","comment":"isolate-inbound-from-home","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-clients"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@home_nets"}},{"drop":null}]}}
]}`
	live, err := parseNftJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(live.rules) != 1 {
		t.Fatalf("want one rule, got %d", len(live.rules))
	}
	r := live.rules[0]
	if !containsStr(r.SetNames, "home_nets") {
		t.Fatalf("set reference must land in SetNames, got %v", r.SetNames)
	}
	for _, d := range r.DAddrs {
		if strings.HasPrefix(d, "@") {
			t.Fatalf("a set reference must not be read as a daddr, got %v", r.DAddrs)
		}
	}
}

// TestIsIPDAddrPayload_AcceptsIP6 pins the one-line change that makes IPv6
// visible to the JSON parser at all. Requiring protocol=="ip" made every IPv6
// exclude rule read as empty, so the spec never matched and the whole table --
// ~17k elements once IPv6 prefixes are loaded -- was rebuilt on every apply.
func TestIsIPDAddrPayload_AcceptsIP6(t *testing.T) {
	for _, proto := range []string{"ip", "ip6"} {
		raw := []byte(`{"payload":{"protocol":"` + proto + `","field":"daddr"}}`)
		if !isIPDAddrPayload(raw) {
			t.Fatalf("%s daddr payload must be recognised", proto)
		}
	}
	if isIPDAddrPayload([]byte(`{"payload":{"protocol":"ip6","field":"saddr"}}`)) {
		t.Fatal("a saddr match is not a destination match")
	}
}
