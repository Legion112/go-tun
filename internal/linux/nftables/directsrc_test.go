package nftables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

func directSrcSpec(srcs ...string) policy.NftSpec {
	spec := textMatchSpec()
	var prefs []netip.Prefix
	for _, s := range srcs {
		prefs = append(prefs, netip.MustParsePrefix(s))
	}
	spec.Chains[0].Rules[1].ExcludeSrcPrefixes = prefs
	return spec
}

// nftTextWithDirectSrc is realNftText with the source bypass in place, in the
// shape nft prints it back: the counter inlined and the host prefix dropped to
// a bare address.
func nftTextWithDirectSrc(lines ...string) string {
	const anchor = "\t\tip daddr 10.10.0.0/24 return comment \"exclude-lan\"\n"
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("\t\t" + l + "\n")
	}
	out := realNftText()
	if !strings.Contains(out, anchor) {
		panic("fixture anchor moved")
	}
	return strings.Replace(out, anchor, b.String()+anchor, 1)
}

func TestRenderFullTable_DirectSrcReturnsBeforeTheMark(t *testing.T) {
	out := RenderFullTable(directSrcSpec("192.168.8.162/32"))
	want := `ip saddr 192.168.8.162/32 return comment "direct-src"`
	if !strings.Contains(out, want) {
		t.Fatalf("rendered table has no source bypass:\n%s", out)
	}
	bypass := strings.Index(out, want)
	mark := strings.Index(out, "meta mark set")
	if bypass < 0 || mark < 0 || bypass > mark {
		t.Fatalf("bypass at %d must precede the mark at %d, or the reply is marked before it is exempted", bypass, mark)
	}
}

// Rendered per family, so an IPv6 bypass compares an ip6 source. "ip saddr"
// against a v6 packet matches nothing at all.
func TestRenderFullTable_DirectSrcUsesTheRuleFamily(t *testing.T) {
	spec := directSrcSpec()
	spec.Chains[0].Rules[1].Family = policy.FamilyV6
	spec.Chains[0].Rules[1].ExcludePrefixes = nil
	spec.Chains[0].Rules[1].ExcludeAddrs = nil
	spec.Chains[0].Rules[1].ExcludeSrcPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8:100::5/128")}
	out := RenderFullTable(spec)
	if !strings.Contains(out, `ip6 saddr 2001:db8:100::5/128 return`) {
		t.Fatalf("expected an ip6 saddr match:\n%s", out)
	}
}

func TestSemanticMatchText_DirectSrcConverges(t *testing.T) {
	live, err := parseNftText(nftTextWithDirectSrc(
		`ip saddr 192.168.8.162 counter packets 0 bytes 0 return comment "direct-src"`))
	if err != nil {
		t.Fatal(err)
	}
	if !semanticMatch(live, directSrcSpec("192.168.8.162/32")) {
		t.Fatal("a box already carrying the bypass must compare as converged, or every apply rewrites the table")
	}
}

func TestSemanticMatchText_MissingDirectSrcIsDrift(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	if semanticMatch(live, directSrcSpec("192.168.8.162/32")) {
		t.Fatal("a requested bypass that is not in the kernel must read as drift")
	}
}

// The case that motivates comparing the set exactly rather than counting
// comments: the host moved, and a bypass left behind for its old address keeps
// exempting whoever holds it now.
func TestSemanticMatchText_StaleDirectSrcIsDrift(t *testing.T) {
	live, err := parseNftText(nftTextWithDirectSrc(
		`ip saddr 192.168.8.162 return comment "direct-src"`))
	if err != nil {
		t.Fatal(err)
	}
	if semanticMatch(live, directSrcSpec("192.168.8.163/32")) {
		t.Fatal("a bypass for the wrong host must read as drift")
	}
	if semanticMatch(live, directSrcSpec()) {
		t.Fatal("a bypass nothing asks for must read as drift, or -direct-src can never be turned off")
	}
}

func TestSemanticMatchText_ExtraDirectSrcIsDrift(t *testing.T) {
	live, err := parseNftText(nftTextWithDirectSrc(
		`ip saddr 192.168.8.162 return comment "direct-src"`,
		`ip saddr 192.168.8.200 return comment "direct-src"`))
	if err != nil {
		t.Fatal(err)
	}
	if semanticMatch(live, directSrcSpec("192.168.8.162/32")) {
		t.Fatal("one bypass too many must read as drift")
	}
}

// "fib saddr type != local" in the SNAT rule contains the word saddr without
// being an address match. Reading its operand puts the literal "type" in
// SAddrs, which would make a converged snat-direct rule compare as drift and
// rewrite the whole table on every single apply.
func TestParseNftText_FibSaddrIsNotAnAddressMatch(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range live.rules {
		if r.Comment != "snat-direct" {
			continue
		}
		if len(r.SAddrs) != 0 {
			t.Fatalf("fib saddr leaked into SAddrs: %v", r.SAddrs)
		}
		return
	}
	t.Fatal("fixture has no snat-direct rule")
}

func TestSemanticMatchJSON_DirectSrc(t *testing.T) {
	spec := baseMarkSpec("10.10.0.0/24", "10.10.0.2")
	spec.Chains[0].Rules[1].ExcludeSrcPrefixes = []netip.Prefix{netip.MustParsePrefix("192.168.8.162/32")}

	withBypass := `{"nftables":[
{"set":{"name":"ru_nets","elem":["10.200.0.0/24","10.200.1.0/24"]}},
{"chain":{"name":"prerouting","type":"filter","hook":"prerouting","prio":-150,"policy":"accept"}},
{"rule":{"chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"chain":"prerouting","comment":"direct-src","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.168.8.162"}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}
]}`
	if !semanticMatchJSON(withBypass, spec) {
		t.Fatal("expected the JSON readback to see the source bypass as converged")
	}

	wrongHost := strings.Replace(withBypass, `"right":"192.168.8.162"`, `"right":"192.168.8.163"`, 1)
	if semanticMatchJSON(wrongHost, spec) {
		t.Fatal("a bypass for another host must not match")
	}

	// A source match must not be mistaken for a destination exclude: the two
	// live in different buckets and satisfying one with the other would exempt
	// the wrong direction entirely.
	asDaddr := strings.Replace(withBypass, `"field":"saddr"`, `"field":"daddr"`, 1)
	if semanticMatchJSON(asDaddr, spec) {
		t.Fatal("an ip daddr match must not satisfy a source bypass")
	}
}
