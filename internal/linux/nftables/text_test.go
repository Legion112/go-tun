package nftables

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// errNoJSON stands in for what a build without JSON support returns.
var errNoJSON = errors.New("nft: JSON support not compiled in")

// realNftText is copied from actual "nft list table" output, not written from the
// manual. The shapes that matter and that an idealised fixture would miss:
// priorities come back symbolic and offset ("mangle + 1" for -149), the mark is
// zero-padded to 0x00000001, counters are inlined, and element lists wrap.
func realNftText() string {
	return `table inet gotun {
	set ru_nets {
		type ipv4_addr
		flags interval
		elements = { 10.200.0.0/24, 10.200.1.0/24,
			     10.200.2.0/24 }
	}

	chain prerouting {
		type filter hook prerouting priority mangle + 1; policy accept;
		iifname != { "br-lan", "br-iot" } return comment "only-marked-ingress"
		ip daddr 10.10.0.0/24 return comment "exclude-lan"
		ip daddr 10.10.0.2 counter packets 0 bytes 0 return comment "exclude-endpoint"
		ip daddr != @ru_nets meta mark set 0x00000001 counter packets 0 bytes 0 comment "mark-non-direct"
	}

	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		meta nfproto ipv4 oifname "eth0" fib saddr type != local counter packets 0 bytes 0 masquerade comment "snat-direct"
	}
}`
}

func TestParseNftText_ResolvesSymbolicPriorities(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	// "mangle + 1" is how nft renders -149; comparing the text would never match.
	if got := live.chains["prerouting"].Priority; got != -149 {
		t.Fatalf("prerouting priority: want -149, got %d", got)
	}
	if got := live.chains["postrouting"].Priority; got != 100 {
		t.Fatalf("postrouting priority: want 100 (srcnat), got %d", got)
	}
	if got := live.chains["prerouting"]; got.Type != "filter" || got.Hook != "prerouting" || got.Policy != "accept" {
		t.Fatalf("prerouting header: %+v", got)
	}
}

func TestParseNftText_WrappedElementsAreAllRead(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	got := live.sets["ru_nets"]
	if len(got) != 3 {
		t.Fatalf("want 3 elements across the wrapped list, got %d: %v", len(got), got)
	}
	for _, want := range []string{"10.200.0.0/24", "10.200.1.0/24", "10.200.2.0/24"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
}

func TestParseNftText_PaddedMarkIsParsed(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range live.rules {
		if r.Comment != "mark-non-direct" {
			continue
		}
		if r.Mark == nil || *r.Mark != 1 {
			t.Fatalf("nft prints 0x00000001; want mark 1, got %v", r.Mark)
		}
		return
	}
	t.Fatal("no mark-non-direct rule parsed")
}

func TestParseNftText_ExtractsMatchTargets(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	find := func(comment string) liveRule {
		for _, r := range live.rules {
			if r.Comment == comment {
				return r
			}
		}
		t.Fatalf("no rule commented %q", comment)
		return liveRule{}
	}
	if got := find("only-marked-ingress").IIfNames; len(got) != 2 || got[0] != "br-lan" || got[1] != "br-iot" {
		t.Fatalf("ingress interfaces: %v", got)
	}
	if got := find("exclude-lan").DAddrs; len(got) != 1 || got[0] != "10.10.0.0/24" {
		t.Fatalf("exclude-lan daddrs: %v", got)
	}
	// A host exclude prints without /32, and an inline counter must not be read
	// as the match target.
	if got := find("exclude-endpoint").DAddrs; len(got) != 1 || got[0] != "10.10.0.2" {
		t.Fatalf("exclude-endpoint daddrs: %v", got)
	}
	snat := find("snat-direct")
	if !snat.Masquerade || len(snat.OIfNames) != 1 || snat.OIfNames[0] != "eth0" {
		t.Fatalf("snat-direct: masq=%v oif=%v", snat.Masquerade, snat.OIfNames)
	}
	// "ip daddr != @ru_nets" is a set reference, not an address to compare.
	if got := find("mark-non-direct").DAddrs; len(got) != 0 {
		t.Fatalf("a set reference must not be read as a daddr, got %v", got)
	}
}

func TestParseNftText_EmptyOutputIsAnError(t *testing.T) {
	if _, err := parseNftText(""); err == nil {
		t.Fatal("empty output must not parse as a table")
	}
}

func textMatchSpec() policy.NftSpec {
	return policy.NftSpec{
		Family: "inet",
		Table:  "gotun",
		Sets: []policy.NftSetSpec{{
			Name: "ru_nets",
			Type: "ipv4_addr",
			Elements: []netip.Prefix{
				netip.MustParsePrefix("10.200.0.0/24"),
				netip.MustParsePrefix("10.200.1.0/24"),
				netip.MustParsePrefix("10.200.2.0/24"),
			},
		}},
		Chains: []policy.NftChainSpec{{
			Name: "prerouting", Type: "filter", Hook: "prerouting", Priority: -149, Policy: "accept",
			Rules: []policy.NftRuleSpec{
				{Description: "only-marked-ingress", IIfNames: []string{"br-lan", "br-iot"}},
				{
					Description:     "mark-non-direct",
					ExcludePrefixes: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
					ExcludeAddrs:    []netip.Addr{netip.MustParseAddr("10.10.0.2")},
					DirectSet:       "ru_nets",
					Mark:            1,
				},
			},
		}},
	}
}

func TestSemanticMatchText_ConvergesOnRealOutput(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	if !semanticMatch(live, textMatchSpec()) {
		t.Fatal("a box already carrying this exact state must compare as converged")
	}
}

func TestSemanticMatchText_EndpointChangeIsDrift(t *testing.T) {
	live, err := parseNftText(realNftText())
	if err != nil {
		t.Fatal(err)
	}
	spec := textMatchSpec()
	spec.Chains[0].Rules[1].ExcludeAddrs = []netip.Addr{netip.MustParseAddr("10.10.0.9")}
	if semanticMatch(live, spec) {
		t.Fatal("a changed endpoint must read as drift, or -endpoint silently stops taking effect")
	}
}

// nojsonRunner is a box built without JSON support: every "nft -j" fails, and the
// plain listing is the only way to see the table.
func nojsonRunner() *linux.RecordingRunner {
	r := linux.NewRecordingRunner()
	r.Errors["nft -j list table inet gotun"] = errNoJSON
	r.Outputs["nft list table inet gotun"] = realNftText()
	return r
}

func TestReconcile_NoJSONBuildStillSeesTheTable(t *testing.T) {
	r := nojsonRunner()
	n, err := Reconcile(r, textMatchSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a converged nojson box must report 0 changes, got %d", n)
	}
}

// The failure this guards is the severe one: with the table read as absent, the
// script is pure "add", which appends. The stale mark rule then sits ahead of the
// fresh exclude returns, so a changed -lan or -endpoint has no effect at all
// while apply reports success.
func TestReconcile_NoJSONBuildDeletesBeforeRewriting(t *testing.T) {
	r := nojsonRunner()
	spec := textMatchSpec()
	spec.Chains[0].Rules[1].ExcludeAddrs = []netip.Addr{netip.MustParseAddr("10.10.0.9")}
	if _, err := Reconcile(r, spec); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, c := range r.Calls {
		if strings.HasPrefix(c, "STDIN:") {
			script = c
		}
	}
	if script == "" {
		t.Fatalf("no nft batch recorded: %v", r.Calls)
	}
	if !strings.Contains(script, "delete table inet gotun") {
		t.Fatalf("the rewrite must delete first or it appends:\n%s", script)
	}
}

func TestCountSetElements_FallsBackToTextListing(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Errors["nft -j list set inet gotun ru_nets"] = errNoJSON
	r.Outputs["nft list set inet gotun ru_nets"] = realNftText()
	n, err := CountSetElements(r, "inet", "gotun", "ru_nets")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("want 3 elements from the text listing, got %d", n)
	}
}
