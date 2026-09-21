package policy_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

// dualPolicy is testPolicy with both families and a peer that can carry IPv6.
func dualPolicy() policy.Policy {
	p := testPolicy(true)
	p.DirectPrefixes = append(p.DirectPrefixes, netip.MustParsePrefix("2a02:6b8::/32"))
	p.LANs = append(p.LANs, netip.MustParsePrefix("fd00:10::/64"))
	p.TunnelEndpoints = append(p.TunnelEndpoints, netip.MustParseAddr("fd00:20::3"))
	p.TunnelCarriesIPv6 = true
	return p
}

func setNames(st policy.DesiredKernelState) map[string]policy.NftSetSpec {
	out := map[string]policy.NftSetSpec{}
	for _, s := range st.Nft.Sets {
		out[s.Name] = s
	}
	return out
}

func rulesByFamily(st policy.DesiredKernelState, chain, desc string) []policy.NftRuleSpec {
	var out []policy.NftRuleSpec
	for _, ch := range st.Nft.Chains {
		if ch.Name != chain {
			continue
		}
		for _, r := range ch.Rules {
			if r.Description == desc {
				out = append(out, r)
			}
		}
	}
	return out
}

// TestCompile_IPv6ClassifiedByDefault is the headline claim of the feature: no
// flag is needed. It is surprising enough to deserve its own named test --
// "enabled by default" means unclassified IPv6 is tunnelled, not leaked.
func TestCompile_IPv6ClassifiedByDefault(t *testing.T) {
	p := dualPolicy()
	if p.IPv6 != policy.IPv6Auto {
		t.Fatal("IPv6Auto must be the zero value, or existing callers change meaning")
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IPv6.Classify || !st.IPv6.Mark {
		t.Fatalf("IPv6 should be classified with no flags set: %+v", st.IPv6)
	}
	sets := setNames(st)
	v6, ok := sets[policy.RuNetsSetNameV6]
	if !ok {
		t.Fatalf("no %s set: %v", policy.RuNetsSetNameV6, sets)
	}
	if v6.Type != "ipv6_addr" || v6.Family != policy.FamilyV6 {
		t.Fatalf("ru_nets6 must be an ipv6_addr set: %+v", v6)
	}
	if len(v6.Elements) != 1 || v6.Elements[0].String() != "2a02:6b8::/32" {
		t.Fatalf("ru_nets6 elements: %v", v6.Elements)
	}
	if n := len(rulesByFamily(st, "prerouting", "mark-non-direct")); n != 2 {
		t.Fatalf("want one mark rule per family, got %d", n)
	}
}

// TestCompile_MixedPrefixesAreSplitByFamily pins that nothing lands in the
// wrong set, which the kernel would accept and then never match.
func TestCompile_MixedPrefixesAreSplitByFamily(t *testing.T) {
	st, err := policy.Compile(dualPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range st.Nft.Sets {
		for _, el := range set.Elements {
			if policy.FamilyOf(el) != set.Family {
				t.Fatalf("set %s (%s) holds %s", set.Name, set.Family, el)
			}
		}
	}
	for _, rule := range rulesByFamily(st, "prerouting", "mark-non-direct") {
		for _, p := range rule.ExcludePrefixes {
			if policy.FamilyOf(p) != rule.Family {
				t.Fatalf("%s rule excludes %s", rule.Family, p)
			}
		}
		for _, a := range rule.ExcludeAddrs {
			if policy.FamilyOfAddr(a) != rule.Family {
				t.Fatalf("%s rule excludes address %s", rule.Family, a)
			}
		}
	}
}

// TestCompile_AutoRefusesWithEmptyIPv6Set is the safety interlock. The rule
// reads "ip6 daddr != @ru_nets6", so against an empty set it matches
// everything: a gateway upgrading with a legacy IPv4-only prefixes.txt would
// push all of its IPv6 into the tunnel on the next apply.
func TestCompile_AutoRefusesWithEmptyIPv6Set(t *testing.T) {
	p := dualPolicy()
	p.DirectPrefixes = []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.IPv6.Classify {
		t.Fatal("an empty IPv6 direct set must not be classified: the rule would mark everything")
	}
	if _, ok := setNames(st)[policy.RuNetsSetNameV6]; ok {
		t.Fatal("no IPv6 objects should be emitted")
	}
	if !warnsAbout(st, "no IPv6 direct prefixes") {
		t.Fatalf("declining to classify must be said out loud: %v", st.Warnings)
	}
}

// TestCompile_OnClassifiesEvenWithEmptySet: -ipv6 on is the explicit "tunnel
// all IPv6" configuration, so it is allowed -- but still warned about.
func TestCompile_OnClassifiesEvenWithEmptySet(t *testing.T) {
	p := dualPolicy()
	p.DirectPrefixes = []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")}
	p.IPv6 = policy.IPv6On
	p.TunnelCarriesIPv6 = false // -ipv6 on ignores what the peer advertises
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IPv6.Classify || !st.IPv6.Mark {
		t.Fatalf("-ipv6 on must classify regardless: %+v", st.IPv6)
	}
	if !warnsAbout(st, "empty IPv6 direct set") {
		t.Fatalf("marking all IPv6 deserves a warning: %v", st.Warnings)
	}
}

// TestCompile_FallbackDirectLeaksAndSaysSo pins the chosen default. The
// behaviour is deliberate; what must not regress is that it is announced.
func TestCompile_FallbackDirectLeaksAndSaysSo(t *testing.T) {
	p := dualPolicy()
	p.TunnelCarriesIPv6 = false
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.IPv6.Classify {
		t.Fatal("fallback=direct emits no IPv6 objects")
	}
	if !warnsAbout(st, "DIRECTLY") || !warnsAbout(st, "real IPv6 address") {
		t.Fatalf("the leak must be stated in as many words: %v", st.Warnings)
	}
}

func TestCompile_FallbackBlackholeTerminatesIPv6(t *testing.T) {
	p := dualPolicy()
	p.TunnelCarriesIPv6 = false
	p.IPv6Fallback = policy.FallbackBlackhole
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IPv6.Classify || !st.IPv6.Mark || st.IPv6.RouteVia {
		t.Fatalf("blackhole fallback marks but must not route via the tunnel: %+v", st.IPv6)
	}
	var sawBlackhole bool
	for _, rt := range st.Routes {
		if rt.Family != policy.FamilyV6 {
			continue
		}
		if rt.Device != "" {
			t.Fatalf("no IPv6 route may point at the tunnel: %+v", rt)
		}
		if rt.Blackhole {
			sawBlackhole = true
		}
	}
	if !sawBlackhole {
		t.Fatalf("want a terminal IPv6 blackhole, got %+v", st.Routes)
	}
}

func TestCompile_FallbackDropUsesADropVerdict(t *testing.T) {
	p := dualPolicy()
	p.TunnelCarriesIPv6 = false
	p.IPv6Fallback = policy.FallbackDrop
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	rules := rulesByFamily(st, "prerouting", "mark-non-direct")
	var v6 *policy.NftRuleSpec
	for i := range rules {
		if rules[i].Family == policy.FamilyV6 {
			v6 = &rules[i]
		}
	}
	if v6 == nil || !v6.DropNonDirect || v6.Mark != 0 {
		t.Fatalf("drop fallback must drop rather than mark: %+v", v6)
	}
	for _, rt := range st.Routes {
		if rt.Family == policy.FamilyV6 {
			t.Fatalf("nothing is marked, so no IPv6 route is needed: %+v", rt)
		}
	}
	for _, r := range st.IPRules {
		if r.Family == policy.FamilyV6 {
			t.Fatalf("nothing is marked, so no IPv6 ip rule is needed: %+v", r)
		}
	}
}

// TestCompile_MarkedIPv6AlwaysHasAnIPRule is the invariant that matters most:
// marking a family with nothing to steer it sends that traffic straight back to
// the main table, so the classifier looks right while every packet leaks.
func TestCompile_MarkedIPv6AlwaysHasAnIPRule(t *testing.T) {
	for _, p := range []policy.Policy{dualPolicy(), func() policy.Policy {
		q := dualPolicy()
		q.TunnelCarriesIPv6 = false
		q.IPv6Fallback = policy.FallbackBlackhole
		return q
	}()} {
		st, err := policy.Compile(p)
		if err != nil {
			t.Fatal(err)
		}
		marked := map[policy.Family]bool{}
		for _, ch := range st.Nft.Chains {
			for _, r := range ch.Rules {
				if r.Mark != 0 {
					marked[r.Family] = true
				}
			}
		}
		steered := map[policy.Family]bool{}
		for _, r := range st.IPRules {
			steered[r.Family] = true
		}
		for fam := range marked {
			if !steered[fam] {
				t.Fatalf("%s is marked with no ip rule to steer it", fam)
			}
		}
	}
}

func TestCompile_DropIPv6AndIPv6OnAreMutuallyExclusive(t *testing.T) {
	p := dualPolicy()
	p.DropIPv6 = true
	p.IPv6 = policy.IPv6On
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("a table that both drops all IPv6 and classifies it is incoherent")
	}
}

// TestCompile_DropIPv6WinsOverAuto keeps existing -drop-ipv6 deployments
// behaving exactly as they did, rather than forcing operators to learn a
// second flag on upgrade.
func TestCompile_DropIPv6WinsOverAuto(t *testing.T) {
	p := dualPolicy()
	p.DropIPv6 = true
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.IPv6.Classify {
		t.Fatal("-drop-ipv6 must suppress classification")
	}
	if !warnsAbout(st, "deprecated") && !warnsAbout(st, "prefer -ipv6 off") {
		t.Fatalf("the deprecation should be mentioned: %v", st.Warnings)
	}
}

func TestCompile_Rejects4In6DirectPrefix(t *testing.T) {
	p := dualPolicy()
	p.DirectPrefixes = append(p.DirectPrefixes, netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("a 4-in-6 prefix would sit in an ipv6_addr set matching nothing")
	}
}

// TestCompile_MandatoryNonRoutableSurvivesAnOverride pins that an operator's
// -non-routable list cannot remove IPv6 link-local or multicast. Marking those
// breaks neighbour discovery, and with it every IPv6 flow on the segment.
func TestCompile_MandatoryNonRoutableSurvivesAnOverride(t *testing.T) {
	p := dualPolicy()
	p.NonRoutablePrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v6 *policy.NftRuleSpec
	for _, r := range rulesByFamily(st, "prerouting", "mark-non-direct") {
		if r.Family == policy.FamilyV6 {
			rr := r
			v6 = &rr
		}
	}
	if v6 == nil {
		t.Fatal("no IPv6 mark rule")
	}
	have := map[string]bool{}
	for _, p := range v6.ExcludePrefixes {
		have[p.String()] = true
	}
	for _, want := range []string{"fe80::/10", "ff00::/8", "::1/128"} {
		if !have[want] {
			t.Fatalf("%s must stay excluded whatever -non-routable says: %v", want, v6.ExcludePrefixes)
		}
	}
}

// TestCompile_ExcludesAreDeduped: the mandatory list and the default one
// deliberately overlap, and each duplicate would be a second identical rule in
// the prerouting hot path.
func TestCompile_ExcludesAreDeduped(t *testing.T) {
	p := dualPolicy()
	p.NonRoutablePrefixes = policy.DefaultNonRoutable()
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rulesByFamily(st, "prerouting", "mark-non-direct") {
		seen := map[netip.Prefix]bool{}
		for _, p := range rule.ExcludePrefixes {
			if seen[p] {
				t.Fatalf("%s rule excludes %s twice: %v", rule.Family, p, rule.ExcludePrefixes)
			}
			seen[p] = true
		}
	}
}

func TestCompile_IPv6ForwardingSysctlOnlyWhenClassifying(t *testing.T) {
	st, err := policy.Compile(dualPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !hasSysctl(st, "net.ipv6.conf.all.forwarding", "1") {
		t.Fatal("classifying IPv6 without forwarding silently drops every forwarded packet")
	}

	p := dualPolicy()
	p.IPv6 = policy.IPv6Off
	st, err = policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if hasSysctl(st, "net.ipv6.conf.all.forwarding", "1") {
		t.Fatal("-ipv6 off must not touch forwarding")
	}
}

func TestParseIPv6ModeAndFallback(t *testing.T) {
	for in, want := range map[string]policy.IPv6Mode{
		"": policy.IPv6Auto, "auto": policy.IPv6Auto,
		"on": policy.IPv6On, "off": policy.IPv6Off,
	} {
		got, err := policy.ParseIPv6Mode(in)
		if err != nil || got != want {
			t.Fatalf("ParseIPv6Mode(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := policy.ParseIPv6Mode("maybe"); err == nil {
		t.Fatal("want an error for an unknown mode")
	}
	for in, want := range map[string]policy.IPv6Fallback{
		"": policy.FallbackDirect, "direct": policy.FallbackDirect,
		"blackhole": policy.FallbackBlackhole, "drop": policy.FallbackDrop,
	} {
		got, err := policy.ParseIPv6Fallback(in)
		if err != nil || got != want {
			t.Fatalf("ParseIPv6Fallback(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := policy.ParseIPv6Fallback("shrug"); err == nil {
		t.Fatal("want an error for an unknown fallback")
	}
}

func warnsAbout(st policy.DesiredKernelState, substr string) bool {
	for _, w := range st.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func hasSysctl(st policy.DesiredKernelState, key, val string) bool {
	for _, s := range st.Sysctls {
		if s.Key == key && s.Value == val {
			return true
		}
	}
	return false
}
