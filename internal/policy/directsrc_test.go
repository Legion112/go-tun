package policy_test

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

// preroutingRule returns the prerouting rule of the given description and
// family, so a test can assert on one rule without walking the chain list.
func preroutingRule(t *testing.T, st policy.DesiredKernelState, desc string, fam policy.Family) (policy.NftRuleSpec, int) {
	t.Helper()
	for _, ch := range st.Nft.Chains {
		if ch.Hook != "prerouting" {
			continue
		}
		for i, r := range ch.Rules {
			if r.Description == desc && r.Family == fam {
				return r, i
			}
		}
	}
	t.Fatalf("no prerouting rule %q for family %v", desc, fam)
	return policy.NftRuleSpec{}, -1
}

func TestCompile_DirectSourceLandsOnTheMarkRuleForItsOwnFamily(t *testing.T) {
	p := testPolicy(true)
	p.IPv6 = policy.IPv6On
	p.DirectPrefixes = append(p.DirectPrefixes, netip.MustParsePrefix("2001:db8:200::/48"))
	p.DirectSources = []netip.Prefix{
		netip.MustParsePrefix("192.168.8.162/32"),
		netip.MustParsePrefix("2001:db8:100::5/128"),
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}

	v4, _ := preroutingRule(t, st, "mark-non-direct", policy.FamilyV4)
	if len(v4.ExcludeSrcPrefixes) != 1 || v4.ExcludeSrcPrefixes[0].String() != "192.168.8.162/32" {
		t.Fatalf("v4 ExcludeSrcPrefixes = %v", v4.ExcludeSrcPrefixes)
	}
	v6, _ := preroutingRule(t, st, "mark-non-direct", policy.FamilyV6)
	if len(v6.ExcludeSrcPrefixes) != 1 || v6.ExcludeSrcPrefixes[0].String() != "2001:db8:100::5/128" {
		t.Fatalf("v6 ExcludeSrcPrefixes = %v", v6.ExcludeSrcPrefixes)
	}
}

// A v4 source must not reach the IPv6 rule. It would compare a v6 packet's
// source against a v4 address, match nothing, and leave the host's IPv6 replies
// going out the exit hop -- the exact failure the flag exists to fix, except
// only on the family clients prefer.
func TestCompile_DirectSourceDoesNotCrossFamilies(t *testing.T) {
	p := testPolicy(true)
	p.IPv6 = policy.IPv6On
	p.DirectPrefixes = append(p.DirectPrefixes, netip.MustParsePrefix("2001:db8:200::/48"))
	p.DirectSources = []netip.Prefix{netip.MustParsePrefix("192.168.8.162/32")}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	v6, _ := preroutingRule(t, st, "mark-non-direct", policy.FamilyV6)
	if len(v6.ExcludeSrcPrefixes) != 0 {
		t.Fatalf("v4 source leaked into the IPv6 rule: %v", v6.ExcludeSrcPrefixes)
	}
}

func TestCompile_NoDirectSourceByDefault(t *testing.T) {
	st, err := policy.Compile(testPolicy(true))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := preroutingRule(t, st, "mark-non-direct", policy.FamilyV4)
	if len(r.ExcludeSrcPrefixes) != 0 {
		t.Fatalf("ExcludeSrcPrefixes = %v, want none", r.ExcludeSrcPrefixes)
	}
}

func TestCompile_DirectSourceDedupes(t *testing.T) {
	p := testPolicy(true)
	p.DirectSources = []netip.Prefix{
		netip.MustParsePrefix("192.168.8.162/32"),
		netip.MustParsePrefix("192.168.8.162/32"),
	}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := preroutingRule(t, st, "mark-non-direct", policy.FamilyV4)
	if len(r.ExcludeSrcPrefixes) != 1 {
		t.Fatalf("duplicate source became %d rules", len(r.ExcludeSrcPrefixes))
	}
}

// A /0 source returns before the mark for every packet. Compile must refuse it
// rather than report success while classifying nothing.
func TestCompile_DirectSourceRejectsEverySource(t *testing.T) {
	for _, pref := range []string{"0.0.0.0/0", "::/0"} {
		p := testPolicy(true)
		p.DirectSources = []netip.Prefix{netip.MustParsePrefix(pref)}
		_, err := policy.Compile(p)
		if err == nil {
			t.Fatalf("%s: expected an error", pref)
		}
		if !strings.Contains(err.Error(), "every source") {
			t.Fatalf("%s: error = %v", pref, err)
		}
	}
}

func TestCompile_DirectSourceRejects4in6(t *testing.T) {
	p := testPolicy(true)
	p.DirectSources = []netip.Prefix{netip.MustParsePrefix("::ffff:192.168.8.162/128")}
	if _, err := policy.Compile(p); err == nil {
		t.Fatal("expected a 4-in-6 rejection")
	}
}

// The source bypass must sit ahead of the mark rule in the chain. It is emitted
// inside the same rule spec, so this pins the thing that actually matters: the
// mark rule carries the bypass rather than a later rule trying to undo a mark
// that has already been set.
func TestCompile_DirectSourceRidesWithTheMarkRule(t *testing.T) {
	p := testPolicy(true)
	p.MarkIIfNames = []string{"br-lan"}
	p.DirectSources = []netip.Prefix{netip.MustParsePrefix("192.168.8.162/32")}
	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	mark, markIdx := preroutingRule(t, st, "mark-non-direct", policy.FamilyV4)
	if len(mark.ExcludeSrcPrefixes) == 0 {
		t.Fatal("the mark rule does not carry the source bypass")
	}
	_, guardIdx := preroutingRule(t, st, "only-marked-ingress", policy.FamilyAny)
	if guardIdx > markIdx {
		t.Fatal("the ingress guard must still precede the mark rule")
	}
}

func TestSemanticEqual_DirectSourceChangeDiffers(t *testing.T) {
	base := testPolicy(true)
	with := testPolicy(true)
	with.DirectSources = []netip.Prefix{netip.MustParsePrefix("192.168.8.162/32")}
	moved := testPolicy(true)
	moved.DirectSources = []netip.Prefix{netip.MustParsePrefix("192.168.8.163/32")}

	a, err := policy.Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policy.Compile(with)
	if err != nil {
		t.Fatal(err)
	}
	c, err := policy.Compile(moved)
	if err != nil {
		t.Fatal(err)
	}
	if policy.SemanticEqual(a, b) {
		t.Fatal("adding a source bypass must read as a change")
	}
	if policy.SemanticEqual(b, c) {
		t.Fatal("moving the bypass to another host must read as a change")
	}
}

// TestSemanticEqual_EveryRuleField guards the trap that ExcludeSrcPrefixes fell
// into when it was added: normalize rebuilds NftRuleSpec field by field, so a
// field it does not list is invisible to SemanticEqual. The symptom is the worst
// kind -- apply reports "0 changes" and converged, while the kernel keeps the
// old rule forever.
//
// It zeroes one field at a time and insists the state stops comparing equal. A
// field whose type it cannot fill fails loudly rather than being skipped.
func TestSemanticEqual_EveryRuleField(t *testing.T) {
	full := fillRule(t)
	rt := reflect.TypeOf(full)
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		holed := full
		reflect.ValueOf(&holed).Elem().Field(i).Set(reflect.Zero(rt.Field(i).Type))
		if policy.SemanticEqual(stateWithRule(full), stateWithRule(holed)) {
			t.Errorf("NftRuleSpec.%s is not compared: zeroing it still reads as equal."+
				" Add it to normalize() in compile.go", name)
		}
	}
}

func stateWithRule(r policy.NftRuleSpec) policy.DesiredKernelState {
	return policy.DesiredKernelState{
		Nft: policy.NftSpec{
			Family: "inet",
			Table:  "gotun",
			Chains: []policy.NftChainSpec{{
				Name: "prerouting", Type: "filter", Hook: "prerouting",
				Priority: policy.MarkChainPriority, Policy: "accept",
				Rules: []policy.NftRuleSpec{r},
			}},
		},
	}
}

// fillRule builds an NftRuleSpec with every field set to a distinguishable
// non-zero value.
func fillRule(t *testing.T) policy.NftRuleSpec {
	t.Helper()
	var r policy.NftRuleSpec
	v := reflect.ValueOf(&r).Elem()
	rt := v.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := v.Field(i)
		switch f.Interface().(type) {
		case string:
			f.SetString("filled-" + rt.Field(i).Name)
		case bool:
			f.SetBool(true)
		case uint32:
			f.SetUint(7)
		case []netip.Prefix:
			f.Set(reflect.ValueOf([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}))
		case []netip.Addr:
			f.Set(reflect.ValueOf([]netip.Addr{netip.MustParseAddr("203.0.113.9")}))
		case []string:
			f.Set(reflect.ValueOf([]string{"filled0"}))
		case policy.Family:
			f.Set(reflect.ValueOf(policy.FamilyV6))
		default:
			t.Fatalf("fillRule does not know how to fill %s %s; add it",
				rt.Field(i).Name, rt.Field(i).Type)
		}
	}
	return r
}
