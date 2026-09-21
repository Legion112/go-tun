package nftables

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// ElementBatchSize is how many CIDRs to put in each nft "add element" statement.
const ElementBatchSize = 4000

// Reconcile applies owned nftables table state in a single nft -f transaction.
// Returns number of semantic changes applied.
func Reconcile(r linux.Runner, spec policy.NftSpec) (int, error) {
	changes := 0
	family, table := spec.Family, spec.Table

	live, tableExists := listLiveTable(r, family, table)

	if tableExists && semanticMatch(live, spec) {
		return 0, nil
	}

	var b strings.Builder
	if tableExists {
		fmt.Fprintf(&b, "delete table %s %s\n", family, table)
	}
	b.WriteString(RenderFullTable(spec))
	if _, err := r.RunWithInput("nft", b.String(), "-f", linux.StdinPath); err != nil {
		return changes, fmt.Errorf("nft apply table: %w", err)
	}
	changes++
	return changes, nil
}

type liveNft struct {
	sets   map[string]map[string]struct{}
	chains map[string]liveChain
	rules  []liveRule
}

type liveChain struct {
	Type     string
	Hook     string
	Priority int
	Policy   string
}

type liveRule struct {
	Chain   string
	Comment string
	Mark    *uint32
	// DAddrs are ip daddr match targets (addr or addr/len), normalized as strings.
	DAddrs []string
	// IIfNames from meta iifname matches.
	IIfNames []string
	// SetNames referenced in daddr set lookups (@home_nets).
	SetNames []string
	// OIfNames from meta oifname matches.
	OIfNames []string
	// Masquerade is true when the rule carries a source-NAT statement.
	Masquerade bool
}

// listLiveTable reads the owned table, preferring JSON and falling back to text.
//
// The fallback is not a nicety. OpenWrt ships nftables-nojson, where "nft -j"
// fails for every table -- and a failure here used to mean "table absent", so the
// delete was skipped, the rewrite became a pure append, and gotun silently
// stopped honouring -lan and -endpoint changes on exactly the class of box this
// is being deployed to. Existence is therefore established from whichever listing
// works, never from JSON alone.
//
// When the table is there but cannot be parsed, it reports exists=true with no
// contents: that compares as drift and rewrites the table, which is the safe
// direction to fail in.
func listLiveTable(r linux.Runner, family, table string) (liveNft, bool) {
	if out, err := r.Run("nft", "-j", "list", "table", family, table); err == nil &&
		out != "" && !strings.Contains(out, "Error") {
		if live, perr := parseNftJSON(out); perr == nil {
			return live, true
		}
	}
	out, err := r.Run("nft", "list", "table", family, table)
	if err != nil || strings.TrimSpace(out) == "" {
		return liveNft{}, false
	}
	live, perr := parseNftText(out)
	if perr != nil {
		return liveNft{}, true
	}
	return live, true
}

func semanticMatchJSON(out string, spec policy.NftSpec) bool {
	live, err := parseNftJSON(out)
	if err != nil {
		return false
	}
	return semanticMatch(live, spec)
}

func semanticMatch(live liveNft, spec policy.NftSpec) bool {
	return desiredPresent(live, spec) && !hasExtraObjects(live, spec)
}

// hasExtraObjects reports whether the live table carries objects the spec does
// not want.
//
// Without this, drift detection is one-directional: it asks "is everything I
// want present?" and never "is anything here that should not be?". Turning a
// feature off -- -ipv6 off after an apply that classified IPv6, or dropping
// -direct-snat -- would then leave its set and its rules in the live table
// forever while apply cheerfully reported 0 changes. Since reconciliation is
// delete-and-rewrite, noticing is the only mechanism that removes anything.
//
// The desired comment multiset comes from running the real renderer and the
// real comment extractor, so render and readback cannot drift apart, and the
// per-prefix exclude fan-out and per-interface SNAT fan-out are counted
// automatically rather than restated here.
func hasExtraObjects(live liveNft, spec policy.NftSpec) bool {
	want := map[string]bool{}
	for _, set := range spec.Sets {
		want[set.Name] = true
	}
	for name := range live.sets {
		if !want[name] {
			return true
		}
	}

	wantChains := map[string]policy.NftChainSpec{}
	for _, ch := range spec.Chains {
		wantChains[ch.Name] = ch
	}
	for name := range live.chains {
		if _, ok := wantChains[name]; !ok {
			return true
		}
	}

	liveCounts := map[string]map[string]int{}
	for _, r := range live.rules {
		if _, ok := liveCounts[r.Chain]; !ok {
			liveCounts[r.Chain] = map[string]int{}
		}
		liveCounts[r.Chain][r.Comment]++
	}
	for name, ch := range wantChains {
		wantCounts := map[string]int{}
		for _, line := range renderRuleLines(ch) {
			wantCounts[ruleCommentText(line)]++
		}
		have := liveCounts[name]
		if len(have) != len(wantCounts) {
			return true
		}
		for cmt, n := range wantCounts {
			if have[cmt] != n {
				return true
			}
		}
	}
	return false
}

func desiredPresent(live liveNft, spec policy.NftSpec) bool {
	if live.sets == nil {
		live.sets = map[string]map[string]struct{}{}
	}
	for _, set := range spec.Sets {
		have, ok := live.sets[set.Name]
		if !ok {
			return false
		}
		want := map[string]struct{}{}
		for _, el := range set.Elements {
			want[el.String()] = struct{}{}
		}
		if len(have) != len(want) {
			return false
		}
		for cidr := range want {
			if _, ok := have[cidr]; !ok {
				return false
			}
		}
	}
	for _, ch := range spec.Chains {
		liveCh, ok := live.chains[ch.Name]
		if !ok {
			return false
		}
		if liveCh.Type != ch.Type || liveCh.Hook != ch.Hook || liveCh.Priority != ch.Priority || liveCh.Policy != ch.Policy {
			return false
		}
		for _, rule := range ch.Rules {
			if !liveHasRule(live.rules, ch.Name, rule) {
				return false
			}
		}
	}
	return true
}

func liveHasRule(rules []liveRule, chain string, want policy.NftRuleSpec) bool {
	switch {
	case want.DropIPv6:
		return countComments(rules, chain, "drop-ipv6") >= 1
	case want.Description == "mark-non-direct":
		wantLAN := map[string]struct{}{}
		for _, p := range want.ExcludePrefixes {
			wantLAN[normalizeDAddr(p.String())] = struct{}{}
		}
		wantEP := map[string]struct{}{}
		for _, a := range want.ExcludeAddrs {
			wantEP[normalizeDAddr(a.String())] = struct{}{}
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, RuleComment("exclude-lan", want.Family)), wantLAN) {
			return false
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, RuleComment("exclude-endpoint", want.Family)), wantEP) {
			return false
		}
		if want.DropNonDirect {
			return countComments(rules, chain, RuleComment("drop-non-direct", want.Family)) >= 1
		}
		verdict := RuleComment("mark-non-direct", want.Family)
		for _, r := range rules {
			if r.Chain == chain && r.Comment == verdict {
				return r.Mark != nil && *r.Mark == want.Mark
			}
		}
		return false
	case want.Description == "only-marked-ingress":
		// Compare the interface set exactly. The default comment-counting branch
		// would accept a guard naming a renamed or removed interface, report
		// convergence, and leave marking applying to nothing at all.
		wantIf := map[string]struct{}{}
		for _, n := range want.IIfNames {
			wantIf[n] = struct{}{}
		}
		for _, r := range rules {
			if r.Chain != chain || r.Comment != "only-marked-ingress" {
				continue
			}
			haveIf := map[string]struct{}{}
			for _, n := range r.IIfNames {
				haveIf[n] = struct{}{}
			}
			return stringSetsEqual(haveIf, wantIf)
		}
		return false
	case want.Description == "snat-direct":
		// The default comment-counting branch is not good enough here: it would
		// accept a rule pointing at the wrong interface, or guarded by stale LAN
		// prefixes, and report convergence while the masquerade matches nothing --
		// silently reinstating the bug this rule exists to fix.
		wantSkip := map[string]struct{}{}
		for _, p := range want.ExcludePrefixes {
			wantSkip[normalizeDAddr(p.String())] = struct{}{}
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, RuleComment("snat-skip-lan", want.Family)), wantSkip) {
			return false
		}
		// Counted per family. The comment carries the family, so the count
		// below stays "one rule per interface" even when a dual-stack policy
		// emits an IPv4 and an IPv6 masquerade for the same interface.
		snat := RuleComment("snat-direct", want.Family)
		haveOIf := map[string]struct{}{}
		n := 0
		for _, r := range rules {
			if r.Chain != chain || r.Comment != snat {
				continue
			}
			n++
			if want.SNATMasquerade && !r.Masquerade {
				return false
			}
			for _, o := range r.OIfNames {
				haveOIf[o] = struct{}{}
			}
		}
		// Exact count, so a leftover rule for a removed interface reads as drift
		// rather than passing.
		if n != len(want.OIfNames) {
			return false
		}
		wantOIf := map[string]struct{}{}
		for _, o := range want.OIfNames {
			wantOIf[o] = struct{}{}
		}
		return stringSetsEqual(haveOIf, wantOIf)
	case want.Description == "isolate-inbound-from-home":
		isolate := RuleComment("isolate-inbound-from-home", want.Family)
		for _, r := range rules {
			if r.Chain != chain || r.Comment != isolate {
				continue
			}
			if want.IIfName != "" && !containsStr(r.IIfNames, want.IIfName) {
				return false
			}
			if want.DropDstSet != "" && !containsStr(r.SetNames, want.DropDstSet) {
				return false
			}
			return true
		}
		return false
	default:
		return countComments(rules, chain, RuleComment(want.Description, want.Family)) >= 1
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func countComments(rules []liveRule, chain, comment string) int {
	n := 0
	for _, r := range rules {
		if r.Chain == chain && r.Comment == comment {
			n++
		}
	}
	return n
}

func daddrsForComment(rules []liveRule, chain, comment string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, r := range rules {
		if r.Chain != chain || r.Comment != comment {
			continue
		}
		for _, d := range r.DAddrs {
			out[normalizeDAddr(d)] = struct{}{}
		}
	}
	return out
}

// normalizeDAddr puts a destination match into canonical prefix form.
//
// nft prints a full-length prefix as a bare address, so ::1/128 comes back as
// "::1" and 10.10.0.2/32 as "10.10.0.2". The desired side is built from a mix
// of netip.Prefix and netip.Addr values, which stringify differently, so both
// sides are normalized here rather than each caller guessing. Without it the
// exclude lists never compare equal and the table is rebuilt on every apply --
// the same defect that bare set elements once caused.
func normalizeDAddr(s string) string {
	if strings.Contains(s, "/") {
		if p, err := netip.ParsePrefix(s); err == nil {
			return p.Masked().String()
		}
		return s
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

func stringSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func parseNftJSON(out string) (liveNft, error) {
	var root struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		return liveNft{}, err
	}
	live := liveNft{
		sets:   map[string]map[string]struct{}{},
		chains: map[string]liveChain{},
	}
	for _, raw := range root.Nftables {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			continue
		}
		if setRaw, ok := wrap["set"]; ok {
			name, elems := parseSetJSON(setRaw)
			if name != "" {
				live.sets[name] = elems
			}
			continue
		}
		if chainRaw, ok := wrap["chain"]; ok {
			name, ch, ok := parseChainJSON(chainRaw)
			if ok {
				live.chains[name] = ch
			}
			continue
		}
		if ruleRaw, ok := wrap["rule"]; ok {
			if r, ok := parseRuleJSON(ruleRaw); ok {
				live.rules = append(live.rules, r)
			}
		}
	}
	return live, nil
}

func parseSetJSON(raw json.RawMessage) (string, map[string]struct{}) {
	var setObj struct {
		Name string            `json:"name"`
		Elem []json.RawMessage `json:"elem"`
	}
	if err := json.Unmarshal(raw, &setObj); err != nil {
		return "", nil
	}
	elems := map[string]struct{}{}
	for _, e := range setObj.Elem {
		if cidr, ok := elemToCIDR(e); ok {
			elems[cidr] = struct{}{}
		}
	}
	return setObj.Name, elems
}

func elemToCIDR(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		if strings.Contains(s, "/") {
			return s, true
		}
		// nft renders a single address as a bare string, with no prefix length.
		// The desired side always carries one (netip.Prefix.String()), so
		// normalise or the element is dropped and the set compares unequal --
		// which makes every apply delete and rebuild the whole table.
		if a, err := netip.ParseAddr(s); err == nil {
			return netip.PrefixFrom(a, a.BitLen()).String(), true
		}
		return "", false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", false
	}
	if p, ok := obj["prefix"]; ok {
		var pref struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		}
		if json.Unmarshal(p, &pref) == nil && pref.Addr != "" {
			return fmt.Sprintf("%s/%d", pref.Addr, pref.Len), true
		}
	}
	// Nested {"elem": ...} wrappers used by some nft versions.
	if inner, ok := obj["elem"]; ok {
		return elemToCIDR(inner)
	}
	if val, ok := obj["val"]; ok {
		return elemToCIDR(val)
	}
	return "", false
}

func parseChainJSON(raw json.RawMessage) (string, liveChain, bool) {
	var ch struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Hook     string `json:"hook"`
		Prio     *int   `json:"prio"`
		Priority *int   `json:"priority"`
		Policy   string `json:"policy"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil || ch.Name == "" {
		return "", liveChain{}, false
	}
	prio := 0
	switch {
	case ch.Prio != nil:
		prio = *ch.Prio
	case ch.Priority != nil:
		prio = *ch.Priority
	}
	return ch.Name, liveChain{Type: ch.Type, Hook: ch.Hook, Priority: prio, Policy: ch.Policy}, true
}

func parseRuleJSON(raw json.RawMessage) (liveRule, bool) {
	var rule struct {
		Chain   string            `json:"chain"`
		Comment string            `json:"comment"`
		Expr    []json.RawMessage `json:"expr"`
	}
	if err := json.Unmarshal(raw, &rule); err != nil {
		return liveRule{}, false
	}
	r := liveRule{Chain: rule.Chain, Comment: rule.Comment}
	if m, ok := findMarkInExpr(rule.Expr); ok {
		r.Mark = &m
	}
	// A destination compared against a named set comes back as the string
	// "@name". It is a set reference, not an address, so it belongs in
	// SetNames -- which is where the text parser puts it, and where
	// liveHasRule looks for it. Leaving it in DAddrs meant the JSON path never
	// matched isolate-inbound-from-home at all, for either family, and the
	// forward chain was rebuilt on every apply on any box with JSON support.
	for _, d := range findDAddrsInExpr(rule.Expr) {
		if name, ok := strings.CutPrefix(d, "@"); ok {
			r.SetNames = append(r.SetNames, name)
			continue
		}
		r.DAddrs = append(r.DAddrs, d)
	}
	r.IIfNames = findIIfNamesInExpr(rule.Expr)
	r.OIfNames = findOIfNamesInExpr(rule.Expr)
	r.Masquerade = hasNATStmtInExpr(rule.Expr)
	r.SetNames = append(r.SetNames, findSetNamesInExpr(rule.Expr)...)
	return r, rule.Chain != ""
}

func findMarkInExpr(exprs []json.RawMessage) (uint32, bool) {
	for _, raw := range exprs {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if mraw, ok := obj["mangle"]; ok {
			var mangle struct {
				Key struct {
					Meta struct {
						Key string `json:"key"`
					} `json:"meta"`
				} `json:"key"`
				Value json.RawMessage `json:"value"`
			}
			if json.Unmarshal(mraw, &mangle) == nil && mangle.Key.Meta.Key == "mark" {
				if v, ok := parseJSONUint32(mangle.Value); ok {
					return v, true
				}
			}
		}
		for _, v := range obj {
			var nested []json.RawMessage
			if json.Unmarshal(v, &nested) == nil {
				if m, ok := findMarkInExpr(nested); ok {
					return m, true
				}
			}
		}
	}
	return 0, false
}

func findDAddrsInExpr(exprs []json.RawMessage) []string {
	var out []string
	seen := map[string]struct{}{}
	var walk func([]json.RawMessage)
	walk = func(exprs []json.RawMessage) {
		for _, raw := range exprs {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			if mraw, ok := obj["match"]; ok {
				if d, ok := daddrFromMatch(mraw); ok {
					if _, dup := seen[d]; !dup {
						seen[d] = struct{}{}
						out = append(out, d)
					}
				}
			}
			for _, v := range obj {
				var nested []json.RawMessage
				if json.Unmarshal(v, &nested) == nil {
					walk(nested)
				}
			}
		}
	}
	walk(exprs)
	return out
}

func daddrFromMatch(mraw json.RawMessage) (string, bool) {
	var m struct {
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return "", false
	}
	if !isIPDAddrPayload(m.Left) {
		return "", false
	}
	return matchRightToString(m.Right)
}

func isIPDAddrPayload(left json.RawMessage) bool {
	var payloadWrap struct {
		Payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
		} `json:"payload"`
	}
	if json.Unmarshal(left, &payloadWrap) == nil && isDAddrProto(payloadWrap.Payload.Protocol, payloadWrap.Payload.Field) {
		return true
	}
	// Some nft versions nest as {"payload":{...}} already unwrapped above;
	// also accept direct payload object.
	var payload struct {
		Protocol string `json:"protocol"`
		Field    string `json:"field"`
	}
	return json.Unmarshal(left, &payload) == nil && isDAddrProto(payload.Protocol, payload.Field)
}

// isDAddrProto accepts both families.
//
// Requiring protocol=="ip" made every ip6 daddr match invisible to the JSON
// parser: the exclude lists for IPv6 came back empty, never matched the spec,
// and the whole table was deleted and rebuilt on every apply. The text parser
// has the opposite blind spot -- it cannot tell the two apart at all -- which
// is why rule comments carry the family. See RuleComment.
func isDAddrProto(protocol, field string) bool {
	return (protocol == "ip" || protocol == "ip6") && field == "daddr"
}

func matchRightToString(right json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(right, &s); err == nil && s != "" {
		return s, true
	}
	var prefWrap struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(right, &prefWrap) == nil && prefWrap.Prefix.Addr != "" {
		return fmt.Sprintf("%s/%d", prefWrap.Prefix.Addr, prefWrap.Prefix.Len), true
	}
	var pref struct {
		Addr string `json:"addr"`
		Len  int    `json:"len"`
	}
	if json.Unmarshal(right, &pref) == nil && pref.Addr != "" {
		return fmt.Sprintf("%s/%d", pref.Addr, pref.Len), true
	}
	return "", false
}

func findIIfNamesInExpr(exprs []json.RawMessage) []string {
	return findMetaMatchesInExpr(exprs, "iifname")
}

func findOIfNamesInExpr(exprs []json.RawMessage) []string {
	return findMetaMatchesInExpr(exprs, "oifname")
}

// findMetaMatchesInExpr returns the right-hand string of every match whose left
// side is meta <metaKey>. The comparison operator is ignored.
func findMetaMatchesInExpr(exprs []json.RawMessage, metaKey string) []string {
	var out []string
	seen := map[string]struct{}{}
	var walk func([]json.RawMessage)
	walk = func(exprs []json.RawMessage) {
		for _, raw := range exprs {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			if mraw, ok := obj["match"]; ok {
				if name, ok := metaNameFromMatch(mraw, metaKey); ok {
					if _, dup := seen[name]; !dup {
						seen[name] = struct{}{}
						out = append(out, name)
					}
				}
			}
			for _, v := range obj {
				var nested []json.RawMessage
				if json.Unmarshal(v, &nested) == nil {
					walk(nested)
				}
			}
		}
	}
	walk(exprs)
	return out
}

// hasNATStmtInExpr reports whether any statement is a source-NAT statement.
//
// A bare masquerade serialises as {"masquerade": null}, so this tests for key
// presence only and must never unmarshal the value.
func hasNATStmtInExpr(exprs []json.RawMessage) bool {
	found := false
	var walk func([]json.RawMessage)
	walk = func(exprs []json.RawMessage) {
		for _, raw := range exprs {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			if _, ok := obj["masquerade"]; ok {
				found = true
				return
			}
			if _, ok := obj["snat"]; ok {
				found = true
				return
			}
			for _, v := range obj {
				var nested []json.RawMessage
				if json.Unmarshal(v, &nested) == nil {
					walk(nested)
				}
			}
		}
	}
	walk(exprs)
	return found
}

func metaNameFromMatch(mraw json.RawMessage, metaKey string) (string, bool) {
	var m struct {
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return "", false
	}
	var metaWrap struct {
		Meta struct {
			Key string `json:"key"`
		} `json:"meta"`
	}
	if json.Unmarshal(m.Left, &metaWrap) != nil || metaWrap.Meta.Key != metaKey {
		return "", false
	}
	var s string
	if json.Unmarshal(m.Right, &s) == nil && s != "" {
		return s, true
	}
	return "", false
}

func findSetNamesInExpr(exprs []json.RawMessage) []string {
	var out []string
	seen := map[string]struct{}{}
	var walk func([]json.RawMessage)
	walk = func(exprs []json.RawMessage) {
		for _, raw := range exprs {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				continue
			}
			if mraw, ok := obj["match"]; ok {
				if name, ok := setNameFromMatch(mraw); ok {
					if _, dup := seen[name]; !dup {
						seen[name] = struct{}{}
						out = append(out, name)
					}
				}
			}
			for _, v := range obj {
				var nested []json.RawMessage
				if json.Unmarshal(v, &nested) == nil {
					walk(nested)
				}
			}
		}
	}
	walk(exprs)
	return out
}

func setNameFromMatch(mraw json.RawMessage) (string, bool) {
	var m struct {
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return "", false
	}
	var setWrap struct {
		Set string `json:"set"`
	}
	if json.Unmarshal(m.Right, &setWrap) == nil && setWrap.Set != "" {
		return setWrap.Set, true
	}
	// Some nft versions: {"right":{"set":{"name":"home_nets"}}}
	var nested struct {
		Set struct {
			Name string `json:"name"`
		} `json:"set"`
	}
	if json.Unmarshal(m.Right, &nested) == nil && nested.Set.Name != "" {
		return nested.Set.Name, true
	}
	return "", false
}

func parseJSONUint32(raw json.RawMessage) (uint32, bool) {
	var n uint32
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if strings.HasPrefix(s, "0x") {
			v, err := strconv.ParseUint(s[2:], 16, 32)
			return uint32(v), err == nil
		}
		v, err := strconv.ParseUint(s, 10, 32)
		return uint32(v), err == nil
	}
	return 0, false
}

// RenderFullTable builds an nft -f script for the owned table (batched add element).
func RenderFullTable(spec policy.NftSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table %s %s\n", spec.Family, spec.Table)
	for _, set := range spec.Sets {
		// Flags come from the spec rather than being hardcoded: they were
		// already carried, sorted and compared by policy.normalize, but never
		// reached the wire, so a set that wanted different flags silently got
		// interval anyway.
		flags := ""
		if len(set.Flags) > 0 {
			flags = "flags " + strings.Join(set.Flags, ",") + "; "
		}
		fmt.Fprintf(&b, "add set %s %s %s { type %s; %s}\n", spec.Family, spec.Table, set.Name, set.Type, flags)
		writeBatchedElements(&b, spec.Family, spec.Table, set.Name, prefixesToStrings(set))
	}
	for _, chain := range spec.Chains {
		fmt.Fprintf(&b, "add chain %s %s %s { type %s hook %s priority %d; policy %s; }\n",
			spec.Family, spec.Table, chain.Name, chain.Type, chain.Hook, chain.Priority, chain.Policy)
		for _, line := range renderRuleLines(chain) {
			fmt.Fprintf(&b, "add rule %s %s %s %s\n", spec.Family, spec.Table, chain.Name, line)
		}
	}
	return b.String()
}

func prefixesToStrings(set policy.NftSetSpec) []string {
	out := make([]string, len(set.Elements))
	for i, el := range set.Elements {
		out[i] = el.String()
	}
	return out
}

func writeBatchedElements(b *strings.Builder, family, table, setName string, elements []string) {
	for i := 0; i < len(elements); i += ElementBatchSize {
		end := i + ElementBatchSize
		if end > len(elements) {
			end = len(elements)
		}
		batch := elements[i:end]
		fmt.Fprintf(b, "add element %s %s %s { %s }\n", family, table, setName, strings.Join(batch, ", "))
	}
}

func renderRuleLines(chain policy.NftChainSpec) []string {
	var lines []string
	for _, rule := range chain.Rules {
		l3, fam := l3(rule.Family), rule.Family
		cmt := func(desc string) string { return RuleComment(desc, fam) }
		switch {
		case rule.DropIPv6:
			lines = append(lines, `meta nfproto ipv6 drop comment "drop-ipv6"`)
		case rule.Description == "mark-non-direct":
			for _, p := range rule.ExcludePrefixes {
				lines = append(lines, fmt.Sprintf(`%s daddr %s return comment %q`, l3, p.String(), cmt("exclude-lan")))
			}
			for _, a := range rule.ExcludeAddrs {
				lines = append(lines, fmt.Sprintf(`%s daddr %s counter return comment %q`, l3, a.String(), cmt("exclude-endpoint")))
			}
			if rule.DropNonDirect {
				// The verdict is drop rather than mark: nothing can carry this
				// family to the exit hop, and letting it out the uplink is the
				// leak this fallback exists to refuse.
				lines = append(lines, fmt.Sprintf(`%s daddr != @%s counter drop comment %q`,
					l3, rule.DirectSet, cmt("drop-non-direct")))
				break
			}
			lines = append(lines, fmt.Sprintf(`%s daddr != @%s meta mark set 0x%x comment %q`,
				l3, rule.DirectSet, rule.Mark, cmt("mark-non-direct")))
		case rule.Description == "only-marked-ingress":
			// Return early for any interface gotun does not steer, so WAN-inbound
			// traffic never reaches the mark rule or walks the direct set.
			if len(rule.IIfNames) == 0 {
				break
			}
			quoted := make([]string, 0, len(rule.IIfNames))
			for _, n := range rule.IIfNames {
				quoted = append(quoted, fmt.Sprintf("%q", n))
			}
			lines = append(lines, fmt.Sprintf(`iifname != { %s } return comment "only-marked-ingress"`,
				strings.Join(quoted, ", ")))
		case rule.Description == "snat-direct":
			for _, pfx := range rule.ExcludePrefixes {
				lines = append(lines, fmt.Sprintf(`%s daddr %s return comment %q`, l3, pfx.String(), cmt("snat-skip-lan")))
			}
			if !rule.SNATMasquerade {
				break
			}
			for _, oif := range rule.OIfNames {
				lines = append(lines, fmt.Sprintf(
					`meta nfproto %s oifname %q fib saddr type != local counter masquerade comment %q`,
					nfproto(fam), oif, cmt("snat-direct")))
			}
		case rule.Description == "isolate-inbound-from-home":
			lines = append(lines, fmt.Sprintf(`iifname "%s" %s daddr @%s drop comment %q`,
				rule.IIfName, l3, rule.DropDstSet, cmt("isolate-inbound-from-home")))
		}
	}
	return lines
}

// SwapSetElements replaces live set contents via a single nft -f transaction.
func SwapSetElements(r linux.Runner, family, table, liveName string, elements []string) (int, error) {
	sort.Strings(elements)
	var b strings.Builder
	fmt.Fprintf(&b, "flush set %s %s %s\n", family, table, liveName)
	writeBatchedElements(&b, family, table, liveName, elements)
	if _, err := r.RunWithInput("nft", b.String(), "-f", linux.StdinPath); err != nil {
		return 0, err
	}
	return 1, nil
}

// CountSetElements returns the number of elements in an nft set, preferring JSON
// and falling back to the plain listing where nft has no JSON support.
func CountSetElements(r linux.Runner, family, table, setName string) (int, error) {
	if out, err := r.Run("nft", "-j", "list", "set", family, table, setName); err == nil {
		if n, cerr := countElementsJSON(out); cerr == nil {
			return n, nil
		}
	}
	out, err := r.Run("nft", "list", "set", family, table, setName)
	if err != nil {
		return 0, err
	}
	live, perr := parseNftText(out)
	if perr != nil {
		return 0, perr
	}
	elems, ok := live.sets[setName]
	if !ok {
		return 0, fmt.Errorf("set %s not found in listing", setName)
	}
	return len(elems), nil
}

func countElementsJSON(out string) (int, error) {
	var root struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &root); err != nil {
		return strings.Count(out, "/"), fmt.Errorf("nft json: %w", err)
	}
	n := 0
	for _, raw := range root.Nftables {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			continue
		}
		setRaw, ok := wrap["set"]
		if !ok {
			continue
		}
		_, elems := parseSetJSON(setRaw)
		n += len(elems)
	}
	return n, nil
}

// Clear removes the owned table.
func Clear(r linux.Runner, family, table string) error {
	_, err := r.Run("nft", "delete", "table", family, table)
	if err != nil && strings.Contains(err.Error(), "No such file") {
		return nil
	}
	if err != nil && strings.Contains(err.Error(), "does not exist") {
		return nil
	}
	return err
}
