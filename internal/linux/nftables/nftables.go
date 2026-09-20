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

	listedJSON, err := r.Run("nft", "-j", "list", "table", family, table)
	tableExists := err == nil && listedJSON != "" && !strings.Contains(listedJSON, "Error")

	if tableExists && semanticMatchJSON(listedJSON, spec) {
		return 0, nil
	}

	var b strings.Builder
	if tableExists {
		fmt.Fprintf(&b, "delete table %s %s\n", family, table)
	}
	b.WriteString(RenderFullTable(spec))
	if _, err := r.RunWithInput("nft", b.String(), "-f", "-"); err != nil {
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

func semanticMatchJSON(out string, spec policy.NftSpec) bool {
	live, err := parseNftJSON(out)
	if err != nil {
		return false
	}
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
			wantLAN[p.String()] = struct{}{}
		}
		wantEP := map[string]struct{}{}
		for _, a := range want.ExcludeAddrs {
			wantEP[a.String()] = struct{}{}
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, "exclude-lan"), wantLAN) {
			return false
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, "exclude-endpoint"), wantEP) {
			return false
		}
		for _, r := range rules {
			if r.Chain == chain && r.Comment == "mark-non-direct" {
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
			wantSkip[p.String()] = struct{}{}
		}
		if !stringSetsEqual(daddrsForComment(rules, chain, "snat-skip-lan"), wantSkip) {
			return false
		}
		haveOIf := map[string]struct{}{}
		n := 0
		for _, r := range rules {
			if r.Chain != chain || r.Comment != "snat-direct" {
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
		for _, r := range rules {
			if r.Chain != chain || r.Comment != "isolate-inbound-from-home" {
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
		return countComments(rules, chain, want.Description) >= 1
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
			out[d] = struct{}{}
		}
	}
	return out
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
	r.DAddrs = findDAddrsInExpr(rule.Expr)
	r.IIfNames = findIIfNamesInExpr(rule.Expr)
	r.OIfNames = findOIfNamesInExpr(rule.Expr)
	r.Masquerade = hasNATStmtInExpr(rule.Expr)
	r.SetNames = findSetNamesInExpr(rule.Expr)
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
	if json.Unmarshal(left, &payloadWrap) == nil &&
		payloadWrap.Payload.Protocol == "ip" && payloadWrap.Payload.Field == "daddr" {
		return true
	}
	// Some nft versions nest as {"payload":{...}} already unwrapped above;
	// also accept direct payload object.
	var payload struct {
		Protocol string `json:"protocol"`
		Field    string `json:"field"`
	}
	return json.Unmarshal(left, &payload) == nil && payload.Protocol == "ip" && payload.Field == "daddr"
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
		fmt.Fprintf(&b, "add set %s %s %s { type %s; flags interval; }\n", spec.Family, spec.Table, set.Name, set.Type)
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
		switch {
		case rule.DropIPv6:
			lines = append(lines, `meta nfproto ipv6 drop comment "drop-ipv6"`)
		case rule.Description == "mark-non-direct":
			for _, p := range rule.ExcludePrefixes {
				lines = append(lines, fmt.Sprintf(`ip daddr %s return comment "exclude-lan"`, p.String()))
			}
			for _, a := range rule.ExcludeAddrs {
				lines = append(lines, fmt.Sprintf(`ip daddr %s counter return comment "exclude-endpoint"`, a.String()))
			}
			lines = append(lines, fmt.Sprintf(`ip daddr != @%s meta mark set 0x%x comment "mark-non-direct"`, rule.DirectSet, rule.Mark))
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
				lines = append(lines, fmt.Sprintf(`ip daddr %s return comment "snat-skip-lan"`, pfx.String()))
			}
			if !rule.SNATMasquerade {
				break
			}
			for _, oif := range rule.OIfNames {
				lines = append(lines, fmt.Sprintf(
					`meta nfproto ipv4 oifname %q fib saddr type != local counter masquerade comment "snat-direct"`,
					oif))
			}
		case rule.Description == "isolate-inbound-from-home":
			lines = append(lines, fmt.Sprintf(`iifname "%s" ip daddr @%s drop comment "isolate-inbound-from-home"`, rule.IIfName, rule.DropDstSet))
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
	if _, err := r.RunWithInput("nft", b.String(), "-f", "-"); err != nil {
		return 0, err
	}
	return 1, nil
}

// CountSetElements returns the number of elements in an nft set via nft -j.
func CountSetElements(r linux.Runner, family, table, setName string) (int, error) {
	out, err := r.Run("nft", "-j", "list", "set", family, table, setName)
	if err != nil {
		return 0, err
	}
	return countElementsJSON(out)
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
