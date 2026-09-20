package nftables

import (
	"fmt"
	"strconv"
	"strings"
)

// namedPriorities are the symbolic hook priorities nft prints instead of numbers.
// nft renders a nearby value as an offset from the closest name, so a chain
// created at -149 comes back as "mangle + 1" and has to be resolved to compare.
var namedPriorities = map[string]int{
	"raw":      -300,
	"mangle":   -150,
	"dstnat":   -100,
	"filter":   0,
	"security": 50,
	"srcnat":   100,
	"out":      0,
}

// parseNftText builds the same liveNft the JSON parser produces, from the plain
// text of "nft list table".
//
// It exists because OpenWrt ships nftables-nojson, where "nft -j" fails for every
// table. Without a text path, a live table read as absent: the delete was never
// emitted, "add rule" appended instead of replacing, and each apply stacked
// another generation of rules on the previous one. The damage went beyond
// duplication -- the fresh exclude returns landed *after* the older mark rule, so
// a changed -lan or -endpoint had no effect at all while apply reported success.
//
// The shapes handled here were taken from real nft output, not from the manual:
// priorities come back named and offset, marks are zero-padded to 0x00000001,
// counters are inlined as "counter packets 0 bytes 0", and long set element lists
// wrap across lines.
func parseNftText(out string) (liveNft, error) {
	live := liveNft{
		sets:   map[string]map[string]struct{}{},
		chains: map[string]liveChain{},
	}

	var (
		curSet   string
		curChain string
		// elemBuf accumulates a wrapped "elements = { ... }" list.
		elemBuf  string
		inElems  bool
		sawTable bool
	)

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if inElems {
			done := false
			if i := strings.LastIndex(line, "}"); i >= 0 {
				line, done = line[:i], true
			}
			elemBuf += " " + line
			if !done {
				continue
			}
			inElems = false
			if curSet != "" {
				live.sets[curSet] = parseElementList(elemBuf)
			}
			elemBuf = ""
			continue
		}

		switch {
		case strings.HasPrefix(line, "table "):
			sawTable = true
			continue
		case strings.HasPrefix(line, "set ") && strings.HasSuffix(line, "{"):
			curSet = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "set "), "{"))
			// A set with no elements still exists, and must not read as absent.
			live.sets[curSet] = map[string]struct{}{}
			continue
		case strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{"):
			curChain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{"))
			live.chains[curChain] = liveChain{}
			continue
		case line == "}":
			curSet, curChain = "", ""
			continue
		}

		if curSet != "" {
			if rest, ok := cutPrefix(line, "elements = {"); ok {
				if i := strings.LastIndex(rest, "}"); i >= 0 {
					live.sets[curSet] = parseElementList(rest[:i])
				} else {
					inElems, elemBuf = true, rest
				}
			}
			continue
		}

		if curChain == "" {
			continue
		}
		if strings.HasPrefix(line, "type ") && strings.Contains(line, "hook ") {
			if ch, ok := parseChainHeaderText(line); ok {
				live.chains[curChain] = ch
			}
			continue
		}
		live.rules = append(live.rules, parseRuleText(curChain, line))
	}

	if !sawTable {
		return liveNft{}, fmt.Errorf("no table in nft output")
	}
	return live, nil
}

// cutPrefix is strings.CutPrefix, kept local so this file builds against the
// Go version pinned in go.mod without assuming a newer stdlib.
func cutPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return s, false
	}
	return strings.TrimSpace(s[len(prefix):]), true
}

func parseElementList(s string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		// Drop any per-element attributes nft may append (timeouts, comments).
		if i := strings.IndexAny(part, " \t"); i >= 0 {
			part = part[:i]
		}
		if part != "" && part != "{" && part != "}" {
			out[part] = struct{}{}
		}
	}
	return out
}

// parseChainHeaderText reads "type filter hook prerouting priority mangle + 1; policy accept;".
func parseChainHeaderText(line string) (liveChain, bool) {
	var ch liveChain
	head, tail, _ := strings.Cut(line, ";")
	fields := strings.Fields(head)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "type":
			if i+1 < len(fields) {
				ch.Type = fields[i+1]
			}
		case "hook":
			if i+1 < len(fields) {
				ch.Hook = fields[i+1]
			}
		case "priority":
			prio, ok := parsePriorityText(fields[i+1:])
			if !ok {
				return liveChain{}, false
			}
			ch.Priority = prio
		}
	}
	for _, f := range strings.Fields(tail) {
		if f == "policy" {
			continue
		}
		ch.Policy = strings.TrimSuffix(f, ";")
		break
	}
	return ch, ch.Type != "" && ch.Hook != ""
}

// parsePriorityText resolves "-150", "mangle", or "mangle + 1".
func parsePriorityText(fields []string) (int, bool) {
	if len(fields) == 0 {
		return 0, false
	}
	base, ok := resolvePriorityWord(fields[0])
	if !ok {
		return 0, false
	}
	if len(fields) >= 3 && (fields[1] == "+" || fields[1] == "-") {
		off, err := strconv.Atoi(fields[2])
		if err != nil {
			return 0, false
		}
		if fields[1] == "-" {
			off = -off
		}
		return base + off, true
	}
	return base, true
}

func resolvePriorityWord(w string) (int, bool) {
	w = strings.TrimSuffix(w, ";")
	if n, err := strconv.Atoi(w); err == nil {
		return n, true
	}
	// A name can carry the offset with no spaces, e.g. "mangle+1".
	for _, sep := range []string{"+", "-"} {
		if name, off, found := strings.Cut(w, sep); found {
			base, ok := namedPriorities[name]
			if !ok {
				return 0, false
			}
			n, err := strconv.Atoi(off)
			if err != nil {
				return 0, false
			}
			if sep == "-" {
				n = -n
			}
			return base + n, true
		}
	}
	n, ok := namedPriorities[w]
	return n, ok
}

// parseRuleText extracts the attributes liveHasRule compares. Anything it does
// not understand simply stays zero, which reads as drift and triggers a rewrite
// -- the safe direction.
func parseRuleText(chain, line string) liveRule {
	r := liveRule{Chain: chain}
	r.Comment = ruleCommentText(line)
	r.Masquerade = strings.Contains(line, "masquerade")

	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "daddr":
			// "ip daddr X", "ip daddr != @set", "ip daddr { a, b }"
			r.DAddrs = append(r.DAddrs, parseMatchValues(fields, i+1)...)
		case "iifname":
			r.IIfNames = append(r.IIfNames, parseMatchValues(fields, i+1)...)
		case "oifname":
			r.OIfNames = append(r.OIfNames, parseMatchValues(fields, i+1)...)
		case "mark":
			// "meta mark set 0x00000001" -- only the set form, not a mark match.
			if i >= 1 && fields[i-1] == "meta" && i+2 < len(fields) && fields[i+1] == "set" {
				if v, err := strconv.ParseUint(strings.TrimPrefix(fields[i+2], "0x"), 16, 32); err == nil {
					m := uint32(v)
					r.Mark = &m
				}
			}
		}
		if strings.HasPrefix(fields[i], "@") {
			r.SetNames = append(r.SetNames, strings.Trim(fields[i], "@{},"))
		}
	}
	return r
}

// parseMatchValues reads the value(s) a match compares against, starting at i:
// a bare token, a quoted name, or a braced list. A set reference is not a value.
func parseMatchValues(fields []string, i int) []string {
	if i < len(fields) && (fields[i] == "!=" || fields[i] == "==") {
		i++
	}
	if i >= len(fields) {
		return nil
	}
	if strings.HasPrefix(fields[i], "@") {
		return nil
	}
	if fields[i] != "{" {
		return []string{strings.Trim(fields[i], `",`)}
	}
	var out []string
	for j := i + 1; j < len(fields); j++ {
		if fields[j] == "}" {
			break
		}
		if v := strings.Trim(fields[j], `",`); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func ruleCommentText(line string) string {
	i := strings.LastIndex(line, `comment "`)
	if i < 0 {
		return ""
	}
	rest := line[i+len(`comment "`):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}
