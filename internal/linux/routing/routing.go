package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// famFlag is the explicit iproute2 family selector for a spec.
//
// Every ip rule and ip route invocation carries one, including the IPv4 ones.
// iproute2 defaults to inet, so an unflagged "ip rule show" reads the IPv4 RPDB
// and would report an IPv6 rule as present when it is not -- and "ip rule del"
// would then delete from the wrong family. The two RPDBs and the two route
// tables are separate kernel objects that merely share a number.
func famFlag(f policy.Family) string {
	if f == policy.FamilyV6 {
		return "-6"
	}
	return "-4"
}

// Reconcile applies owned ip rules and routes. Returns changes count.
func Reconcile(r linux.Runner, rules []policy.IPRuleSpec, routes []policy.RouteSpec) (int, error) {
	changes := 0

	for _, rule := range rules {
		fam := famFlag(rule.Family)
		out, _ := r.Run("ip", fam, "rule", "show")
		want := fmt.Sprintf("%d:", rule.Priority)
		markTok := fmt.Sprintf("fwmark 0x%x", rule.Mark)
		tableTok := fmt.Sprintf("lookup %d", rule.Table)
		if strings.Contains(out, want) && strings.Contains(out, markTok) && strings.Contains(out, tableTok) {
			continue
		}
		// delete any existing at priority then add
		_, _ = r.Run("ip", fam, "rule", "del", "priority", fmt.Sprintf("%d", rule.Priority))
		if _, err := r.Run("ip", fam, "rule", "add", "priority", fmt.Sprintf("%d", rule.Priority),
			"fwmark", fmt.Sprintf("0x%x", rule.Mark), "lookup", fmt.Sprintf("%d", rule.Table)); err != nil {
			return changes, err
		}
		changes++
	}

	// Owned tables are every table gotun points a rule at, UNION every table it
	// wants a route in -- not just the latter.
	//
	// Deriving the work list from the desired routes alone means a table whose
	// desired set is empty is never even inspected, so a route left over from a
	// previous policy survives while apply reports convergence. That is exactly
	// the fail-open case: withdrawing the tunnel route must also remove a
	// blackhole installed by an earlier fail-closed apply, or the box stays
	// fail-closed while claiming otherwise.
	// Keyed by (family, table), not table alone. Table 100 for IPv4 and table
	// 100 for IPv6 are independent kernel tables, so merging them would let one
	// family's desired routes decide whether the other family's table gets
	// flushed.
	type tableKey struct {
		Family policy.Family
		Table  int
	}
	byTable := map[tableKey][]policy.RouteSpec{}
	for _, rule := range rules {
		k := tableKey{Family: rule.Family, Table: rule.Table}
		if _, ok := byTable[k]; !ok {
			byTable[k] = nil
		}
	}
	for _, rt := range routes {
		k := tableKey{Family: rt.Family, Table: rt.Table}
		byTable[k] = append(byTable[k], rt)
	}
	// Sorted, so the command sequence is deterministic for tests and logs.
	keys := make([]tableKey, 0, len(byTable))
	for k := range byTable {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Family != keys[j].Family {
			return keys[i].Family < keys[j].Family
		}
		return keys[i].Table < keys[j].Table
	})
	for _, k := range keys {
		want := byTable[k]
		fam := famFlag(k.Family)
		out, _ := r.Run("ip", fam, "route", "show", "table", fmt.Sprintf("%d", k.Table))
		if tableRoutesMatch(out, want) {
			continue
		}
		_, _ = r.Run("ip", fam, "route", "flush", "table", fmt.Sprintf("%d", k.Table))
		for _, rt := range want {
			if err := addRoute(r, rt); err != nil {
				return changes, err
			}
		}
		changes++
	}
	return changes, nil
}

func tableRoutesMatch(out string, want []policy.RouteSpec) bool {
	live := parseRouteKeys(out)
	desired := map[string]struct{}{}
	for _, rt := range want {
		desired[routeKey(rt)] = struct{}{}
	}
	if len(live) != len(desired) {
		return false
	}
	for k := range desired {
		if _, ok := live[k]; !ok {
			return false
		}
	}
	return true
}

// routeKey identifies a route by everything that changes where packets go.
//
// The nexthop is part of that, even though nothing gotun installs sets one: a
// route left behind with a "via" would otherwise compare equal to the
// device-scoped route that is wanted, so the wrong nexthop would be treated as
// converged and never corrected. Desired routes have no gateway, so the key
// carries an empty one and anything with a via reads as drift.
func routeKey(rt policy.RouteSpec) string {
	dst := "default"
	if rt.Destination.IsValid() && rt.Destination.Bits() != 0 {
		dst = rt.Destination.Masked().String()
	}
	metric := rt.Metric
	if rt.Blackhole {
		return fmt.Sprintf("blackhole|%s|metric=%d", dst, metric)
	}
	return fmt.Sprintf("dev=%s|via=|%s|metric=%d", rt.Device, dst, metric)
}

func parseRouteKeys(out string) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, ok := parseRouteLine(line); ok {
			keys[k] = struct{}{}
		}
	}
	return keys
}

func parseRouteLine(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	metric := 0
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "metric" {
			metric, _ = strconv.Atoi(fields[i+1])
		}
	}
	// "blackhole default dev lo metric 100 pref medium" is how the kernel lists
	// an IPv6 blackhole; the extra tokens are ignored by the scan above.
	start := 0
	blackhole := fields[0] == "blackhole" || fields[0] == "unreachable" || fields[0] == "prohibit"
	if blackhole {
		start = 1
		if len(fields) < 2 {
			return "", false
		}
	}
	dst, ok := routeDest(fields[start])
	if !ok {
		return "", false
	}
	if blackhole {
		return fmt.Sprintf("blackhole|%s|metric=%d", dst, metric), true
	}
	dev, via := "", ""
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			dev = fields[i+1]
		case "via":
			via = fields[i+1]
		}
	}
	if dev == "" {
		return "", false
	}
	return fmt.Sprintf("dev=%s|via=%s|%s|metric=%d", dev, via, dst, metric), true
}

// routeDest canonicalizes the destination field of an "ip route show" line.
// A /0 prints as "default" for both families, so both spellings collapse to the
// same key.
func routeDest(field string) (string, bool) {
	if field == "default" {
		return "default", true
	}
	if strings.Contains(field, "/") {
		p, err := netip.ParsePrefix(field)
		if err != nil {
			return "", false
		}
		if p.Bits() == 0 {
			return "default", true
		}
		return p.Masked().String(), true
	}
	a, err := netip.ParseAddr(field)
	if err != nil {
		return "", false
	}
	return netip.PrefixFrom(a, a.BitLen()).String(), true
}

func addRoute(r linux.Runner, rt policy.RouteSpec) error {
	table := fmt.Sprintf("%d", rt.Table)
	fam := famFlag(rt.Family)
	// Destination is honoured rather than assumed: the literal "default" was
	// hardcoded here while RouteSpec.Destination was carried, compared and
	// ignored, so a non-default route could never have been installed.
	dst := "default"
	if rt.Destination.IsValid() && rt.Destination.Bits() != 0 {
		dst = rt.Destination.Masked().String()
	}
	args := []string{fam, "route", "replace"}
	if rt.Blackhole {
		args = append(args, "blackhole", dst, "table", table)
	} else {
		args = append(args, dst, "dev", rt.Device, "table", table)
	}
	if rt.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
	}
	_, err := r.Run("ip", args...)
	return err
}

// Clear removes owned rules and flushes the routing table.
//
// An object that is already gone is not a failure -- clear has to be safe to run
// on a box that was never set up, or after a partial teardown -- but anything
// else is reported, because this is the rollback path.
// Clear tears down both families.
//
// Doing only IPv4 leaves the IPv6 fwmark rule pointing at a table that has just
// been emptied, which is worse than leaving the policy in place: depending on
// fall-through the box either blackholes IPv6 or leaks it, on a machine the
// operator has been told is clean.
func Clear(r linux.Runner, priority, table int) error {
	var errs []error
	for _, fam := range []policy.Family{policy.FamilyV4, policy.FamilyV6} {
		f := famFlag(fam)
		if _, err := r.Run("ip", f, "rule", "del", "priority", fmt.Sprintf("%d", priority)); err != nil && !isAbsent(err) {
			errs = append(errs, fmt.Errorf("ip %s rule del priority %d: %w", f, priority, err))
		}
		if _, err := r.Run("ip", f, "route", "flush", "table", fmt.Sprintf("%d", table)); err != nil && !isAbsent(err) {
			errs = append(errs, fmt.Errorf("ip %s route flush table %d: %w", f, table, err))
		}
	}
	return errors.Join(errs...)
}

// isAbsent reports whether an iproute2 error just means "it was not there".
func isAbsent(err error) bool {
	msg := err.Error()
	for _, s := range []string{"No such file or directory", "does not exist", "Cannot find"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
