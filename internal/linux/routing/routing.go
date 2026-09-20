package routing

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile applies owned ip rules and routes. Returns changes count.
func Reconcile(r linux.Runner, rules []policy.IPRuleSpec, routes []policy.RouteSpec) (int, error) {
	changes := 0

	for _, rule := range rules {
		out, _ := r.Run("ip", "rule", "show")
		want := fmt.Sprintf("%d:", rule.Priority)
		markTok := fmt.Sprintf("fwmark 0x%x", rule.Mark)
		tableTok := fmt.Sprintf("lookup %d", rule.Table)
		if strings.Contains(out, want) && strings.Contains(out, markTok) && strings.Contains(out, tableTok) {
			continue
		}
		// delete any existing at priority then add
		_, _ = r.Run("ip", "rule", "del", "priority", fmt.Sprintf("%d", rule.Priority))
		if _, err := r.Run("ip", "rule", "add", "priority", fmt.Sprintf("%d", rule.Priority),
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
	byTable := map[int][]policy.RouteSpec{}
	for _, rule := range rules {
		if _, ok := byTable[rule.Table]; !ok {
			byTable[rule.Table] = nil
		}
	}
	for _, rt := range routes {
		byTable[rt.Table] = append(byTable[rt.Table], rt)
	}
	// Sorted, so the command sequence is deterministic for tests and logs.
	tables := make([]int, 0, len(byTable))
	for t := range byTable {
		tables = append(tables, t)
	}
	sort.Ints(tables)
	for _, table := range tables {
		want := byTable[table]
		out, _ := r.Run("ip", "route", "show", "table", fmt.Sprintf("%d", table))
		if tableRoutesMatch(out, want) {
			continue
		}
		_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", table))
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
	metric := rt.Metric
	if rt.Blackhole {
		return fmt.Sprintf("blackhole|default|metric=%d", metric)
	}
	return fmt.Sprintf("dev=%s|via=|default|metric=%d", rt.Device, metric)
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
	switch {
	case fields[0] == "blackhole" || fields[0] == "unreachable":
		// blackhole default [metric N]
		return fmt.Sprintf("blackhole|default|metric=%d", metric), true
	case fields[0] == "default":
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
		return fmt.Sprintf("dev=%s|via=%s|default|metric=%d", dev, via, metric), true
	default:
		return "", false
	}
}

func addRoute(r linux.Runner, rt policy.RouteSpec) error {
	table := fmt.Sprintf("%d", rt.Table)
	if rt.Blackhole {
		args := []string{"route", "replace", "blackhole", "default", "table", table}
		if rt.Metric > 0 {
			args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
		}
		_, err := r.Run("ip", args...)
		return err
	}
	args := []string{"route", "replace", "default", "dev", rt.Device, "table", table}
	if rt.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
	}
	_, err := r.Run("ip", args...)
	return err
}

// Clear removes owned rules and flushes the routing table.
func Clear(r linux.Runner, priority, table int) error {
	_, _ = r.Run("ip", "rule", "del", "priority", fmt.Sprintf("%d", priority))
	_, _ = r.Run("ip", "route", "flush", "table", fmt.Sprintf("%d", table))
	return nil
}
