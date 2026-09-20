package routing

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

func TestTableRoutesMatch_Exact(t *testing.T) {
	want := []policy.RouteSpec{
		{Table: 100, Device: "wg-exit", Metric: policy.TunnelRouteMetric},
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "default dev wg-exit metric 10 \nblackhole default metric 100\n"
	if !tableRoutesMatch(out, want) {
		t.Fatal("expected exact dual-route match")
	}
}

func TestTableRoutesMatch_StaleDeviceRejected(t *testing.T) {
	// Desired is blackhole-only (tunnel down), but a stale low-metric device route remains.
	want := []policy.RouteSpec{
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "default dev wg-exit metric 10\nblackhole default metric 100\n"
	if tableRoutesMatch(out, want) {
		t.Fatal("stale device route must make table mismatch")
	}
}

func TestTableRoutesMatch_SubsetNotEnough(t *testing.T) {
	want := []policy.RouteSpec{
		{Table: 100, Device: "wg-exit", Metric: policy.TunnelRouteMetric},
		{Table: 100, Blackhole: true, Metric: policy.FailClosedRouteMetric},
	}
	out := "blackhole default metric 100\n"
	if tableRoutesMatch(out, want) {
		t.Fatal("missing device route must mismatch")
	}
}

func ruleSpec() []policy.IPRuleSpec {
	return []policy.IPRuleSpec{{Priority: 100, Mark: 0x1, Table: 100}}
}

// The trap: fail-open withdraws the tunnel route, so the desired route set for
// table 100 is empty. If Reconcile derived its work list from the desired routes
// alone it would never look at table 100, and a blackhole left by an earlier
// fail-closed apply would survive while apply reported convergence -- leaving the
// box fail-closed while claiming to be fail-open.
func TestReconcile_OwnedTableWithNoDesiredRoutesIsFlushed(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "blackhole default metric 100\n"

	n, err := Reconcile(r, ruleSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removing a stale route is a change, got %d", n)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "ip route flush table 100") {
		t.Fatalf("table 100 must be flushed:\n%s", joined)
	}
	if strings.Contains(joined, "ip route replace") {
		t.Fatalf("nothing should be installed:\n%s", joined)
	}
}

// ...and it must stay idempotent: an already-empty owned table is no change.
func TestReconcile_OwnedEmptyTableIsNoChange(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "\n"

	n, err := Reconcile(r, ruleSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an already-empty table is converged, got %d changes; calls=%v", n, r.Calls)
	}
	if strings.Contains(strings.Join(r.Calls, "\n"), "flush") {
		t.Fatalf("must not flush a converged table:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestReconcile_InstallsDesiredTunnelRoute(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "\n"
	routes := []policy.RouteSpec{{
		Table: 100, Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Device: "wg-exit", Metric: 10,
	}}
	n, err := Reconcile(r, ruleSpec(), routes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d changes", n)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "ip route replace default dev wg-exit table 100 metric 10") {
		t.Fatalf("calls:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestReconcile_ConvergedTunnelRouteIsNoChange(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "default dev wg-exit metric 10\n"
	routes := []policy.RouteSpec{{
		Table: 100, Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Device: "wg-exit", Metric: 10,
	}}
	n, err := Reconcile(r, ruleSpec(), routes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("got %d changes; calls=%v", n, r.Calls)
	}
}

// Switching fail-closed -> fail-open must actively delete the blackhole.
func TestReconcile_FailClosedToFailOpenRemovesBlackhole(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "default dev wg-exit metric 10\nblackhole default metric 100\n"
	routes := []policy.RouteSpec{{
		Table: 100, Destination: netip.MustParsePrefix("0.0.0.0/0"),
		Device: "wg-exit", Metric: 10,
	}}
	n, err := Reconcile(r, ruleSpec(), routes)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d changes", n)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "ip route flush table 100") {
		t.Fatalf("the blackhole must be flushed away:\n%s", joined)
	}
}

// A route with the wrong nexthop must not pass as converged. Nothing gotun
// installs sets a "via", so a live one is drift by definition -- but keyed on dev
// and metric alone the two are indistinguishable and the stale nexthop survives
// every apply.
func TestReconcile_LiveGatewayRouteIsNotConverged(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "default via 10.20.0.9 dev wg-exit metric 10"

	n, err := Reconcile(r,
		[]policy.IPRuleSpec{{Priority: 100, Mark: 1, Table: 100}},
		[]policy.RouteSpec{{Table: 100, Device: "wg-exit", Metric: 10}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("a route via the wrong nexthop must read as drift")
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "ip route flush table 100") {
		t.Fatalf("expected the table to be rewritten:\n%s", joined)
	}
}

// The converse, so the key is not simply always-drift: the exact desired route
// reports zero changes.
func TestReconcile_DeviceRouteWithoutGatewayIsConverged(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip rule show"] = "100:\tfrom all fwmark 0x1 lookup 100"
	r.Outputs["ip route show table 100"] = "default dev wg-exit metric 10"

	n, err := Reconcile(r,
		[]policy.IPRuleSpec{{Priority: 100, Mark: 1, Table: 100}},
		[]policy.RouteSpec{{Table: 100, Device: "wg-exit", Metric: 10}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an already-correct table must report 0 changes, got %d; calls=%v", n, r.Calls)
	}
}
