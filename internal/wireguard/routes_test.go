package wireguard

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
)

func TestRouteExists_CIDRPresent(t *testing.T) {
	out := "10.67.0.0/24 dev wg-exit scope link\n10.99.0.0/30 dev wg-exit scope link\n"
	if !routeExists(out, netip.MustParsePrefix("10.67.0.0/24")) {
		t.Fatal("should find an existing CIDR route")
	}
}

func TestRouteExists_Absent(t *testing.T) {
	out := "10.67.0.0/24 dev wg-exit scope link\n"
	if routeExists(out, netip.MustParsePrefix("10.99.0.0/30")) {
		t.Fatal("should not find a route that is not there")
	}
}

// iproute2 prints a host route without its prefix length, so a textual compare
// would miss it and the route would be replaced (and counted) on every apply.
func TestRouteExists_HostRoutePrintedWithoutPrefixLength(t *testing.T) {
	out := "10.0.0.5 dev wg-exit scope link\n"
	if !routeExists(out, netip.MustParsePrefix("10.0.0.5/32")) {
		t.Fatal("a /32 printed bare must still be recognised")
	}
}

func TestRouteExists_IgnoresDefaultAndGarbage(t *testing.T) {
	out := "default via 10.0.0.1 dev eth0\nbroadcast something\n\n"
	if routeExists(out, netip.MustParsePrefix("10.67.0.0/24")) {
		t.Fatal("unrelated lines must not match")
	}
}

func TestRouteExists_EmptyOutput(t *testing.T) {
	if routeExists("", netip.MustParsePrefix("10.67.0.0/24")) {
		t.Fatal("no routes means not present")
	}
}

// The defect: a route that is already correct was replaced and counted on every
// apply, so a converged gateway never reported 0 changes.
func TestEnsureAllowedIPRoutes_PresentRouteIsNotCounted(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip -4 route show dev wg-exit"] = "10.67.0.0/24 dev wg-exit scope link\n"
	n, err := ensureAllowedIPRoutes(r, "wg-exit", []netip.Prefix{
		netip.MustParsePrefix("10.67.0.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an already-present route must not count as a change, got %d", n)
	}
	if strings.Contains(strings.Join(r.Calls, "\n"), "route replace") {
		t.Fatalf("must not replace a correct route:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestEnsureAllowedIPRoutes_MissingRouteIsInstalledAndCounted(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip -4 route show dev wg-exit"] = "\n"
	n, err := ensureAllowedIPRoutes(r, "wg-exit", []netip.Prefix{netip.MustParsePrefix("10.67.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a missing route must be installed and counted, got %d", n)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "ip -4 route replace 10.67.0.0/24 dev wg-exit") {
		t.Fatalf("expected the replace:\n%s", strings.Join(r.Calls, "\n"))
	}
}

// Behaviour preserved from the fix that made these routes survive a bounce: the
// check still runs, only the accounting changed.
func TestEnsureAllowedIPRoutes_PartiallyMissingInstallsOnlyTheMissing(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip -4 route show dev wg-exit"] = "10.67.0.0/24 dev wg-exit scope link\n"
	n, err := ensureAllowedIPRoutes(r, "wg-exit", []netip.Prefix{
		netip.MustParsePrefix("10.67.0.0/24"),
		netip.MustParsePrefix("10.99.0.0/30"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("only the missing route should count, got %d", n)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "ip -4 route replace 10.99.0.0/30 dev wg-exit") {
		t.Fatalf("missing route not installed:\n%s", joined)
	}
	if strings.Contains(joined, "ip -4 route replace 10.67.0.0/24") {
		t.Fatalf("present route should be left alone:\n%s", joined)
	}
}

// A peer with only default AllowedIPs must not even read the route table.
func TestEnsureAllowedIPRoutes_DefaultsOnlyIssuesNoCommands(t *testing.T) {
	r := linux.NewRecordingRunner()
	n, err := ensureAllowedIPRoutes(r, "wg-exit", []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	})
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(r.Calls) != 0 {
		t.Fatalf("expected no commands, got %q", r.Calls)
	}
}
