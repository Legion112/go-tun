package gotunclient

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %s: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %s: %v", s, err)
	}
	return a
}

// Captured from first_pi: on-link, local, and unallocated-in-prefix answers.
const (
	routeGetOnLink      = "192.168.8.1 dev wlan0 src 192.168.8.224 uid 0 \n    cache \n"
	routeGetLocal       = "local 10.99.99.2 dev lo src 10.99.99.2 uid 0 \n    cache <local> \n"
	routeGetUnallocated = "192.168.8.77 dev wlan0 src 192.168.8.224 uid 0 \n    cache \n"
	routeGetViaGotun    = "104.26.12.205 via 192.168.8.162 dev wlan0 src 192.168.8.224 uid 0 \n    cache expires 599sec mtu 1280 \n"
	routeGetViaFlint    = "1.1.1.1 via 192.168.8.1 dev wlan0 src 192.168.8.224 uid 0 \n    cache \n"
)

func TestParseRouteGet_OnLink(t *testing.T) {
	res, err := parseRouteGet(routeGetOnLink)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Via.IsValid() {
		t.Fatalf("on-link route should have no nexthop, got %s", res.Via)
	}
	if res.Dev != "wlan0" {
		t.Fatalf("dev = %q", res.Dev)
	}
}

func TestParseRouteGet_ViaGateway(t *testing.T) {
	res, err := parseRouteGet(routeGetViaGotun)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.Via.String() != "192.168.8.162" || res.Dev != "wlan0" {
		t.Fatalf("got via=%s dev=%s", res.Via, res.Dev)
	}
}

func TestParseRouteGet_LocalDevLo(t *testing.T) {
	res, err := parseRouteGet(routeGetLocal)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !res.Local || res.Dev != "lo" || res.Via.IsValid() {
		t.Fatalf("got %+v", res)
	}
}

func TestParseRouteGet_UnreachableErrors(t *testing.T) {
	if _, err := parseRouteGet("unreachable 10.0.0.1 dev lo src 127.0.0.1\n"); err == nil {
		t.Fatal("want error for unreachable destination")
	}
}

func TestParseRouteGet_EmptyErrors(t *testing.T) {
	if _, err := parseRouteGet("   \n"); err == nil {
		t.Fatal("want error for empty output")
	}
}

// Regression: the previous implementation substring-matched "via <gw>", so a
// gateway of 192.168.8.16 matched a route line reading "via 192.168.8.162".
func TestRouteViaGateway_DoesNotSubstringMatchGateway(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip -4 route get 104.26.12.205"] = routeGetViaGotun
	via, _, err := RouteViaGateway(r, mustAddr(t, "104.26.12.205"), mustAddr(t, "192.168.8.16"))
	if err != nil {
		t.Fatalf("RouteViaGateway: %v", err)
	}
	if via {
		t.Fatal("192.168.8.16 must not match a route via 192.168.8.162")
	}
}

func TestRouteViaGateway_ExactMatch(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip -4 route get 104.26.12.205"] = routeGetViaGotun
	via, _, err := RouteViaGateway(r, mustAddr(t, "104.26.12.205"), mustAddr(t, "192.168.8.162"))
	if err != nil || !via {
		t.Fatalf("via=%v err=%v", via, err)
	}
}

func lanRunner(outputs map[string]string) *linux.RecordingRunner {
	r := linux.NewRecordingRunner()
	for k, v := range outputs {
		r.Outputs[k] = v
	}
	return r
}

func TestAssertLANsOnLink_AllOnLinkPasses(t *testing.T) {
	r := lanRunner(map[string]string{
		"ip -4 route get 192.168.8.1":   routeGetOnLink,
		"ip -4 route get 192.168.8.254": routeGetUnallocated,
		"ip -4 route get 10.99.99.1":    routeGetLocal,
		"ip -4 route get 10.99.99.2":    routeGetLocal,
	})
	protected := []netip.Prefix{mustPrefix(t, "192.168.8.0/24"), mustPrefix(t, "10.99.99.0/30")}
	if err := AssertLANsOnLink(r, protected, mustAddr(t, "192.168.8.162")); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestAssertLANsOnLink_OneViaGatewayFailsAndNamesPrefix(t *testing.T) {
	r := lanRunner(map[string]string{
		"ip -4 route get 192.168.8.1":   routeGetOnLink,
		"ip -4 route get 192.168.8.254": routeGetOnLink,
		"ip -4 route get 192.168.1.1":   "192.168.1.1 via 192.168.8.162 dev wlan0 src 192.168.8.224\n",
		"ip -4 route get 192.168.1.254": "192.168.1.254 via 192.168.8.162 dev wlan0 src 192.168.8.224\n",
	})
	protected := []netip.Prefix{mustPrefix(t, "192.168.8.0/24"), mustPrefix(t, "192.168.1.0/24")}
	err := AssertLANsOnLink(r, protected, mustAddr(t, "192.168.8.162"))
	if err == nil {
		t.Fatal("want failure")
	}
	if !strings.Contains(err.Error(), "192.168.1.0/24") {
		t.Fatalf("error should name the offending prefix: %v", err)
	}
}

// A stale redirect exception on the first probe address must not make the whole
// prefix read on-link -- which is why two hosts per prefix are probed.
func TestAssertLANsOnLink_SecondProbeCatchesHairpin(t *testing.T) {
	r := lanRunner(map[string]string{
		"ip -4 route get 192.168.8.1":   routeGetOnLink,
		"ip -4 route get 192.168.8.254": "192.168.8.254 via 192.168.8.162 dev wlan0\n",
	})
	err := AssertLANsOnLink(r, []netip.Prefix{mustPrefix(t, "192.168.8.0/24")}, mustAddr(t, "192.168.8.162"))
	if err == nil || !strings.Contains(err.Error(), "192.168.8.254") {
		t.Fatalf("want the second probe to fail, got %v", err)
	}
}

func TestAssertLANsOnLink_SkipsProbeEqualToGateway(t *testing.T) {
	// 192.168.8.162/32 probes only the gateway itself, which proves nothing.
	r := lanRunner(nil)
	if err := AssertLANsOnLink(r, []netip.Prefix{mustPrefix(t, "192.168.8.162/32")}, mustAddr(t, "192.168.8.162")); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
	if len(r.Calls) != 0 {
		t.Fatalf("should issue no route lookups, got %q", r.Calls)
	}
}

func TestAssertDefaultViaGateway_Ok(t *testing.T) {
	r := lanRunner(map[string]string{"ip -4 route get 1.1.1.1": routeGetViaGotun})
	if err := AssertDefaultViaGateway(r, mustAddr(t, "1.1.1.1"), mustAddr(t, "192.168.8.162")); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestAssertDefaultViaGateway_WrongGatewayFails(t *testing.T) {
	r := lanRunner(map[string]string{"ip -4 route get 1.1.1.1": routeGetViaFlint})
	err := AssertDefaultViaGateway(r, mustAddr(t, "1.1.1.1"), mustAddr(t, "192.168.8.162"))
	if err == nil || !strings.Contains(err.Error(), "192.168.8.1") {
		t.Fatalf("want failure naming the wrong nexthop, got %v", err)
	}
}

func TestAssertDefaultViaGateway_OnLinkFails(t *testing.T) {
	r := lanRunner(map[string]string{"ip -4 route get 1.1.1.1": routeGetOnLink})
	if err := AssertDefaultViaGateway(r, mustAddr(t, "1.1.1.1"), mustAddr(t, "192.168.8.162")); err == nil {
		t.Fatal("an on-link off-LAN probe must fail")
	}
}

func TestAssertSingleDefaultRoute_One(t *testing.T) {
	r := lanRunner(map[string]string{"ip -4 route show default": "default via 192.168.8.162 dev wlan0 metric 600\n"})
	if err := AssertSingleDefaultRoute(r); err != nil {
		t.Fatalf("want pass, got %v", err)
	}
}

func TestAssertSingleDefaultRoute_TwoFails(t *testing.T) {
	out := "default via 192.168.8.162 dev wlan0 metric 600\ndefault via 192.168.8.1 dev eth0 metric 100\n"
	r := lanRunner(map[string]string{"ip -4 route show default": out})
	err := AssertSingleDefaultRoute(r)
	if err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Fatalf("want failure counting 2, got %v", err)
	}
}

func TestAssertSingleDefaultRoute_NoneFails(t *testing.T) {
	r := lanRunner(map[string]string{"ip -4 route show default": "\n"})
	if err := AssertSingleDefaultRoute(r); err == nil {
		t.Fatal("want failure when there is no default route")
	}
}

func TestProbeHosts_Slash24FirstAndLastUsable(t *testing.T) {
	hosts, err := ProbeHosts(mustPrefix(t, "192.168.8.0/24"))
	if err != nil {
		t.Fatalf("ProbeHosts: %v", err)
	}
	if len(hosts) != 2 || hosts[0].String() != "192.168.8.1" || hosts[1].String() != "192.168.8.254" {
		t.Fatalf("got %v", hosts)
	}
}

func TestProbeHosts_Slash30(t *testing.T) {
	hosts, err := ProbeHosts(mustPrefix(t, "10.99.99.0/30"))
	if err != nil {
		t.Fatalf("ProbeHosts: %v", err)
	}
	if len(hosts) != 2 || hosts[0].String() != "10.99.99.1" || hosts[1].String() != "10.99.99.2" {
		t.Fatalf("got %v", hosts)
	}
}

func TestProbeHosts_Slash32ReturnsItself(t *testing.T) {
	hosts, err := ProbeHosts(mustPrefix(t, "192.168.8.162/32"))
	if err != nil {
		t.Fatalf("ProbeHosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].String() != "192.168.8.162" {
		t.Fatalf("got %v", hosts)
	}
}

func TestProbeHosts_Slash31StaysInPrefix(t *testing.T) {
	p := mustPrefix(t, "10.0.0.0/31")
	hosts, err := ProbeHosts(p)
	if err != nil {
		t.Fatalf("ProbeHosts: %v", err)
	}
	for _, h := range hosts {
		if !p.Contains(h) {
			t.Fatalf("%s outside %s", h, p)
		}
	}
}

func TestProbeHosts_Slash16(t *testing.T) {
	hosts, err := ProbeHosts(mustPrefix(t, "172.17.0.0/16"))
	if err != nil {
		t.Fatalf("ProbeHosts: %v", err)
	}
	if hosts[0].String() != "172.17.0.1" || hosts[1].String() != "172.17.255.254" {
		t.Fatalf("got %v", hosts)
	}
}

func TestProbeHost_InvalidPrefixErrors(t *testing.T) {
	if _, err := ProbeHost(netip.Prefix{}); err == nil {
		t.Fatal("want error for invalid prefix")
	}
}

func TestMergePrefixes_DedupesAndMasks(t *testing.T) {
	base := []netip.Prefix{mustPrefix(t, "192.168.8.0/24")}
	got := MergePrefixes(base, mustPrefix(t, "192.168.8.99/24"), mustPrefix(t, "10.0.0.0/8"))
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 unique prefixes", got)
	}
}

func TestMergePrefixes_SkipsIPv6(t *testing.T) {
	got := MergePrefixes(nil, mustPrefix(t, "2001:db8::/32"), mustPrefix(t, "10.0.0.0/8"))
	if len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("got %v", got)
	}
}
