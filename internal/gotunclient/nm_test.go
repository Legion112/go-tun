package gotunclient

import (
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
)

// Captured verbatim from first_pi (Debian 13, NetworkManager 1.52.1),
// `nmcli -t -f <nmReadFields> connection show MTS_GPON_2F34`.
const fixtureAutoDHCP = `ipv4.method:auto
ipv4.gateway:
ipv4.dns:
ipv4.ignore-auto-dns:no
ipv4.never-default:no
ipv4.routes:
ipv4.route-metric:-1
ipv6.ignore-auto-dns:no`

// Captured from a dummy connection created with static addresses and routes.
const fixtureManualRoutes = `ipv4.method:manual
ipv4.gateway:
ipv4.dns:10.98.0.53,10.98.0.54
ipv4.ignore-auto-dns:no
ipv4.never-default:yes
ipv4.routes:10.97.0.0/16 10.98.0.1 300, 10.96.0.0/16 10.98.0.1
ipv4.route-metric:250
ipv6.ignore-auto-dns:no`

func TestParseNMProps_AutoDHCPAllUnset(t *testing.T) {
	p, err := parseNMProps(fixtureAutoDHCP)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Method != "auto" {
		t.Fatalf("method = %q, want auto", p.Method)
	}
	for name, v := range map[string]*string{"gateway": p.Gateway, "dns": p.DNS, "routes": p.Routes, "route-metric": p.RouteMetric} {
		if v != nil {
			t.Errorf("%s = %q, want nil (unset)", name, *v)
		}
	}
	if p.IgnoreAutoDNS || p.NeverDefault || p.IPv6IgnoreDNS {
		t.Errorf("booleans should all be false: %+v", p)
	}
}

func TestParseNMProps_RouteMetricMinusOneIsUnset(t *testing.T) {
	p, _ := parseNMProps(fixtureAutoDHCP)
	if p.RouteMetric != nil {
		t.Fatalf("route-metric -1 should be unset, got %q", *p.RouteMetric)
	}
}

func TestParseNMProps_ManualWithRoutes(t *testing.T) {
	p, err := parseNMProps(fixtureManualRoutes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Method != "manual" {
		t.Fatalf("method = %q", p.Method)
	}
	if p.Routes == nil || *p.Routes != "10.97.0.0/16 10.98.0.1 300, 10.96.0.0/16 10.98.0.1" {
		t.Fatalf("routes = %v", p.Routes)
	}
	if p.DNS == nil || *p.DNS != "10.98.0.53,10.98.0.54" {
		t.Fatalf("dns = %v", p.DNS)
	}
	if p.RouteMetric == nil || *p.RouteMetric != "250" {
		t.Fatalf("route-metric = %v", p.RouteMetric)
	}
	if !p.NeverDefault {
		t.Fatalf("never-default should be true")
	}
}

// Terse mode prints an empty value for unset; pretty mode prints "--".
func TestParseNMProps_DoubleDashIsUnset(t *testing.T) {
	p, err := parseNMProps("ipv4.method:auto\nipv4.gateway:--\nipv4.routes:--")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Gateway != nil || p.Routes != nil {
		t.Fatalf("-- should mean unset: gateway=%v routes=%v", p.Gateway, p.Routes)
	}
}

func TestParseNMProps_RepeatedRoutesLinesJoined(t *testing.T) {
	p, err := parseNMProps("ipv4.method:manual\nipv4.routes:10.1.0.0/16 10.0.0.1\nipv4.routes:10.2.0.0/16 10.0.0.1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Routes == nil || *p.Routes != "10.1.0.0/16 10.0.0.1, 10.2.0.0/16 10.0.0.1" {
		t.Fatalf("routes = %v", p.Routes)
	}
}

func TestParseNMProps_MissingMethodErrors(t *testing.T) {
	if _, err := parseNMProps("ipv4.gateway:\n"); err == nil {
		t.Fatal("want error when ipv4.method is absent")
	}
}

func TestParseNMProps_BooleanSpellings(t *testing.T) {
	p, _ := parseNMProps("ipv4.method:auto\nipv4.never-default:yes\nipv4.ignore-auto-dns:true\nipv6.ignore-auto-dns:1")
	if !p.NeverDefault || !p.IgnoreAutoDNS || !p.IPv6IgnoreDNS {
		t.Fatalf("all should be true: %+v", p)
	}
}

func TestSplitTerse_EscapedColonInValue(t *testing.T) {
	got := splitTerse(`Home\:Net:wlan0:wifi:activated`)
	want := []string{"Home:Net", "wlan0", "wifi", "activated"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitTerse_EscapedBackslash(t *testing.T) {
	got := splitTerse(`a\\b:c`)
	if len(got) != 2 || got[0] != `a\b` || got[1] != "c" {
		t.Fatalf("got %q", got)
	}
}

func TestReadNMProps_RequestsEveryFieldInOneCall(t *testing.T) {
	r := linux.NewRecordingRunner()
	key := "nmcli -t -f " + strings.Join(nmReadFields, ",") + " connection show MTS_GPON_2F34"
	r.Outputs[key] = fixtureAutoDHCP
	if _, err := ReadNMProps(r, "MTS_GPON_2F34"); err != nil {
		t.Fatalf("ReadNMProps: %v", err)
	}
	if len(r.Calls) != 1 {
		t.Fatalf("want exactly one nmcli call, got %q", r.Calls)
	}
	if r.Calls[0] != key {
		t.Fatalf("call = %q, want %q", r.Calls[0], key)
	}
}

// Captured from first_pi with both wlan0 and the eth0 lifeline active.
const fixtureActive = `MTS_GPON_2F34:wlan0:802-11-wireless:activated
Wired connection 1:eth0:802-3-ethernet:activated
lo:lo:loopback:activated`

func TestParseActiveConns_SkipsNonActivated(t *testing.T) {
	conns := parseActiveConns(fixtureActive + "\nOther:eth9:802-3-ethernet:activating")
	if len(conns) != 3 {
		t.Fatalf("got %d conns: %+v", len(conns), conns)
	}
}

func TestParseActiveConns_EscapedColonInName(t *testing.T) {
	conns := parseActiveConns(`My\:Wifi:wlan0:802-11-wireless:activated`)
	if len(conns) != 1 || conns[0].ID != "My:Wifi" {
		t.Fatalf("got %+v", conns)
	}
}

func TestDefaultRouteDevices_SingleDefault(t *testing.T) {
	devs := defaultRouteDevices("default via 192.168.8.1 dev wlan0 proto dhcp src 192.168.8.224 metric 600 \n")
	if len(devs) != 1 || devs[0] != "wlan0" {
		t.Fatalf("got %q", devs)
	}
}

func TestDefaultRouteDevices_OrdersByMetric(t *testing.T) {
	out := "default via 192.168.8.1 dev wlan0 metric 600\ndefault via 192.168.8.1 dev eth0 metric 100\n"
	devs := defaultRouteDevices(out)
	if len(devs) != 2 || devs[0] != "eth0" || devs[1] != "wlan0" {
		t.Fatalf("got %q, want [eth0 wlan0]", devs)
	}
}

func TestDefaultRouteDevices_NoDefaultReturnsEmpty(t *testing.T) {
	if devs := defaultRouteDevices("192.168.8.0/24 dev wlan0 proto kernel scope link\n"); len(devs) != 0 {
		t.Fatalf("got %q", devs)
	}
}

func TestDefaultRouteDevices_IgnoresNonDefaultLines(t *testing.T) {
	out := "10.99.99.0/30 dev eth0 proto kernel scope link src 10.99.99.2 metric 3000\ndefault via 192.168.8.1 dev wlan0 metric 600\n"
	devs := defaultRouteDevices(out)
	if len(devs) != 1 || devs[0] != "wlan0" {
		t.Fatalf("got %q", devs)
	}
}

func detectRunner(active, routes string) *linux.RecordingRunner {
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active"] = active
	r.Outputs["ip -4 route show default"] = routes
	return r
}

func TestDetectActiveConn_SingleCandidate(t *testing.T) {
	r := detectRunner(fixtureActive, "default via 192.168.8.1 dev wlan0 metric 600\n")
	c, err := DetectActiveConn(r, "")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if c.ID != "MTS_GPON_2F34" || c.Device != "wlan0" {
		t.Fatalf("got %+v", c)
	}
}

func TestDetectActiveConn_NoDefaultRouteErrors(t *testing.T) {
	r := detectRunner(fixtureActive, "")
	if _, err := DetectActiveConn(r, ""); err == nil || !strings.Contains(err.Error(), "no IPv4 default route") {
		t.Fatalf("err = %v", err)
	}
}

func TestDetectActiveConn_PrefersLowestMetric(t *testing.T) {
	r := detectRunner(fixtureActive, "default via 192.168.8.1 dev wlan0 metric 600\ndefault via 192.168.8.1 dev eth0 metric 100\n")
	c, err := DetectActiveConn(r, "")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if c.Device != "eth0" {
		t.Fatalf("got %+v, want eth0 (lower metric)", c)
	}
}

func TestDetectActiveConn_MetricTieErrors(t *testing.T) {
	r := detectRunner(fixtureActive, "default via 192.168.8.1 dev wlan0 metric 100\ndefault via 192.168.8.1 dev eth0 metric 100\n")
	_, err := DetectActiveConn(r, "")
	if err == nil || !strings.Contains(err.Error(), "-connection") {
		t.Fatalf("want ambiguity error naming -connection, got %v", err)
	}
}

func TestDetectActiveConn_DefaultDeviceWithoutProfileErrors(t *testing.T) {
	r := detectRunner("lo:lo:loopback:activated", "default via 10.0.0.1 dev ppp0 metric 100\n")
	_, err := DetectActiveConn(r, "")
	if err == nil || !strings.Contains(err.Error(), "ppp0") {
		t.Fatalf("want error naming ppp0, got %v", err)
	}
}

func TestDetectActiveConn_ExplicitConnectionWins(t *testing.T) {
	r := detectRunner(fixtureActive, "default via 192.168.8.1 dev wlan0 metric 600\n")
	c, err := DetectActiveConn(r, "Wired connection 1")
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if c.Device != "eth0" {
		t.Fatalf("got %+v", c)
	}
	for _, call := range r.Calls {
		if strings.Contains(call, "ip -4 route show default") {
			t.Fatal("explicit -connection should not need the default route")
		}
	}
}

func TestDetectActiveConn_ExplicitConnectionNotActiveErrors(t *testing.T) {
	r := detectRunner(fixtureActive, "")
	_, err := DetectActiveConn(r, "Nope")
	if err == nil || !strings.Contains(err.Error(), "not activated") {
		t.Fatalf("err = %v", err)
	}
}

func TestDeviceDNS_ParsesIndexedFields(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f IP4.DNS device show wlan0"] = "IP4.DNS[1]:192.168.8.1\nIP4.DNS[2]:1.1.1.1\n"
	dns, err := DeviceDNS(r, "wlan0")
	if err != nil {
		t.Fatalf("DeviceDNS: %v", err)
	}
	if len(dns) != 2 || dns[0] != "192.168.8.1" || dns[1] != "1.1.1.1" {
		t.Fatalf("got %q", dns)
	}
}
