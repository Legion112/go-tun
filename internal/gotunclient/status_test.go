package gotunclient

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

func statusRunner(t *testing.T) *linux.RecordingRunner {
	t.Helper()
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active"] = fixtureActive
	r.Outputs["ip -4 route show default"] = gwRoutes
	r.Outputs["nmcli -t -f "+strings.Join(nmReadFields, ",")+" connection show "+testConn] = fixtureAutoDHCP
	r.Outputs["nmcli -t -f IP4.DNS device show "+testDev] = "IP4.DNS[1]:192.168.8.1\n"
	return r
}

func TestStatus_ReportsDisabledWithoutStateFile(t *testing.T) {
	restoreDetect(t)
	r := statusRunner(t)
	onLinkAll(r)
	rep, err := Status(r, "/nonexistent/state.json", netip.MustParseAddr(testGW), nil)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Enabled {
		t.Fatal("should report not enabled")
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	if !strings.Contains(out.String(), "not enabled") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestStatus_ReportsEnabledFromStateFile(t *testing.T) {
	restoreDetect(t)
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := statusRunner(t)
	onLinkAll(r)
	rep, err := Status(r, p, netip.MustParseAddr("10.0.0.1"), nil)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !rep.Enabled {
		t.Fatal("should report enabled")
	}
	// The gateway recorded at enable time must win over the flag default.
	if rep.Gateway.String() != testGW {
		t.Fatalf("gateway = %s, want %s from state", rep.Gateway, testGW)
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	if !strings.Contains(out.String(), "ENABLED") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestStatus_MarksPrefixRoutingViaGotun(t *testing.T) {
	restoreDetect(t)
	r := statusRunner(t)
	onLinkAll(r)
	detectPrefixes = func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
	}
	r.Outputs["ip -4 route get 192.168.1.1"] = "192.168.1.1 via 192.168.8.162 dev wlan0\n"
	r.Outputs["ip -4 route get 192.168.1.254"] = "192.168.1.254 via 192.168.8.162 dev wlan0\n"
	rep, err := Status(r, "/nonexistent/state.json", netip.MustParseAddr(testGW), nil)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	if !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("hairpinned prefix should be flagged FAIL:\n%s", out.String())
	}
}

// status must be safe to run unprivileged at any time.
func TestStatus_IssuesNoMutatingCommands(t *testing.T) {
	restoreDetect(t)
	inner := statusRunner(t)
	onLinkAll(inner)
	var sink bytes.Buffer
	d := DryRunner{Inner: inner, Out: &sink}
	if _, err := Status(d, "/nonexistent/state.json", netip.MustParseAddr(testGW), nil); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if strings.Contains(sink.String(), "DRY-RUN") {
		t.Fatalf("status issued a mutating command:\n%s", sink.String())
	}
}

func TestStatus_SurvivesMissingDefaultRoute(t *testing.T) {
	restoreDetect(t)
	r := statusRunner(t)
	onLinkAll(r)
	r.Outputs["ip -4 route show default"] = "\n"
	if _, err := Status(r, "/nonexistent/state.json", netip.MustParseAddr(testGW), nil); err == nil {
		t.Fatal("detection legitimately fails without a default route")
	}
}

func TestPrintStatus_ListsEveryProtectedPrefix(t *testing.T) {
	rep := StatusReport{
		Conn:  ActiveConn{ID: "c", Device: "wlan0", Type: "wifi"},
		Props: NMProps{Method: "auto"},
		Protected: []ProtectedVerdict{
			{Prefix: netip.MustParsePrefix("192.168.8.0/24"), Probe: netip.MustParseAddr("192.168.8.1")},
			{Prefix: netip.MustParsePrefix("10.99.99.0/30"), Probe: netip.MustParseAddr("10.99.99.1")},
		},
		StatePath: "/x",
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	for _, want := range []string{"192.168.8.0/24", "10.99.99.0/30", "protected LANs (2)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPrintStatus_ShowsConfirmedState(t *testing.T) {
	rep := StatusReport{
		Conn:    ActiveConn{ID: "c", Device: "wlan0"},
		Enabled: true,
		State: &State{
			Version: StateVersion, ConnectionID: "c", EnabledGateway: testGW,
			EnabledDNS: testDNS, Mode: "persistent", Confirmed: true, SavedAt: time.Now().UTC(),
		},
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	if !strings.Contains(out.String(), "confirmed") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// status runs unprivileged, and the state file is 0600 root-owned. A read
// failure must not be reported as "not enabled" while the default route is
// visibly pointing at the gateway.
func TestStatus_UnreadableStateReportsEnabledNotDisabled(t *testing.T) {
	restoreDetect(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := os.WriteFile(p, []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := statusRunner(t)
	onLinkAll(r)
	rep, err := Status(r, p, netip.MustParseAddr(testGW), nil)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !rep.Enabled {
		t.Fatal("an existing but unreadable state file means enabled, not disabled")
	}
	if rep.StateErr == nil {
		t.Fatal("StateErr should explain why the state could not be read")
	}
	var out bytes.Buffer
	PrintStatus(&out, rep)
	if !strings.Contains(out.String(), "unreadable") {
		t.Fatalf("output should say the state is unreadable:\n%s", out.String())
	}
	if strings.Contains(out.String(), "not enabled") {
		t.Fatalf("must not claim not-enabled:\n%s", out.String())
	}
}
