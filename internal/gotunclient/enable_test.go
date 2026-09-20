package gotunclient

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

func init() {
	// Keep settle() from really sleeping in tests.
	sleepFunc = func(time.Duration) {}
}

// restoreDetect puts the real interface scan back after a test swapped it.
func restoreDetect(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { detectPrefixes = DetectOnLinkPrefixes })
}

const (
	testGW    = "192.168.8.162"
	testDNS   = "192.168.8.1"
	testConn  = "MTS_GPON_2F34"
	testDev   = "wlan0"
	defRoutes = "default via 192.168.8.1 dev wlan0 metric 600\n"
	gwRoutes  = "default via 192.168.8.162 dev wlan0 proto static metric 600\n"
)

// enableRunner scripts a host where everything succeeds and the default route
// has already moved to the gotun gateway.
func enableRunner(t *testing.T) *linux.RecordingRunner {
	t.Helper()
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active"] = fixtureActive
	r.Outputs["ip -4 route show default"] = gwRoutes
	r.Outputs["nmcli -t -f "+strings.Join(nmReadFields, ",")+" connection show "+testConn] = fixtureAutoDHCP
	r.Outputs["nmcli -t -f GENERAL.STATE device show "+testDev] = "GENERAL.STATE:100 (connected)"
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaGotun
	return r
}

// onLinkAll pins the protected set to the two prefixes first_pi actually has
// and scripts every probe in them as on-link.
func onLinkAll(r *linux.RecordingRunner) {
	detectPrefixes = func() ([]netip.Prefix, error) {
		return []netip.Prefix{
			netip.MustParsePrefix("192.168.8.0/24"),
			netip.MustParsePrefix("10.99.99.0/30"),
		}, nil
	}
	r.Outputs["ip -4 route get 192.168.8.1"] = routeGetOnLink
	r.Outputs["ip -4 route get 192.168.8.254"] = routeGetUnallocated
	r.Outputs["ip -4 route get 10.99.99.1"] = routeGetLocal
	r.Outputs["ip -4 route get 10.99.99.2"] = routeGetLocal
}

func enableOpts(t *testing.T, dir string) EnableOptions {
	t.Helper()
	return EnableOptions{
		Gateway:        netip.MustParseAddr(testGW),
		DNS:            netip.MustParseAddr(testDNS),
		Probe:          netip.MustParseAddr("1.1.1.1"),
		StatePath:      filepath.Join(dir, "state.json"),
		Mode:           ApplyPersistent,
		ConfirmTimeout: 120 * time.Second,
		SettleTimeout:  time.Second,
		SelfPath:       "/usr/local/bin/gotun-client",
	}
}

func TestBuildEnableArgs_NeverDefaultAndStaticDefault(t *testing.T) {
	got := strings.Join(buildEnableArgs(EnableOptions{
		Gateway: netip.MustParseAddr(testGW),
		DNS:     netip.MustParseAddr(testDNS),
	}), "|")
	want := "ipv4.never-default|yes|+ipv4.routes|0.0.0.0/0 192.168.8.162|ipv4.ignore-auto-dns|yes|ipv4.dns|192.168.8.1|ipv6.ignore-auto-dns|yes"
	if got != want {
		t.Fatalf("argv =\n  %s\nwant\n  %s", got, want)
	}
}

// ipv4.gateway is inert under method=auto, so it must never be written.
func TestBuildEnableArgs_NeverWritesIPv4Gateway(t *testing.T) {
	for _, a := range buildEnableArgs(EnableOptions{Gateway: netip.MustParseAddr(testGW), DNS: netip.MustParseAddr(testDNS)}) {
		if a == "ipv4.gateway" {
			t.Fatal("ipv4.gateway must not be written: NM ignores it under method=auto")
		}
	}
}

func TestBuildEnableArgs_UsesPlusRoutesNotAssignment(t *testing.T) {
	args := buildEnableArgs(EnableOptions{Gateway: netip.MustParseAddr(testGW), DNS: netip.MustParseAddr(testDNS)})
	found := false
	for _, a := range args {
		if a == "ipv4.routes" {
			t.Fatal("plain ipv4.routes assignment would clobber pre-existing static routes")
		}
		if a == "+ipv4.routes" {
			found = true
		}
	}
	if !found {
		t.Fatal("want +ipv4.routes")
	}
}

// The route spec must be ONE argv element; split across two it is a usage error
// that a space-joined substring assertion would not notice.
func TestBuildEnableArgs_RouteSpecIsSingleArgument(t *testing.T) {
	args := buildEnableArgs(EnableOptions{Gateway: netip.MustParseAddr(testGW), DNS: netip.MustParseAddr(testDNS)})
	for i, a := range args {
		if a == "+ipv4.routes" {
			if args[i+1] != "0.0.0.0/0 192.168.8.162" {
				t.Fatalf("route spec = %q, want one element %q", args[i+1], "0.0.0.0/0 192.168.8.162")
			}
			return
		}
	}
	t.Fatal("+ipv4.routes not found")
}

func TestBuildRestoreArgs_ClearsUnsetPropertiesWithEmptyString(t *testing.T) {
	saved, _ := parseNMProps(fixtureAutoDHCP)
	got := strings.Join(buildRestoreArgs(saved), "|")
	want := "ipv4.never-default|no|ipv4.routes||ipv4.route-metric||ipv4.ignore-auto-dns|no|ipv4.dns||ipv6.ignore-auto-dns|no"
	if got != want {
		t.Fatalf("argv =\n  %s\nwant\n  %s", got, want)
	}
}

func TestBuildRestoreArgs_RestoresSetProperties(t *testing.T) {
	saved, _ := parseNMProps(fixtureManualRoutes)
	got := strings.Join(buildRestoreArgs(saved), "|")
	if !strings.Contains(got, "ipv4.routes|10.97.0.0/16 10.98.0.1 300, 10.96.0.0/16 10.98.0.1") {
		t.Fatalf("routes not restored verbatim: %s", got)
	}
	if !strings.Contains(got, "ipv4.route-metric|250") || !strings.Contains(got, "ipv4.never-default|yes") {
		t.Fatalf("argv = %s", got)
	}
}

func TestEnable_SnapshotWrittenBeforeAnyMutation(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v\n%s", err, out.String())
	}
	joined := strings.Join(r.Calls, "\n")
	modifyIdx := strings.Index(joined, "connection modify")
	armIdx := strings.Index(joined, "systemd-run")
	if armIdx < 0 || modifyIdx < 0 {
		t.Fatalf("expected both arming and modify:\n%s", joined)
	}
	if armIdx > modifyIdx {
		t.Fatal("rollback must be armed BEFORE the connection is modified")
	}
}

func TestEnable_ArmsRollbackBeforeConnectionUp(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	var out bytes.Buffer
	if err := Enable(r, &out, enableOpts(t, dir)); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(r.Calls, "\n")
	if strings.Index(joined, "systemd-run") > strings.Index(joined, "connection up") {
		t.Fatalf("arming must precede connection up:\n%s", joined)
	}
}

func TestEnable_ArmRollbackPassesSelfPathAndStatePath(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	var armed string
	for _, c := range r.Calls {
		if strings.HasPrefix(c, "systemd-run") {
			armed = c
		}
	}
	for _, want := range []string{"--on-active=120s", "--unit=" + rollbackUnit, "/usr/local/bin/gotun-client disable -state " + o.StatePath} {
		if !strings.Contains(armed, want) {
			t.Fatalf("armed call %q missing %q", armed, want)
		}
	}
}

func TestEnable_WritesStateFileWithSnapshot(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	st, err := LoadState(o.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if st.Saved.Method != "auto" || st.Saved.Routes != nil || st.Saved.NeverDefault {
		t.Fatalf("snapshot should be the pre-change config: %+v", st.Saved)
	}
	if st.EnabledGateway != testGW || st.ConnectionID != testConn {
		t.Fatalf("state = %+v", st)
	}
}

func TestEnable_RefusesWhenAlreadyEnabled(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("first Enable: %v", err)
	}
	err := Enable(r, &out, o)
	if err == nil || !strings.Contains(err.Error(), "already enabled") {
		t.Fatalf("second Enable should refuse, got %v", err)
	}
}

// The dangerous one: a -force that re-snapshotted would record the ENABLED
// config as the original, turning disable into a no-op with no way back.
func TestEnable_ForceReusesOriginalSnapshot(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("first Enable: %v", err)
	}
	// Now the host reads back as already-modified.
	r.Outputs["nmcli -t -f "+strings.Join(nmReadFields, ",")+" connection show "+testConn] =
		"ipv4.method:auto\nipv4.gateway:\nipv4.dns:192.168.8.1\nipv4.ignore-auto-dns:yes\nipv4.never-default:yes\nipv4.routes:0.0.0.0/0 192.168.8.162\nipv4.route-metric:-1\nipv6.ignore-auto-dns:yes"
	o.Force = true
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("forced Enable: %v", err)
	}
	st, err := LoadState(o.StatePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if st.Saved.NeverDefault || st.Saved.Routes != nil || st.Saved.IgnoreAutoDNS {
		t.Fatalf("-force must keep the ORIGINAL snapshot, got %+v", st.Saved)
	}
}

func TestEnable_RefusesUnsupportedMethod(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["nmcli -t -f "+strings.Join(nmReadFields, ",")+" connection show "+testConn] = "ipv4.method:shared\n"
	var out bytes.Buffer
	err := Enable(r, &out, enableOpts(t, dir))
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("want refusal for method=shared, got %v", err)
	}
}

func TestEnable_RefusesPreexistingRoutesWithoutForce(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["nmcli -t -f "+strings.Join(nmReadFields, ",")+" connection show "+testConn] = fixtureManualRoutes
	var out bytes.Buffer
	err := Enable(r, &out, enableOpts(t, dir))
	if err == nil || !strings.Contains(err.Error(), "already set") {
		t.Fatalf("want refusal for pre-existing routes, got %v", err)
	}
}

func TestEnable_ModifyFailureRollsBackAndRemovesState(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.FailOn = "ipv4.never-default yes"
	o := enableOpts(t, dir)
	var out bytes.Buffer
	err := Enable(r, &out, o)
	if err == nil {
		t.Fatal("want failure")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if StateExists(o.StatePath) {
		t.Fatal("state file should be removed after a successful rollback")
	}
}

func TestEnable_LANSafetyFailureRollsBackAndNamesPrefix(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	o.ExtraLANs = []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")}
	r.Outputs["ip -4 route get 192.168.77.1"] = "192.168.77.1 via 192.168.8.162 dev wlan0\n"
	r.Outputs["ip -4 route get 192.168.77.254"] = "192.168.77.254 via 192.168.8.162 dev wlan0\n"
	var out bytes.Buffer
	err := Enable(r, &out, o)
	if err == nil {
		t.Fatal("want LAN-safety failure")
	}
	if !strings.Contains(err.Error(), "192.168.77.0/24") {
		t.Fatalf("error should name the offending prefix: %v", err)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "connection modify "+testConn+" ipv4.never-default no") {
		t.Fatalf("expected a restore modify in:\n%s", strings.Join(r.Calls, "\n"))
	}
	if StateExists(o.StatePath) {
		t.Fatal("state should be removed after rollback")
	}
}

func TestEnable_DefaultRouteNotMovedRollsBack(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	o := enableOpts(t, dir)
	var out bytes.Buffer
	err := Enable(r, &out, o)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback when the default route did not move, got %v", err)
	}
}

func TestEnable_TwoDefaultRoutesRollsBack(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["ip -4 route show default"] = "default via 192.168.8.162 dev wlan0 proto static metric 100\n" +
		"default via 192.168.8.1 dev eth0 metric 600\n"
	o := enableOpts(t, dir)
	var out bytes.Buffer
	err := Enable(r, &out, o)
	if err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Fatalf("want rollback on a competing default route, got %v", err)
	}
}

func TestEnable_RollbackDisarmsTimer(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	var out bytes.Buffer
	_ = Enable(r, &out, enableOpts(t, dir))
	if !strings.Contains(strings.Join(r.Calls, "\n"), "systemctl stop "+rollbackUnit+".timer") {
		t.Fatalf("rollback should disarm the timer:\n%s", strings.Join(r.Calls, "\n"))
	}
}

// A rollback failure must never hide the reason we rolled back, and must leave
// the timer armed as the last line of defence.
func TestEnable_RollbackFailureReportsBothErrorsAndKeepsTimer(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	r.Errors["nmcli connection modify "+testConn+" ipv4.never-default no ipv4.routes  ipv4.route-metric  ipv4.ignore-auto-dns no ipv4.dns  ipv6.ignore-auto-dns no"] =
		errFake("restore exploded")
	o := enableOpts(t, dir)
	var out bytes.Buffer
	err := Enable(r, &out, o)
	if err == nil {
		t.Fatal("want failure")
	}
	msg := err.Error()
	if !strings.Contains(msg, "192.168.8.1") {
		t.Errorf("original cause missing from %q", msg)
	}
	if !strings.Contains(msg, "ROLLBACK ALSO FAILED") {
		t.Errorf("rollback failure missing from %q", msg)
	}
	if strings.Contains(strings.Join(r.Calls, "\n"), "systemctl stop") {
		t.Error("timer must stay armed when rollback failed")
	}
	if !StateExists(o.StatePath) {
		t.Error("state must be kept so a retry is possible")
	}
}

func TestEnable_ZeroConfirmTimeoutSkipsArmingAndWarns(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	o.ConfirmTimeout = 0
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if strings.Contains(strings.Join(r.Calls, "\n"), "systemd-run") {
		t.Fatal("no timer should be armed")
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("want a warning, got %q", out.String())
	}
}

func TestEnable_PrintsConfirmBanner(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	var out bytes.Buffer
	if err := Enable(r, &out, enableOpts(t, dir)); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !strings.Contains(out.String(), "ARMED") || !strings.Contains(out.String(), "gotun-client confirm") {
		t.Fatalf("banner should name the confirm command, got:\n%s", out.String())
	}
}

func TestEnable_DeviceModeUsesDeviceModifyAndNoConnectionUp(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	o.Mode = ApplyDevice
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "nmcli device modify "+testDev+" ipv4.never-default yes") {
		t.Fatalf("want device modify:\n%s", joined)
	}
	if strings.Contains(joined, "connection up") {
		t.Fatal("device mode must not bounce the link")
	}
}

func TestEnable_TemporaryModeUsesTemporaryFlag(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	o := enableOpts(t, dir)
	o.Mode = ApplyTemporary
	var out bytes.Buffer
	if err := Enable(r, &out, o); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "connection modify --temporary "+testConn) {
		t.Fatalf("want --temporary:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestEnable_DeviceModeRollsBackWithReapply(t *testing.T) {
	dir := t.TempDir()
	r := enableRunner(t)
	restoreDetect(t)
	onLinkAll(r)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	o := enableOpts(t, dir)
	o.Mode = ApplyDevice
	var out bytes.Buffer
	if err := Enable(r, &out, o); err == nil {
		t.Fatal("want failure")
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "nmcli device reapply "+testDev) {
		t.Fatalf("device mode should roll back via reapply:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestSettle_TimesOutWhenNeverConnected(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f GENERAL.STATE device show wlan0"] = "GENERAL.STATE:30 (disconnected)"
	if err := settle(r, "wlan0", 10*time.Millisecond); err == nil {
		t.Fatal("want timeout")
	}
}

func TestSettle_PassesWhenConnectedWithDefaultRoute(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f GENERAL.STATE device show wlan0"] = "GENERAL.STATE:100 (connected)"
	r.Outputs["ip -4 route show default"] = defRoutes
	if err := settle(r, "wlan0", time.Second); err != nil {
		t.Fatalf("settle: %v", err)
	}
}

func TestSettle_ConnectedButNoDefaultRouteTimesOut(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f GENERAL.STATE device show wlan0"] = "GENERAL.STATE:100 (connected)"
	r.Outputs["ip -4 route show default"] = "\n"
	err := settle(r, "wlan0", 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("err = %v", err)
	}
}

func disableState(t *testing.T, dir string, saved NMProps, mode ApplyMode) string {
	t.Helper()
	p := filepath.Join(dir, "state.json")
	st := &State{
		Version: StateVersion, ConnectionID: testConn, Device: testDev,
		Saved: saved, EnabledGateway: testGW, EnabledDNS: testDNS,
		Mode: string(mode), SelfPath: "/usr/local/bin/gotun-client",
		SavedAt: time.Now().UTC(), ArmUnit: rollbackUnit,
	}
	if err := SaveState(p, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	return p
}

func disableRunner(t *testing.T) *linux.RecordingRunner {
	t.Helper()
	r := linux.NewRecordingRunner()
	r.Outputs["nmcli -t -f GENERAL.STATE device show "+testDev] = "GENERAL.STATE:100 (connected)"
	r.Outputs["ip -4 route show default"] = defRoutes
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	return r
}

func TestDisable_RestoresClearingUnsetProperties(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := disableRunner(t)
	var out bytes.Buffer
	if err := Disable(r, &out, p); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	want := "nmcli connection modify " + testConn + " ipv4.never-default no ipv4.routes  ipv4.route-metric  ipv4.ignore-auto-dns no ipv4.dns  ipv6.ignore-auto-dns no"
	if !strings.Contains(strings.Join(r.Calls, "\n"), want) {
		t.Fatalf("want restore call\n  %s\ngot\n%s", want, strings.Join(r.Calls, "\n"))
	}
	if StateExists(p) {
		t.Fatal("state file should be removed")
	}
}

func TestDisable_DisarmsRollbackTimer(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := disableRunner(t)
	var out bytes.Buffer
	if err := Disable(r, &out, p); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "systemctl stop "+rollbackUnit+".timer") {
		t.Fatalf("want the timer stopped:\n%s", strings.Join(r.Calls, "\n"))
	}
}

// Still routing via the gotun gateway after a restore means the restore did not
// take -- keep the state so a retry is possible.
func TestDisable_KeepsStateWhenDefaultStillViaGateway(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := disableRunner(t)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaGotun
	var out bytes.Buffer
	err := Disable(r, &out, p)
	if err == nil || !strings.Contains(err.Error(), "still routes via") {
		t.Fatalf("err = %v", err)
	}
	if !StateExists(p) {
		t.Fatal("state must be kept for a retry")
	}
}

func TestDisable_RestoreFailureKeepsState(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := disableRunner(t)
	r.FailOn = "connection modify"
	var out bytes.Buffer
	if err := Disable(r, &out, p); err == nil {
		t.Fatal("want failure")
	}
	if !StateExists(p) {
		t.Fatal("state must be kept for a retry")
	}
}

func TestDisable_DeviceModeUsesReapply(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyDevice)
	r := disableRunner(t)
	var out bytes.Buffer
	if err := Disable(r, &out, p); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "nmcli device reapply "+testDev) {
		t.Fatalf("want reapply:\n%s", strings.Join(r.Calls, "\n"))
	}
}

func TestDisable_MissingStateErrors(t *testing.T) {
	var out bytes.Buffer
	if err := Disable(disableRunner(t), &out, filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("want error for a missing state file")
	}
}

func TestConfirm_StopsTimerAndMarksConfirmed(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	r := linux.NewRecordingRunner()
	var out bytes.Buffer
	if err := Confirm(r, &out, p); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !strings.Contains(strings.Join(r.Calls, "\n"), "systemctl stop "+rollbackUnit+".timer") {
		t.Fatalf("want the timer stopped:\n%s", strings.Join(r.Calls, "\n"))
	}
	st, err := LoadState(p)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !st.Confirmed {
		t.Fatal("state should be marked confirmed")
	}
}

func TestConfirm_SecondCallIsNoop(t *testing.T) {
	dir := t.TempDir()
	saved, _ := parseNMProps(fixtureAutoDHCP)
	p := disableState(t, dir, saved, ApplyPersistent)
	var out bytes.Buffer
	if err := Confirm(linux.NewRecordingRunner(), &out, p); err != nil {
		t.Fatalf("first Confirm: %v", err)
	}
	r := linux.NewRecordingRunner()
	if err := Confirm(r, &out, p); err != nil {
		t.Fatalf("second Confirm: %v", err)
	}
	if len(r.Calls) != 0 {
		t.Fatalf("second confirm should issue no commands, got %q", r.Calls)
	}
}

func TestConfirm_MissingStateErrors(t *testing.T) {
	var out bytes.Buffer
	if err := Confirm(linux.NewRecordingRunner(), &out, filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("want error")
	}
}

func TestParseApplyMode(t *testing.T) {
	for _, s := range []string{"device", "temporary", "persistent"} {
		if _, err := ParseApplyMode(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := ParseApplyMode("metric"); err == nil {
		t.Error("want error for an unknown mode")
	}
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }
func errFake(s string) error    { return fakeErr(s) }

func TestDetach_DeviceModeNeverDetaches(t *testing.T) {
	r := linux.NewRecordingRunner()
	var out bytes.Buffer
	handed, err := detach(r, &out, EnableOptions{Detach: true, Mode: ApplyDevice, SelfPath: "/x"})
	if err != nil || handed {
		t.Fatalf("device mode does not bounce the link, so must not detach (handed=%v err=%v)", handed, err)
	}
	if len(r.Calls) != 0 {
		t.Fatalf("no commands expected, got %q", r.Calls)
	}
}

func TestDetach_PersistentModeReexecsUnderSystemd(t *testing.T) {
	r := linux.NewRecordingRunner()
	var out bytes.Buffer
	o := EnableOptions{
		Detach: true, Mode: ApplyPersistent, SelfPath: "/usr/local/bin/gotun-client",
		Args: []string{"-apply-mode", "persistent", "-confirm-timeout", "120s"},
	}
	handed, err := detach(r, &out, o)
	if err != nil || !handed {
		t.Fatalf("handed=%v err=%v", handed, err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "systemd-run --collect --unit="+enableUnit) {
		t.Fatalf("want a transient unit:\n%s", joined)
	}
	// The child must not detach again, or it re-execs forever.
	if !strings.Contains(joined, "-detach=false") {
		t.Fatalf("child must be told not to detach:\n%s", joined)
	}
	if !strings.Contains(joined, "-apply-mode persistent") {
		t.Fatalf("original flags must be replayed:\n%s", joined)
	}
}

func TestDetach_FallsBackInlineWithoutSystemd(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "test -d /run/systemd/system"
	var out bytes.Buffer
	handed, err := detach(r, &out, EnableOptions{Detach: true, Mode: ApplyPersistent, SelfPath: "/x"})
	if err != nil || handed {
		t.Fatalf("should fall back to inline, got handed=%v err=%v", handed, err)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Fatalf("want a warning about running inline, got %q", out.String())
	}
}

func TestDetach_DryRunDoesNotDetach(t *testing.T) {
	r := linux.NewRecordingRunner()
	var out bytes.Buffer
	handed, _ := detach(r, &out, EnableOptions{Detach: true, Mode: ApplyPersistent, DryRun: true, SelfPath: "/x"})
	if handed {
		t.Fatal("a dry run must stay inline so it can print the plan")
	}
}

func TestDetach_DisabledRunsInline(t *testing.T) {
	r := linux.NewRecordingRunner()
	var out bytes.Buffer
	handed, _ := detach(r, &out, EnableOptions{Detach: false, Mode: ApplyPersistent, SelfPath: "/x"})
	if handed {
		t.Fatal("-detach=false must run inline")
	}
}
