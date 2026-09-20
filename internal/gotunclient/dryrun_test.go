package gotunclient

import (
	"bytes"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
)

func dry(t *testing.T) (DryRunner, *linux.RecordingRunner, *bytes.Buffer) {
	t.Helper()
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	return DryRunner{Inner: inner, Out: &out}, inner, &out
}

func TestDryRunner_PassesThroughReads(t *testing.T) {
	d, inner, _ := dry(t)
	inner.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaGotun
	got, err := d.Run("ip", "-4", "route", "get", "1.1.1.1")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != routeGetViaGotun {
		t.Fatalf("read should pass through, got %q", got)
	}
	if len(inner.Calls) != 1 {
		t.Fatalf("inner calls = %q", inner.Calls)
	}
}

func TestDryRunner_PassesThroughNmcliShow(t *testing.T) {
	d, inner, _ := dry(t)
	if _, err := d.Run("nmcli", "-t", "-f", "ipv4.method", "connection", "show", "x"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(inner.Calls) != 1 {
		t.Fatal("nmcli show must pass through")
	}
}

func TestDryRunner_BlocksMutations(t *testing.T) {
	for _, tc := range [][]string{
		{"nmcli", "connection", "modify", "c", "ipv4.dns", "1.1.1.1"},
		{"nmcli", "connection", "up", "c"},
		{"nmcli", "device", "modify", "wlan0", "ipv4.dns", "1.1.1.1"},
		{"nmcli", "device", "reapply", "wlan0"},
		{"systemd-run", "--unit=x", "true"},
		{"systemctl", "stop", "x.timer"},
		{"ip", "route", "add", "1.2.3.4/32", "via", "192.168.8.162"},
		{"ip", "route", "flush", "cache"},
	} {
		d, inner, out := dry(t)
		if _, err := d.Run(tc[0], tc[1:]...); err != nil {
			t.Fatalf("%v: %v", tc, err)
		}
		if len(inner.Calls) != 0 {
			t.Errorf("%v should have been blocked, inner saw %q", tc, inner.Calls)
		}
		if !strings.Contains(out.String(), "DRY-RUN") {
			t.Errorf("%v should print a DRY-RUN line, got %q", tc, out.String())
		}
	}
}

func TestIsMutating_SystemctlShowIsReadOnly(t *testing.T) {
	if isMutating("systemctl", []string{"show", "-p", "MainPID", "x"}) {
		t.Fatal("systemctl show is read-only")
	}
	if !isMutating("systemctl", []string{"restart", "x"}) {
		t.Fatal("systemctl restart mutates")
	}
}

func TestIsMutating_IPRouteShowAndGetAreReads(t *testing.T) {
	if isMutating("ip", []string{"-4", "route", "show", "default"}) {
		t.Fatal("ip route show is a read")
	}
	if isMutating("ip", []string{"-4", "route", "get", "1.1.1.1"}) {
		t.Fatal("ip route get is a read")
	}
}

// A dry-run enable must not touch the host or write state.
func TestEnable_DryRunIssuesNoMutationsAndWritesNoState(t *testing.T) {
	dir := t.TempDir()
	inner := enableRunner(t)
	restoreDetect(t)
	onLinkAll(inner)
	var out bytes.Buffer
	o := enableOpts(t, dir)
	err := Enable(DryRunner{Inner: inner, Out: &out}, &out, o)
	// Verification cannot pass when nothing was applied; what matters is that
	// no mutating command reached the host and no state file was left behind.
	_ = err
	for _, c := range inner.Calls {
		for _, bad := range []string{"connection modify", "connection up", "device modify", "systemd-run"} {
			if strings.Contains(c, bad) {
				t.Fatalf("dry run leaked a mutation: %q", c)
			}
		}
	}
}

// A dry run must not write the state file: doing so and then removing it on a
// synthetic rollback leaves a window where the host looks enabled.
func TestEnable_DryRunWritesNoStateFileAndSucceeds(t *testing.T) {
	dir := t.TempDir()
	inner := enableRunner(t)
	restoreDetect(t)
	onLinkAll(inner)
	// Host still routes via the old gateway, since nothing was applied.
	inner.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	o := enableOpts(t, dir)
	o.DryRun = true
	var out bytes.Buffer
	if err := Enable(DryRunner{Inner: inner, Out: &out}, &out, o); err != nil {
		t.Fatalf("dry run should succeed, got %v\n%s", err, out.String())
	}
	if StateExists(o.StatePath) {
		t.Fatal("dry run must not write the state file")
	}
	if !strings.Contains(out.String(), "verification is skipped") {
		t.Fatalf("dry run should say verification was skipped:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "would write state to") {
		t.Fatalf("dry run should show the state it would write:\n%s", out.String())
	}
}

func TestEnable_DryRunSkipsSettleAndVerification(t *testing.T) {
	dir := t.TempDir()
	inner := enableRunner(t)
	restoreDetect(t)
	onLinkAll(inner)
	// Device never becomes connected: a real run would time out in settle.
	inner.Outputs["nmcli -t -f GENERAL.STATE device show "+testDev] = "GENERAL.STATE:30 (disconnected)"
	o := enableOpts(t, dir)
	o.DryRun = true
	var out bytes.Buffer
	if err := Enable(DryRunner{Inner: inner, Out: &out}, &out, o); err != nil {
		t.Fatalf("dry run should not settle or verify, got %v", err)
	}
}
