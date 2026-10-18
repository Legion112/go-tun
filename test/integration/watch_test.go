//go:build integration

package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestWatch_DeadTunnelFallsBackAndRecovers is the property the 22 Sep outage
// exposed: a tunnel that is up but carrying nothing keeps its route and swallows
// every packet, with nothing watching. Here the watchdog notices and withdraws
// the route so traffic falls back to the uplink, then restores it.
//
// The failure is induced by dropping the tunnel's own underlay packets rather
// than downing the link, because link-down is the easy case the kernel already
// handles -- up-but-dead is the one that went unnoticed for an entire outage.
func TestWatch_DeadTunnelFallsBackAndRecovers(t *testing.T) {
	tp := setupTopo(t)
	ctx := context.Background()

	// Probe a destination only the tunnel can reach, bound to the tunnel device.
	must(t, tp.lab.ExecOK(ctx, "gotun", "sh", "-c",
		"gotun watch -prefixes /tmp/ru.txt -non-routable "+labNonRoutable+
			" -endpoint 10.20.0.3 -lan 10.10.0.0/24,10.20.0.0/24,10.200.0.0/24"+
			" -wg-config /tmp/wg-exit.conf -fail-mode open"+
			" -probe-target 10.30.0.10:8080 -probe-interval 2s -probe-timeout 2s"+
			" -fail-after 2 -recover-after 1 -cooldown 0"+
			" > /tmp/watch.log 2>&1 &"))
	t.Cleanup(func() { _, _ = tp.lab.Exec(context.Background(), "gotun", "killall", "gotun") })

	waitFor(t, tp, "baseline: foreign reachable through the tunnel", func() bool {
		out, _ := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "3", "http://10.30.0.10:8080/id")
		return strings.TrimSpace(out) == "FOREIGN"
	})

	// Up but dead: the interface stays up, the underlay is black-holed.
	must(t, tp.lab.ExecOK(ctx, "gotun", "sh", "-c",
		"nft add table inet cut; "+
			"nft 'add chain inet cut out { type filter hook output priority 0 ; policy accept ; }'; "+
			"nft add rule inet cut out udp dport 51820 drop"))

	waitFor(t, tp, "watchdog withdraws the route and traffic falls back to the uplink", func() bool {
		rt, _ := tp.lab.Exec(ctx, "gotun", "ip", "route", "show", "table", "100")
		if strings.TrimSpace(rt) != "" {
			return false
		}
		out, _ := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "3", "http://10.30.0.10:8080/id")
		return strings.TrimSpace(out) == "FOREIGN"
	})

	// The interface must never have been forced down: that is what lets the
	// transport re-establish itself.
	link, err := tp.lab.Exec(ctx, "gotun", "ip", "link", "show", "dev", "wg-exit")
	if err != nil || !strings.Contains(link, "UP") {
		t.Fatalf("wg-exit must stay up so it can recover, got %q (%v)", link, err)
	}

	must(t, tp.lab.ExecOK(ctx, "gotun", "nft", "delete", "table", "inet", "cut"))

	waitFor(t, tp, "watchdog restores the tunnel route once the probe succeeds again", func() bool {
		rt, _ := tp.lab.Exec(ctx, "gotun", "ip", "route", "show", "table", "100")
		return strings.Contains(rt, "wg-exit")
	})
}

// waitFor polls until cond holds, so the test tracks the watchdog's own cadence
// instead of guessing a single sleep long enough to be flaky.
func waitFor(t *testing.T, tp *topo, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Second)
	}
	logs, _ := tp.lab.Exec(context.Background(), "gotun", "cat", "/tmp/watch.log")
	t.Fatalf("timed out waiting for %s\nwatch log:\n%s", what, logs)
}
