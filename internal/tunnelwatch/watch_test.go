package tunnelwatch_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/tunnelwatch"
)

// fakeProbe answers from a queue so a test can script a sequence of ticks.
type fakeProbe struct {
	errs   []error
	calls  []string
	cursor int
}

func (f *fakeProbe) Probe(_ context.Context, iface, target string, _ time.Duration) error {
	f.calls = append(f.calls, iface+" -> "+target)
	if f.cursor >= len(f.errs) {
		if len(f.errs) == 0 {
			return nil
		}
		return f.errs[len(f.errs)-1]
	}
	err := f.errs[f.cursor]
	f.cursor++
	return err
}

func upRunner() *linux.RecordingRunner {
	r := linux.NewRecordingRunner()
	r.Outputs["ip link show dev xray0"] = "9: xray0: <POINTOPOINT,UP,LOWER_UP> mtu 1400"
	// The kernel agrees with the loop's belief: the tunnel route is installed.
	r.Outputs["ip -4 route show table 100"] = "default dev xray0 scope link metric 10"
	return r
}

type applyLog struct{ ups []bool }

func (a *applyLog) apply(_ context.Context, up bool) error {
	a.ups = append(a.ups, up)
	return nil
}

func newWatcher(r linux.Runner, p tunnelwatch.Prober, a *applyLog, cfg tunnelwatch.Config) *tunnelwatch.Watcher {
	cfg.Iface, cfg.Target = "xray0", "1.1.1.1:443"
	return tunnelwatch.New(r, p, a.apply, cfg, log.New(io.Discard, "", 0))
}

func TestWatch_HealthyTunnelChangesNothing(t *testing.T) {
	a := &applyLog{}
	w := newWatcher(upRunner(), &fakeProbe{}, a, tunnelwatch.Config{})
	for i := 0; i < 5; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 0 {
		t.Fatalf("a healthy tunnel must not be re-applied: %v", a.ups)
	}
	if !w.TunnelUp() {
		t.Fatal("belief should still be up")
	}
}

// The debounce exists so one slow probe does not cost the house its geo-routing.
func TestWatch_SingleFailureDoesNotFailOver(t *testing.T) {
	a := &applyLog{}
	p := &fakeProbe{errs: []error{errors.New("timeout"), nil, nil}}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{FailAfter: 3})
	for i := 0; i < 3; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 0 {
		t.Fatalf("one failure must not trigger failover: %v", a.ups)
	}
}

func TestWatch_SustainedFailureWithdrawsTheRoute(t *testing.T) {
	a := &applyLog{}
	p := &fakeProbe{errs: []error{errors.New("timeout")}}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{FailAfter: 3})
	for i := 0; i < 3; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 1 || a.ups[0] != false {
		t.Fatalf("want exactly one apply with tunnel-up=false, got %v", a.ups)
	}
	if w.TunnelUp() {
		t.Fatal("belief should be down after failover")
	}
}

func TestWatch_RecoveryRestoresTheRoute(t *testing.T) {
	a := &applyLog{}
	p := &fakeProbe{errs: []error{
		errors.New("t"), errors.New("t"), errors.New("t"), // fail over
		nil, nil, // recover
	}}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{FailAfter: 3, RecoverAfter: 2})
	for i := 0; i < 5; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 2 || a.ups[0] != false || a.ups[1] != true {
		t.Fatalf("want down then up, got %v", a.ups)
	}
	if !w.TunnelUp() {
		t.Fatal("belief should be up again")
	}
}

// Acting on an inconclusive check is how a watchdog breaks a working network.
func TestWatch_UnknownNeverActs(t *testing.T) {
	a := &applyLog{}
	p := &fakeProbe{errs: []error{fmt.Errorf("%w: no CAP_NET_RAW", tunnelwatch.ErrProbeUnavailable)}}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{FailAfter: 1})
	for i := 0; i < 10; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 0 {
		t.Fatalf("Unknown must never trigger an apply: %v", a.ups)
	}
	if !w.TunnelUp() {
		t.Fatal("belief must be unchanged on Unknown")
	}
}

// A missing interface is the benign failure -- the kernel has already withdrawn
// the device route -- but the loop must still agree with reality.
func TestWatch_AbsentInterfaceIsUnhealthy(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Errors["ip link show dev xray0"] = errors.New(`Device "xray0" does not exist`)
	a := &applyLog{}
	w := newWatcher(r, &fakeProbe{}, a, tunnelwatch.Config{FailAfter: 1})
	w.Tick(context.Background())
	if len(a.ups) != 1 || a.ups[0] != false {
		t.Fatalf("an absent interface must fail over, got %v", a.ups)
	}
}

// A failed apply must not be recorded as success, or the loop stops retrying.
func TestWatch_FailedApplyIsRetried(t *testing.T) {
	p := &fakeProbe{errs: []error{errors.New("timeout")}}
	calls := 0
	failing := func(_ context.Context, _ bool) error { calls++; return errors.New("nft busy") }
	w := tunnelwatch.New(upRunner(), p, failing,
		tunnelwatch.Config{Iface: "xray0", Target: "t:443", FailAfter: 1},
		log.New(io.Discard, "", 0))
	w.Tick(context.Background())
	w.Tick(context.Background())
	if calls != 2 {
		t.Fatalf("a failed apply should be retried on the next tick, got %d attempts", calls)
	}
	if !w.TunnelUp() {
		t.Fatal("belief must not change when the apply failed")
	}
}

// The route can vanish underneath the loop -- the transport restarting takes its
// interface, and the device route with it -- while probes then succeed again, so
// there is no transition to act on. Without a drift check the table stays empty
// forever with everything reporting healthy: the same silent shape as the outage
// this watchdog exists to prevent.
func TestWatch_RepairsRouteLostWhileHealthy(t *testing.T) {
	r := upRunner()
	r.Outputs["ip -4 route show table 100"] = "" // route gone, belief still "up"
	a := &applyLog{}
	w := newWatcher(r, &fakeProbe{}, a, tunnelwatch.Config{})
	w.Tick(context.Background())
	if len(a.ups) != 1 || a.ups[0] != true {
		t.Fatalf("a missing route under a healthy tunnel must be re-applied, got %v", a.ups)
	}
}

// And it must stay quiet when the kernel already agrees, or it re-applies the
// whole policy every minute forever.
func TestWatch_NoRepairWhenKernelAgrees(t *testing.T) {
	a := &applyLog{}
	w := newWatcher(upRunner(), &fakeProbe{}, a, tunnelwatch.Config{})
	for i := 0; i < 5; i++ {
		w.Tick(context.Background())
	}
	if len(a.ups) != 0 {
		t.Fatalf("no re-apply expected when the route is present: %v", a.ups)
	}
}

func TestWatch_BounceIsOffByDefault(t *testing.T) {
	r := upRunner()
	a := &applyLog{}
	p := &fakeProbe{errs: []error{errors.New("timeout")}}
	w := newWatcher(r, p, a, tunnelwatch.Config{FailAfter: 1})
	for i := 0; i < 5; i++ {
		w.Tick(context.Background())
	}
	if strings.Contains(strings.Join(r.Calls, "\n"), "ip link set dev xray0 down") {
		t.Fatalf("bounce must be opt-in; another daemon may own the interface:\n%v", r.Calls)
	}
}

// The probe must name the tunnel device, since that is what makes it immune to
// the route having been withdrawn.
func TestWatch_ProbeTargetsTheTunnelDevice(t *testing.T) {
	p := &fakeProbe{}
	a := &applyLog{}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{})
	w.Tick(context.Background())
	if len(p.calls) != 1 || !strings.HasPrefix(p.calls[0], "xray0 -> ") {
		t.Fatalf("probe must be bound to the tunnel interface, got %v", p.calls)
	}
}

// --- Reapply -----------------------------------------------------------------

// A poke must re-apply without probing.
//
// The distinction is the whole point. A poke means a device the policy depends
// on has just changed -- an ifup of the tunnel -- so what is wanted is the
// policy put back the way the loop already believes it should be. Probing
// instead would ask a question nobody asked, and would get the wrong answer at
// exactly the moment an ifup fires: the device is up but not yet carrying
// traffic.
func TestWatch_ReapplyDoesNotProbe(t *testing.T) {
	a := &applyLog{}
	p := &fakeProbe{}
	w := newWatcher(upRunner(), p, a, tunnelwatch.Config{Interval: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()

	w.Reapply()
	waitFor(t, func() bool { return len(a.ups) == 1 })

	cancel()
	<-done

	if len(p.calls) != 0 {
		t.Errorf("Reapply probed %v; it must re-assert the current belief, not re-decide it",
			p.calls)
	}
	if len(a.ups) != 1 || !a.ups[0] {
		t.Errorf("applies were %v, want exactly one at tunnel-up=true", a.ups)
	}
}

// The belief is re-asserted, not reset. A poke arriving while the route is
// withdrawn must not quietly restore it: the tunnel is still dead, and putting
// traffic back into it is the outage this watchdog exists to prevent.
func TestWatch_ReapplyKeepsAWithdrawnRouteWithdrawn(t *testing.T) {
	a := &applyLog{}
	r := upRunner()
	r.Errors["ip link show dev xray0"] = errors.New(`Cannot find device "xray0"`)
	w := newWatcher(r, &fakeProbe{}, a, tunnelwatch.Config{FailAfter: 1, Interval: time.Hour})

	// One tick with the device absent withdraws the route.
	w.Tick(context.Background())
	if len(a.ups) != 1 || a.ups[0] {
		t.Fatalf("precondition: want one apply at tunnel-up=false, got %v", a.ups)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	w.Reapply()
	waitFor(t, func() bool { return len(a.ups) == 2 })
	cancel()
	<-done

	if a.ups[1] {
		t.Error("the poke re-applied at tunnel-up=true while the tunnel was known dead," +
			" putting traffic back into a tunnel that swallows it")
	}
}

// Several ifups arriving together are one request. Without this a flapping
// interface would queue a re-apply per event and the loop would spend its time
// rebuilding the ruleset.
func TestWatch_ReapplyCoalesces(t *testing.T) {
	a := &applyLog{}
	w := newWatcher(upRunner(), &fakeProbe{}, a, tunnelwatch.Config{Interval: time.Hour})

	// Nothing is reading the channel yet, so these all land on a buffer of one.
	for i := 0; i < 50; i++ {
		w.Reapply()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	waitFor(t, func() bool { return len(a.ups) >= 1 })
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if len(a.ups) != 1 {
		t.Errorf("50 pokes produced %d applies, want 1", len(a.ups))
	}
}

// Reapply must never block, whatever the loop is doing -- a hotplug handler
// waiting on a busy watchdog is a netifd event handler that does not return.
func TestWatch_ReapplyNeverBlocks(t *testing.T) {
	a := &applyLog{}
	w := newWatcher(upRunner(), &fakeProbe{}, a, tunnelwatch.Config{Interval: time.Hour})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			w.Reapply() // no loop running at all: the buffer fills and stays full
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reapply blocked with no loop running")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the loop to act")
}
