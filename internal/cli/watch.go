package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/tunnelwatch"
)

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	f := registerApplyFlags(fs)
	probeTarget := fs.String("probe-target", "1.1.1.1:443",
		"host:port to connect to through the tunnel to prove it carries traffic")
	probeInterval := fs.Duration("probe-interval", tunnelwatch.DefaultInterval, "how often to probe")
	probeTimeout := fs.Duration("probe-timeout", tunnelwatch.DefaultTimeout, "per-probe connect timeout")
	failAfter := fs.Int("fail-after", tunnelwatch.DefaultFailAfter,
		"consecutive failed probes before the tunnel route is withdrawn")
	recoverAfter := fs.Int("recover-after", tunnelwatch.DefaultRecoverAfter,
		"consecutive successful probes before the tunnel route is restored")
	cooldown := fs.Duration("cooldown", tunnelwatch.DefaultCooldown,
		"minimum gap between route transitions, bounding how fast the route can flap; 0 disables")
	bounceAfter := fs.Duration("bounce-after", 0,
		"recreate the tunnel interface once it has been dead this long; 0 disables."+
			" Leave it disabled whenever another daemon owns the interface (sing-box, netifd):"+
			" bouncing a tun out from under its owner breaks the transport being recovered")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o, err := f.options()
	if err != nil {
		return err
	}
	return Watch(WatchOptions{
		Apply:        o,
		ProbeTarget:  strings.TrimSpace(*probeTarget),
		Interval:     *probeInterval,
		Timeout:      *probeTimeout,
		FailAfter:    *failAfter,
		RecoverAfter: *recoverAfter,
		Cooldown:     *cooldown,
		BounceAfter:  *bounceAfter,
	})
}

// WatchOptions configures the watch daemon.
type WatchOptions struct {
	Apply        ApplyOptions
	ProbeTarget  string
	Interval     time.Duration
	Timeout      time.Duration
	FailAfter    int
	RecoverAfter int
	Cooldown     time.Duration
	BounceAfter  time.Duration
}

// Watch applies the policy once and then keeps table 100 honest about whether
// the tunnel is actually carrying traffic.
//
// It re-applies through the same Apply path rather than a separate code path, so
// a failover cannot produce a policy that differs from what `apply` would have
// installed -- and a prefix-list update is picked up at the next transition.
func Watch(o WatchOptions) error {
	if o.Apply.DryRun {
		return fmt.Errorf("-dry-run makes no sense for watch: it would never change anything")
	}
	lg := log.New(os.Stderr, "gotun watch: ", log.LstdFlags)

	// Converge once up front, exactly as the old one-shot service did, so the
	// box is in policy before the first probe interval elapses.
	initial := o.Apply
	initial.TunnelUp = true
	if err := Apply(initial); err != nil {
		return fmt.Errorf("initial apply: %w", err)
	}

	apply := func(_ context.Context, up bool) error {
		next := o.Apply
		next.TunnelUp = up
		return Apply(next)
	}

	iface := o.Apply.TunnelIface
	if iface == "" {
		iface = policy.DefaultTunnelIface
	}
	w := tunnelwatch.New(linux.ExecRunner{}, tunnelwatch.DeviceDialer{}, apply, tunnelwatch.Config{
		Iface:        iface,
		Target:       o.ProbeTarget,
		Interval:     o.Interval,
		Timeout:      o.Timeout,
		FailAfter:    o.FailAfter,
		RecoverAfter: o.RecoverAfter,
		Cooldown:     o.Cooldown,
		BounceAfter:  o.BounceAfter,
	}, lg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return w.Run(ctx)
}
