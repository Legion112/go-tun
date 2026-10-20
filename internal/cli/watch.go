package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/tunnelwatch"
)

// watchFlags is what `watch` adds on top of the policy flags in applyFlags.
// It is registered separately from runWatch so that the set of flags the
// command accepts can be enumerated without running it -- which is what lets a
// test compare it against the flags deploy/openwrt/gotun.init passes. A flag
// renamed here and not there is not a test failure on the router, it is a
// gateway that does not come back from a reboot.
type watchFlags struct {
	probeTarget   *string
	probeInterval *time.Duration
	probeTimeout  *time.Duration
	failAfter     *int
	recoverAfter  *int
	cooldown      *time.Duration
	healthListen  *string
	bounceAfter   *time.Duration
	pidFile       *string
}

func registerWatchFlags(fs *flag.FlagSet) (*applyFlags, *watchFlags) {
	f := registerApplyFlags(fs)
	w := &watchFlags{
		probeTarget: fs.String("probe-target", "1.1.1.1:443",
			"host:port to connect to through the tunnel to prove it carries traffic"),
		probeInterval: fs.Duration("probe-interval", tunnelwatch.DefaultInterval, "how often to probe"),
		probeTimeout:  fs.Duration("probe-timeout", tunnelwatch.DefaultTimeout, "per-probe connect timeout"),
		failAfter: fs.Int("fail-after", tunnelwatch.DefaultFailAfter,
			"consecutive failed probes before the tunnel route is withdrawn"),
		recoverAfter: fs.Int("recover-after", tunnelwatch.DefaultRecoverAfter,
			"consecutive successful probes before the tunnel route is restored"),
		cooldown: fs.Duration("cooldown", tunnelwatch.DefaultCooldown,
			"minimum gap between route transitions, bounding how fast the route can flap; 0 disables"),
		healthListen: fs.String("health-listen", "",
			"serve GET /alive on this address, 200 while the tunnel carries traffic and 503 once the"+
				" route has been withdrawn. It exists for a phone's IKEv2 On-Demand URLStringProbe:"+
				" published through the NATs in front of the gateway, it turns a dead exit hop into a"+
				" VPN icon that is visibly off instead of a silent fallback to the local uplink."+
				" The body says only up or down, because strangers can read it"),
		pidFile: fs.String("pidfile", deployconf.DefaultPidFile,
			"write the watcher's pid here so `gotun hotplug` can ask it to re-apply."+
				" Empty disables it, and then an ifup of the tunnel does nothing"),
		bounceAfter: fs.Duration("bounce-after", 0,
			"recreate the tunnel interface once it has been dead this long; 0 disables."+
				" Leave it disabled whenever another daemon owns the interface (sing-box, netifd):"+
				" bouncing a tun out from under its owner breaks the transport being recovered"),
	}
	return f, w
}

// registerWatchFlagsOnly is registerWatchFlags for a command that needs the
// same flags but none of the watchFlags half -- `check`, which validates what
// `watch` would run with.
func registerWatchFlagsOnly(fs *flag.FlagSet) *applyFlags {
	f, _ := registerWatchFlags(fs)
	return f
}

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	f, w := registerWatchFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := loadConfigInto(fs, *f.configPath, deployconf.WatchFlags); err != nil {
		return err
	}
	o, err := f.options()
	if err != nil {
		return err
	}
	return Watch(WatchOptions{
		Apply:        o,
		ProbeTarget:  strings.TrimSpace(*w.probeTarget),
		Interval:     *w.probeInterval,
		Timeout:      *w.probeTimeout,
		FailAfter:    *w.failAfter,
		RecoverAfter: *w.recoverAfter,
		Cooldown:     *w.cooldown,
		BounceAfter:  *w.bounceAfter,
		HealthListen: strings.TrimSpace(*w.healthListen),
		PidFile:      strings.TrimSpace(*w.pidFile),
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
	// HealthListen is the address the /alive probe endpoint binds to. Empty
	// disables it.
	HealthListen string
	// PidFile is where the watcher records its pid for `gotun hotplug` to
	// find. Empty disables it, and then an ifup of the tunnel does nothing.
	PidFile string
}

// writePidFile records this process's pid for `gotun hotplug`.
//
// Written and renamed rather than written in place, so a hotplug handler that
// reads it at the wrong moment gets either the old pid or the new one and never
// a half-written line.
func writePidFile(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
	//
	// A failure here used to be fatal, and that was the wrong call. At boot the
	// usual cause is the tunnel device not existing yet -- gotun is START=99
	// and sing-box is still coming up -- and watch exiting on that put procd
	// into an unbounded respawn loop: a restart roughly every five seconds,
	// rebuilding the whole nft table (some 17,000 set elements on the router)
	// each time, for as long as the device stayed missing. Measured in the
	// deploy lab.
	//
	// The loop it was refusing to enter is exactly what recovers from this. A
	// probe against an absent device reads Unhealthy, transition() withdraws
	// nothing it has not installed, and once the device appears repairDrift()
	// notices table 100 has no route through it and re-applies. Meanwhile the
	// classifier is already in place with an empty table 100, so marked
	// traffic falls through to main and the house has plain internet.
	//
	// A ConfigError is different: it will fail identically forever, so carrying
	// on would mean a loop nobody is watching. Those stay fatal.
	initial := o.Apply
	initial.TunnelUp = true
	if err := Apply(initial); err != nil {
		var ce ConfigError
		if errors.As(err, &ce) {
			return fmt.Errorf("initial apply: %w", err)
		}
		lg.Printf("initial apply did not complete: %v", err)
		lg.Printf("continuing anyway: the classifier is installed and table %d is empty,"+
			" so marked traffic uses the uplink until the tunnel device appears",
			policy.DefaultTableID)
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
		Table:        policy.DefaultTableID,
		Interval:     o.Interval,
		Timeout:      o.Timeout,
		FailAfter:    o.FailAfter,
		RecoverAfter: o.RecoverAfter,
		Cooldown:     o.Cooldown,
		BounceAfter:  o.BounceAfter,
	}, lg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP means re-apply now. It is what `gotun hotplug` sends when netifd
	// reports the tunnel device coming up, and it is a signal rather than a
	// second process because the watcher is single-threaded by design: a
	// concurrent apply racing the watchdog is the class of bug this layer
	// already has. Reapply only hands the request to the loop.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				w.Reapply()
			}
		}
	}()

	if o.PidFile != "" {
		// Removed on the way out, so a stale file cannot have `gotun hotplug`
		// signalling a pid the kernel has handed to something else. hotplug
		// checks the pid is still gotun for the same reason, since a crash
		// leaves the file behind.
		if err := writePidFile(o.PidFile); err != nil {
			// Not fatal: losing the ability to re-apply on demand is worse than
			// nothing, but much better than losing the watchdog.
			lg.Printf("could not write %s, so an ifup of the tunnel will not trigger a"+
				" re-apply: %v", o.PidFile, err)
		} else {
			defer os.Remove(o.PidFile)
		}
	}

	if o.HealthListen != "" {
		// Started after the watcher exists so the handler never sees a nil
		// snapshot, and in a goroutine because a bind failure must not stop the
		// loop: losing the thing that reports on the tunnel is better than
		// losing the tunnel.
		go tunnelwatch.ServeAlive(ctx, o.HealthListen, w.Snapshot, lg.Printf)
	}

	return w.Run(ctx)
}
