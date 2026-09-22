package tunnelwatch

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

// Defaults chosen to be conservative: a false failover costs the whole house
// its geo-routing, so the loop would rather be a minute late than wrong.
const (
	DefaultInterval     = 60 * time.Second
	DefaultTimeout      = 5 * time.Second
	DefaultFailAfter    = 3
	DefaultRecoverAfter = 2
	DefaultCooldown     = 2 * time.Minute
)

// Applier re-applies the policy with a new view of whether the tunnel carries
// traffic. It is injected rather than imported so this package does not depend
// on the CLI that owns policy construction.
type Applier func(ctx context.Context, tunnelUp bool) error

// Config configures the watch loop.
type Config struct {
	Iface  string
	Target string
	// Table is the policy routing table whose contents should agree with the
	// loop's belief about the tunnel.
	Table        int
	Interval     time.Duration
	Timeout      time.Duration
	FailAfter    int
	RecoverAfter int
	// Cooldown is the minimum gap between transitions, bounding how fast the
	// route can flap. Zero or negative disables it; the CLI supplies the
	// default so "0" means what it says rather than silently becoming 2m.
	Cooldown time.Duration
	// BounceAfter recreates the interface once it has been dead this long. Zero
	// disables it, which is the right setting whenever another daemon owns the
	// interface -- bouncing a tun out from under sing-box would break the very
	// transport we are trying to recover. It exists for interfaces gotun itself
	// manages, where a stuck WireGuard socket can need a fresh one.
	BounceAfter time.Duration
}

func (c *Config) withDefaults() {
	if c.Table <= 0 {
		c.Table = 100 // policy.DefaultTableID; not imported to keep this package standalone
	}
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.FailAfter <= 0 {
		c.FailAfter = DefaultFailAfter
	}
	if c.RecoverAfter <= 0 {
		c.RecoverAfter = DefaultRecoverAfter
	}
}

// Watcher holds the loop state. It is not safe for concurrent use; one loop.
type Watcher struct {
	cfg   Config
	r     linux.Runner
	p     Prober
	apply Applier
	log   *log.Logger
	now   func() time.Time

	tunnelUp        bool
	consecutiveFail int
	consecutiveOK   int
	deadSince       time.Time
	lastTransition  time.Time
	lastBounce      time.Time
}

// New builds a Watcher that starts out believing the tunnel carries traffic,
// matching the state the initial apply installs.
func New(r linux.Runner, p Prober, apply Applier, cfg Config, lg *log.Logger) *Watcher {
	cfg.withDefaults()
	return &Watcher{
		cfg: cfg, r: r, p: p, apply: apply, log: lg,
		now:      time.Now,
		tunnelUp: true,
	}
}

// TunnelUp reports the loop's current belief, for tests and status output.
func (w *Watcher) TunnelUp() bool { return w.tunnelUp }

// Tick runs one health check and acts on it. Exported so tests drive the state
// machine directly instead of waiting on a ticker.
func (w *Watcher) Tick(ctx context.Context) {
	h := Check(ctx, w.r, w.p, CheckConfig{Iface: w.cfg.Iface, Target: w.cfg.Target, Timeout: w.cfg.Timeout})

	switch h.Verdict {
	case Unknown:
		// Deliberately inert. An inconclusive check is not evidence.
		w.log.Printf("health unknown, taking no action: %s", h.Reason)
		return

	case Healthy:
		w.consecutiveFail = 0
		w.deadSince = time.Time{}
		w.consecutiveOK++
		if w.tunnelUp {
			w.repairDrift(ctx)
			return
		}
		if w.consecutiveOK < w.cfg.RecoverAfter {
			return
		}
		if !w.cooledDown() {
			return
		}
		w.log.Printf("tunnel is carrying traffic again after %s; restoring the tunnel route", h.Reason)
		w.transition(ctx, true)

	case Unhealthy:
		w.consecutiveOK = 0
		w.consecutiveFail++
		if w.deadSince.IsZero() {
			w.deadSince = w.now()
		}
		w.log.Printf("health check failed (%d/%d): %s", w.consecutiveFail, w.cfg.FailAfter, h.Reason)
		if w.tunnelUp && w.consecutiveFail >= w.cfg.FailAfter && w.cooledDown() {
			// Loudly: from here on, foreign traffic silently egresses the ISP
			// and geo-blocked services simply behave as if you never left.
			w.log.Printf("TUNNEL DOWN: withdrawing the tunnel route so traffic falls back to the uplink."+
				" Foreign destinations are no longer going through the tunnel (%s)", h.Reason)
			w.transition(ctx, false)
		}
		w.maybeBounce()
	}
}

// repairDrift re-applies when the kernel no longer agrees with the loop's
// belief.
//
// Believing is not enough. The route can vanish underneath us: the transport
// restarting takes its interface with it, and the kernel withdraws the device
// route at the same time. The probe then starts succeeding again, the loop sees
// no transition to act on, and table 100 stays empty forever -- traffic silently
// on the uplink with everything reporting healthy. That is the same shape as the
// outage this watchdog exists to prevent, so it checks the kernel rather than
// trusting memory.
func (w *Watcher) repairDrift(ctx context.Context) {
	out, err := w.r.Run("ip", "-4", "route", "show", "table", strconv.Itoa(w.cfg.Table))
	if err != nil {
		return // Cannot tell; churning on an unreadable table helps nobody.
	}
	if strings.Contains(out, w.cfg.Iface) {
		return
	}
	w.log.Printf("table %d lost the tunnel route while the tunnel is healthy; re-applying", w.cfg.Table)
	if err := w.apply(ctx, true); err != nil {
		w.log.Printf("re-apply after drift failed, will retry: %v", err)
	}
}

func (w *Watcher) cooledDown() bool {
	if w.cfg.Cooldown <= 0 || w.lastTransition.IsZero() {
		return true
	}
	return w.now().Sub(w.lastTransition) >= w.cfg.Cooldown
}

func (w *Watcher) transition(ctx context.Context, up bool) {
	if err := w.apply(ctx, up); err != nil {
		// Leave the belief unchanged so the next tick retries rather than
		// assuming a failed apply took effect.
		w.log.Printf("re-apply with tunnel-up=%v failed, will retry: %v", up, err)
		return
	}
	w.tunnelUp = up
	w.lastTransition = w.now()
	w.consecutiveFail, w.consecutiveOK = 0, 0
}

// maybeBounce recreates a gotun-managed interface that has stayed dead. It is
// off unless BounceAfter is set; see the field comment for why.
func (w *Watcher) maybeBounce() {
	if w.cfg.BounceAfter <= 0 || w.deadSince.IsZero() {
		return
	}
	now := w.now()
	if now.Sub(w.deadSince) < w.cfg.BounceAfter {
		return
	}
	if !w.lastBounce.IsZero() && now.Sub(w.lastBounce) < w.cfg.BounceAfter {
		return
	}
	w.log.Printf("tunnel dead for %s; bouncing %s to force a fresh session",
		now.Sub(w.deadSince).Round(time.Second), w.cfg.Iface)
	_, _ = w.r.Run("ip", "link", "set", "dev", w.cfg.Iface, "down")
	if _, err := w.r.Run("ip", "link", "set", "dev", w.cfg.Iface, "up"); err != nil {
		w.log.Printf("bounce of %s failed: %v", w.cfg.Iface, err)
	}
	w.lastBounce = now
}

// Run ticks until the context is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	w.log.Printf("watching %s via %s every %s; declaring dead after %d consecutive failures",
		w.cfg.Iface, w.cfg.Target, w.cfg.Interval, w.cfg.FailAfter)
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			w.Tick(ctx)
		}
	}
}
