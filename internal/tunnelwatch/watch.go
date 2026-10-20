package tunnelwatch

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
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

	// snap is the loop's latest conclusion, published for readers in other
	// goroutines. An atomic rather than a mutex because there is exactly one
	// writer and the readers only ever want the newest value.
	snap atomic.Pointer[Snapshot]

	// poke asks the loop to re-assert the policy out of band. Buffered to one
	// and written without blocking: several requests arriving together are one
	// request, and nothing may stall waiting for the loop.
	poke chan struct{}

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
	w := &Watcher{
		cfg: cfg, r: r, p: p, apply: apply, log: lg,
		now:      time.Now,
		tunnelUp: true,
		poke:     make(chan struct{}, 1),
	}
	// Published before the first probe, so a reader arriving in the gap sees
	// the same belief the initial apply installed rather than a zero value --
	// which would read as "tunnel down" and, for the phone's on-demand probe,
	// would send it direct for one probe interval on every restart.
	w.publish(Health{Verdict: Unknown, Reason: "no probe yet"})
	return w
}

// Snapshot is the loop's latest conclusion, safe to read from another
// goroutine.
type Snapshot struct {
	// TunnelUp is the belief the loop has acted on, which is what table 100
	// currently reflects.
	TunnelUp bool
	// Verdict and Reason are the most recent check. They are reported
	// separately from TunnelUp because the two deliberately disagree for a
	// while: a single failure does not withdraw the route.
	Verdict Verdict
	Reason  string
	At      time.Time
}

// Snapshot returns the latest published conclusion.
func (w *Watcher) Snapshot() Snapshot {
	if s := w.snap.Load(); s != nil {
		return *s
	}
	return Snapshot{TunnelUp: true, Verdict: Unknown, Reason: "no probe yet"}
}

func (w *Watcher) publish(h Health) {
	w.snap.Store(&Snapshot{
		TunnelUp: w.tunnelUp,
		Verdict:  h.Verdict,
		Reason:   h.Reason,
		At:       w.now(),
	})
}

// TunnelUp reports the loop's current belief, for tests and status output.
func (w *Watcher) TunnelUp() bool { return w.tunnelUp }

// Tick runs one health check and acts on it. Exported so tests drive the state
// machine directly instead of waiting on a ticker.
func (w *Watcher) Tick(ctx context.Context) {
	h := Check(ctx, w.r, w.p, CheckConfig{Iface: w.cfg.Iface, Target: w.cfg.Target, Timeout: w.cfg.Timeout})
	// Published on the way out rather than here, so the snapshot carries the
	// belief after this tick acted rather than the one it is about to change.
	defer func() { w.publish(h) }()

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

// Reapply asks the loop to re-assert the policy now, rather than at the next
// tick. It never blocks and may be called from any goroutine -- the Watcher
// itself is single-threaded, so the request is handed to the loop and the loop
// does the work. That is deliberate: a second apply running concurrently with
// the watchdog's own is the class of bug this layer already has.
//
// It is what an ifup of the tunnel device triggers. Without it the policy comes
// back at the next tick instead, up to a whole interval later, during which the
// gateway is a classifier marking traffic into an empty table -- healthy from
// every direction except an egress-identity check.
func (w *Watcher) Reapply() {
	select {
	case w.poke <- struct{}{}:
	default: // one already pending; it will do the same work
	}
}

// reassert re-applies at the current belief, without probing.
//
// Not a Tick, and the difference matters. A poke means a device the policy
// depends on has just changed, so what is wanted is the policy put back the way
// the loop already believes it should be. Probing instead would ask a question
// nobody asked -- and would get the wrong answer whenever the device is up but
// not yet carrying traffic, which is precisely the moment an ifup fires.
func (w *Watcher) reassert(ctx context.Context) {
	w.log.Printf("re-asserting policy on request, tunnel-up=%v", w.tunnelUp)
	if err := w.apply(ctx, w.tunnelUp); err != nil {
		w.log.Printf("re-assert failed, the next tick will retry: %v", err)
	}
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
		case <-w.poke:
			w.reassert(ctx)
		}
	}
}
