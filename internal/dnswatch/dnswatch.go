// Package dnswatch keeps dnsmasq's upstream list pointed at resolvers that are
// actually answering.
//
// The chain on the gateway is dnsmasq -> filter (AdGuard Home) -> gotun-dns ->
// Direct or Exit, with a local resolver as the last resort. dnsmasq does walk
// down that list when a server fails, but only when the client retries: on the
// GL-MT6000, with strict-order, every uncached lookup cost about 2 s for as
// long as the filter was down or hung, and a glibc client with its default 5 s
// timeout would wait 5 s. Without strict-order it was worse -- a hung filter
// failed the lookup outright after 6 s. The fallback that was already live,
// gotun-dns then the local resolver, had the same 2 s penalty.
//
// Losing ad blocking is acceptable; losing DNS is not. So a hop that stops
// answering is taken out of the list and dnsmasq is told to re-read it, and it
// goes back in once it has answered for a while.
package dnswatch

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Defaults. Faster than tunnelwatch's on purpose: a false failover here costs
// ad blocking or geo-correct answers for a few seconds, while a slow one costs
// every lookup in the house a two-second stall. At 5 s and 1.5 s it took about
// 10 s to drop a hung AdGuard Home, and four lookups stalled meanwhile; at these
// values a dead hop is out in about 5 s. A probe is three queries, two of them
// to localhost, so the cost is about one real upstream query a second.
const (
	DefaultInterval     = 2 * time.Second
	DefaultTimeout      = 1 * time.Second
	DefaultFailAfter    = 2
	DefaultRecoverAfter = 3

	// The canaries are one name per gotun-dns path, so a resolver that can
	// still reach Yandex but not the tunnel counts as broken. A gotun-dns that
	// answers only .ru names is no better than the local resolver for the
	// rest, and worse, because it makes them wait for a timeout first.
	DefaultDirectCanary = "ya.ru."
	DefaultExitCanary   = "cloudflare.com."

	// DefaultPidGlob matches the pid file of every dnsmasq instance procd
	// runs, which names each after its uci section.
	DefaultPidGlob = "/var/run/dnsmasq/dnsmasq.*.pid"

	// DefaultServersFile lives under /etc/gotun, which sysupgrade keeps, and
	// is written only on a change, so the flash sees a write per failover.
	// dnsmasq starts long before this watcher and must find a list there.
	DefaultServersFile = "/etc/gotun/dnsmasq.servers"
)

// Config configures the loop. Addresses are host:port.
type Config struct {
	// Filter is the blocking resolver in front of Resolver. Empty means there
	// is none and the list is just Resolver then Fallback.
	Filter string
	// Resolver is gotun-dns.
	Resolver string
	// Fallback is the last resort, and is never removed: with nothing else
	// answering, a local resolver's answer is better than none.
	Fallback string

	// ServersFile is the dnsmasq --servers-file this loop owns.
	ServersFile string
	// PidGlob finds the dnsmasq processes to SIGHUP after a change.
	PidGlob string

	Interval     time.Duration
	Timeout      time.Duration
	FailAfter    int
	RecoverAfter int
	DirectCanary string
	ExitCanary   string
}

func (c *Config) withDefaults() {
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
	if c.DirectCanary == "" {
		c.DirectCanary = DefaultDirectCanary
	}
	if c.ExitCanary == "" {
		c.ExitCanary = DefaultExitCanary
	}
	if c.PidGlob == "" {
		c.PidGlob = DefaultPidGlob
	}
}

// Validate refuses a configuration the loop cannot act on.
func (c Config) Validate() error {
	if c.ServersFile == "" {
		return fmt.Errorf("no servers file: dnsmasq has nothing to read the list from")
	}
	for _, a := range []struct{ name, addr string }{
		{"resolver", c.Resolver}, {"fallback", c.Fallback}, {"filter", c.Filter},
	} {
		if a.addr == "" && a.name == "filter" {
			continue
		}
		if _, err := ServerLine(a.addr); err != nil {
			return fmt.Errorf("%s: %w", a.name, err)
		}
	}
	return nil
}

// Chain is the upstream list for a given belief about the hops, in the order
// dnsmasq should try them.
//
// With the resolver down the filter goes too, because its only upstream is the
// resolver: kept, it would answer nothing but its own blocks and cache, and
// make every other lookup wait for its upstream timeout first.
func Chain(c Config, filterUp, resolverUp bool) []string {
	var out []string
	if resolverUp {
		if c.Filter != "" && filterUp {
			out = append(out, c.Filter)
		}
		out = append(out, c.Resolver)
	}
	return append(out, c.Fallback)
}

// ServerLine renders host:port the way dnsmasq's server= wants it: host#port,
// with the port left off when it is 53. A wildcard listen address becomes
// loopback, which is where something on the same box reaches it.
func ServerLine(addr string) (string, error) {
	ap, err := hostPort(addr)
	if err != nil {
		return "", err
	}
	if ap.Port() == 53 {
		return ap.Addr().String(), nil
	}
	return ap.Addr().String() + "#" + strconv.Itoa(int(ap.Port())), nil
}

// dialAddr is the address to probe for a configured one.
func dialAddr(addr string) (string, error) {
	ap, err := hostPort(addr)
	if err != nil {
		return "", err
	}
	return ap.String(), nil
}

func hostPort(addr string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not host:port: %w", addr, err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return netip.AddrPort{}, fmt.Errorf("%q: bad port", addr)
	}
	var ip netip.Addr
	if host == "" {
		ip = netip.MustParseAddr("127.0.0.1")
	} else if ip, err = netip.ParseAddr(host); err != nil {
		// dnsmasq takes an address here, and a name would need DNS to find
		// the DNS server.
		return netip.AddrPort{}, fmt.Errorf("%q: the host must be an IP address", addr)
	}
	if ip.IsUnspecified() {
		if ip.Is6() {
			ip = netip.IPv6Loopback()
		} else {
			ip = netip.MustParseAddr("127.0.0.1")
		}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), nil
}

// Render is the servers file for a chain.
func Render(chain []string, state string) (string, error) {
	var b strings.Builder
	b.WriteString("# Written by gotun dnswatch; edits are overwritten. ")
	b.WriteString("State: " + state + "\n")
	for _, a := range chain {
		l, err := ServerLine(a)
		if err != nil {
			return "", err
		}
		b.WriteString("server=" + l + "\n")
	}
	return b.String(), nil
}

// tracker turns probe results into a belief, with hysteresis both ways.
type tracker struct {
	up     bool
	streak int // consecutive results disagreeing with up
}

// observe records one result and reports whether the belief changed.
func (t *tracker) observe(ok bool, failAfter, recoverAfter int) bool {
	if ok == t.up {
		t.streak = 0
		return false
	}
	t.streak++
	need := failAfter
	if ok {
		need = recoverAfter
	}
	if t.streak < need {
		return false
	}
	t.up, t.streak = ok, 0
	return true
}

// Prober asks addr for name and reports whether it answered usefully.
type Prober func(ctx context.Context, addr, name string) error

// Watcher holds the loop state. One loop; not safe for concurrent use.
type Watcher struct {
	cfg   Config
	probe Prober
	// hup tells dnsmasq to re-read the file. Injected for tests.
	hup func() error
	log *log.Logger

	filter, resolver tracker
}

// New builds a watcher. Both hops start believed up, so a restart does not
// begin by stripping the list it inherited; a hop that is really down is out
// within FailAfter intervals.
func New(cfg Config, probe Prober, logger *log.Logger) *Watcher {
	cfg.withDefaults()
	w := &Watcher{cfg: cfg, probe: probe, log: logger,
		filter: tracker{up: true}, resolver: tracker{up: true}}
	w.hup = func() error { return hupAll(cfg.PidGlob) }
	return w
}

func (w *Watcher) state() string {
	parts := []string{}
	if w.cfg.Filter != "" {
		parts = append(parts, "filter "+upDown(w.filter.up))
	}
	parts = append(parts, "resolver "+upDown(w.resolver.up))
	return strings.Join(parts, ", ")
}

func upDown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}

// Step probes every hop once and rewrites the list if the belief changed, or if
// the file no longer says what it should.
func (w *Watcher) Step(ctx context.Context) error {
	changed := false
	if w.cfg.Filter != "" {
		// Through the filter, the direct canary only: what is being asked is
		// whether the filter process answers, and the resolver behind it is
		// probed on its own below.
		ok := w.ask(ctx, w.cfg.Filter, w.cfg.DirectCanary)
		changed = w.filter.observe(ok, w.cfg.FailAfter, w.cfg.RecoverAfter) || changed
	}
	ok := w.ask(ctx, w.cfg.Resolver, w.cfg.DirectCanary) &&
		w.ask(ctx, w.cfg.Resolver, w.cfg.ExitCanary)
	changed = w.resolver.observe(ok, w.cfg.FailAfter, w.cfg.RecoverAfter) || changed
	if changed {
		w.log.Printf("dnswatch: %s; upstreams now %v", w.state(),
			Chain(w.cfg, w.filter.up, w.resolver.up))
	}
	return w.reconcile(Chain(w.cfg, w.filter.up, w.resolver.up), w.state())
}

func (w *Watcher) ask(ctx context.Context, addr, name string) bool {
	a, err := dialAddr(addr)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()
	return w.probe(ctx, a, name) == nil
}

// reconcile writes the file only when its content differs, so a steady state
// costs one read per interval and no flash writes, and dnsmasq -- whose cache a
// SIGHUP clears -- is signalled only on a real change.
//
// The file is rewritten in place rather than renamed over. procd can run
// dnsmasq in a jail with the servers file bind-mounted in, and a rename would
// leave the jail holding the old inode.
func (w *Watcher) reconcile(chain []string, state string) error {
	want, err := Render(chain, state)
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(w.cfg.ServersFile); err == nil && string(have) == want {
		return nil
	}
	if err := os.WriteFile(w.cfg.ServersFile, []byte(want), 0o644); err != nil {
		return err
	}
	if err := w.hup(); err != nil {
		// The file is right; dnsmasq picks it up on its next start.
		w.log.Printf("dnswatch: wrote %s but could not signal dnsmasq: %v", w.cfg.ServersFile, err)
	}
	return nil
}

// Run probes until ctx ends, then leaves the full configured list behind: with
// the watcher gone nothing would put a recovered hop back, and the full list
// is what dnsmasq would have had without one -- slower to fail over, never
// missing a hop.
func (w *Watcher) Run(ctx context.Context) error {
	if err := w.cfg.Validate(); err != nil {
		return err
	}
	w.log.Printf("dnswatch: filter=%q resolver=%s fallback=%s file=%s every %s",
		w.cfg.Filter, w.cfg.Resolver, w.cfg.Fallback, w.cfg.ServersFile, w.cfg.Interval)
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		if err := w.Step(ctx); err != nil {
			w.log.Printf("dnswatch: %v", err)
		}
		select {
		case <-ctx.Done():
			return w.reconcile(Chain(w.cfg, true, true), "watcher stopped, full list")
		case <-t.C:
		}
	}
}

// hupAll signals every dnsmasq whose pid file matches glob.
func hupAll(glob string) error {
	files, err := filepath.Glob(glob)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no pid file matches %s", glob)
	}
	var firstErr error
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err == nil {
			var pid int
			if pid, err = strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				err = syscall.Kill(pid, syscall.SIGHUP)
			}
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", f, err)
		}
	}
	return firstErr
}
