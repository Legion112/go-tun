// Package tunnelwatch keeps table 100 honest about whether the tunnel actually
// works.
//
// Route-level fail-open only reacts to the interface going down. A tunnel that
// is up but carrying nothing -- no handshake, a dead proxy outbound, a silently
// throttled session -- keeps its route and swallows every packet, with no
// symptom in any log. That is exactly how the 22 Sep outage went unnoticed:
// nothing was watching, so the box blackholed foreign traffic until someone
// noticed by hand.
package tunnelwatch

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

// ErrProbeUnavailable means the probe could not be carried out at all, as
// opposed to being carried out and failing.
var ErrProbeUnavailable = errors.New("probe unavailable")

// Verdict is the outcome of one health check.
type Verdict int

const (
	// Healthy means the tunnel carried the probe.
	Healthy Verdict = iota
	// Unhealthy means the tunnel is genuinely not carrying traffic.
	Unhealthy
	// Unknown means health could not be established. Acting on Unknown is how
	// a watchdog turns a working network into a broken one, so it never does.
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Healthy:
		return "healthy"
	case Unhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// Prober opens a connection through a specific interface.
type Prober interface {
	Probe(ctx context.Context, iface, target string, timeout time.Duration) error
}

// Health is one diagnosis, with the reason kept so the log says why.
type Health struct {
	Verdict Verdict
	Reason  string
}

// CheckConfig configures a single health check.
type CheckConfig struct {
	Iface   string
	Target  string
	Timeout time.Duration
}

// Check diagnoses the tunnel: the interface must exist and be up, and a
// connection bound to it must complete.
func Check(ctx context.Context, r linux.Runner, p Prober, cfg CheckConfig) Health {
	out, err := r.Run("ip", "link", "show", "dev", cfg.Iface)
	switch {
	case err != nil, out == "", strings.Contains(out, "does not exist"), strings.Contains(out, "Cannot find"):
		// The transport's own supervisor owns bringing this back. Reporting it
		// unhealthy keeps table 100 consistent with reality in the meantime.
		return Health{Unhealthy, "interface " + cfg.Iface + " is absent"}
	case !strings.Contains(out, "UP"):
		return Health{Unhealthy, "interface " + cfg.Iface + " is down"}
	}

	if err := p.Probe(ctx, cfg.Iface, cfg.Target, cfg.Timeout); err != nil {
		if errors.Is(err, ErrProbeUnavailable) {
			return Health{Unknown, err.Error()}
		}
		if ctx.Err() != nil {
			// Shutting down mid-probe is not evidence about the tunnel.
			return Health{Unknown, "probe cancelled"}
		}
		return Health{Unhealthy, "probe to " + cfg.Target + " failed: " + err.Error()}
	}
	return Health{Healthy, "probe to " + cfg.Target + " via " + cfg.Iface + " succeeded"}
}
