package gotunclient

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"text/tabwriter"

	"github.com/legion/go-tun/internal/linux"
)

// ProtectedVerdict is one protected prefix and how the kernel would reach it.
type ProtectedVerdict struct {
	Prefix   netip.Prefix
	Probe    netip.Addr
	ViaGotun bool
	Line     string
	Err      error
}

// StatusReport is a read-only snapshot of the client's routing and DNS state.
type StatusReport struct {
	Conn        ActiveConn
	Props       NMProps
	DefaultVia  netip.Addr
	DefaultDev  string
	DefaultsAll string
	DNS         []string
	Protected   []ProtectedVerdict
	StatePath   string
	Enabled     bool
	State       *State
	// StateErr is set when a state file exists but could not be read -- most
	// often because status is running unprivileged against a 0600 root-owned
	// file. Reporting "not enabled" in that case would be a lie.
	StateErr error
	Gateway  netip.Addr
}

// Status collects the current picture without mutating anything.
func Status(r linux.Runner, statePath string, gw netip.Addr, extraLANs []netip.Prefix) (StatusReport, error) {
	rep := StatusReport{StatePath: statePath, Gateway: gw}

	st, stErr := LoadState(statePath)
	switch {
	case stErr == nil:
		rep.Enabled = true
		rep.State = st
		// The gateway recorded at enable time beats the flag default.
		if a, perr := netip.ParseAddr(st.EnabledGateway); perr == nil {
			rep.Gateway = a
		}
	case StateExists(statePath):
		// Present but unreadable: enabled, details unavailable.
		rep.Enabled = true
		rep.StateErr = stErr
	}

	conn, err := DetectActiveConn(r, "")
	if err != nil {
		return rep, err
	}
	rep.Conn = conn

	if props, err := ReadNMProps(r, conn.ID); err == nil {
		rep.Props = props
	}
	if dns, err := DeviceDNS(r, conn.Device); err == nil {
		rep.DNS = dns
	}

	if out, err := r.Run("ip", "-4", "route", "show", "default"); err == nil {
		rep.DefaultsAll = strings.TrimSpace(out)
		if res, perr := parseRouteGet(out); perr == nil {
			rep.DefaultVia, rep.DefaultDev = res.Via, res.Dev
		}
	}

	protected, err := protectedSet(extraLANs)
	if err != nil {
		return rep, err
	}
	for _, p := range protected {
		hosts, herr := ProbeHosts(p)
		if herr != nil {
			rep.Protected = append(rep.Protected, ProtectedVerdict{Prefix: p, Err: herr})
			continue
		}
		for _, h := range hosts {
			if h == rep.Gateway {
				continue
			}
			via, line, rerr := RouteViaGateway(r, h, rep.Gateway)
			rep.Protected = append(rep.Protected, ProtectedVerdict{Prefix: p, Probe: h, ViaGotun: via, Line: line, Err: rerr})
		}
	}
	return rep, nil
}

// PrintStatus renders a StatusReport as plain text.
func PrintStatus(w io.Writer, s StatusReport) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "connection:\t%s (%s, %s)\n", s.Conn.ID, s.Conn.Device, s.Conn.Type)
	fmt.Fprintf(tw, "ipv4.method:\t%s\n", s.Props.Method)
	if s.DefaultVia.IsValid() {
		fmt.Fprintf(tw, "default:\tvia %s dev %s\n", s.DefaultVia, s.DefaultDev)
	} else {
		fmt.Fprintf(tw, "default:\t%s\n", orNone(s.DefaultsAll))
	}
	fmt.Fprintf(tw, "dns:\t%s\n", orNone(strings.Join(s.DNS, ", ")))
	switch {
	case s.Enabled && s.State != nil:
		confirmed := "ARMED (not confirmed)"
		if s.State.Confirmed {
			confirmed = "confirmed"
		}
		fmt.Fprintf(tw, "gotun:\tENABLED gateway=%s dns=%s mode=%s %s\n",
			s.State.EnabledGateway, s.State.EnabledDNS, s.State.Mode, confirmed)
		fmt.Fprintf(tw, "state:\t%s (saved %s)\n", s.StatePath, s.State.SavedAt.Format("2006-01-02T15:04:05Z"))
	case s.Enabled:
		fmt.Fprintf(tw, "gotun:\tENABLED (state file present but unreadable -- run as root for details)\n")
		fmt.Fprintf(tw, "state:\t%s: %v\n", s.StatePath, s.StateErr)
	default:
		fmt.Fprintf(tw, "gotun:\tnot enabled (no state at %s)\n", s.StatePath)
	}
	fmt.Fprintf(tw, "nm props:\tnever-default=%s ignore-auto-dns=%s route-metric=%s\n",
		yesNo(s.Props.NeverDefault), yesNo(s.Props.IgnoreAutoDNS), orUnset(s.Props.RouteMetric))
	fmt.Fprintf(tw, "\tipv4.routes=%s\n", orUnset(s.Props.Routes))
	tw.Flush()

	fmt.Fprintf(w, "protected LANs (%d):\n", len(s.Protected))
	for _, v := range s.Protected {
		switch {
		case v.Err != nil:
			fmt.Fprintf(w, "  ERR   %-18s %v\n", v.Prefix, v.Err)
		case v.ViaGotun:
			fmt.Fprintf(w, "  FAIL  %-18s probe %-15s %s\n", v.Prefix, v.Probe, v.Line)
		default:
			fmt.Fprintf(w, "  ok    %-18s probe %-15s %s\n", v.Prefix, v.Probe, v.Line)
		}
	}
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

func orUnset(v *string) string {
	if v == nil {
		return "unset"
	}
	return *v
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
