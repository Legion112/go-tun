package gotunclient

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/legion/go-tun/internal/linux"
)

// nmReadFields are the properties snapshotted and restored, in a stable order.
var nmReadFields = []string{
	"ipv4.method",
	"ipv4.gateway",
	"ipv4.dns",
	"ipv4.ignore-auto-dns",
	"ipv4.never-default",
	"ipv4.routes",
	"ipv4.route-metric",
	"ipv6.ignore-auto-dns",
}

// splitTerse splits one `nmcli -t` line on unescaped colons, honouring \: and \\.
func splitTerse(line string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range line {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

// nmOptional maps nmcli's unset spellings to nil. Terse mode prints an empty
// value; pretty mode prints "--". Both mean "not set".
func nmOptional(raw string) *string {
	v := strings.TrimSpace(raw)
	if v == "" || v == "--" {
		return nil
	}
	s := v
	return &s
}

// nmBool parses nmcli's boolean spellings.
func nmBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true", "1":
		return true
	}
	return false
}

// nmArg renders a snapshotted value for `nmcli connection modify`. An unset
// property becomes "", which resets it to its default.
func nmArg(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// nmBoolArg renders a boolean for nmcli.
func nmBoolArg(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// parseNMProps parses `nmcli -t -f <nmReadFields> connection show <con>` output.
func parseNMProps(out string) (NMProps, error) {
	var p NMProps
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := splitTerse(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSpace(fields[0])
		val := strings.Join(fields[1:], ":")
		seen[key] = true
		switch key {
		case "ipv4.method":
			p.Method = strings.TrimSpace(val)
		case "ipv4.gateway":
			p.Gateway = nmOptional(val)
		case "ipv4.dns":
			p.DNS = nmOptional(val)
		case "ipv4.ignore-auto-dns":
			p.IgnoreAutoDNS = nmBool(val)
		case "ipv4.never-default":
			p.NeverDefault = nmBool(val)
		case "ipv4.routes":
			// A connection with several static routes still prints one line,
			// comma separated. Accumulate anyway so a per-route layout works.
			if v := nmOptional(val); v != nil {
				if p.Routes == nil {
					p.Routes = v
				} else {
					joined := *p.Routes + ", " + *v
					p.Routes = &joined
				}
			}
		case "ipv4.route-metric":
			// -1 is nmcli's "unset" sentinel for this property.
			if v := nmOptional(val); v != nil && *v != "-1" {
				p.RouteMetric = v
			}
		case "ipv6.ignore-auto-dns":
			p.IPv6IgnoreDNS = nmBool(val)
		}
	}
	if !seen["ipv4.method"] {
		return p, fmt.Errorf("nmcli output has no ipv4.method line")
	}
	return p, nil
}

// ReadNMProps snapshots the properties of a connection profile.
func ReadNMProps(r linux.Runner, conID string) (NMProps, error) {
	out, err := r.Run("nmcli", "-t", "-f", strings.Join(nmReadFields, ","), "connection", "show", conID)
	if err != nil {
		return NMProps{}, fmt.Errorf("read nm properties for %q: %w", conID, err)
	}
	return parseNMProps(out)
}

// ActiveConn is an activated NM connection profile and the device it owns.
type ActiveConn struct {
	ID     string
	Device string
	Type   string
	State  string
}

// parseActiveConns parses `nmcli -t -f NAME,DEVICE,TYPE,STATE connection show --active`.
func parseActiveConns(out string) []ActiveConn {
	var conns []ActiveConn
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := splitTerse(line)
		if len(f) < 4 {
			continue
		}
		c := ActiveConn{ID: f[0], Device: f[1], Type: f[2], State: f[3]}
		if !strings.EqualFold(c.State, "activated") {
			continue
		}
		conns = append(conns, c)
	}
	return conns
}

// defaultRouteDevices returns the devices of every IPv4 default route in
// `ip -4 route show default`, ordered by ascending metric.
func defaultRouteDevices(out string) []string {
	type entry struct {
		dev    string
		metric int
	}
	var entries []entry
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		e := entry{metric: 0}
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "dev":
				e.dev = f[i+1]
			case "metric":
				if m, err := strconv.Atoi(f[i+1]); err == nil {
					e.metric = m
				}
			}
		}
		if e.dev != "" {
			entries = append(entries, e)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].metric < entries[j].metric })
	var devs []string
	for _, e := range entries {
		devs = append(devs, e.dev)
	}
	return devs
}

// defaultRouteMetrics returns the metric of each default route on dev, so a tie
// between two uplinks can be detected rather than guessed at.
func defaultRouteMetrics(out string) map[string]int {
	m := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		dev, metric := "", 0
		for i := 0; i < len(f)-1; i++ {
			switch f[i] {
			case "dev":
				dev = f[i+1]
			case "metric":
				if v, err := strconv.Atoi(f[i+1]); err == nil {
					metric = v
				}
			}
		}
		if dev != "" {
			m[dev] = metric
		}
	}
	return m
}

// DetectActiveConn finds the activated connection carrying the IPv4 default
// route. wantID, when non-empty, selects that profile by name instead.
func DetectActiveConn(r linux.Runner, wantID string) (ActiveConn, error) {
	activeOut, err := r.Run("nmcli", "-t", "-f", "NAME,DEVICE,TYPE,STATE", "connection", "show", "--active")
	if err != nil {
		return ActiveConn{}, fmt.Errorf("list active connections: %w", err)
	}
	active := parseActiveConns(activeOut)

	if wantID != "" {
		for _, c := range active {
			if c.ID == wantID {
				return c, nil
			}
		}
		return ActiveConn{}, fmt.Errorf("connection %q is not activated (active: %s)", wantID, describeConns(active))
	}

	routeOut, err := r.Run("ip", "-4", "route", "show", "default")
	if err != nil {
		return ActiveConn{}, fmt.Errorf("read default routes: %w", err)
	}
	devs := defaultRouteDevices(routeOut)
	if len(devs) == 0 {
		return ActiveConn{}, fmt.Errorf("no IPv4 default route found; pass -connection to choose a profile")
	}

	byDev := map[string]ActiveConn{}
	for _, c := range active {
		if c.Device != "" {
			byDev[c.Device] = c
		}
	}

	// A tie on metric between two default routes is ambiguous: guessing which
	// uplink to reroute is how you lock yourself out of the wrong one.
	metrics := defaultRouteMetrics(routeOut)
	if len(devs) > 1 && metrics[devs[0]] == metrics[devs[1]] {
		return ActiveConn{}, fmt.Errorf("several default routes tie at metric %d (%s); pass -connection",
			metrics[devs[0]], strings.Join(devs, ", "))
	}

	c, ok := byDev[devs[0]]
	if !ok {
		return ActiveConn{}, fmt.Errorf("default route device %q has no activated NM profile; pass -connection", devs[0])
	}
	return c, nil
}

func describeConns(conns []ActiveConn) string {
	if len(conns) == 0 {
		return "none"
	}
	var parts []string
	for _, c := range conns {
		parts = append(parts, fmt.Sprintf("%s (%s)", c.ID, c.Device))
	}
	return strings.Join(parts, ", ")
}

// deviceConnected reports whether nmcli sees dev as fully connected.
func deviceConnected(r linux.Runner, dev string) (bool, error) {
	out, err := r.Run("nmcli", "-t", "-f", "GENERAL.STATE", "device", "show", dev)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "(connected)"), nil
}

// DeviceDNS returns the DNS servers NM has applied to dev.
func DeviceDNS(r linux.Runner, dev string) ([]string, error) {
	out, err := r.Run("nmcli", "-t", "-f", "IP4.DNS", "device", "show", dev)
	if err != nil {
		return nil, err
	}
	var dns []string
	for _, line := range strings.Split(out, "\n") {
		f := splitTerse(strings.TrimRight(line, "\r"))
		if len(f) < 2 || !strings.HasPrefix(f[0], "IP4.DNS") {
			continue
		}
		if v := strings.TrimSpace(strings.Join(f[1:], ":")); v != "" {
			dns = append(dns, v)
		}
	}
	return dns, nil
}
