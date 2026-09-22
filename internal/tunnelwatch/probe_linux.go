package tunnelwatch

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DeviceDialer probes the tunnel by opening a TCP connection whose socket is
// bound to the tunnel device itself.
//
// Binding to the device rather than setting the routing mark is the whole point.
// A marked probe looks correct and is subtly useless: under fail-open the route
// is withdrawn precisely when the tunnel is dead, so the marked probe falls
// through to the main table, reaches the target over the ISP, and reports the
// tunnel healthy. The watchdog would then restore the route, the probe would
// fail again, and it would flap forever.
//
// SO_BINDTODEVICE forces the packet out of that interface whatever the routing
// tables say, so this answers "does the transport carry traffic" independently
// of "is policy currently routing into it".
type DeviceDialer struct{}

func (DeviceDialer) Probe(ctx context.Context, iface, target string, timeout time.Duration) error {
	if iface == "" {
		return fmt.Errorf("%w: no tunnel interface given", ErrProbeUnavailable)
	}
	var bindErr error
	d := net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			if err := c.Control(func(fd uintptr) {
				bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return bindErr
		},
	}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		// A refused bind is our problem, not the tunnel's: without
		// CAP_NET_RAW the probe cannot be trusted either way, so report it as
		// unavailable rather than letting it read as a dead tunnel.
		if bindErr != nil {
			return fmt.Errorf("%w: bind to %s: %v", ErrProbeUnavailable, iface, bindErr)
		}
		return err
	}
	return conn.Close()
}
