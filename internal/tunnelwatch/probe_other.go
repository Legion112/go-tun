//go:build !linux

package tunnelwatch

import (
	"context"
	"fmt"
	"time"
)

// DeviceDialer cannot bind a socket to an interface off Linux. It reports the
// probe as unavailable, which the watchdog treats as Unknown and never acts on.
type DeviceDialer struct{}

func (DeviceDialer) Probe(_ context.Context, iface, _ string, _ time.Duration) error {
	return fmt.Errorf("%w: SO_BINDTODEVICE is Linux-only (iface %s)", ErrProbeUnavailable, iface)
}
