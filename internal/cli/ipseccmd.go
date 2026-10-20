package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/ikev2"
	"github.com/legion/go-tun/internal/linux"
)

// Defaults for the xfrm interface an IKEv2 CHILD_SA surfaces on.
//
// The if-id comes from ikev2.DefaultIfID rather than being spelled again here,
// because it is the one value that must match what swanctl is rendered with: a
// device and a connection carrying different if_ids negotiate perfectly and
// then the decrypted packets surface nowhere.
const (
	defaultIPsecIface = "ipsec0"

	// The address is load-bearing, not cosmetic. charon installs no route for
	// an xfrm interface, so without an on-link prefix every reply to a client
	// fails source address selection -- while the SA still reads ESTABLISHED
	// and the handshake counters look perfect. /24 rather than /32 for the same
	// reason: a /32 leaves nothing on-link.
	defaultIPsecAddr = "10.231.17.1/24"

	defaultIPsecMTU = "1400"

	// lo rather than the WAN device. The parent is only a hint to the kernel --
	// the if_id is what binds SAs to the interface -- and naming the WAN would
	// be wrong the moment ESP arrives somewhere else, such as from a client
	// already on the home LAN.
	defaultIPsecParent = "lo"
)

// IPsecDevice is the interface gotun ipsec manages.
type IPsecDevice struct {
	Iface  string
	IfID   string
	Addr   string
	MTU    string
	Parent string
}

type ipsecFlags struct {
	configPath, iface, ifID, addr, mtu, parent *string
}

func registerIPsecFlags(fs *flag.FlagSet) *ipsecFlags {
	return &ipsecFlags{
		configPath: fs.String("config", "",
			"read the GOTUN_IPSEC_* settings from this gotun.conf"),
		iface:  fs.String("iface", defaultIPsecIface, "name of the xfrm interface"),
		ifID:   fs.String("if-id", ikev2.DefaultIfID, "xfrm interface id; must match the swanctl connection"),
		addr:   fs.String("addr", defaultIPsecAddr, "on-link address, without which replies to clients fail source selection"),
		mtu:    fs.String("mtu", defaultIPsecMTU, "interface MTU"),
		parent: fs.String("parent", defaultIPsecParent, "parent device, a hint to the kernel only"),
	}
}

func (f *ipsecFlags) device() IPsecDevice {
	return IPsecDevice{
		Iface:  strings.TrimSpace(*f.iface),
		IfID:   strings.TrimSpace(*f.ifID),
		Addr:   strings.TrimSpace(*f.addr),
		MTU:    strings.TrimSpace(*f.mtu),
		Parent: strings.TrimSpace(*f.parent),
	}
}

// runIPsec creates and removes the xfrm interface an IKEv2 CHILD_SA surfaces on.
//
// Route-based rather than policy-based IPsec is what lets gotun classify a
// phone at all: decrypted packets surface on a named device, so -mark-iface and
// the home_nets forward rule -- both interface-named -- apply unchanged.
// Policy-based IPsec surfaces them on the physical WAN device, where neither
// has anything to attach to.
//
// Not netifd's, although OpenWrt has a "proto xfrm". That handler creates the
// device and assigns no address, and the address is load-bearing. Rather than
// have netifd own half of it and a hotplug script the other half, one owner
// owns all of it.
func runIPsec(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun ipsec <up|down> [flags]")
	}
	verb := args[0]
	switch verb {
	case "up", "down":
	default:
		return fmt.Errorf("unknown ipsec command %q (want up or down)", verb)
	}

	fs := flag.NewFlagSet("ipsec "+verb, flag.ContinueOnError)
	f := registerIPsecFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("gotun ipsec %s: unexpected argument %q", verb, fs.Arg(0))
	}
	if err := loadConfigInto(fs, *f.configPath, deployconf.IPsecFlags); err != nil {
		return err
	}

	r := linux.ExecRunner{}
	if verb == "up" {
		return IPsecUp(r, f.device())
	}
	return IPsecDown(r, f.device())
}

// IPsecUp creates the interface if it is absent and reasserts its address and
// MTU either way.
//
// Idempotent on purpose: a phone's live SA is bound to this device, so
// recreating it on every start would drop every established session. An
// existing device is kept and only its settings are reapplied.
func IPsecUp(r linux.Runner, d IPsecDevice) error {
	if d.Iface == "" {
		return fmt.Errorf("-iface is required")
	}
	if !deviceExists(r, d.Iface) {
		// Best effort, and its failure is not reported: on a kernel with the
		// support built in there is no module to load, and the next command
		// says whether it worked far more reliably than this one does.
		_, _ = r.Run("modprobe", "xfrm_interface")

		if _, err := r.Run("ip", "link", "add", d.Iface, "type", "xfrm",
			"dev", d.Parent, "if_id", d.IfID); err != nil {
			return fmt.Errorf("creating %s: %w%s", d.Iface, err, xfrmHint(err))
		}
	}
	if _, err := r.Run("ip", "link", "set", d.Iface, "mtu", d.MTU); err != nil {
		return fmt.Errorf("setting mtu on %s: %w", d.Iface, err)
	}
	if _, err := r.Run("ip", "address", "replace", d.Addr, "dev", d.Iface); err != nil {
		return fmt.Errorf("addressing %s: %w", d.Iface, err)
	}
	if _, err := r.Run("ip", "link", "set", d.Iface, "up"); err != nil {
		return fmt.Errorf("bringing %s up: %w", d.Iface, err)
	}
	return nil
}

// IPsecDown removes the interface. An interface that is already gone is not a
// failure: `down` has to succeed at shutdown and on a repeat, and the shell
// version reported failure for both because `ip link del` was its last command.
func IPsecDown(r linux.Runner, d IPsecDevice) error {
	if d.Iface == "" {
		return fmt.Errorf("-iface is required")
	}
	if !deviceExists(r, d.Iface) {
		return nil
	}
	if _, err := r.Run("ip", "link", "del", d.Iface); err != nil {
		return fmt.Errorf("removing %s: %w", d.Iface, err)
	}
	return nil
}

func deviceExists(r linux.Runner, iface string) bool {
	out, err := r.Run("ip", "link", "show", iface)
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

// xfrmHint turns the kernel's and busybox's unhelpful answers into the two
// packages that are actually missing.
//
// This replaces a `[ -d /sys/module/xfrm_interface ]` gate, which tested the
// wrong thing: it passes on a kernel with the support compiled in and no
// module, it passes in a container whose host kernel has the module while the
// container's own `ip` cannot use it, and it says nothing at all about busybox.
// Attempting the operation and reading the failure covers every case with one
// code path.
func xfrmHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Not supported"), strings.Contains(msg, "not supported"):
		return ". The kernel has no xfrm interface support: opkg install kmod-xfrm-interface"
	case strings.Contains(msg, "Invalid argument"):
		// busybox's ip accepts the words and never passes the if_id, so the
		// kernel rejects the request. It reads exactly like a kernel problem.
		return ". This is what busybox's ip answers because it cannot pass if_id:" +
			" opkg install ip-full (and kmod-xfrm-interface if it is also missing)"
	}
	return ""
}
