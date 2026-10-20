package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/policy"
)

// runHotplug is /etc/hotplug.d/iface/99-gotun, in Go.
//
// netifd runs the hook for every interface event on the box, so almost every
// invocation of this is a no-op, and saying so quietly is the job.
//
// The one event it acts on is the tunnel device coming up. After a transport
// bounce the kernel has withdrawn the device route from table 100 and nothing
// puts it back, so the gateway stays a classifier marking traffic into an empty
// table: geo-routing has stopped while every other indicator still looks fine.
//
// It re-applies by signalling the running watcher rather than starting anything.
// The shell version ran `/etc/init.d/gotun start`, which procd treats as a
// no-op on a running service -- so the hook fired, logged that it had, and
// accomplished nothing, for as long as it had existed.
func runHotplug(args []string) error {
	fs := flag.NewFlagSet("hotplug", flag.ContinueOnError)
	configPath := fs.String("config", "",
		"the gotun.conf whose GOTUN_TUNNEL_IFACE names the interface to react to")
	pidFile := fs.String("pidfile", deployconf.DefaultPidFile,
		"where `gotun watch` recorded its pid")
	action := fs.String("action", "",
		"the event, defaulting to $ACTION as the hotplug caller sets it")
	iface := fs.String("interface", "",
		"defaulting to $INTERFACE: the UCI section name in an iface event,"+
			" the device name in a net event")
	device := fs.String("device", "",
		"defaulting to $DEVICE: the device name in an iface event, empty in a net event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("gotun hotplug: unexpected argument %q; the event arrives in"+
			" $ACTION and $INTERFACE", fs.Arg(0))
	}

	// The environment is how the hotplug caller passes the event; the flags
	// exist so the same decision can be exercised without one.
	if *action == "" {
		*action = os.Getenv("ACTION")
	}
	if *iface == "" {
		*iface = os.Getenv("INTERFACE")
	}
	if *device == "" {
		*device = os.Getenv("DEVICE")
	}

	// The two kinds of hotplug event describe themselves differently, and the
	// difference is the whole reason this hook never worked. Measured in the
	// lab against real netifd:
	//
	//   iface  ACTION=ifup  INTERFACE=<UCI section>  DEVICE=<device>
	//   net    ACTION=add   INTERFACE=<device>       DEVICE=<empty>
	//
	// So an iface event names the section, not the device, and the shell
	// version compared that against a device name -- which matches only where
	// the two happen to coincide. flint2 is such a box (network.xray0 carries
	// device xray0); anywhere the section is named differently, it never
	// matched at all.
	//
	// And a device netifd does not manage produces only the net event, so a
	// tun with no UCI section is invisible to a hook in iface/ alone.
	//
	// Both shapes are handled, and the hook is installed in both directories.
	switch *action {
	case "ifup", "add":
	default:
		return nil
	}

	// DEVICE when the event has one, INTERFACE otherwise -- which in a net
	// event is the device.
	got := *device
	if got == "" {
		got = *iface
	}

	// Which device matters comes from the config, so it cannot disagree with
	// what the watcher is routing into. The shell version compared against its
	// own hardcoded fallback, which did not match the Go default -- with the
	// variable unset the hook could never fire at all.
	want := policy.DefaultTunnelIface
	if *configPath != "" {
		conf, err := deployconf.Load(*configPath, deployconf.GotunConf)
		if err != nil {
			return err
		}
		if v, ok := conf.Get("GOTUN_TUNNEL_IFACE"); ok && strings.TrimSpace(v) != "" {
			want = strings.TrimSpace(v)
		}
	}
	if got != want {
		return nil
	}

	pid, err := watcherPid(*pidFile)
	if err != nil {
		return err
	}
	if pid == 0 {
		// Nothing is running, so there is nothing to re-apply -- and this is
		// also what keeps a service the operator stopped on purpose stopped.
		// The shell version needed two gates to get here, `enabled` and a ubus
		// query, and `enabled` was the wrong question: it means "starts at
		// boot", so a deliberately stopped service is still enabled.
		return nil
	}

	fmt.Printf("gotun hotplug: reapplying policy after %s of %s\n", *action, got)
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signalling gotun watch (pid %d): %w", pid, err)
	}
	return nil
}

// watcherPid returns the pid in path, or 0 when there is no watcher to signal.
//
// A missing file is the ordinary case -- the service is not running -- and not
// an error. A file naming a pid that is gone, or that the kernel has since
// handed to something else, is treated the same way: a crash leaves the file
// behind, and signalling a stranger because of it would be worse than doing
// nothing.
func watcherPid(path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("%s does not contain a pid: %q", path, strings.TrimSpace(string(data)))
	}
	if !pidIsGotun(pid) {
		return 0, nil
	}
	return pid, nil
}

// pidIsGotun reports whether pid is still a gotun process.
//
// A variable so a test can stand in for it: the check has to stay, because a
// crash leaves the pidfile behind and the kernel may have handed that pid to
// something else by the time an ifup arrives, but the test binary is not called
// gotun and cannot satisfy it.
var pidIsGotun = realPidIsGotun

func realPidIsGotun(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	// cmdline is NUL-separated; only the program name is needed.
	argv0, _, _ := strings.Cut(string(data), "\x00")
	return strings.Contains(argv0, "gotun")
}
