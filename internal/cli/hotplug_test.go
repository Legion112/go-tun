package cli

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// hotplugFixture writes a config naming xray0 and a pidfile holding pid.
func hotplugFixture(t *testing.T, pid int) (confPath, pidPath string) {
	t.Helper()
	dir := t.TempDir()
	confPath = filepath.Join(dir, "gotun.conf")
	if err := os.WriteFile(confPath, []byte("GOTUN_TUNNEL_IFACE=xray0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidPath = filepath.Join(dir, "gotun.pid")
	if pid != 0 {
		if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return confPath, pidPath
}

// netifd runs this hook for every interface event on the box, so the overwhelming
// majority of invocations must do nothing -- quietly, and without needing a
// watcher to exist.
func TestHotplug_IgnoresEventsItDoesNotOwn(t *testing.T) {
	conf, pidFile := hotplugFixture(t, os.Getpid())
	pidIsGotun = func(int) bool { return true }
	t.Cleanup(func() { pidIsGotun = realPidIsGotun })

	for _, c := range []struct{ name, action, iface string }{
		{"ifdown of the tunnel", "ifdown", "xray0"},
		{"ifup of the LAN", "ifup", "lan"},
		{"ifup of the WAN", "ifup", "wan"},
		{"an event with no action", "", "xray0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := catchHUP(t, func() error {
				return runHotplug([]string{
					"-config", conf, "-pidfile", pidFile,
					"-action", c.action, "-interface", c.iface,
				})
			})
			if got {
				t.Error("the hook re-applied the policy for an event it does not own")
			}
		})
	}
}

// The event it exists for. The shell version got this far and then ran
// `/etc/init.d/gotun start`, which procd treats as a no-op on a running
// service, so it accomplished nothing for as long as it existed.
func TestHotplug_SignalsTheWatcherOnTunnelIfup(t *testing.T) {
	conf, pidFile := hotplugFixture(t, os.Getpid())
	pidIsGotun = func(int) bool { return true }
	t.Cleanup(func() { pidIsGotun = realPidIsGotun })

	got := catchHUP(t, func() error {
		return runHotplug([]string{
			"-config", conf, "-pidfile", pidFile,
			"-action", "ifup", "-interface", "xray0",
		})
	})
	if !got {
		t.Error("an ifup of the tunnel did not signal the watcher, so the route the kernel" +
			" withdrew on the bounce never comes back")
	}
}

// With no pidfile there is nothing running, so there is nothing to re-apply --
// and that is also what keeps a service the operator stopped on purpose
// stopped. The shell version needed two gates for this, one of which asked the
// wrong question: `enabled` means "starts at boot", so a deliberately stopped
// service is still enabled.
func TestHotplug_DoesNothingWithNoWatcherRunning(t *testing.T) {
	conf, pidFile := hotplugFixture(t, 0) // no pidfile written

	got := catchHUP(t, func() error {
		return runHotplug([]string{
			"-config", conf, "-pidfile", pidFile,
			"-action", "ifup", "-interface", "xray0",
		})
	})
	if got {
		t.Error("something was signalled although no watcher is running")
	}
}

// A crash leaves the pidfile behind, and by the time an ifup arrives the kernel
// may have handed that pid to something else. Signalling a stranger because of
// a stale file would be worse than doing nothing.
func TestHotplug_IgnoresAStalePidfile(t *testing.T) {
	conf, pidFile := hotplugFixture(t, os.Getpid())
	pidIsGotun = func(int) bool { return false } // the pid is somebody else now
	t.Cleanup(func() { pidIsGotun = realPidIsGotun })

	got := catchHUP(t, func() error {
		return runHotplug([]string{
			"-config", conf, "-pidfile", pidFile,
			"-action", "ifup", "-interface", "xray0",
		})
	})
	if got {
		t.Error("a pid that is no longer gotun was signalled anyway")
	}
}

// The interface to react to comes from the config, so it cannot disagree with
// what the watcher routes into. The shell version compared against its own
// hardcoded fallback, which did not match the Go default -- so with the
// variable unset the hook could never fire.
func TestHotplug_TheInterfaceComesFromTheConfig(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "gotun.conf")
	if err := os.WriteFile(conf, []byte("GOTUN_TUNNEL_IFACE=ipsec0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "gotun.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidIsGotun = func(int) bool { return true }
	t.Cleanup(func() { pidIsGotun = realPidIsGotun })

	if got := catchHUP(t, func() error {
		return runHotplug([]string{"-config", conf, "-pidfile", pidFile,
			"-action", "ifup", "-interface", "xray0"})
	}); got {
		t.Error("the hook fired for xray0 although the config names ipsec0")
	}
	if got := catchHUP(t, func() error {
		return runHotplug([]string{"-config", conf, "-pidfile", pidFile,
			"-action", "ifup", "-interface", "ipsec0"})
	}); !got {
		t.Error("the hook did not fire for the interface the config names")
	}
}

// With no config the hook falls back to the Go default rather than to a
// different string of its own, which is the defect this replaces.
func TestHotplug_WithNoConfigItUsesTheGoDefault(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "gotun.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pidIsGotun = func(int) bool { return true }
	t.Cleanup(func() { pidIsGotun = realPidIsGotun })

	got := catchHUP(t, func() error {
		return runHotplug([]string{"-pidfile", pidFile, "-action", "ifup",
			"-interface", "wg-exit"}) // policy.DefaultTunnelIface
	})
	if !got {
		t.Error("with no config the hook did not react to the Go default interface")
	}
}

func TestHotplug_RefusesPositionalArguments(t *testing.T) {
	err := runHotplug([]string{"ifup", "xray0"})
	if err == nil {
		t.Fatal("want an error: the event arrives in the environment")
	}
	if !strings.Contains(err.Error(), "$ACTION") {
		t.Errorf("the refusal does not say where the event comes from: %v", err)
	}
}

func TestHotplug_ReportsAnUnreadableConfig(t *testing.T) {
	err := runHotplug([]string{"-config", "/nope.conf", "-action", "ifup", "-interface", "xray0"})
	if err == nil {
		t.Fatal("want an error for a config that cannot be read")
	}
}

// catchHUP runs f with a SIGHUP handler installed and reports whether one
// arrived. The signal has to be caught: the default disposition would kill the
// test binary.
func catchHUP(t *testing.T, f func() error) bool {
	t.Helper()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	if err := f(); err != nil {
		t.Fatalf("runHotplug: %v", err)
	}
	select {
	case <-ch:
		return true
	case <-time.After(200 * time.Millisecond):
		return false
	}
}
