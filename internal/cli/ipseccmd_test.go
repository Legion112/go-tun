package cli

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/ikev2"
)

func testDevice() IPsecDevice {
	return IPsecDevice{
		Iface: "ipsec0", IfID: "0x61", Addr: "10.231.17.1/24", MTU: "1400", Parent: "lo",
	}
}

// absentRunner answers as a box with no such interface.
func absentRunner() *fakeRunner {
	return &fakeRunner{reply: func(name string, args ...string) (string, error) {
		if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "show" {
			return "", errors.New(`Device "ipsec0" does not exist.`)
		}
		return "", nil
	}}
}

// presentRunner answers as a box where the interface is already up, which is
// what a running gateway looks like.
func presentRunner() *fakeRunner {
	return &fakeRunner{reply: func(name string, args ...string) (string, error) {
		if name == "ip" && len(args) >= 2 && args[0] == "link" && args[1] == "show" {
			return "12: ipsec0@lo: <NOARP,UP,LOWER_UP> mtu 1400", nil
		}
		return "", nil
	}}
}

func TestIPsecUp_CreatesTheDeviceAndAddressesIt(t *testing.T) {
	r := absentRunner()
	if err := IPsecUp(r, testDevice()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"ip link add ipsec0 type xfrm dev lo if_id 0x61",
		"ip link set ipsec0 mtu 1400",
		"ip address replace 10.231.17.1/24 dev ipsec0",
		"ip link set ipsec0 up",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q from:\n%s", want, joined)
		}
	}
	// The address has to be on before the link comes up, or the first replies
	// to a client leave before source selection can succeed.
	addr := strings.Index(joined, "ip address replace")
	up := strings.Index(joined, "ip link set ipsec0 up")
	if addr < 0 || up < 0 || addr > up {
		t.Errorf("the address must be assigned before the link is brought up:\n%s", joined)
	}
}

// The invariant that matters most on the live gateway: a phone's established SA
// is bound to this device, so a second `up` must not recreate it. The shell
// version got this right and the Go version has to keep it.
func TestIPsecUp_DoesNotRecreateALiveDevice(t *testing.T) {
	r := presentRunner()
	if err := IPsecUp(r, testDevice()); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "link add") {
			t.Errorf("an existing device was recreated, dropping every established SA on it: %q", c)
		}
		if strings.Contains(c, "link del") {
			t.Errorf("an existing device was deleted: %q", c)
		}
	}
	// But the settings are still reasserted, so an MTU or address edited in
	// the config takes effect on a restart without a reboot.
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{"mtu 1400", "address replace 10.231.17.1/24"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q from:\n%s", want, joined)
		}
	}
}

func TestIPsecDown_RemovesTheDevice(t *testing.T) {
	r := presentRunner()
	if err := IPsecDown(r, testDevice()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "ip link del ipsec0") {
		t.Errorf("the device was not removed: %v", r.calls)
	}
}

// `down` has to succeed at shutdown and on a repeat. The shell version reported
// failure for both, because `ip link del` on a missing device exits non-zero
// and was the last command in stop().
func TestIPsecDown_AnAbsentDeviceIsNotAFailure(t *testing.T) {
	r := absentRunner()
	if err := IPsecDown(r, testDevice()); err != nil {
		t.Fatalf("removing an already-absent device must succeed: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "link del") {
			t.Errorf("a device that does not exist was deleted anyway: %q", c)
		}
	}
}

// The kernel and busybox both answer unhelpfully, and the two answers mean
// different missing packages. This replaces a /sys/module check that tested the
// wrong thing and could not tell them apart at all.
func TestIPsecUp_NamesTheMissingPackage(t *testing.T) {
	for _, c := range []struct {
		name, kernelSays, wantPackage string
	}{
		{"no kernel support", "RTNETLINK answers: Not supported", "kmod-xfrm-interface"},
		{"busybox ip", "RTNETLINK answers: Invalid argument", "ip-full"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{reply: func(name string, args ...string) (string, error) {
				if name == "ip" && len(args) >= 2 && args[1] == "show" {
					return "", errors.New("does not exist")
				}
				if name == "ip" && len(args) >= 2 && args[1] == "add" {
					return "", errors.New(c.kernelSays)
				}
				return "", nil
			}}
			err := IPsecUp(r, testDevice())
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), c.wantPackage) {
				t.Errorf("the failure does not name the missing package %q: %v",
					c.wantPackage, err)
			}
		})
	}
}

func TestIPsecUp_RefusesAnEmptyInterfaceName(t *testing.T) {
	d := testDevice()
	d.Iface = ""
	if err := IPsecUp(absentRunner(), d); err == nil {
		t.Fatal("want an error rather than an `ip link add` with no name")
	}
}

// The settings must come from the config, which is what the shell version got
// wrong: it resolved its defaults at file scope, before start() sourced the
// file, so every GOTUN_IPSEC_* line was silently ignored.
func TestIPsecFlags_ComeFromTheConfig(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "gotun.conf")
	if err := os.WriteFile(conf, []byte(strings.Join([]string{
		"GOTUN_IPSEC_IFACE=ipsec9",
		"GOTUN_IPSEC_IFID=0x62",
		"GOTUN_IPSEC_ADDR=10.231.18.1/24",
		"GOTUN_IPSEC_MTU=1380",
		"GOTUN_IPSEC_PARENT=eth0",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := flag.NewFlagSet("ipsec up", flag.ContinueOnError)
	f := registerIPsecFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigInto(fs, conf, deployconf.IPsecFlags); err != nil {
		t.Fatal(err)
	}
	got := f.device()
	want := IPsecDevice{
		Iface: "ipsec9", IfID: "0x62", Addr: "10.231.18.1/24", MTU: "1380", Parent: "eth0",
	}
	if got != want {
		t.Errorf("resolved %+v, want %+v", got, want)
	}
}

// An explicit flag still wins, so a bad value in the file can be overridden
// from the init script rather than by editing the file on a box whose network
// may be the thing that is broken.
func TestIPsecFlags_AnExplicitFlagWins(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "gotun.conf")
	if err := os.WriteFile(conf, []byte("GOTUN_IPSEC_IFACE=ipsec9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("ipsec up", flag.ContinueOnError)
	f := registerIPsecFlags(fs)
	if err := fs.Parse([]string{"-iface", "ipsec0"}); err != nil {
		t.Fatal(err)
	}
	if err := loadConfigInto(fs, conf, deployconf.IPsecFlags); err != nil {
		t.Fatal(err)
	}
	if got := f.device().Iface; got != "ipsec0" {
		t.Errorf("-iface = %q, want the explicitly passed ipsec0", got)
	}
}

// The device's if_id and the swanctl connection's must be the same number. A
// pair that disagrees negotiates perfectly and then the decrypted packets
// surface nowhere, with every counter reading healthy.
func TestIPsecFlags_IfIDDefaultMatchesTheProfile(t *testing.T) {
	fs := flag.NewFlagSet("ipsec up", flag.ContinueOnError)
	registerIPsecFlags(fs)
	g := fs.Lookup("if-id")
	if g == nil {
		t.Fatal("no -if-id flag")
	}
	if g.DefValue != ikev2.DefaultIfID {
		t.Errorf("-if-id defaults to %q but the profile uses %q", g.DefValue, ikev2.DefaultIfID)
	}
}

func TestRunIPsec_RefusesAnUnknownVerb(t *testing.T) {
	for _, args := range [][]string{nil, {"sideways"}} {
		err := runIPsec(args)
		if err == nil {
			t.Errorf("runIPsec(%q) should have refused", args)
			continue
		}
		if !strings.Contains(err.Error(), "up") || !strings.Contains(err.Error(), "down") {
			t.Errorf("the refusal does not name the verbs: %v", err)
		}
	}
}
