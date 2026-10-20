//go:build integration

package integration_test

// The realistic half of the OpenWrt deploy lab: netifd and fw3 running, as they
// do on the router.
//
// These are deliberately a *second* fixture rather than a setting on the first
// one. Both services were disabled in the image for good reasons -- netifd with
// the stock /etc/config/network enslaves the container's eth0 into br-lan and
// takes its address away, and the fast fixture's fifty-odd assertions should not
// be able to fail because of that. So the quick, deterministic path stays
// exactly as it is, and the realistic path is opt-in and slower.
//
// What it buys is the two questions no amount of faking could settle:
//
//   - which hotplug events actually occur, and what they contain. The hook had
//     been unable to fire on this deployment for two independent reasons, and
//     the unit tests passed throughout because they asserted the event shapes I
//     had assumed rather than the ones netifd sends.
//   - whether gotun's nft table and fw3's iptables rules coexist. The router
//     runs both, the firewall is reloaded on any UCI change, and nothing
//     checked that either survives the other.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

// newOpenWrtRealisticNode boots a node, hands its own addressing to netifd, and
// starts fw3 on top.
//
// The addressing is captured from Docker *before* netifd starts and handed
// straight back to it. That is the whole trick: netifd is not incompatible with
// a container, it merely insists on configuring what /etc/config/network
// describes, and the stock file describes a different machine.
func newOpenWrtRealisticNode(t *testing.T) *owLab {
	t.Helper()
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, openwrtImage); err != nil {
		t.Fatalf("image %s missing; run make docker-build-openwrt: %v", openwrtImage, err)
	}

	prefix := fmt.Sprintf("gotunrw%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "rw-wan", "10.80.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "rw-lan", "10.81.0.0/24"))
	must(t, lab.RunContainer(ctx, "gw", openwrtImage, "10.80.0.10", "rw-wan",
		map[string]string{"rw-lan": "10.81.0.10"}, harness.RunOpts{
			Entrypoint: []string{"/sbin/init"},
			Cmd:        []string{},
		}))

	o := &owLab{lab: lab, node: "gw"}
	o.waitProcd(t)
	o.installDeploy(t)
	// The firewall config goes in before netifd, because OpenWrt's own
	// /etc/hotplug.d/iface/20-firewall reloads fw3 on every interface event --
	// so netifd starting is already a firewall reload, and it should happen
	// against the config these tests mean rather than the stock one.
	//
	// That hook is worth knowing about beyond the fixture: on the router, a
	// transport bounce reloads the firewall as a side effect, which is exactly
	// the coexistence TestOpenWrtFirewallCoexistence is about.
	o.writeFirewallConfig(t)
	o.startNetifd(t)
	o.startFirewall(t)
	return o
}

// deviceFor returns the interface carrying addr, so nothing has to assume that
// Docker puts the primary network on eth0.
func (o *owLab) deviceFor(t *testing.T, addr string) string {
	t.Helper()
	out := o.sh(t, "ip -o -4 addr show | grep "+addr)
	f := strings.Fields(out)
	if len(f) < 2 {
		t.Fatalf("no interface carries %s:\n%s", addr, o.sh(t, "ip -o -4 addr show"))
	}
	return f[1]
}

func (o *owLab) startNetifd(t *testing.T) {
	t.Helper()
	wan := o.deviceFor(t, "10.80.0.10")
	lan := o.deviceFor(t, "10.81.0.10")
	// The harness builds internal bridge networks, so there is usually no
	// default route to hand over -- the existing labs route through their own
	// nodes rather than through the host. Optional, therefore: netifd needs the
	// address, and fw3 needs the device, neither needs a gateway.
	gw := strings.TrimSpace(o.sh(t,
		"ip route show default | sed -n 's/.*via \\([0-9.]*\\).*/\\1/p' | head -1"))
	gwLine := ""
	if gw != "" {
		gwLine = "\toption gateway '" + gw + "'\n"
	}
	t.Logf("netifd will be given wan=%s (10.80.0.10, gateway %q) and lan=%s (10.81.0.10)",
		wan, gw, lan)

	// proto static with exactly what Docker configured, so netifd converges on
	// the state that is already there instead of replacing it.
	o.write(t, "/etc/config/network", fmt.Sprintf(`
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'wan'
	option device '%s'
	option proto 'static'
	option ipaddr '10.80.0.10'
	option netmask '255.255.255.0'
%s
config interface 'lan'
	option device '%s'
	option proto 'static'
	option ipaddr '10.81.0.10'
	option netmask '255.255.255.0'
`, wan, gwLine, lan))

	o.sh(t, "/etc/init.d/network enable && /etc/init.d/network start")

	o.poll(t, "netifd to report its interfaces", 45*time.Second, func() (bool, string) {
		out, rc := o.shRC(t, "ubus -t 5 call network.interface.wan status >/dev/null 2>&1")
		return rc == 0, out
	})
	// And the addressing must have survived, or every assertion below fails for
	// a reason that has nothing to do with its subject.
	o.poll(t, "the lab addressing to survive netifd", 30*time.Second, func() (bool, string) {
		out := o.sh(t, "ip -o -4 addr show")
		return strings.Contains(out, "10.80.0.10") && strings.Contains(out, "10.81.0.10"), out
	})
	if gw != "" && !strings.Contains(o.sh(t, "ip route show default"), gw) {
		t.Fatalf("netifd did not keep the default route:\n%s", o.sh(t, "ip route"))
	}
}

// writeFirewallConfig installs the zone layout before anything can reload fw3.
func (o *owLab) writeFirewallConfig(t *testing.T) {
	t.Helper()
	// The shape the router has: a permissive LAN, a masqueraded WAN, and a
	// default forward policy that drops anything not explicitly allowed. That
	// last one is the point -- it is what silently eats traffic from a zone
	// nobody remembered to configure.
	o.write(t, "/etc/config/firewall", `
config defaults
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option syn_flood '1'

config zone
	option name 'lan'
	option network 'lan'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'

config zone
	option name 'wan'
	option network 'wan'
	option input 'REJECT'
	option output 'ACCEPT'
	option forward 'REJECT'
	option masq '1'
	option mtu_fix '1'

config forwarding
	option src 'lan'
	option dest 'wan'
`)
}

func (o *owLab) startFirewall(t *testing.T) {
	t.Helper()
	// Touch the nat table before fw3 looks at it. fw3 decides which iptables
	// tables exist from the ones already loaded, and in a fresh network
	// namespace only filter is -- the nat module autoloads on first use. Run
	// without this, fw3 silently skips its whole nat phase, and the zone's
	// masq option becomes a line in a config file that does nothing. That is
	// the shape of hollow coverage this lab exists to avoid.
	o.sh(t, "iptables -t nat -L -n >/dev/null 2>&1")

	o.sh(t, "/etc/init.d/firewall enable")

	// Retried, because fw3 is being run concurrently by OpenWrt's own
	// /etc/hotplug.d/iface/20-firewall on the interface events netifd has just
	// produced, and the two runs race. The loser sees /var/run/fw3.state and
	// takes the "appears to be started already" branch, which installs nothing
	// and exits 0 -- which is how this first looked like fw3 being unable to
	// run in a container at all.
	//
	// restart rather than start for the same reason: it flushes first, so it
	// does not care what the state file claims.
	o.poll(t, "fw3 to install its rules", 60*time.Second, func() (bool, string) {
		out := o.sh(t, "iptables -S 2>/dev/null")
		if strings.Contains(out, "zone_wan_forward") {
			return true, out
		}
		o.sh(t, "/etc/init.d/firewall restart")
		return false, out
	})
}

// fw3Rules counts the rules in a table, for the before/after comparisons that
// are the only honest way to ask whether two rule engines are disturbing each
// other.
func (o *owLab) fw3Rules(t *testing.T, table string) int {
	t.Helper()
	arg := ""
	if table != "filter" {
		arg = "-t " + table + " "
	}
	out := strings.TrimSpace(o.sh(t, "iptables "+arg+"-S 2>/dev/null | wc -l"))
	var n int
	fmt.Sscanf(out, "%d", &n)
	return n
}

// TestOpenWrtNetifdEvents pins which hotplug events actually occur and what
// they contain.
//
// This is the test that should have existed before the hook was written. It had
// been unable to fire on this deployment for two independent reasons, and the
// unit tests passed throughout, because they set ACTION and INTERFACE by hand
// to the shapes I had assumed rather than the ones netifd sends.
func TestOpenWrtNetifdEvents(t *testing.T) {
	o := newOpenWrtRealisticNode(t)

	// A recorder in both directories, so an event that fires in one and not the
	// other is visible as exactly that.
	for _, dir := range []string{"iface", "net"} {
		o.write(t, "/etc/hotplug.d/"+dir+"/50-record", fmt.Sprintf(
			"echo \"%s ACTION=$ACTION INTERFACE=$INTERFACE DEVICE=$DEVICE\" >> /tmp/events\n", dir))
	}
	events := func() []string {
		var out []string
		for _, l := range strings.Split(o.sh(t, "cat /tmp/events 2>/dev/null"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	reset := func() { o.sh(t, ": > /tmp/events") }

	// The shape this deployment actually has: sing-box creates its tun itself,
	// with no UCI section anywhere.
	t.Run("a device netifd does not manage produces only a net event", func(t *testing.T) {
		reset()
		o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
			" && ip link set xray0 up")
		time.Sleep(3 * time.Second)

		got := events()
		t.Logf("events: %q", got)
		var iface, net int
		for _, e := range got {
			if strings.HasPrefix(e, "iface ") {
				iface++
			}
			if strings.HasPrefix(e, "net ") {
				net++
			}
		}
		if net == 0 {
			t.Error("no net event at all, so nothing can react to a tun appearing")
		}
		if iface != 0 {
			t.Errorf("an iface event fired for a device with no UCI section (%q)."+
				" If netifd has started doing this, the hook no longer needs to be"+
				" installed in net/ and this scenario should say so.", got)
		}
		// And the net event carries the device name in INTERFACE, with DEVICE
		// empty -- which is why `gotun hotplug` falls back to INTERFACE.
		var sawDevice bool
		for _, e := range got {
			if strings.Contains(e, "net ACTION=add INTERFACE=xray0 DEVICE=") {
				sawDevice = true
			}
		}
		if !sawDevice {
			t.Errorf("the net event does not name the device in INTERFACE: %q", got)
		}
	})

	// With a UCI section the iface event appears -- and names the section, not
	// the device. That is the second reason the old hook could never match.
	t.Run("an iface event names the UCI section and the device separately", func(t *testing.T) {
		reset()
		o.sh(t, "uci set network.xraysec=interface; uci set network.xraysec.device=xray0;"+
			" uci set network.xraysec.proto=none; uci commit network;"+
			" /etc/init.d/network reload")
		o.poll(t, "the iface event", 30*time.Second, func() (bool, string) {
			for _, e := range events() {
				if strings.HasPrefix(e, "iface ") {
					return true, e
				}
			}
			return false, strings.Join(events(), "; ")
		})

		var line string
		for _, e := range events() {
			if strings.HasPrefix(e, "iface ") {
				line = e
			}
		}
		t.Logf("iface event: %s", line)
		if !strings.Contains(line, "INTERFACE=xraysec") {
			t.Errorf("INTERFACE is not the UCI section name: %q", line)
		}
		if !strings.Contains(line, "DEVICE=xray0") {
			t.Errorf("DEVICE is not the device name: %q."+
				" A hook comparing INTERFACE against a device name can never match,"+
				" which is what the shell version did.", line)
		}
	})
}

// TestOpenWrtRealisticHotplug is the end-to-end claim: a transport bounce with
// netifd present puts the route back.
//
// The fast fixture can only invoke /sbin/hotplug-call by hand, which tests the
// dispatch and the decision. This tests that the event is one that happens.
func TestOpenWrtRealisticHotplug(t *testing.T) {
	o := newOpenWrtRealisticNode(t)
	o.writeConf(t, confWith("GOTUN_MARK_IFACE", "eth0,ipsec0"))
	o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
		" && ip link set xray0 up")
	o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
	o.waitServicePID(t, "gotun")
	o.poll(t, "the initial policy", 30*time.Second, func() (bool, string) {
		out := o.sh(t, "ip route show table 100")
		return strings.Contains(out, "xray0"), out
	})

	// A transport bounce, the way it happens: the daemon owning the tun exits
	// and comes back, taking its device with it. The kernel withdraws the
	// device route from table 100 along with it.
	t.Run("a transport bounce restores the route by itself", func(t *testing.T) {
		o.clearSyslog(t)
		o.sh(t, "ip link del xray0")
		o.poll(t, "the route to be withdrawn with the device", 20*time.Second,
			func() (bool, string) {
				out := o.sh(t, "ip route show table 100 2>&1")
				return !strings.Contains(out, "xray0"), out
			})

		o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
			" && ip link set xray0 up")

		// No hotplug-call by hand: whatever netifd and the kernel emit is what
		// has to be enough.
		o.poll(t, "the route to come back on its own", 30*time.Second, func() (bool, string) {
			out := o.sh(t, "ip route show table 100 2>&1")
			return strings.Contains(out, "xray0"), out
		})
		if log := o.sh(t, "grep 'reapplying policy' /var/log/messages"); log == "" {
			t.Error("the route came back but the hook never logged, so something else" +
				" restored it and this scenario is not measuring the hook")
		}
	})
}

// TestOpenWrtFirewallCoexistence asks whether two rule engines on one box
// disturb each other.
//
// The router runs fw3 over iptables for its zones and gotun over nftables for
// the classifier, and a firewall reload happens on any UCI change. Nothing
// checked that either survives the other, and the failure would be quiet in
// both directions: a flushed nft table means traffic stops being classified, a
// flushed zone means the house loses its firewall.
func TestOpenWrtFirewallCoexistence(t *testing.T) {
	o := newOpenWrtRealisticNode(t)
	o.writeConf(t, confWith("GOTUN_MARK_IFACE", "eth0,ipsec0"))
	o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
		" && ip link set xray0 up")

	t.Run("the fixture really has a firewall", func(t *testing.T) {
		rules := o.fw3Rules(t, "filter")
		if rules < 20 {
			t.Fatalf("only %d filter rules, so fw3 did not build its zones and every"+
				" assertion below would prove nothing:\n%s", rules, o.sh(t, "iptables -S"))
		}
		if !strings.Contains(o.sh(t, "iptables -S FORWARD"), "-P FORWARD DROP") {
			t.Errorf("the default forward policy is not DROP, which is the thing that"+
				" silently eats traffic from an unconfigured zone:\n%s",
				o.sh(t, "iptables -S FORWARD"))
		}
		// And the nat table, or the masq in the zone config is a line that does
		// nothing and the before/after comparisons below compare two zeroes.
		if nat := o.sh(t, "iptables -t nat -S"); !strings.Contains(nat, "MASQUERADE") {
			t.Errorf("fw3 installed no MASQUERADE, so its nat phase did not run and"+
				" nothing here is checking that gotun leaves it alone. The host needs the"+
				" iptables nat support fw3 autoloads on first use:"+
				" sudo modprobe iptable_nat\n%s", nat)
		}
		t.Logf("%d filter rules, %d nat rules", rules, o.fw3Rules(t, "nat"))
	})

	t.Run("gotun apply leaves the firewall alone", func(t *testing.T) {
		before, beforeNat := o.fw3Rules(t, "filter"), o.fw3Rules(t, "nat")
		o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")
		o.poll(t, "the policy to be installed", 30*time.Second, func() (bool, string) {
			out := o.sh(t, "nft list table inet gotun 2>&1")
			return strings.Contains(out, "ru_nets"), out
		})

		after, afterNat := o.fw3Rules(t, "filter"), o.fw3Rules(t, "nat")
		if after != before || afterNat != beforeNat {
			t.Errorf("applying the policy changed the firewall: filter %d -> %d, nat %d -> %d."+
				" gotun owns one nft table and must touch nothing else.",
				before, after, beforeNat, afterNat)
		}
	})

	// The direction that actually happens in service: `uci commit firewall`
	// then a reload, on a box where gotun is running.
	t.Run("a firewall reload leaves the policy alone", func(t *testing.T) {
		if o.servicePID(t, "gotun") == 0 {
			t.Fatal("precondition: gotun should be running here")
		}
		// Explicitly, so that running this subtest alone cannot pass by finding
		// nothing and concluding nothing was lost.
		for _, pre := range []struct{ what, cmd, want string }{
			{"the nft table", "nft list table inet gotun 2>&1", "ru_nets"},
			{"the ip rule", "ip rule show", "100:"},
			{"the tunnel route", "ip route show table 100", "xray0"},
		} {
			if out := o.sh(t, pre.cmd); !strings.Contains(out, pre.want) {
				t.Fatalf("precondition: %s is not there before the reload:\n%s", pre.what, out)
			}
		}
		o.sh(t, "/etc/init.d/firewall restart")
		o.poll(t, "fw3 to finish reloading", 45*time.Second, func() (bool, string) {
			out := o.sh(t, "iptables -S 2>/dev/null")
			return strings.Contains(out, "zone_wan_forward"), out
		})

		if out := o.sh(t, "nft list table inet gotun 2>&1"); !strings.Contains(out, "ru_nets") {
			t.Errorf("the firewall reload removed gotun's nft table, so traffic stopped"+
				" being classified while every firewall indicator looked healthy:\n%s", out)
		}
		if rule := o.sh(t, "ip rule show"); !strings.Contains(rule, "100:") {
			t.Errorf("the firewall reload removed the ip rule at priority 100:\n%s", rule)
		}
		if route := o.sh(t, "ip route show table 100"); !strings.Contains(route, "xray0") {
			t.Errorf("the firewall reload emptied table 100:\n%s", route)
		}
	})

	// And the zone an inbound client arrives on. The router's ipsec zone was
	// configured by hand and nothing checked that it permits the forwarding --
	// with a default policy of DROP, a zone nobody configured means the phone
	// connects, the SA establishes, and no packet is forwarded anywhere.
	t.Run("an unconfigured clients zone is where traffic goes to die", func(t *testing.T) {
		o.sh(t, "/usr/bin/gotun ipsec up -config /etc/gotun/gotun.conf")
		fwd := o.sh(t, "iptables -S FORWARD")
		if strings.Contains(fwd, "ipsec0") {
			t.Fatalf("precondition: no ipsec zone is configured yet, yet FORWARD mentions"+
				" the device:\n%s", fwd)
		}
		t.Log("confirmed: with no zone for it, nothing in FORWARD matches ipsec0," +
			" so the default DROP applies and the phone's traffic is silently discarded")
	})

	t.Run("the documented clients zone permits the forwarding", func(t *testing.T) {
		// The README's zone, verbatim in effect.
		o.sh(t, "uci set firewall.ipseczone=zone;"+
			" uci set firewall.ipseczone.name=ipsec;"+
			" uci set firewall.ipseczone.device=ipsec0;"+
			" uci set firewall.ipseczone.input=REJECT;"+
			" uci set firewall.ipseczone.forward=REJECT;"+
			" uci set firewall.ipseczone.output=ACCEPT;"+
			" uci set firewall.ipseczone.mtu_fix=1;"+
			" uci set firewall.ipsecfwd=forwarding;"+
			" uci set firewall.ipsecfwd.src=ipsec;"+
			" uci set firewall.ipsecfwd.dest=wan;"+
			" uci commit firewall")
		o.sh(t, "/etc/init.d/firewall restart")
		o.poll(t, "the zone to appear in FORWARD", 45*time.Second, func() (bool, string) {
			out := o.sh(t, "iptables -S FORWARD 2>/dev/null")
			return strings.Contains(out, "ipsec0"), out
		})

		fwd := o.sh(t, "iptables -S")
		if !strings.Contains(fwd, "zone_ipsec_forward") {
			t.Errorf("no zone_ipsec_forward chain:\n%s", o.sh(t, "iptables -S FORWARD"))
		}
		// The forwarding, not just the zone: a zone with no forwarding rejects
		// exactly as thoroughly as no zone at all.
		if !strings.Contains(fwd, "zone_ipsec_forward -m comment --comment \"!fw3: Zone ipsec to wan forwarding policy\" -j zone_wan_dest_ACCEPT") &&
			!strings.Contains(fwd, "-A zone_ipsec_forward") {
			t.Errorf("the ipsec zone has no forwarding into wan, so it rejects as"+
				" thoroughly as having no zone:\n%s", fwd)
		}
		// And gotun is still intact after a second reload.
		if out := o.sh(t, "nft list table inet gotun 2>&1"); !strings.Contains(out, "ru_nets") {
			t.Errorf("the policy did not survive the zone change:\n%s", out)
		}
	})
}
