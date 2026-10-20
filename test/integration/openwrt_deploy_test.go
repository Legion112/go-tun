//go:build integration

package integration_test

// Scenarios for the OpenWrt deploy lab. See openwrt_fixture_test.go for what
// this lab is for and what it deliberately does not test.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestOpenWrtFixture checks the lab itself.
//
// Every one of these guards against the rest of the suite passing while proving
// nothing, which is the characteristic failure of a lab built on a container
// pretending to be a router. They are cheap and they are the first thing to
// read when something below starts failing for no apparent reason.
func TestOpenWrtFixture(t *testing.T) {
	o := newOpenWrtNode(t, "fix")

	t.Run("procd supervises", func(t *testing.T) {
		if got := strings.TrimSpace(o.sh(t, "cat /proc/1/comm")); got != "procd" {
			t.Fatalf("PID 1 is %q, want procd", got)
		}
		if out, rc := o.shRC(t, "ubus -t 5 call service list >/dev/null"); rc != 0 {
			t.Fatalf("procd's service object does not reply (rc=%d): %s", rc, out)
		}
	})

	t.Run("ip is iproute2 and can make an xfrm device", func(t *testing.T) {
		if v := o.sh(t, "ip -V"); !strings.Contains(v, "iproute2") {
			t.Fatalf("ip is not iproute2: %q -- busybox ip cannot create an xfrm device,"+
				" so every ipsec scenario would fail before reaching its subject", v)
		}
		out, rc := o.shRC(t, "ip link add fixt0 type xfrm dev lo if_id 0x61")
		if rc != 0 {
			t.Fatalf("ip link add type xfrm failed (rc=%d): %s\n"+
				"the host needs the xfrm_interface module: modprobe xfrm_interface", rc, out)
		}
		o.sh(t, "ip link del fixt0")
	})

	// This is the lab's unique value. The Debian lab has nftables with JSON, so
	// it only ever exercises gotun's JSON readback path. The router has
	// nftables-nojson, which exercises the text path -- and the text path is
	// where the two-interface ingress-guard bug lived. If this image ever gains
	// JSON support, that coverage evaporates silently.
	t.Run("nft has the text path and no JSON", func(t *testing.T) {
		if out, rc := o.shRC(t, "nft list ruleset >/dev/null"); rc != 0 {
			t.Fatalf("nft text listing failed (rc=%d): %s", rc, out)
		}
		if _, rc := o.shRC(t, "nft -j list ruleset >/dev/null 2>&1"); rc == 0 {
			t.Fatal("nft in this image supports JSON, so the lab no longer exercises gotun's" +
				" text readback path -- the one thing it exists for. Check that the image still" +
				" installs nftables-nojson rather than nftables.")
		}
	})

	t.Run("syslog is collected", func(t *testing.T) {
		o.sh(t, `logger -t fixture "fixture marker"`)
		o.poll(t, "the marker to arrive in syslog", 10*time.Second, func() (bool, string) {
			out := o.sh(t, "grep -c 'fixture marker' /var/log/messages 2>/dev/null")
			return strings.TrimSpace(out) != "" && strings.TrimSpace(out) != "0", out
		})
	})

	t.Run("the deploy scripts are installed and executable", func(t *testing.T) {
		for _, dst := range deployFiles {
			if out, rc := o.shRC(t, "test -x "+dst); rc != 0 {
				t.Errorf("%s is not installed or not executable: %s", dst, out)
			}
		}
	})
}

// TestOpenWrtArgv checks what gotun.init actually hands the binary.
//
// Most deploy-layer defects are of exactly this shape, and the argv is a
// string: asserting on it directly is both faster and more precise than
// inferring it from kernel state, which topology_test.go already covers in
// depth. One container, no extra networks, many fast subtests.
func TestOpenWrtArgv(t *testing.T) {
	o := newOpenWrtNode(t, "argv")
	o.recordArgv(t)

	t.Run("a full config maps every value onto a flag", func(t *testing.T) {
		o.writeConf(t, owConf)
		o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		argv := o.argv(t, "watch")
		for _, c := range []struct{ flag, want string }{
			{"prefixes", "/etc/gotun/prefixes.txt"},
			{"endpoint", "10.60.0.2"},
			{"tunnel-iface", "xray0"},
			{"lan", "10.60.0.0/24"},
			{"mark-iface", "eth0,ipsec0"},
			{"clients-iface", "ipsec0"},
			{"fail-mode", "open"},
			{"ipv6", "off"},
			{"ipv6-fallback", "direct"},
			{"probe-target", "10.60.0.2:443"},
			{"probe-interval", "1h"},
			{"fail-after", "3"},
			{"recover-after", "2"},
		} {
			got, ok := flagValue(argv, c.flag)
			if !ok {
				t.Errorf("-%s is not passed at all; the operator's value for it is ignored", c.flag)
				continue
			}
			if got != c.want {
				t.Errorf("-%s = %q, want %q", c.flag, got, c.want)
			}
		}
	})

	// GOTUN_IPV6_FALLBACK was documented in gotun.conf.example and passed by
	// nothing, so an operator who set blackhole specifically to stop their real
	// IPv6 address being seen was still egressing it. The value happened to
	// coincide with the Go default, which is why nobody noticed.
	t.Run("ipv6-fallback reaches the binary", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.recordArgv(t)
		o.writeConf(t, confWith("GOTUN_IPV6_FALLBACK", "blackhole"))
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		if got, _ := flagValue(o.argv(t, "watch"), "ipv6-fallback"); got != "blackhole" {
			t.Errorf("-ipv6-fallback = %q, want blackhole: the knob is documented, so setting it"+
				" must do something", got)
		}
	})

	// An unset variable passed as a bare "$VAR" hands the binary an empty
	// string, which overrides the Go default rather than letting it apply.
	t.Run("an unset tunnel iface falls back to the Go default, not to empty", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.recordArgv(t)
		o.writeConf(t, confWithout("GOTUN_TUNNEL_IFACE"))
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		got, ok := flagValue(o.argv(t, "watch"), "tunnel-iface")
		if ok && got == "" {
			t.Error("-tunnel-iface is passed as an empty string, which overrides the Go default" +
				" with nothing instead of leaving it in place")
		}
		if ok && got != "wg-exit" {
			t.Errorf("-tunnel-iface = %q, want wg-exit (policy.DefaultTunnelIface)", got)
		}
	})

	// off leaves IPv6 alone, which means it egresses the uplink directly. auto
	// is both the Go default and the safer of the two, and a parameter must not
	// mean one thing when set and another when unset.
	t.Run("an unset ipv6 mode falls back to auto", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.recordArgv(t)
		o.writeConf(t, confWithout("GOTUN_IPV6"))
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		if got, _ := flagValue(o.argv(t, "watch"), "ipv6"); got != "auto" {
			t.Errorf("-ipv6 = %q, want auto", got)
		}
	})

	// A flag whose value is the empty string is not the same as a flag that is
	// absent: the first overrides a default, the second lets it apply. Any flag
	// with a non-empty Go default must never be handed "".
	t.Run("no flag is handed an empty value", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.recordArgv(t)
		// Every optional value removed at once: the worst realistic config, a
		// file half-written by an interrupted sysupgrade.
		conf := owConf
		for _, k := range []string{
			"GOTUN_TUNNEL_IFACE", "GOTUN_IPV6", "GOTUN_IPV6_FALLBACK", "GOTUN_FAIL_MODE",
			"GOTUN_PROBE_TARGET", "GOTUN_PROBE_INTERVAL", "GOTUN_FAIL_AFTER", "GOTUN_RECOVER_AFTER",
		} {
			conf = strings.Join(strings.Split(conf, k+"="), "#removed=")
		}
		o.writeConf(t, conf)
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		argv := o.argv(t, "watch")
		for _, f := range []string{
			"tunnel-iface", "ipv6", "ipv6-fallback", "fail-mode",
			"probe-target", "probe-interval", "fail-after", "recover-after",
		} {
			if got, ok := flagValue(argv, f); ok && got == "" {
				t.Errorf("-%s is passed as an empty string with no value behind it", f)
			}
		}
		t.Logf("argv with every optional value removed:\n  %s", argv)
	})
}

// TestOpenWrtLifecycle covers what procd does with gotun.init: enable, start,
// respawn, restart, stop, and the two refusals.
//
// It uses the argv recorder rather than the real binary, because the subject
// here is the supervision contract, not the policy. The scenarios that need
// real kernel state are in TestOpenWrtPolicy.
func TestOpenWrtLifecycle(t *testing.T) {
	o := newOpenWrtNode(t, "life")
	o.recordArgv(t)
	o.writeConf(t, owConf)

	t.Run("enable writes rc.d and enabled agrees", func(t *testing.T) {
		if _, rc := o.shRC(t, "/etc/init.d/gotun enable"); rc != 0 {
			t.Fatal("enable failed")
		}
		if out := o.sh(t, "ls /etc/rc.d/ | grep gotun"); !strings.Contains(out, "S99gotun") {
			t.Errorf("want S99gotun in /etc/rc.d, got %q", out)
		}
		// The hotplug hook gates itself on `enabled`, so a START edit that
		// makes this false disables the hook too, silently.
		if _, rc := o.shRC(t, "/etc/init.d/gotun enabled"); rc != 0 {
			t.Error("`enabled` reports false right after `enable`; the hotplug hook checks this" +
				" and would never fire")
		}
	})

	t.Run("start yields one supervised instance", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun start")
		pid := o.waitServicePID(t, "gotun")
		t.Logf("supervised pid %d", pid)
		if _, rc := o.shRC(t, "kill -0 "+itoa(pid)); rc != 0 {
			t.Errorf("procd reports pid %d but the process does not exist", pid)
		}
	})

	// Characterisation, not a complaint: procd's start on a running service is
	// a no-op. It matters because the hotplug hook's last line is
	// `/etc/init.d/gotun start`, so the hook cannot re-apply anything while the
	// service is up -- which is the whole reason the hook exists.
	t.Run("start on a running service is a no-op", func(t *testing.T) {
		before := o.servicePID(t, "gotun")
		if before == 0 {
			t.Fatal("precondition: gotun should be running here")
		}
		o.sh(t, "/etc/init.d/gotun start")
		after := o.servicePID(t, "gotun")
		if after != before {
			t.Errorf("pid changed %d -> %d; procd start is no longer a no-op, which means the"+
				" hotplug hook's `start` now has an effect and its scenarios need revisiting",
				before, after)
		}
		// And it started no second process behind procd's back.
		if n := len(o.invocations(t)); n != 1 {
			t.Errorf("want 1 recorded invocation, got %d: a second one would be two processes"+
				" fighting over ip rule priority 100", n)
		}
	})

	t.Run("procd respawns a killed instance", func(t *testing.T) {
		was := o.servicePID(t, "gotun")
		if was == 0 {
			t.Fatal("precondition: gotun should be running here")
		}
		o.sh(t, "kill -9 "+itoa(was))
		now := o.waitNewServicePID(t, "gotun", was)
		t.Logf("respawned %d -> %d", was, now)
	})

	t.Run("restart picks up an edited config", func(t *testing.T) {
		was := o.servicePID(t, "gotun")
		o.recordArgv(t)
		o.writeConf(t, confWith("GOTUN_MARK_IFACE", "br-lan,ipsec0"))
		o.sh(t, "/etc/init.d/gotun restart")
		now := o.waitNewServicePID(t, "gotun", was)
		if got, _ := flagValue(o.argv(t, "watch"), "mark-iface"); got != "br-lan,ipsec0" {
			t.Errorf("-mark-iface = %q after restart, want br-lan,ipsec0: the restart did not re-read"+
				" the config", got)
		}
		t.Logf("restarted %d -> %d", was, now)
	})

	t.Run("stop withdraws the policy and leaves nothing running", func(t *testing.T) {
		o.recordArgv(t)
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")

		o.sh(t, "/etc/init.d/gotun stop")
		o.poll(t, "gotun to have no running instance", 30*time.Second, func() (bool, string) {
			return o.servicePID(t, "gotun") == 0, ""
		})
		// stop_service runs `gotun clear`, which is what actually removes the
		// ip rule and the nft table. A stop that kills the watcher without
		// clearing would leave the box steering traffic into a table nothing
		// maintains any more.
		var sawClear bool
		for _, inv := range o.invocations(t) {
			if len(inv) > 0 && inv[0] == "clear" {
				sawClear = true
			}
		}
		if !sawClear {
			t.Errorf("stop did not run `gotun clear`; recorded invocations were %q",
				o.invocations(t))
		}
	})

	// rc.common's stop runs stop_service *before* procd_kill, so `gotun clear`
	// runs while the watcher is still alive. The comment in gotun.init claims
	// the opposite ordering. Pinning the real order matters because a tunnel
	// transition inside that window has the watcher re-apply policy that the
	// clear has just removed, leaving the box steered into a table with no
	// supervisor.
	t.Run("clear runs before the watcher is killed", func(t *testing.T) {
		o.recordArgv(t)
		// A shim that records the clear along with whether the watcher was
		// still alive at that moment.
		o.write(t, "/usr/bin/gotun", `#!/bin/sh
{
	echo "=== invocation ==="
	for a in "$@"; do printf ':%s\n' "$a"; done
} >> /tmp/gotun.argv
case "$1" in
	watch) exec sleep infinity ;;
	clear)
		if pgrep -f "sleep infinity" >/dev/null 2>&1; then
			echo watcher-alive > /tmp/clear-order
		else
			echo watcher-gone > /tmp/clear-order
		fi
		;;
esac
exit 0
`)
		o.sh(t, "chmod 0755 /usr/bin/gotun; rm -f /tmp/clear-order")
		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")
		o.sh(t, "/etc/init.d/gotun stop")

		got := strings.TrimSpace(o.sh(t, "cat /tmp/clear-order 2>/dev/null"))
		if got != "watcher-alive" {
			t.Logf("clear observed the watcher as %q", got)
		}
		if got == "watcher-alive" {
			t.Log("confirmed: rc.common runs stop_service before procd_kill, so `gotun clear`" +
				" runs while the watcher is still alive. gotun.init's comment describing the" +
				" opposite ordering is wrong.")
		}
		if got == "" {
			t.Error("the clear shim never ran, so this scenario proved nothing")
		}
		o.recordArgv(t) // restore the plain recorder for later subtests
	})

	// What `start` reports when it refuses is worth pinning: if rc.common
	// swallows start_service's non-zero return, then the operator's primary
	// recovery command reports success while having done nothing, and the next
	// incident is diagnosed from a lie.
	t.Run("a missing config is refused", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.recordArgv(t)
		o.sh(t, "mv /etc/gotun/gotun.conf /etc/gotun/gotun.conf.away")
		t.Cleanup(func() { o.sh(t, "mv /etc/gotun/gotun.conf.away /etc/gotun/gotun.conf") })

		out, rc := o.shRC(t, "/etc/init.d/gotun start 2>&1")
		if pid := o.servicePID(t, "gotun"); pid != 0 {
			t.Errorf("gotun started (pid %d) with no config; it must refuse rather than guess"+
				" a policy", pid)
		}
		if n := len(o.invocations(t)); n != 0 {
			t.Errorf("the binary was invoked %d times despite the config being absent: %q",
				n, o.invocations(t))
		}
		if !strings.Contains(out, "gotun.conf") {
			t.Errorf("the refusal does not name the missing file, so an operator cannot act on"+
				" it: %q", out)
		}
		t.Logf("`/etc/init.d/gotun start` with no config: exit %d, output %q", rc, out)
		if rc == 0 {
			t.Log("note: the command reports success while having started nothing. That is" +
				" rc.common swallowing start_service's return, and it means the operator's" +
				" primary recovery command cannot be trusted to have worked.")
		}
	})

	t.Run("a missing prefix list is refused", func(t *testing.T) {
		o.recordArgv(t)
		o.writeConf(t, owConf)
		o.sh(t, "rm -f /etc/gotun/prefixes.txt")
		t.Cleanup(func() { o.write(t, "/etc/gotun/prefixes.txt", owPrefixes) })

		out, rc := o.shRC(t, "/etc/init.d/gotun start 2>&1")
		if pid := o.servicePID(t, "gotun"); pid != 0 {
			t.Errorf("gotun started (pid %d) with no prefix list. An empty direct set does not"+
				" degrade gracefully -- it tunnels everything, including the traffic that must"+
				" stay local.", pid)
		}
		if !strings.Contains(out, "prefix") {
			t.Errorf("the refusal does not mention the prefix list: %q", out)
		}
		t.Logf("`start` with no prefix list: exit %d, output %q", rc, out)
	})
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// TestOpenWrtPolicy runs the real binary under procd against the real
// nftables-nojson, and is the reason this lab exists at all.
//
// gotun reads its nft state back either as JSON or as text, depending on what
// nft supports. Every other test in this package runs on Debian, where nft has
// JSON -- so the text path, which is the one the router uses, has never run end
// to end anywhere. A misparse there does not fail loudly: it makes gotun
// believe the ruleset differs from what it wants and rebuild the whole thing on
// every tick, forever. That is exactly the bug the two-interface ingress guard
// had, and the second-apply scenario below is what would have caught it.
func TestOpenWrtPolicy(t *testing.T) {
	o := newOpenWrtNode(t, "pol")

	// A dummy stands in for the sing-box tun. It is enough because the config
	// pushes the probe interval out to an hour, so the watchdog never runs
	// during the test and never needs the device to carry anything -- all that
	// is being exercised here is the initial apply, which is what boot does.
	o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0 && ip link set xray0 up")
	o.writeConf(t, owConf)
	o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
	o.waitServicePID(t, "gotun")

	t.Run("the policy is installed", func(t *testing.T) {
		o.poll(t, "the ip rule at priority 100", 30*time.Second, func() (bool, string) {
			out := o.sh(t, "ip rule show")
			return strings.Contains(out, "100:"), out
		})
		if out := o.sh(t, "nft list table inet gotun"); !strings.Contains(out, "ru_nets") {
			t.Errorf("the nft table is missing or has no prefix set:\n%s", out)
		}
		if out := o.sh(t, "ip route show table 100"); !strings.Contains(out, "xray0") {
			t.Errorf("table 100 has no route via the tunnel device:\n%s", out)
		}
	})

	// The one with the most value in the whole lab.
	t.Run("a second apply changes nothing", func(t *testing.T) {
		out := o.sh(t, "/usr/bin/gotun apply"+applyArgsFrom(owConf))
		if !strings.Contains(out, "0 changes") {
			t.Errorf("re-applying the same policy reports changes, so something read back from"+
				" nft does not match what was written. On the router this means the ruleset is"+
				" rebuilt on every tick, forever.\n%s", out)
		}
	})

	t.Run("stop removes everything it installed", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop")
		o.poll(t, "the policy to be withdrawn", 30*time.Second, func() (bool, string) {
			rule := o.sh(t, "ip rule show")
			return !strings.Contains(rule, "100:"), rule
		})
		if out := o.sh(t, "ip route show table 100"); strings.TrimSpace(out) != "" {
			t.Errorf("table 100 still has routes after stop:\n%s", out)
		}
		if out, rc := o.shRC(t, "nft list table inet gotun 2>&1"); rc == 0 {
			t.Errorf("the nft table survives stop:\n%s", out)
		}
	})

	// gotun clear takes no flags and removes a hardcoded set of interfaces. On
	// this deployment both happen to be absent, so it is a no-op -- but a box
	// whose tunnel is named one of them would have `/etc/init.d/gotun stop`
	// delete the live transport out from under its owner.
	t.Run("stop does not delete a device gotun does not own", func(t *testing.T) {
		o.sh(t, "ip link add wg-exit type dummy && ip link set wg-exit up")
		t.Cleanup(func() { o.sh(t, "ip link del wg-exit 2>/dev/null") })

		o.sh(t, "/etc/init.d/gotun start")
		o.waitServicePID(t, "gotun")
		o.sh(t, "/etc/init.d/gotun stop")

		if _, rc := o.shRC(t, "ip link show wg-exit"); rc != 0 {
			t.Error("`/etc/init.d/gotun stop` deleted wg-exit, a device gotun did not create." +
				" On a box whose transport carries that name, stopping gotun takes the" +
				" transport down with it.")
		}
	})
}

// applyArgsFrom turns a gotun.conf into the apply flags equivalent to what
// gotun.init builds for watch, so the second-apply scenario compares like with
// like. It is deliberately a separate, dumb translation: sharing code with the
// init script is the thing being tested.
func applyArgsFrom(conf string) string {
	v := map[string]string{}
	for _, l := range strings.Split(conf, "\n") {
		k, val, ok := strings.Cut(l, "=")
		if ok {
			v[k] = val
		}
	}
	return fmt.Sprintf(
		" -prefixes %s -endpoint %s -tunnel-iface %s -lan %s -mark-iface %s"+
			" -clients-iface %s -fail-mode %s -ipv6 %s -ipv6-fallback %s",
		v["GOTUN_PREFIXES"], v["GOTUN_ENDPOINT"], v["GOTUN_TUNNEL_IFACE"], v["GOTUN_LAN"],
		v["GOTUN_MARK_IFACE"], v["GOTUN_CLIENTS_IFACE"], v["GOTUN_FAIL_MODE"],
		v["GOTUN_IPV6"], v["GOTUN_IPV6_FALLBACK"])
}

// TestOpenWrtDegradedStart measures what happens when the tunnel device does
// not exist yet at start, which is the ordinary case on every reboot: gotun is
// START=99 and sing-box is still coming up.
//
// gotun.init's header promises graceful degradation here. Half of that is true
// and the half that is not costs real CPU on the router, so both halves are
// pinned: whichever way the refactor resolves it, it has to argue with this
// test rather than with a comment.
func TestOpenWrtDegradedStart(t *testing.T) {
	o := newOpenWrtNode(t, "degr")
	o.writeConf(t, owConf) // names xray0, which is deliberately never created
	o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")

	// The promise that holds: the classifier goes in, and table 100 is left
	// empty. An ip rule pointing at an empty table falls through to main, so
	// traffic keeps flowing on the uplink -- degraded, not broken.
	t.Run("the classifier is installed and traffic is not black-holed", func(t *testing.T) {
		o.poll(t, "the nft table to appear", 30*time.Second, func() (bool, string) {
			_, rc := o.shRC(t, "nft list table inet gotun >/dev/null 2>&1")
			return rc == 0, ""
		})
		if !strings.Contains(o.sh(t, "ip rule show"), "100:") {
			t.Error("no ip rule at priority 100, so nothing is classified at all")
		}
		out := o.sh(t, "ip route show table 100 2>&1")
		if strings.Contains(out, "default") {
			t.Errorf("table 100 has a default route although the tunnel device is absent: %q", out)
		}
	})

	// The promise that does not hold. Watch returns an error from its initial
	// apply, and `respawn 3600 5 0` has an unlimited retry count, so procd
	// restarts it every five seconds for as long as the device stays missing --
	// rebuilding the whole nft table each time, which on the router is some
	// 17,000 set elements.
	//
	// It does self-heal: once the device appears, the next respawn succeeds.
	// The cost is the interval before that, and the pathological case is a
	// transport that never comes up at all.
	t.Run("the service crash-loops instead of degrading", func(t *testing.T) {
		// Counted from syslog, not by sampling the supervised pid. During a
		// respawn loop the instance spends most of its time *not* running --
		// it sits in procd's five-second gap -- so polling for a live pid
		// catches nothing and would read as "started once, stable". The count
		// of failed initial applies is direct evidence and cannot be missed.
		first := o.applyFailures(t)
		time.Sleep(11 * time.Second)
		second := o.applyFailures(t)

		t.Logf("failed initial applies: %d, then %d eleven seconds later", first, second)
		if first == 0 {
			t.Fatal("the initial apply did not fail at all, so this scenario is no longer" +
				" measuring what it was written for -- re-read it before deleting it")
		}
		if second <= first {
			t.Logf("note: the count stopped growing, so the service is no longer restarting." +
				" If Watch has been changed to survive a failed initial apply, this scenario" +
				" is now the regression guard for that and should assert a stable pid instead.")
			return
		}
		// Roughly one attempt per five seconds, each one rebuilding the entire
		// nft table -- on the router, some 17,000 set elements.
		t.Logf("confirmed: procd is restarting gotun about every %.1fs and will keep doing so"+
			" for as long as the device is missing, because `respawn 3600 5 0` has an"+
			" unlimited retry count", 11.0/float64(second-first))
	})

	// And the recovery path, which is what makes the crash loop survivable
	// rather than fatal: the device appearing is enough.
	t.Run("it converges once the device appears", func(t *testing.T) {
		o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
			" && ip link set xray0 up")
		o.poll(t, "table 100 to gain the tunnel route", 45*time.Second, func() (bool, string) {
			out := o.sh(t, "ip route show table 100 2>&1")
			return strings.Contains(out, "xray0"), out
		})
		// And the restarting stops, which is the other half of converging.
		settled := o.applyFailures(t)
		time.Sleep(7 * time.Second)
		if now := o.applyFailures(t); now != settled {
			t.Errorf("the initial apply is still failing after the device appeared"+
				" (%d -> %d failures)", settled, now)
		}
	})
}

// TestOpenWrtHotplug drives the hook the way netifd does, through
// /sbin/hotplug-call, so the filename ordering and the dispatch are the real
// ones rather than a direct invocation of the script.
func TestOpenWrtHotplug(t *testing.T) {
	o := newOpenWrtNode(t, "hp")
	o.writeConf(t, owConf)
	o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
		" && ip link set xray0 up")
	o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
	o.waitServicePID(t, "gotun")
	o.poll(t, "the initial policy", 30*time.Second, func() (bool, string) {
		out := o.sh(t, "ip route show table 100")
		return strings.Contains(out, "xray0"), out
	})

	ifup := func(iface string) string {
		return fmt.Sprintf("ACTION=ifup INTERFACE=%s DEVICE=%s /sbin/hotplug-call iface", iface, iface)
	}

	// The reason the hook exists. A transport bounce has the kernel withdraw
	// the device route from table 100, and only a re-apply puts it back; until
	// then the gateway is a classifier that marks traffic into an empty table,
	// so geo-routing has quietly stopped while everything still appears to work.
	t.Run("ifup of the tunnel restores a withdrawn route", func(t *testing.T) {
		o.sh(t, "ip route flush table 100")
		if out := o.sh(t, "ip route show table 100 2>&1"); strings.Contains(out, "xray0") {
			t.Fatalf("precondition: table 100 should be empty here, got %q", out)
		}

		o.sh(t, ifup("xray0"))
		restored := false
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if strings.Contains(o.sh(t, "ip route show table 100"), "xray0") {
				restored = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if !restored {
			t.Error("ifup of the tunnel did not restore the route. The hook's last line is" +
				" `/etc/init.d/gotun start`, and procd's start on a running service is a" +
				" no-op -- so the re-apply the hook exists to perform never happens." +
				" See TestOpenWrtLifecycle/start_on_a_running_service_is_a_no-op.")
		}
		if out := o.sh(t, "grep 'reapplying policy after ifup' /var/log/messages"); out == "" {
			t.Error("the hook did not even log that it had fired, so it did not match the" +
				" interface at all")
		}
	})

	t.Run("an unrelated interface is ignored", func(t *testing.T) {
		o.clearSyslog(t)
		o.sh(t, ifup("lan"))
		if out := o.sh(t, "grep -c 'reapplying policy' /var/log/messages"); strings.TrimSpace(out) != "0" {
			t.Errorf("the hook reacted to an ifup of an unrelated interface (%q matches)", out)
		}
	})

	t.Run("ifdown is ignored", func(t *testing.T) {
		o.clearSyslog(t)
		o.sh(t, "ACTION=ifdown INTERFACE=xray0 DEVICE=xray0 /sbin/hotplug-call iface")
		if out := o.sh(t, "grep -c 'reapplying policy' /var/log/messages"); strings.TrimSpace(out) != "0" {
			t.Errorf("the hook reacted to an ifdown (%q matches)", out)
		}
	})

	// Without this gate the hook re-arms the policy on any ifup, including one
	// done while debugging a dead tunnel -- which is how it once put every LAN
	// client back onto a broken path after the operator had torn the policy
	// down deliberately.
	t.Run("a disabled service is left alone", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun stop && /etc/init.d/gotun disable")
		t.Cleanup(func() { o.sh(t, "/etc/init.d/gotun enable") })
		o.clearSyslog(t)

		o.sh(t, ifup("xray0"))
		if out := o.sh(t, "grep -c 'reapplying policy' /var/log/messages"); strings.TrimSpace(out) != "0" {
			t.Errorf("the hook fired for a disabled service (%q matches)", out)
		}
	})
}

// TestOpenWrtDNS covers gotun-dns's one deployment-specific decision.
func TestOpenWrtDNS(t *testing.T) {
	o := newOpenWrtNode(t, "dns")

	// The trip-wire for the refactor. gotun-dns's own default is :53, and
	// 127.0.0.2:53 exists only as a shell fallback in the init script -- so the
	// moment that mapping moves into Go without carrying the override, this
	// service starts binding the address dnsmasq already owns. dnsmasq is
	// started here deliberately to make the collision real rather than
	// hypothetical.
	t.Run("it does not collide with dnsmasq on port 53", func(t *testing.T) {
		o.sh(t, "/etc/init.d/dnsmasq start")
		o.poll(t, "dnsmasq to own :53", 30*time.Second, func() (bool, string) {
			out := o.sh(t, "netstat -lnup 2>/dev/null | grep ':53 '")
			return strings.Contains(out, "dnsmasq"), out
		})

		o.sh(t, "/etc/init.d/gotun-dns enable && /etc/init.d/gotun-dns start")
		pid := o.waitServicePID(t, "gotun-dns")
		t.Logf("gotun-dns supervised pid %d", pid)

		listeners := o.sh(t, "netstat -lnup 2>/dev/null | grep ':53 '")
		if !strings.Contains(listeners, "127.0.0.2:53") {
			t.Errorf("gotun-dns is not listening on 127.0.0.2:53:\n%s", listeners)
		}
		if strings.Contains(listeners, "0.0.0.0:53") {
			t.Errorf("something bound 0.0.0.0:53, which is dnsmasq's address on this box:\n%s",
				listeners)
		}
	})

	t.Run("its own config file is honoured", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun-dns stop")
		o.write(t, "/etc/gotun/gotun-dns.conf", "GOTUN_DNS_LISTEN=127.0.0.3:5353\n")
		o.sh(t, "/etc/init.d/gotun-dns start")
		o.waitServicePID(t, "gotun-dns")

		o.poll(t, "the configured address to be bound", 20*time.Second, func() (bool, string) {
			out := o.sh(t, "netstat -lnup 2>/dev/null | grep ':5353 '")
			return strings.Contains(out, "127.0.0.3:5353"), out
		})
	})
}

// TestOpenWrtIPsec covers the xfrm device the IKEv2 CHILD_SA surfaces on.
func TestOpenWrtIPsec(t *testing.T) {
	o := newOpenWrtNode(t, "ipsec")
	o.writeConf(t, owConf)

	t.Run("start creates the device from the config", func(t *testing.T) {
		if out, rc := o.shRC(t, "/etc/init.d/gotun-ipsec start 2>&1"); rc != 0 {
			t.Fatalf("start failed (rc=%d): %s", rc, out)
		}
		out := o.sh(t, "ip -d link show ipsec0")
		if !strings.Contains(out, "xfrm") {
			t.Fatalf("ipsec0 is not an xfrm device:\n%s", out)
		}
		if !strings.Contains(out, "if_id 0x61") {
			t.Errorf("want if_id 0x61 in:\n%s", out)
		}
		if !strings.Contains(out, "mtu 1400") {
			t.Errorf("want mtu 1400 in:\n%s", out)
		}
		// The address is load-bearing: charon installs no route for an xfrm
		// interface, so without an on-link prefix every reply to a client fails
		// source address selection while the SA still reads ESTABLISHED.
		if addr := o.sh(t, "ip -o -4 addr show dev ipsec0"); !strings.Contains(addr, "10.231.17.1/24") {
			t.Errorf("want 10.231.17.1/24 on ipsec0, got %q", addr)
		}
	})

	// The config used to be read at file scope, before start() sourced it, so
	// every GOTUN_IPSEC_* value an operator set was silently ignored and the
	// script used its own defaults. Nothing announced it: the device came up,
	// just not the one that was asked for.
	t.Run("non-default values from the config take effect", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun-ipsec stop")
		conf := confWith("GOTUN_IPSEC_IFACE", "ipsec9")
		conf = strings.ReplaceAll(conf, "GOTUN_IPSEC_IFID=0x61", "GOTUN_IPSEC_IFID=0x62")
		conf = strings.ReplaceAll(conf, "GOTUN_IPSEC_ADDR=10.231.17.1/24", "GOTUN_IPSEC_ADDR=10.231.18.1/24")
		conf = strings.ReplaceAll(conf, "GOTUN_IPSEC_MTU=1400", "GOTUN_IPSEC_MTU=1380")
		o.writeConf(t, conf)

		if out, rc := o.shRC(t, "/etc/init.d/gotun-ipsec start 2>&1"); rc != 0 {
			t.Fatalf("start failed (rc=%d): %s", rc, out)
		}
		out := o.sh(t, "ip -d link show ipsec9 2>&1")
		for _, want := range []string{"xfrm", "if_id 0x62", "mtu 1380"} {
			if !strings.Contains(out, want) {
				t.Errorf("want %q in:\n%s", want, out)
			}
		}
		if addr := o.sh(t, "ip -o -4 addr show dev ipsec9"); !strings.Contains(addr, "10.231.18.1/24") {
			t.Errorf("want 10.231.18.1/24 on ipsec9, got %q", addr)
		}
		// stop must resolve the same name start did, or it deletes nothing.
		o.sh(t, "/etc/init.d/gotun-ipsec stop")
		if _, rc := o.shRC(t, "ip link show ipsec9 2>/dev/null"); rc == 0 {
			t.Error("stop left ipsec9 behind: it resolved a different interface name than" +
				" start created, which happens when it does not read the config")
		}
		o.writeConf(t, owConf)
	})

	// A phone's live SA is bound to this device. Recreating it on every start
	// would drop every established session, so a second start must reassert the
	// address and MTU and leave the device itself alone.
	t.Run("a second start does not disturb a live device", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun-ipsec start")
		before := strings.Fields(o.sh(t, "cat /sys/class/net/ipsec0/ifindex"))
		o.sh(t, "/etc/init.d/gotun-ipsec start")
		after := strings.Fields(o.sh(t, "cat /sys/class/net/ipsec0/ifindex"))
		if len(before) == 0 || len(after) == 0 || before[0] != after[0] {
			t.Errorf("the device was recreated (ifindex %v -> %v); every established SA on it"+
				" would have been dropped", before, after)
		}
	})

	t.Run("stop removes it and is idempotent", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun-ipsec stop")
		if _, rc := o.shRC(t, "ip link show ipsec0 2>/dev/null"); rc == 0 {
			t.Error("ipsec0 survived stop")
		}
		if out, rc := o.shRC(t, "/etc/init.d/gotun-ipsec stop 2>&1"); rc != 0 {
			t.Errorf("stopping an already-stopped service must succeed, got rc=%d: %s", rc, out)
		}
	})

	// The xfrm device has to exist before anything routes into it.
	t.Run("it starts before gotun in the boot order", func(t *testing.T) {
		o.sh(t, "/etc/init.d/gotun-ipsec enable && /etc/init.d/gotun enable")
		out := o.sh(t, "ls /etc/rc.d/ | grep -E 'gotun' | sort")
		ipsec := strings.Index(out, "S89gotun-ipsec")
		gotun := strings.Index(out, "S99gotun")
		if ipsec < 0 || gotun < 0 {
			t.Fatalf("expected both S89gotun-ipsec and S99gotun in:\n%s", out)
		}
		if ipsec > gotun {
			t.Errorf("gotun-ipsec sorts after gotun, so the device would be created after the"+
				" thing that routes into it:\n%s", out)
		}
	})
}

// TestOpenWrtSingbox covers singbox.init's two gates. sing-box itself is a
// twenty-line fake: the subject is whether the init script refuses to start a
// transport whose config is bad, not what sing-box does with a good one.
func TestOpenWrtSingbox(t *testing.T) {
	o := newOpenWrtNode(t, "sb")

	installFake := func(checkRC int) {
		o.write(t, "/usr/bin/sing-box", fmt.Sprintf(`#!/bin/sh
printf ':%%s\n' "$@" >> /tmp/singbox.argv
case "$1" in
	check) exit %d ;;
	run)   exec sleep infinity ;;
esac
exit 0
`, checkRC))
		o.sh(t, "chmod 0755 /usr/bin/sing-box; : > /tmp/singbox.argv")
	}

	t.Run("a missing config is refused", func(t *testing.T) {
		installFake(0)
		o.sh(t, "rm -f /etc/gotun/singbox.json")
		out, _ := o.shRC(t, "/etc/init.d/singbox start 2>&1")
		if pid := o.servicePID(t, "singbox"); pid != 0 {
			t.Errorf("sing-box started (pid %d) with no config", pid)
		}
		if !strings.Contains(out, "missing") {
			t.Errorf("the refusal does not say the config is missing: %q", out)
		}
	})

	// The check gate is the only thing standing between a bad config and a
	// transport that comes up at boot and routes nothing.
	t.Run("a config sing-box rejects is refused", func(t *testing.T) {
		installFake(1)
		o.write(t, "/etc/gotun/singbox.json", "{}")
		out, _ := o.shRC(t, "/etc/init.d/singbox start 2>&1")
		if pid := o.servicePID(t, "singbox"); pid != 0 {
			t.Errorf("sing-box started (pid %d) although check rejected its config", pid)
		}
		if !strings.Contains(out, "rejected") {
			t.Errorf("the refusal does not mention the rejected config: %q", out)
		}
	})

	t.Run("a good config starts it with the expected argv", func(t *testing.T) {
		installFake(0)
		o.write(t, "/etc/gotun/singbox.json", "{}")
		o.sh(t, "/etc/init.d/singbox start")
		o.waitServicePID(t, "singbox")

		argv := o.sh(t, "grep -A2 '^:run$' /tmp/singbox.argv | tr -d ':' | tr '\\n' ' '")
		if !strings.Contains(argv, "run") || !strings.Contains(argv, "-c") ||
			!strings.Contains(argv, "/etc/gotun/singbox.json") {
			t.Errorf("want `run -c /etc/gotun/singbox.json`, recorded %q", argv)
		}
	})
}

// TestOpenWrtHotplugDoesNotRevive is the other half of the hook's gate, split
// out because it needs the service enabled and stopped, which the scenarios in
// TestOpenWrtHotplug deliberately leave running.
//
// The hook re-applies with `restart`, since procd's start on a running service
// is a no-op. That makes the `enabled` check insufficient on its own: enabled
// means "starts at boot", so a service the operator stopped on purpose -- to
// debug a dead tunnel, say -- is still enabled, and restarting it on any ifup
// would put every LAN client back onto the path the operator had just torn
// down. Which is exactly the failure the enabled check was written to prevent.
func TestOpenWrtHotplugDoesNotRevive(t *testing.T) {
	o := newOpenWrtNode(t, "hprev")
	o.writeConf(t, owConf)
	o.sh(t, "ip link add xray0 type dummy && ip addr add 10.70.0.1/24 dev xray0"+
		" && ip link set xray0 up")
	o.sh(t, "/etc/init.d/gotun enable && /etc/init.d/gotun start")
	o.waitServicePID(t, "gotun")

	// Stopped on purpose, and left enabled -- which is what `stop` does.
	o.sh(t, "/etc/init.d/gotun stop")
	o.poll(t, "gotun to be stopped", 30*time.Second, func() (bool, string) {
		return o.servicePID(t, "gotun") == 0, ""
	})
	if _, rc := o.shRC(t, "/etc/init.d/gotun enabled"); rc != 0 {
		t.Fatal("precondition: stop should leave the service enabled")
	}
	o.clearSyslog(t)

	o.sh(t, "ACTION=ifup INTERFACE=xray0 DEVICE=xray0 /sbin/hotplug-call iface")
	time.Sleep(2 * time.Second)

	if pid := o.servicePID(t, "gotun"); pid != 0 {
		t.Errorf("the hook revived a service the operator had stopped (pid %d)", pid)
	}
	if out := o.sh(t, "grep -c 'reapplying policy' /var/log/messages"); strings.TrimSpace(out) != "0" {
		t.Errorf("the hook re-applied the policy for a stopped service (%q matches)", out)
	}
}
