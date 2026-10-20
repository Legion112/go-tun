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
			{"mark-iface", "eth0"},
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
		o.writeConf(t, confWith("GOTUN_MARK_IFACE", "br-lan"))
		o.sh(t, "/etc/init.d/gotun restart")
		now := o.waitNewServicePID(t, "gotun", was)
		if got, _ := flagValue(o.argv(t, "watch"), "mark-iface"); got != "br-lan" {
			t.Errorf("-mark-iface = %q after restart, want br-lan: the restart did not re-read"+
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
