//go:build integration

package integration_test

// Scenarios for the OpenWrt deploy lab. See openwrt_fixture_test.go for what
// this lab is for and what it deliberately does not test.

import (
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
