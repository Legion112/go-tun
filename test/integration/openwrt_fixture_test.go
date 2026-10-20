//go:build integration

package integration_test

// The fixture for the OpenWrt deploy lab.
//
// This lab answers a different question from every other test in this package.
// The others ask whether a packet reaches the right place; this one asks whether
// the five shell scripts in deploy/openwrt/ hand the binary the right arguments,
// under the real init system, in the real boot order. Anything here that starts
// asserting on where packets end up is duplicating topology_test.go at several
// times the cost, so it belongs there instead.
//
// Two things about the container are worth knowing before reading further,
// because both were found the hard way and both present as something else:
//
//   - procd must be PID 1 and must be *answering ubus*. Those are not the same
//     condition. A procd blocked on a syslog write stays alive, keeps its ubus
//     object registered, and simply never replies -- at which point
//     `/etc/init.d/x start` hangs forever instead of failing. The readiness
//     ladder below therefore polls the service object itself, not the process.
//   - the image disables netifd and logd for reasons given in its Dockerfile.
//     So there is no `logread` here; syslog arrives in /var/log/messages
//     courtesy of logsink, which is where procd's messages and every service's
//     stderr can be read.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

const openwrtImage = "gotun:openwrt"

// deployFiles are the files the README installs on the router, mapped to where
// it installs them. The lab copies them from the working tree at run time and
// never bakes them into the image: a cached image carrying last week's
// gotun.init would silently test last week's script, in a suite whose entire
// purpose is confidence that nothing changed.
var deployFiles = map[string]string{
	"gotun.init":          "/etc/init.d/gotun",
	"gotun-dns.init":      "/etc/init.d/gotun-dns",
	"gotun-ipsec.init":    "/etc/init.d/gotun-ipsec",
	"singbox.init":        "/etc/init.d/singbox",
	"hotplug-iface-gotun": "/etc/hotplug.d/iface/99-gotun",
}

type owLab struct {
	lab  *harness.Lab
	node string
}

// newOpenWrtNode boots one OpenWrt container with procd as PID 1 and waits
// until procd is actually serving, then installs the deploy scripts.
func newOpenWrtNode(t *testing.T, prefixHint string) *owLab {
	t.Helper()
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	// Fatal rather than Skip, deliberately: CI fails the lab job on any
	// `--- SKIP`, so a lab that quietly stops running is a red build rather
	// than a green one that proves nothing.
	if err := harness.ImageExists(ctx, openwrtImage); err != nil {
		t.Fatalf("image %s missing; run make docker-build-openwrt: %v", openwrtImage, err)
	}

	prefix := fmt.Sprintf("gotunow%s%d", prefixHint, time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "ow-net", "10.60.0.0/24"))
	// /sbin/init, not the harness default of `sleep infinity`: the whole point
	// is that procd runs the init scripts the way the router does.
	must(t, lab.RunContainer(ctx, "gw", openwrtImage, "10.60.0.10", "ow-net", nil, harness.RunOpts{
		Entrypoint: []string{"/sbin/init"},
		Cmd:        []string{},
	}))

	o := &owLab{lab: lab, node: "gw"}
	o.waitProcd(t)
	o.installDeploy(t)
	return o
}

func (o *owLab) exec(t *testing.T, args ...string) string {
	t.Helper()
	out, err := o.lab.Exec(context.Background(), o.node, args...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// sh runs a shell snippet and returns its combined output, ignoring the exit
// status. Note `sh`, not `bash`: this is busybox ash, and bash does not exist.
func (o *owLab) sh(t *testing.T, script string) string {
	t.Helper()
	out, _ := o.lab.Exec(context.Background(), o.node, "sh", "-c", script)
	return out
}

// shRC runs a shell snippet and reports its exit status separately, for the
// scenarios whose entire subject is whether a service refused to start.
func (o *owLab) shRC(t *testing.T, script string) (string, int) {
	t.Helper()
	out, _ := o.lab.Exec(context.Background(), o.node,
		"sh", "-c", script+"; echo __rc=$?")
	rc := -1
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "__rc="); ok {
			fmt.Sscanf(v, "%d", &rc)
		}
	}
	// Strip the marker so callers can assert on the real output.
	i := strings.LastIndex(out, "__rc=")
	if i >= 0 {
		out = out[:i]
	}
	return out, rc
}

// waitProcd is a ladder of distinct observable facts, each polled rather than
// slept on. They are separate rungs because each one failing means something
// different, and because a lab that proceeds past any of them produces tests
// that pass while proving nothing.
func (o *owLab) waitProcd(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	must(t, o.lab.WaitReady(ctx, o.node))

	// Rung 1: PID 1 is procd. If an image change ever makes it a shell, every
	// `/etc/init.d/x start` below would run as a plain function call, outside
	// supervision, and the whole supervision half of this lab would pass
	// vacuously.
	o.poll(t, "PID 1 is procd", 30*time.Second, func() (bool, string) {
		out := o.sh(t, "cat /proc/1/comm")
		return strings.TrimSpace(out) == "procd", out
	})

	// Rung 2: ubusd accepts connections.
	o.poll(t, "ubusd answers", 30*time.Second, func() (bool, string) {
		out, rc := o.shRC(t, "ubus -t 5 list >/dev/null 2>&1")
		return rc == 0, out
	})

	// Rung 3: procd's own service object replies. This is the rung that
	// matters: until it does, `/etc/init.d/x start` appears to work and
	// supervises nothing, or hangs.
	o.poll(t, "procd service object replies", 60*time.Second, func() (bool, string) {
		out, rc := o.shRC(t, "ubus -t 5 call service list >/dev/null 2>&1")
		return rc == 0, out
	})

	// Rung 4: syslog is being collected, or every assertion about a service's
	// stderr below would silently match nothing.
	o.poll(t, "logsink is collecting syslog", 30*time.Second, func() (bool, string) {
		out, rc := o.shRC(t, "test -S /dev/log && test -f /var/log/messages")
		return rc == 0, out
	})
}

func (o *owLab) poll(t *testing.T, what string, timeout time.Duration, f func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ok, out := f()
		if ok {
			return
		}
		last = out
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s.\nlast output: %s\nsyslog:\n%s",
		timeout, what, last, o.sh(t, "tail -40 /var/log/messages 2>/dev/null"))
}

// installDeploy puts the working tree's scripts where the README puts them.
//
// It chmods them, and a static test in internal/cli owns the file modes
// instead. The split is deliberate: if this did not chmod, every scenario would
// fail for a reason unrelated to its subject, and if the static test did not
// exist, a 0644 init script would never be noticed at all -- which is exactly
// what had happened to gotun-ipsec.init.
func (o *owLab) installDeploy(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	must(t, o.lab.ExecOK(ctx, o.node, "mkdir", "-p", "/etc/gotun", "/etc/hotplug.d/iface"))
	for src, dst := range deployFiles {
		must(t, o.lab.Copy(ctx, o.node, filepath.Join("../../deploy/openwrt", src), dst))
		must(t, o.lab.ExecOK(ctx, o.node, "chmod", "0755", dst))
	}
}

// write puts content at path inside the container.
func (o *owLab) write(t *testing.T, path, content string) {
	t.Helper()
	host := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(host, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	must(t, o.lab.Copy(context.Background(), o.node, host, path))
}

// recordArgv replaces /usr/bin/gotun with a shim that records the arguments it
// was given.
//
// Most deploy-layer defects are "the init script handed the binary the wrong
// argv", and proving that through kernel state is slow, indirect, and couples
// the assertion to policy behaviour that topology_test.go already covers. The
// exact argv the deployed script produced is a list of strings, and that is what
// should be asserted on.
//
// One argument per line, not "$*". Flattening to a single string loses argument
// boundaries, and the boundary is the whole point here: a flag passed an empty
// value and a flag not passed at all look identical once joined by spaces, yet
// they do opposite things -- the first overrides the Go default with nothing,
// the second lets it apply. An earlier version of this shim used "$*" and so
// could not have detected the defect it was written for.
//
// Each line carries a leading sentinel so that no line is ever empty, because
// harness.Exec trims its output: a trailing empty argument -- which is exactly
// what a flag passed an unset variable produces, and the last flag gotun.init
// passes is one -- would otherwise be trimmed away and read as absent.
//
// It sleeps only for `watch`, so procd sees a healthy long-running service
// instead of respawn-storming, and exits 0 for everything else -- `clear` in
// particular, which stop_service runs synchronously and which would otherwise
// hang the stop.
func (o *owLab) recordArgv(t *testing.T) {
	t.Helper()
	o.write(t, "/usr/bin/gotun", `#!/bin/sh
{
	echo "`+argvMarker+`"
	for a in "$@"; do printf '`+argvPrefix+`%s\n' "$a"; done
} >> `+argvFile+`
case "$1" in
	watch) exec sleep infinity ;;
esac
exit 0
`)
	must(t, o.lab.ExecOK(context.Background(), o.node, "chmod", "0755", "/usr/bin/gotun"))
	o.sh(t, ": > "+argvFile)
}

const (
	argvFile   = "/tmp/gotun.argv"
	argvMarker = "=== invocation ==="
	argvPrefix = ":"
)

// invocations returns every recorded call, each as its own argument list.
func (o *owLab) invocations(t *testing.T) [][]string {
	t.Helper()
	var all [][]string
	cur := -1
	for _, l := range strings.Split(o.sh(t, "cat "+argvFile+" 2>/dev/null"), "\n") {
		if l == argvMarker {
			all = append(all, nil)
			cur = len(all) - 1
			continue
		}
		arg, ok := strings.CutPrefix(l, argvPrefix)
		if !ok || cur < 0 {
			continue // blank padding, or output before the first marker
		}
		all[cur] = append(all[cur], arg)
	}
	return all
}

// argv returns the single recorded invocation of one subcommand, failing if
// there is not exactly one. "Exactly one" is part of the assertion: two
// recorded `watch` calls mean procd started a second instance, and two
// instances would fight over ip rule priority 100.
func (o *owLab) argv(t *testing.T, subcommand string) []string {
	t.Helper()
	var hits [][]string
	for _, inv := range o.invocations(t) {
		if len(inv) > 0 && inv[0] == subcommand {
			hits = append(hits, inv)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one recorded `gotun %s`, got %d: %q", subcommand, len(hits), hits)
	}
	return hits[0]
}

// flagValue pulls one flag's value out of a recorded argv.
//
// The two return values are different facts and callers depend on both: a flag
// that is absent lets the Go default apply, while a flag present with an empty
// value replaces that default with nothing.
func flagValue(argv []string, name string) (string, bool) {
	for i, w := range argv {
		if w == "-"+name {
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", true
		}
	}
	return "", false
}

// --- a realistic configuration ---------------------------------------------

// owConf is the config the scenarios start from: the shape of the live
// router's, with lab addresses. Probing is pushed out of the way on purpose --
// these scenarios are about the initial apply and the service lifecycle, and a
// watchdog that withdraws the route three minutes in because 1.1.1.1 is not
// reachable from an internal bridge would flap a later assertion and get
// blamed on something else.
const owConf = `GOTUN_PREFIXES=/etc/gotun/prefixes.txt
GOTUN_ENDPOINT=10.60.0.2
GOTUN_TUNNEL_IFACE=xray0
GOTUN_LAN=10.60.0.0/24
GOTUN_MARK_IFACE=eth0
GOTUN_CLIENTS_IFACE=ipsec0
GOTUN_DIRECT_SRC=
GOTUN_FAIL_MODE=open
GOTUN_IPV6=off
GOTUN_IPV6_FALLBACK=direct
GOTUN_PROBE_TARGET=10.60.0.2:443
GOTUN_PROBE_INTERVAL=1h
GOTUN_FAIL_AFTER=3
GOTUN_RECOVER_AFTER=2
GOTUN_HEALTH_LISTEN=
GOTUN_IPSEC_IFACE=ipsec0
GOTUN_IPSEC_IFID=0x61
GOTUN_IPSEC_ADDR=10.231.17.1/24
GOTUN_IPSEC_MTU=1400
GOTUN_IPSEC_PARENT=lo
`

const owPrefixes = "77.88.8.0/24\n5.255.255.0/24\n"

func (o *owLab) writeConf(t *testing.T, conf string) {
	t.Helper()
	o.write(t, "/etc/gotun/gotun.conf", conf)
	o.write(t, "/etc/gotun/prefixes.txt", owPrefixes)
}

// confWithout returns owConf with one variable's assignment removed, for the
// scenarios about a config that lost a line -- a half-written file after a
// sysupgrade, say.
func confWithout(key string) string {
	var out []string
	for _, l := range strings.Split(owConf, "\n") {
		if strings.HasPrefix(l, key+"=") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// confWith returns owConf with one variable's value replaced.
func confWith(key, value string) string {
	var out []string
	for _, l := range strings.Split(owConf, "\n") {
		if strings.HasPrefix(l, key+"=") {
			out = append(out, key+"="+value)
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// --- asking procd what it is supervising -----------------------------------

// procdInstance is the part of `ubus call service list` this lab reads back.
// It is parsed rather than grepped because the two facts that matter -- whether
// an instance exists at all, and what pid it has -- are exactly the two a grep
// conflates: procd restarting a crash-looping instance every five seconds
// satisfies "a pid appears in the output" forever.
type procdInstance struct {
	Running bool     `json:"running"`
	Pid     int      `json:"pid"`
	Command []string `json:"command"`
}

type procdService struct {
	Instances map[string]procdInstance `json:"instances"`
}

// service returns what procd currently knows about one service. A service procd
// has never been told about is absent from the map, which is different from a
// service it knows about with no running instance.
func (o *owLab) service(t *testing.T, name string) (procdService, bool) {
	t.Helper()
	out := o.sh(t, fmt.Sprintf("ubus -t 5 -S call service list '{\"name\":\"%s\"}'", name))
	m := map[string]procdService{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		t.Fatalf("parsing `ubus call service list` for %s: %v\noutput: %q", name, err, out)
	}
	svc, ok := m[name]
	return svc, ok
}

// servicePID returns the pid of the one running instance, or 0. It insists on
// there being at most one: two instances of gotun would be two processes
// fighting over ip rule priority 100.
func (o *owLab) servicePID(t *testing.T, name string) int {
	t.Helper()
	svc, ok := o.service(t, name)
	if !ok {
		return 0
	}
	var pids []int
	for _, inst := range svc.Instances {
		if inst.Running && inst.Pid != 0 {
			pids = append(pids, inst.Pid)
		}
	}
	if len(pids) > 1 {
		t.Fatalf("%s has %d running instances (%v); they would fight over the same policy",
			name, len(pids), pids)
	}
	if len(pids) == 0 {
		return 0
	}
	return pids[0]
}

// waitServicePID waits for a running instance to appear and returns its pid.
func (o *owLab) waitServicePID(t *testing.T, name string) int {
	t.Helper()
	var pid int
	o.poll(t, "a supervised instance of "+name, 30*time.Second, func() (bool, string) {
		pid = o.servicePID(t, name)
		return pid != 0, fmt.Sprintf("pid=%d", pid)
	})
	return pid
}

// waitNewServicePID waits until the running instance's pid differs from was,
// which is how a respawn or a restart is observed without sleeping for the
// respawn threshold.
func (o *owLab) waitNewServicePID(t *testing.T, name string, was int) int {
	t.Helper()
	var pid int
	o.poll(t, fmt.Sprintf("%s to come back with a pid other than %d", name, was),
		45*time.Second, func() (bool, string) {
			pid = o.servicePID(t, name)
			return pid != 0 && pid != was, fmt.Sprintf("pid=%d", pid)
		})
	return pid
}
