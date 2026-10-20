package cli

// Static guards over deploy/openwrt/.
//
// Those scripts are the only thing that turns /etc/gotun/gotun.conf into a
// running service on the household's only gateway, and every parameter in them
// is described three times: once in gotun.conf.example as documentation, once
// in an init script as a mapping to a flag, and once in Go as a flag and a
// default. Nothing checks that the three agree.
//
// These tests check it, in milliseconds and with no container. They live in
// package cli because that is where the flag sets are: comparing against the
// real flag.FlagSet rather than against a list copied out of it is the whole
// point, since a copied list drifts in exactly the same way the shell does.
//
// The failure being guarded against is not subtle. START=99 means gotun starts
// last at boot; a flag renamed in Go and not in the script makes that start
// fail with "flag provided but not defined", and the first anyone hears of it
// is that the house has no internet after a reboot.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/policy"
)

const deployDir = "../../deploy/openwrt"

// shellFlag is one `-flag "value"` as an init script passes it.
type shellFlag struct {
	name string
	// raw is the value exactly as written, e.g. `$GOTUN_LAN` or
	// `${GOTUN_IPV6:-off}` or a bare literal.
	raw  string
	line int
}

// varName is the GOTUN_* variable the value reads, or "" for a literal.
func (f shellFlag) varName() string {
	if m := varRefRe.FindStringSubmatch(f.raw); m != nil {
		return m[1]
	}
	return ""
}

// shellDefault is the `:-default` fallback, and whether there was one. A flag
// whose value is a bare "$VAR" has no fallback, which means an unset variable
// hands the binary an empty string rather than letting the Go default apply.
func (f shellFlag) shellDefault() (string, bool) {
	if m := varDefaultRe.FindStringSubmatch(f.raw); m != nil {
		return m[2], true
	}
	return "", false
}

var (
	flagRe       = regexp.MustCompile(`(?m)^\s*-([a-z0-9][a-z0-9-]*)\s+"([^"]*)"`)
	varRefRe     = regexp.MustCompile(`^\$\{?([A-Z_][A-Z0-9_]*)`)
	varDefaultRe = regexp.MustCompile(`^\$\{([A-Z_][A-Z0-9_]*):-([^}]*)\}$`)
	anyVarRe     = regexp.MustCompile(`\$\{?(GOTUN_[A-Z0-9_]+)`)
	assignRe     = regexp.MustCompile(`(?m)^\s*(?:export\s+)?(GOTUN_[A-Z0-9_]+)=`)
)

func readDeploy(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(deployDir, name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// codeLines strips whole-line comments, so that a variable merely discussed in
// a comment does not count as one the script reads. Inline comments are left
// alone: none of these scripts uses one after a variable reference, and
// pretending to parse shell properly would be worse than this being explicit.
func codeLines(src string) []string {
	out := make([]string, 0, 64)
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, "")
			continue
		}
		out = append(out, l)
	}
	return out
}

func parseFlags(src string) []shellFlag {
	lines := codeLines(src)
	var out []shellFlag
	for i, l := range lines {
		for _, m := range flagRe.FindAllStringSubmatch(l, -1) {
			out = append(out, shellFlag{name: m[1], raw: m[2], line: i + 1})
		}
	}
	return out
}

func varsRead(src string) []string {
	var out []string
	for _, l := range codeLines(src) {
		for _, m := range anyVarRe.FindAllStringSubmatch(l, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
	}
	slices.Sort(out)
	return out
}

// watchFlagSet is the flag set `gotun watch` actually parses, defaults and all.
func watchFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	registerWatchFlags(fs)
	return fs
}

func lookup(fs *flag.FlagSet, name string) *flag.Flag {
	return fs.Lookup(name)
}

// --- A1: every flag an init passes must exist -------------------------------

func TestGotunInitFlagsExist(t *testing.T) {
	fs := watchFlagSet()
	for _, f := range parseFlags(readDeploy(t, "gotun.init")) {
		if lookup(fs, f.name) == nil {
			t.Errorf("gotun.init:%d passes -%s, which `gotun watch` does not define."+
				" At START=99 this makes the gateway fail to start after a reboot.", f.line, f.name)
		}
	}
}

// gotun-dns's flags live on the global flag package inside its own main, so
// they are read out of the source rather than out of a flag.FlagSet. That is
// weaker -- it compares two parses rather than a parse against the real thing
// -- but it still catches a rename, which is the failure that matters.
func TestGotunDNSInitFlagsExist(t *testing.T) {
	src, err := os.ReadFile("../../cmd/gotun-dns/main.go")
	if err != nil {
		t.Fatal(err)
	}
	defined := regexp.MustCompile(`flag\.(?:String|Int|Bool|Duration)\("([a-z0-9-]+)"`)
	var names []string
	for _, m := range defined.FindAllStringSubmatch(string(src), -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatal("found no flag definitions in cmd/gotun-dns/main.go; the parser needs updating")
	}
	for _, f := range parseFlags(readDeploy(t, "gotun-dns.init")) {
		if !slices.Contains(names, f.name) {
			t.Errorf("gotun-dns.init:%d passes -%s, which gotun-dns does not define (it defines %v)",
				f.line, f.name, names)
		}
	}
}

// --- A2: no flag may be handed an unconditionally empty value ---------------

func TestNoFlagIsPassedAnUnconditionallyEmptyValue(t *testing.T) {
	fs := watchFlagSet()
	for _, f := range parseFlags(readDeploy(t, "gotun.init")) {
		v := f.varName()
		if v == "" {
			continue
		}
		if _, ok := f.shellDefault(); ok {
			continue
		}
		g := lookup(fs, f.name)
		if g == nil {
			continue // reported by TestGotunInitFlagsExist
		}
		if g.DefValue != "" {
			t.Errorf("gotun.init:%d passes -%s %q with no :- fallback, so an unset %s hands the"+
				" binary an empty string and silently overrides the Go default %q."+
				" Either give the variable a fallback or do not pass the flag when it is unset.",
				f.line, f.name, f.raw, v, g.DefValue)
		}
	}
}

// --- A3: a shell fallback must agree with the Go default --------------------

// justifiedDivergence records the places a script deliberately overrides a Go
// default, with the reason. Anything not listed here must agree, because three
// sources of truth with no stated reason is how a parameter ends up meaning two
// different things depending on whether the operator set it.
var justifiedDivergence = map[string]map[string]string{
	"gotun-dns.init": {
		"listen": "dnsmasq owns :53 on this box and forwards to 127.0.0.2; the Go default" +
			" of :53 is right for a standalone resolver and wrong for this deployment",
	},
}

func TestShellFallbacksMatchGoDefaults(t *testing.T) {
	fs := watchFlagSet()
	for _, f := range parseFlags(readDeploy(t, "gotun.init")) {
		def, ok := f.shellDefault()
		if !ok {
			continue
		}
		g := lookup(fs, f.name)
		if g == nil {
			continue
		}
		if reason, ok := justifiedDivergence["gotun.init"][f.name]; ok {
			t.Logf("gotun.init -%s diverges deliberately: %s", f.name, reason)
			continue
		}
		if !sameFlagValue(t, g, def, g.DefValue) {
			t.Errorf("gotun.init:%d passes -%s with shell fallback %q, but the Go default is %q."+
				" The parameter now means one thing when the operator sets it and another when"+
				" they do not.", f.line, f.name, def, g.DefValue)
		}
	}
}

// sameFlagValue compares two flag values the way the flag package would, so
// that a duration written as 60s is not reported as differing from 1m0s.
func sameFlagValue(t *testing.T, g *flag.Flag, a, b string) bool {
	t.Helper()
	if a == b {
		return true
	}
	if da, err := time.ParseDuration(a); err == nil {
		if db, err := time.ParseDuration(b); err == nil {
			return da == db
		}
	}
	return false
}

// --- A4/A5: documentation and use must cover each other ---------------------

// scriptsReadingGotunConf are the files that still source
// /etc/gotun/gotun.conf. gotun.init no longer does: it passes the path to the
// binary, which reads it through internal/deployconf.
//
// The companion to this test used to assert the other direction -- that every
// documented variable is read by some script -- and it has been retired rather
// than fixed. Its premise is now false: the fifteen policy settings are read by
// the binary, not by a script, and "some script greps for it" was only ever a
// proxy for "something consumes it". TestSchemaMatchesTheExample asserts that
// directly and in both directions, against the single source of truth instead
// of against whichever file happens to mention the name.
var scriptsReadingGotunConf = []string{"gotun-ipsec.init", "hotplug-iface-gotun"}

func TestEveryReadVariableIsDocumented(t *testing.T) {
	documented := assignedVars(readDeploy(t, "gotun.conf.example"))
	for _, s := range scriptsReadingGotunConf {
		for _, v := range varsRead(readDeploy(t, s)) {
			if !slices.Contains(documented, v) {
				t.Errorf("%s reads %s, which gotun.conf.example does not document", s, v)
			}
		}
	}
}

// gotun-dns.init sources its own file, /etc/gotun/gotun-dns.conf, for which the
// repository ships no example at all -- so all four of its variables are
// undocumented and an operator has no way to discover them.
func TestGotunDNSConfHasAnExample(t *testing.T) {
	want := filepath.Join(deployDir, "gotun-dns.conf.example")
	if _, err := os.Stat(want); err != nil {
		read := varsRead(readDeploy(t, "gotun-dns.init"))
		t.Errorf("gotun-dns.init sources /etc/gotun/gotun-dns.conf and reads %v, but there is no"+
			" gotun-dns.conf.example to document them: %v", read, err)
	}
}

func assignedVars(src string) []string {
	var out []string
	for _, m := range assignRe.FindAllStringSubmatch(src, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return out
}

// --- A6: the example must assign each variable exactly once -----------------

func TestExampleAssignsEachVariableOnce(t *testing.T) {
	src := readDeploy(t, "gotun.conf.example")
	lines := strings.Split(src, "\n")
	seen := map[string]int{}
	for i, l := range lines {
		m := assignRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if first, ok := seen[m[1]]; ok {
			t.Errorf("gotun.conf.example assigns %s twice, at line %d and line %d."+
				" The file is sourced, so the last one silently wins and the first is a lie.",
				m[1], first, i+1)
			continue
		}
		seen[m[1]] = i + 1
	}
}

// --- A7: the hotplug hook's own default ------------------------------------

func TestHotplugTunnelIfaceDefaultMatchesGo(t *testing.T) {
	src := readDeploy(t, "hotplug-iface-gotun")
	m := regexp.MustCompile(`\$\{GOTUN_TUNNEL_IFACE:-([^}]*)\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("hotplug-iface-gotun no longer compares $INTERFACE against a GOTUN_TUNNEL_IFACE fallback")
	}
	if m[1] != policy.DefaultTunnelIface {
		t.Errorf("hotplug-iface-gotun falls back to %q but policy.DefaultTunnelIface is %q,"+
			" so with GOTUN_TUNNEL_IFACE unset the hook compares against a device name that"+
			" cannot exist and can never fire.", m[1], policy.DefaultTunnelIface)
	}
}

// --- A8: the config must be sourced before anything reads it ---------------

func TestConfigIsSourcedBeforeItsVariablesAreRead(t *testing.T) {
	for _, name := range scriptsReadingGotunConf {
		lines := codeLines(readDeploy(t, name))
		source := -1
		for i, l := range lines {
			if strings.Contains(l, `. "$CONF"`) {
				source = i
				break
			}
		}
		if source < 0 {
			t.Errorf("%s does not source $CONF at all", name)
			continue
		}
		for i, l := range lines {
			if i >= source {
				break
			}
			if m := anyVarRe.FindStringSubmatch(l); m != nil {
				t.Errorf("%s:%d reads %s at line %d but only sources $CONF at line %d,"+
					" so every value the operator sets for it in gotun.conf is ignored and the"+
					" script silently uses its own default instead.",
					name, i+1, m[1], i+1, source+1)
			}
		}
	}
}

// --- A9: file modes --------------------------------------------------------

// The README installs these with scp, which preserves the source mode. A
// non-executable init script is not a service that misbehaves, it is a service
// that does not exist: procd skips it and the boot carries on quietly.
func TestInitScriptsAreExecutable(t *testing.T) {
	for _, name := range []string{
		"gotun.init", "gotun-dns.init", "gotun-ipsec.init", "singbox.init", "hotplug-iface-gotun",
	} {
		// -C: git resolves pathspecs against the working directory, which for a
		// test is the package directory, not the repository root.
		out, err := exec.Command("git", "-C", "../..", "ls-files", "-s",
			filepath.Join("deploy/openwrt", name)).Output()
		if err != nil {
			t.Fatalf("git ls-files %s: %v", name, err)
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 {
			t.Fatalf("%s is not tracked by git", name)
		}
		if fields[0] != "100755" {
			t.Errorf("deploy/openwrt/%s is mode %s in git, want 100755."+
				" scp preserves the mode, so this lands on the router non-executable.", name, fields[0])
		}
	}
}

// --- A10: boot and shutdown ordering ---------------------------------------

func TestStartStopOrdering(t *testing.T) {
	type svc struct{ file string }
	order := []string{"gotun-ipsec.init", "gotun-dns.init", "singbox.init", "gotun.init"}
	starts := map[string]int{}
	stops := map[string]int{}
	for _, f := range order {
		src := readDeploy(t, f)
		starts[f] = mustNum(t, f, src, "START")
		stops[f] = mustNum(t, f, src, "STOP")
	}

	// gotun routes into the devices the others create, so it must start last.
	for _, f := range order[:len(order)-1] {
		if starts[f] >= starts["gotun.init"] {
			t.Errorf("%s has START=%d but gotun.init has START=%d; gotun must start after the"+
				" devices it routes into exist", f, starts[f], starts["gotun.init"])
		}
	}
	// The xfrm device must exist before anything that routes into it.
	if starts["gotun-ipsec.init"] >= starts["gotun.init"] {
		t.Errorf("gotun-ipsec START=%d is not before gotun START=%d",
			starts["gotun-ipsec.init"], starts["gotun.init"])
	}
	// And on the way down, gotun must withdraw the policy before the devices
	// it steers into are destroyed under it.
	for _, f := range order[:len(order)-1] {
		if stops["gotun.init"] >= stops[f] {
			t.Errorf("gotun.init has STOP=%d and %s has STOP=%d; K scripts run in ascending"+
				" order, so gotun must stop first", stops["gotun.init"], f, stops[f])
		}
	}
}

func mustNum(t *testing.T, file, src, key string) int {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + key + `=(\d+)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s has no %s=", file, key)
	}
	var n int
	fmt.Sscanf(m[1], "%d", &n)
	return n
}

// --- A11: the example is sourced as root ------------------------------------

// Three services source this file as root at boot. A command substitution in it
// is not a configuration error, it is root code execution on every boot, so the
// file must contain nothing but assignments and comments.
func TestExampleIsOnlyAssignmentsAndComments(t *testing.T) {
	src := readDeploy(t, "gotun.conf.example")
	for i, l := range strings.Split(src, "\n") {
		s := strings.TrimSpace(l)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if strings.ContainsAny(s, "`") || strings.Contains(s, "$(") {
			t.Errorf("gotun.conf.example:%d contains a command substitution: %q."+
				" The file is sourced as root by three services at boot.", i+1, s)
		}
		if !regexp.MustCompile(`^(export\s+)?[A-Za-z_][A-Za-z0-9_]*=`).MatchString(s) {
			t.Errorf("gotun.conf.example:%d is neither a comment nor an assignment: %q", i+1, s)
		}
	}
}

func TestExampleParsesAsShell(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no sh available: %v", err)
	}
	out, err := exec.Command("sh", "-n", filepath.Join(deployDir, "gotun.conf.example")).CombinedOutput()
	if err != nil {
		t.Errorf("gotun.conf.example is not valid shell, yet it is sourced at boot: %v\n%s", err, out)
	}
}

// --- A12: gotun-dns must agree with gotun on the mark ----------------------

// The mark is the one parameter the two daemons must agree on exactly: gotun
// steers marked packets into table 100, and gotun-dns marks its own upstream
// queries to be steered the same way. A split here does not fail loudly, it
// quietly stops DNS being tunnelled, which is the failure that returns a
// geo-localised address for a foreign name.
func TestGotunDNSMarkMatchesPolicyDefault(t *testing.T) {
	src := readDeploy(t, "gotun-dns.init")
	m := regexp.MustCompile(`\$\{GOTUN_DNS_MARK:-([^}]*)\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("gotun-dns.init no longer passes -mark with a GOTUN_DNS_MARK fallback")
	}
	want := fmt.Sprintf("0x%x", policy.DefaultMark)
	if m[1] != want {
		t.Errorf("gotun-dns.init falls back to -mark %q but policy.DefaultMark is %s", m[1], want)
	}
}

// --- A13: the README must install what the repository ships -----------------

// Shipping a service nobody is told to install is how the hotplug hook came to
// be documented, committed, and absent from the router for months -- the
// repository described a component that was not deployed and would not have
// worked if it were.
func TestEveryInitScriptHasAnInstallStep(t *testing.T) {
	readme := readDeploy(t, "README.md")
	for _, name := range []string{
		"gotun.init", "gotun-dns.init", "gotun-ipsec.init", "singbox.init",
		"hotplug-iface-gotun",
	} {
		if !strings.Contains(readme, "deploy/openwrt/"+name) {
			t.Errorf("deploy/openwrt/%s is shipped but the README never installs it,"+
				" so an operator following the instructions ends up without it", name)
		}
	}
}

// A firmware upgrade keeps /etc only for the paths listed in
// /etc/sysupgrade.conf. Anything the README installs there and does not list is
// silently gone after the next upgrade -- and gone quietly, because the ip rule
// and the nft table are kernel state, so traffic simply reverts to leaving via
// the ISP for everything.
func TestEveryInstalledEtcPathPersistsAcrossSysupgrade(t *testing.T) {
	readme := readDeploy(t, "README.md")

	// The paths the README's sysupgrade.conf lines name, including directories,
	// which cover everything beneath them.
	var listed []string
	for _, m := range regexp.MustCompile(`printf '([^']*)' >> /etc/sysupgrade\.conf`).
		FindAllStringSubmatch(readme, -1) {
		for _, p := range strings.Split(m[1], `\n`) {
			if p != "" {
				listed = append(listed, p)
			}
		}
	}
	if len(listed) == 0 {
		t.Fatal("found no sysupgrade.conf lines in the README; the parser needs updating")
	}

	installs := regexp.MustCompile(`(?m)^scp \S+ root@router:(/etc/\S+)`).
		FindAllStringSubmatch(readme, -1)
	if len(installs) == 0 {
		t.Fatal("found no scp lines installing into /etc; the parser needs updating")
	}
	for _, m := range installs {
		dst := m[1]
		covered := false
		for _, l := range listed {
			if l == dst || (strings.HasSuffix(l, "/") && strings.HasPrefix(dst, l)) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("the README installs %s but never adds it to /etc/sysupgrade.conf,"+
				" so the next firmware upgrade removes it. Nothing breaks loudly when that"+
				" happens: traffic just reverts to leaving via the ISP for everything.",
				dst)
		}
	}
}

// busybox's ip cannot create an xfrm interface even with kmod-xfrm-interface
// loaded, and it does not say so -- it answers "RTNETLINK answers: Invalid
// argument", because it never passes the if_id, which reads as a kernel problem
// rather than a missing package. The IKEv2 install list went a long time
// without ip-full because this router has it from its vendor firmware.
func TestIKEv2InstallListIncludesIPFull(t *testing.T) {
	readme := readDeploy(t, "README.md")
	m := regexp.MustCompile(`(?m)^opkg install (.*kmod-xfrm-interface.*)$`).FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("found no `opkg install` line mentioning kmod-xfrm-interface")
	}
	pkgs := strings.Fields(m[1])
	if !slices.Contains(pkgs, "ip-full") {
		t.Errorf("the IKEv2 install list is %v, with no ip-full. A fresh router following"+
			" these instructions fails at the first `ip link add type xfrm`.", pkgs)
	}
	// netifd's proto xfrm, which gotun-ipsec.init deliberately does not use.
	if slices.Contains(pkgs, "xfrm") {
		t.Errorf("the install list includes the `xfrm` package, which only adds netifd's"+
			" proto xfrm to /etc/config/network. gotun-ipsec.init owns the device itself"+
			" on purpose, so this package is not wanted: %v", pkgs)
	}
}

// --- A14: the config schema must match the flags and the documentation ------

// internal/deployconf names a flag for each setting. A name that does not
// resolve is a setting that silently does nothing -- the same failure the shell
// mapping had, moved into Go, which would be the worst possible outcome of
// replacing one with the other.
func TestSchemaFlagsResolve(t *testing.T) {
	fs := watchFlagSet()
	for key, name := range deployconf.WatchFlags {
		if lookup(fs, name) == nil {
			t.Errorf("deployconf maps %s to -%s, which `gotun watch` does not define", key, name)
		}
	}
}

// The schema is now the single source of truth for what gotun.conf may contain,
// so the example must agree with it exactly. One direction catches a setting
// nobody can discover; the other catches a documented knob that does nothing.
func TestSchemaMatchesTheExample(t *testing.T) {
	documented := assignedVars(readDeploy(t, "gotun.conf.example"))
	known := deployconf.GotunConf.Keys()

	for _, k := range known {
		if !slices.Contains(documented, k) {
			t.Errorf("the schema accepts %s but gotun.conf.example does not document it,"+
				" so an operator has no way to discover it", k)
		}
	}
	for _, k := range documented {
		if !slices.Contains(known, k) {
			t.Errorf("gotun.conf.example documents %s but the schema rejects it,"+
				" so copying the example produces a config gotun refuses", k)
		}
	}
}

func TestDNSSchemaMatchesItsExample(t *testing.T) {
	documented := assignedVars(readDeploy(t, "gotun-dns.conf.example"))
	known := deployconf.GotunDNSConf.Keys()
	for _, k := range known {
		if !slices.Contains(documented, k) {
			t.Errorf("the DNS schema accepts %s, undocumented in gotun-dns.conf.example", k)
		}
	}
	for _, k := range documented {
		if !slices.Contains(known, k) {
			t.Errorf("gotun-dns.conf.example documents %s, which the DNS schema rejects", k)
		}
	}
}

// --- A15: Validate must classify its own errors ----------------------------

// watch keeps running after a failed apply, because at boot the usual cause is
// a transport that is not up yet and the watchdog recovers on its own. It can
// only do that safely if a configuration that will never work is distinguished
// from one that is merely early, so these two sets must not blur.
func TestValidate_ConfigProblemsAreConfigErrors(t *testing.T) {
	prefixes := filepath.Join(t.TempDir(), "prefixes.txt")
	if err := os.WriteFile(prefixes, []byte("77.88.8.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := ApplyOptions{PrefixesPath: prefixes, Endpoint: "185.80.130.211", MarkIfaceCSV: "br-lan"}

	for _, c := range []struct {
		name string
		edit func(*ApplyOptions)
	}{
		{"no prefix list", func(o *ApplyOptions) { o.PrefixesPath = "" }},
		{"prefix list missing", func(o *ApplyOptions) { o.PrefixesPath = "/nope.txt" }},
		{"no endpoint", func(o *ApplyOptions) { o.Endpoint = "" }},
		{"endpoint is not an address", func(o *ApplyOptions) { o.Endpoint = "vpn.example" }},
		{"lan is not a prefix", func(o *ApplyOptions) { o.LANCSV = "192.168.8.1" }},
		{"direct-src is not a host", func(o *ApplyOptions) { o.DirectSrcCSV = "nonsense" }},
		{"non-routable is not a prefix", func(o *ApplyOptions) { o.NonRoutableCSV = "nonsense" }},
		{"wg config missing", func(o *ApplyOptions) { o.WGConfig = "/nope.conf" }},
		{
			// The policy itself refuses this: a clients interface absent from
			// the ingress guard means those clients are never classified.
			name: "clients interface not marked",
			edit: func(o *ApplyOptions) { o.ClientsIfaceCSV = "ipsec0"; o.MarkIfaceCSV = "br-lan" },
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := base
			c.edit(&o)
			_, err := Validate(o)
			if err == nil {
				t.Fatal("want an error")
			}
			var ce ConfigError
			if !errors.As(err, &ce) {
				t.Errorf("want a ConfigError so watch treats it as fatal, got %T: %v", err, err)
			}
		})
	}
}

func TestValidate_AcceptsAUsableConfiguration(t *testing.T) {
	prefixes := filepath.Join(t.TempDir(), "prefixes.txt")
	if err := os.WriteFile(prefixes, []byte("77.88.8.0/24\n5.255.255.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Validate(ApplyOptions{
		PrefixesPath:    prefixes,
		Endpoint:        "185.80.130.211",
		LANCSV:          "192.168.8.0/24",
		MarkIfaceCSV:    "br-lan,ipsec0",
		ClientsIfaceCSV: "ipsec0",
		TunnelIface:     "xray0",
		FailMode:        policy.FailOpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.TunnelInterface != "xray0" {
		t.Errorf("TunnelInterface = %q", p.TunnelInterface)
	}
	if len(p.DirectPrefixes) != 2 {
		t.Errorf("got %d direct prefixes, want 2", len(p.DirectPrefixes))
	}
}
