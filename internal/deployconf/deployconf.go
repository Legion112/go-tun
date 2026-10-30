// Package deployconf reads the /etc/gotun/*.conf files the OpenWrt services are
// configured with.
//
// It exists to delete a third copy of every parameter. Each one used to be
// described in gotun.conf.example as documentation, again in an init script as
// a mapping to a command-line flag, and again in Go as a flag and a default,
// with nothing checking that the three agreed -- and they did not, in eight
// places. Eight of the fourteen defects found in the deploy layer existed only
// because that middle copy could drift.
//
// The package is separate from internal/cli because gotun-dns is its own binary
// and must read its own file without depending on the CLI.
package deployconf

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Mapping ties each variable to the flag it sets.
//
// One file serves several commands -- gotun.conf configures both the policy and
// the xfrm device -- so a mapping covers one command and a Schema collects the
// mappings that share a file.
type Mapping map[string]string

// ApplyFlags is what `gotun apply` reads: the policy, and nothing else.
//
// It is a separate mapping from WatchFlags rather than the same one, because
// apply has no flags for the watchdog settings -- and Into refuses a mapping
// that names a flag the command does not define, deliberately, since silently
// skipping one is how a typo becomes a setting that does nothing. One mapping
// for both commands made `gotun apply -config` fail outright on
// GOTUN_RECOVER_AFTER, which is how this was found: on the router, by hand,
// after the whole suite had passed.
var ApplyFlags = Mapping{
	"GOTUN_PREFIXES":      "prefixes",
	"GOTUN_ENDPOINT":      "endpoint",
	"GOTUN_TUNNEL_IFACE":  "tunnel-iface",
	"GOTUN_LAN":           "lan",
	"GOTUN_MARK_IFACE":    "mark-iface",
	"GOTUN_CLIENTS_IFACE": "clients-iface",
	"GOTUN_DIRECT_SRC":    "direct-src",
	"GOTUN_FAIL_MODE":     "fail-mode",
	"GOTUN_IPV6":          "ipv6",
	"GOTUN_IPV6_FALLBACK": "ipv6-fallback",
}

// watchOnlyFlags are the watchdog settings, which only `watch` has flags for.
var watchOnlyFlags = Mapping{
	"GOTUN_HEALTH_LISTEN":  "health-listen",
	"GOTUN_PROBE_TARGET":   "probe-target",
	"GOTUN_PROBE_INTERVAL": "probe-interval",
	"GOTUN_FAIL_AFTER":     "fail-after",
	"GOTUN_RECOVER_AFTER":  "recover-after",
}

// WatchFlags is what `gotun watch` reads, and `gotun check` with it: check
// answers the question "what would watch run with", so it has to see the same
// settings.
var WatchFlags = union(ApplyFlags, watchOnlyFlags)

func union(ms ...Mapping) Mapping {
	out := Mapping{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// IPsecFlags is what `gotun ipsec up|down` reads, out of the same file.
var IPsecFlags = Mapping{
	"GOTUN_IPSEC_IFACE":  "iface",
	"GOTUN_IPSEC_IFID":   "if-id",
	"GOTUN_IPSEC_ADDR":   "addr",
	"GOTUN_IPSEC_MTU":    "mtu",
	"GOTUN_IPSEC_PARENT": "parent",
}

// IKEv2Flags is the gateway an IKEv2 profile describes, read by `gotun ikev2`
// and by every `gotun ikev2 user` subcommand.
//
// It exists so that issuing a credential is `gotun ikev2 user add <name>` and
// not that plus a dozen flags describing the same gateway each time. Every one
// of those was a chance to generate a profile for a gateway slightly unlike the
// one that is running, which installs cleanly and then does not connect.
//
// The interface id is deliberately GOTUN_IPSEC_IFID, the same key `gotun ipsec`
// reads: it is one number, it has to match the xfrm device the CHILD_SA
// surfaces on, and a device and a connection carrying different if_ids
// negotiate perfectly and then deliver packets nowhere.
var IKEv2Flags = Mapping{
	"GOTUN_IKEV2_SERVER":       "server",
	"GOTUN_IKEV2_GATEWAY_ID":   "gateway-id",
	"GOTUN_IKEV2_VIP_SUBNET":   "vip-subnet",
	"GOTUN_IKEV2_VIP_GATEWAY":  "vip-gateway",
	"GOTUN_IKEV2_POOL":         "pool",
	"GOTUN_IKEV2_FAMILIES":     "families",
	"GOTUN_IKEV2_NON_ROUTABLE": "non-routable",
	"GOTUN_IKEV2_CA":           "ca",
	"GOTUN_IKEV2_SERVER_CERT":  "server-cert",
	"GOTUN_IKEV2_PROBE_URL":    "probe-url",
	"GOTUN_IKEV2_HOME_SSID":    "home-ssid",
	"GOTUN_IKEV2_DNS_MATCH":    "dns-match",
	"GOTUN_IKEV2_DPD":          "dpd",
	"GOTUN_IKEV2_ON_DEMAND":    "on-demand",
	"GOTUN_IKEV2_KEEPALIVE":    "keepalive",
	"GOTUN_IKEV2_NAME":         "name",
	"GOTUN_IKEV2_IDENTIFIER":   "identifier",
	"GOTUN_IPSEC_IFID":         "if-id",
}

// IKEv2DirFlags is for the user subcommands that describe no gateway --
// `list` and `revoke` need to find the credentials and nothing more.
var IKEv2DirFlags = Mapping{
	"GOTUN_IKEV2_USER_DIR": "dir",
}

// IKEv2UserFlags is the gateway plus the credential directory, for the
// subcommands that write a profile.
var IKEv2UserFlags = union(IKEv2Flags, IKEv2DirFlags)

// DNSFlags is what gotun-dns reads.
var DNSFlags = Mapping{
	"GOTUN_DNS_LISTEN": "listen",
	"GOTUN_DNS_DIRECT": "direct-upstream",
	"GOTUN_DNS_EXIT":   "exit-upstream",
	"GOTUN_DNS_MARK":   "mark",
}

// DNSWatchFlags is what `gotun dnswatch` reads, out of the same file as
// gotun-dns. The resolver it watches is gotun-dns's listen address and its last
// resort is gotun-dns's own direct upstream: one variable each, so the watcher
// cannot end up probing a resolver other than the one that is running.
var DNSWatchFlags = Mapping{
	"GOTUN_DNS_LISTEN":       "resolver",
	"GOTUN_DNS_DIRECT":       "fallback",
	"GOTUN_DNS_FILTER":       "filter",
	"GOTUN_DNS_SERVERS_FILE": "servers-file",
}

// Schema is one configuration file: the mappings that read it, and so the set
// of variables it may contain.
type Schema struct {
	// File is the conventional path. It appears in messages only; Load takes
	// the path to read as an argument, because the lab and the tests use
	// another one.
	File     string
	Mappings []Mapping
}

// GotunConf and GotunDNSConf are the two files the services read.
var (
	GotunConf = Schema{
		File:     "/etc/gotun/gotun.conf",
		Mappings: []Mapping{WatchFlags, IPsecFlags, IKEv2UserFlags},
	}
	GotunDNSConf = Schema{
		File:     "/etc/gotun/gotun-dns.conf",
		Mappings: []Mapping{DNSFlags, DNSWatchFlags},
	}
)

// DefaultPidFile is where `gotun watch` records its pid and where
// `gotun hotplug` looks for it. One constant, so the two agree by construction
// rather than by a test that notices when they stop agreeing.
const DefaultPidFile = "/var/run/gotun.pid"

// Keys is every variable the file may contain, sorted.
func (s Schema) Keys() []string {
	// A variable can be read by more than one command -- GOTUN_DNS_LISTEN is
	// where gotun-dns listens and what dnswatch probes -- so the set, not the sum.
	seen := map[string]bool{}
	var out []string
	for _, m := range s.Mappings {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s Schema) knows(key string) bool {
	for _, m := range s.Mappings {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

// Conf is a parsed configuration file.
type Conf struct {
	Path string
	vals map[string]string
}

// Load reads and validates path against the schema.
//
// It refuses what being sourced by a shell accepted silently: a variable the
// schema does not know (a typo reads as a knob that does nothing), a variable
// assigned twice (the later one wins and the earlier is a lie -- which had
// happened, thirty lines apart with different values), and anything that is
// neither a comment nor an assignment.
func Load(path string, s Schema) (*Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Conf{Path: path, vals: map[string]string{}}
	seen := map[string]int{}

	for i, raw := range strings.Split(string(data), "\n") {
		line := i + 1
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		// `export VAR=` is what a shell would accept; the example says it is
		// not needed, but a file that has it must not be rejected for it.
		text = strings.TrimPrefix(text, "export ")

		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: not a comment or an assignment: %q", path, line, text)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if !s.knows(key) {
			return nil, fmt.Errorf("%s:%d: unknown setting %s. %s", path, line, key,
				nearest(key, s.Keys()))
		}
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s is already set on line %d."+
				" Two values for one setting means one of them does nothing,"+
				" and which one is not obvious from reading the file",
				path, line, key, first)
		}
		v, err := unquote(value)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %s: %w", path, line, key, err)
		}
		seen[key] = line
		c.vals[key] = v
	}
	return c, nil
}

// unquote strips one layer of matching quotes and refuses the shell syntax this
// file must not contain.
//
// A trailing comment is refused rather than stripped. The file used to be
// sourced as root, where `VAR=value # note` quietly assigned `value`; now that
// Go reads it, silently agreeing with the old behaviour is worth less than
// telling the operator where to put the comment.
func unquote(v string) (string, error) {
	if strings.ContainsAny(v, "`") || strings.Contains(v, "$(") {
		return "", fmt.Errorf("command substitution is not allowed here: %q", v)
	}
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1], nil
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		return "", fmt.Errorf("value %q looks like it carries a trailing comment;"+
			" put the comment on its own line, because a value is taken literally here", v)
	}
	return v, nil
}

// Get returns a variable's value and whether the file set it.
func (c *Conf) Get(key string) (string, bool) {
	v, ok := c.vals[key]
	return v, ok
}

// Into fills in the flags in m that the operator did not pass explicitly.
//
// An explicit flag wins over the file. That ordering is for the live gateway:
// it means a bad value in the file can be overridden with a one-line edit to
// the init script rather than a reflash.
//
// A variable the file does not set is never passed, so the flag keeps its Go
// default. That is what makes a whole class of defect impossible rather than
// merely tested for: the init scripts used to expand an unset variable into an
// empty string and hand that to the flag, overriding the default with nothing.
func (c *Conf) Into(fs *flag.FlagSet, m Mapping) error {
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	for key, name := range m {
		v, ok := c.Get(key)
		if !ok || explicit[name] {
			continue
		}
		if fs.Lookup(name) == nil {
			// A mapping naming a flag this command does not define is a bug in
			// the mapping, not in the operator's file.
			return fmt.Errorf("internal: %s maps to -%s, which %s does not define",
				key, name, fs.Name())
		}
		if err := fs.Set(name, v); err != nil {
			return fmt.Errorf("%s:%s=%s: %w", c.Path, key, v, err)
		}
	}
	return nil
}

// nearest suggests the closest known key, so a typo is one line of output away
// from being fixed rather than a hunt through the example file.
func nearest(key string, known []string) string {
	best, bestD := "", 1<<31-1
	for _, k := range known {
		if d := editDistance(key, k); d < bestD {
			best, bestD = k, d
		}
	}
	// Past a third of the length the "closest" key is noise, and a confident
	// wrong suggestion is worse than none.
	if best == "" || bestD > len(key)/3+1 {
		return "See gotun.conf.example for the settings this file may contain."
	}
	return fmt.Sprintf("Did you mean %s?", best)
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, min(cur[j-1]+1, prev[j-1]+cost))
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
