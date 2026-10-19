package ikev2_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/ikev2"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

func testConfig() ikev2.Config {
	return ikev2.Config{
		Server:      "vpn.example.net",
		ClientID:    "iphone",
		VIPSubnet:   netip.MustParsePrefix("10.231.17.0/24"),
		VIPGateway:  netip.MustParseAddr("10.231.17.1"),
		Pool:        netip.MustParsePrefix("10.231.17.16/28"),
		NonRoutable: policy.DefaultNonRoutable(),
		Families:    prefixes.Families{V4: true, V6: true},
		ProbeURL:    "http://vpn.example.net:8443/alive",
		HomeSSIDs:   []string{"HomeWiFi"},
	}
}

// The gateway's own tunnel-side address is RFC1918, so the list that keeps the
// phone's local networks on-link also cuts the address gotun-dns listens on.
// Without the punch-back the phone resolves through whatever network it is
// attached to: a healthy tunnel with every GeoDNS answer quietly wrong.
func TestSelectors_VIPSubnetSurvivesTheNonRoutableCut(t *testing.T) {
	sel := testConfig().Selectors()
	var found bool
	for _, p := range sel {
		if p == netip.MustParsePrefix("10.231.17.0/24") {
			found = true
		}
	}
	if !found {
		t.Fatalf("VIP subnet missing from selectors: %v", sel)
	}
}

// Selectors covering private space cost the phone every local network it is
// attached to -- the printer, the Chromecast, the hotel portal -- and the only
// symptom is that local things stop working while the internet is fine. It is
// one careless NonRoutable list away, so there is a floor underneath it.
func TestSelectors_NeverCoverPrivateSpace(t *testing.T) {
	cases := []struct {
		name string
		cut  []netip.Prefix
	}{
		{name: "nothing excluded at all", cut: nil},
		{
			// The shape a real mistake takes: a list that remembers the
			// famous blocks and forgets CGNAT, which is what carriers put
			// phones behind.
			name: "CGNAT forgotten",
			cut: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			c.NonRoutable = tc.cut
			err := c.Validate()
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), "private space") {
				t.Errorf("error should name the consequence, got: %v", err)
			}
		})
	}
}

// IPv6 is offered as global unicast rather than as the complement of the
// non-routable list: 2000::/3 is the only routable IPv6 range, so one selector
// is both exactly right and twenty shorter.
func TestSelectors_IPv6IsOneGlobalUnicastSelector(t *testing.T) {
	c := testConfig()
	c.Families = prefixes.Families{V6: true}
	c.VIPSubnet = netip.MustParsePrefix("fd00:231:17::/64")
	c.VIPGateway = netip.MustParseAddr("fd00:231:17::1")
	c.Pool = netip.MustParsePrefix("fd00:231:17::10/124")

	sel := c.Selectors()
	var v6 []netip.Prefix
	for _, p := range sel {
		if !p.Addr().Is4() {
			v6 = append(v6, p)
		}
	}
	// Global unicast plus the ULA VIP subnet, which sits outside 2000::/3 and
	// therefore has to be added rather than left over by a complement.
	if len(v6) != 2 {
		t.Fatalf("want 2 IPv6 selectors (global unicast + the VIP subnet), got %v", v6)
	}
	if !containsPrefix(v6, ikev2.GlobalUnicastV6()) {
		t.Errorf("global unicast missing: %v", v6)
	}
	if !containsPrefix(v6, c.VIPSubnet) {
		t.Errorf("ULA VIP subnet missing: %v", v6)
	}
}

// The selector count is pinned because it is the one number that could stop
// this working on a real iPhone, and nothing documents the limit.
//
// 52 IPv4 prefixes is the honest cost of the measured decision to send
// prefixes rather than ranges: the same space is four ranges. If iOS turns out
// to reject a list this long, the fix is not to switch to ranges -- charon's
// client proves those round up and swallow the phone's own LAN -- it is to
// coarsen the exclusion, which trades correctness for length. Change this
// number only alongside that argument.
func TestSelectors_IPv4CountIsPinned(t *testing.T) {
	c := testConfig()
	c.Families = prefixes.Families{V4: true}
	sel := c.Selectors()
	if len(sel) != 52 {
		t.Errorf("IPv4 selector count is %d, was 52: %v", len(sel), sel)
	}
}

// The probe is fetched over the physical interface while the tunnel is down.
// A private address there fails precisely when the tunnel is down, so the
// Connect rule never matches and the phone never connects at all -- which
// looks like fail-open working perfectly, because traffic does flow.
func TestValidate_RejectsAProbeThePhoneCannotReach(t *testing.T) {
	for _, url := range []string{
		"http://192.168.8.1:8443/alive",
		"http://10.231.17.1/alive",
		"http://127.0.0.1:8443/alive",
	} {
		c := testConfig()
		c.ProbeURL = url
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want an error", url)
		}
	}
}

func TestValidate_RejectsIncoherentVIPGeometry(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ikev2.Config)
		want string
	}{
		{
			name: "resolver outside the tunnel subnet",
			mut:  func(c *ikev2.Config) { c.VIPGateway = netip.MustParseAddr("10.99.0.1") },
			want: "outside VIPSubnet",
		},
		{
			name: "pool outside the tunnel subnet",
			mut:  func(c *ikev2.Config) { c.Pool = netip.MustParsePrefix("10.99.0.0/28") },
			want: "not inside VIPSubnet",
		},
		{
			// Apple does not clamp a shorter interval, it ignores the key, so
			// the keepalive silently reverts to the system default and the
			// battery argument quietly stops applying.
			name: "keepalive below Apple's minimum",
			mut:  func(c *ikev2.Config) { c.KeepAliveInterval = 10 },
			want: "minimum of 20",
		},
		{
			name: "unknown DPD rate",
			mut:  func(c *ikev2.Config) { c.DPDRate = "Often" },
			want: "DeadPeerDetectionRate",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// The requirement, as configuration. On-Demand is not a kill switch unless the
// profile makes it one, and the two ways to make it one are a single key apart
// from the correct shape.
func TestProfile_IsNotAKillSwitch(t *testing.T) {
	b, err := ikev2.EncodeProfile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	// Supervised Always-On blocks traffic when the tunnel is down.
	if strings.Contains(got, "AlwaysOn") {
		t.Error("profile must never be an Always-On VPN payload")
	}
	// The last rule has to be a bare Disconnect: iOS takes the first match, so
	// a catch-all anywhere else, or absent, leaves an unreachable gateway
	// holding traffic instead of releasing it.
	rules := strings.LastIndex(got, "<key>OnDemandRules</key>")
	if rules < 0 {
		t.Fatal("no OnDemandRules")
	}
	tail := got[rules:]
	if strings.LastIndex(tail, "Disconnect") < strings.LastIndex(tail, "Connect</string>") {
		t.Error("the last on-demand rule must be a Disconnect catch-all")
	}
	if !strings.Contains(got, "<key>URLStringProbe</key>") {
		t.Error("the Connect rule must be gated on a probe, or the phone sits in 'connecting'")
	}
	if !strings.Contains(got, "<key>OnDemandEnabled</key>\n\t\t\t<integer>1</integer>") {
		t.Error("on-demand must be enabled, or the tunnel never comes back by itself")
	}
}

// Nothing this tool writes to disk may be a credential. The profile gets
// AirDropped or emailed to a phone and then sits in Downloads; the swanctl
// config lands in the operator's editor, shell history and backups.
func TestGeneratedFilesCarryNoCredential(t *testing.T) {
	prof, err := ikev2.EncodeProfile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"AuthPassword", "SharedSecret", "Password</key>"} {
		if strings.Contains(string(prof), bad) {
			t.Errorf("profile contains %q", bad)
		}
	}

	conf, err := ikev2.RenderSwanctl(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // the placeholder stanza is a comment on purpose
		}
		if strings.Contains(trimmed, "secret =") {
			t.Errorf("swanctl output contains a live secret line: %q", line)
		}
	}
}

// iOS keys an installed profile by its PayloadUUID, so a random one on every
// run adds a second VPN entry beside the first rather than replacing it --
// leaving two profiles with the same display name and no way to tell which one
// On-Demand is using.
func TestProfile_UUIDsAreDeterministic(t *testing.T) {
	a, err := ikev2.EncodeProfile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ikev2.EncodeProfile(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("two runs produced different profiles")
	}

	// ...and a different profile name must not collide with the first.
	c := testConfig()
	c.ProfileName = "Second phone"
	other, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if uuidOf(t, string(other)) == uuidOf(t, string(a)) {
		t.Error("two differently named profiles share a UUID")
	}
}

// The invariant that justifies one command emitting both halves: the identity
// the phone expects must be the identity the gateway presents. A mismatch fails
// authentication after a successful handshake, which reads as a crypto problem
// rather than a naming one.
func TestSwanctlAndProfileAgreeOnIdentityAndResolver(t *testing.T) {
	c := testConfig()
	c.GatewayID = "vpn.example.net"

	conf, err := ikev2.RenderSwanctl(c)
	if err != nil {
		t.Fatal(err)
	}
	prof, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(conf, "id = "+c.GatewayID) {
		t.Errorf("swanctl does not present %q", c.GatewayID)
	}
	if !strings.Contains(string(prof), "<string>"+c.GatewayID+"</string>") {
		t.Errorf("profile does not expect %q", c.GatewayID)
	}
	// The resolver the pool pushes has to be inside the selectors the same
	// call produced; Validate refuses otherwise, so reaching here proves it.
	if !strings.Contains(conf, "dns = "+c.VIPGateway.String()) {
		t.Errorf("swanctl does not push %s as DNS", c.VIPGateway)
	}
}

// local_ts is the single source of truth rendered out. If it ever diverged
// from Selectors, the lab would still pass -- it reads the negotiated
// selectors, which come from this line -- while the phone tunnelled something
// the operator never asked for.
func TestSwanctl_LocalTSIsExactlyTheSelectorList(t *testing.T) {
	c := testConfig()
	conf, err := ikev2.RenderSwanctl(c)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(conf, "\n") {
		if strings.Contains(l, "local_ts = ") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		t.Fatal("no local_ts line")
	}
	got := strings.Split(strings.TrimPrefix(line, "local_ts = "), ",")
	want := ikev2.SelectorStrings(c)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("local_ts differs from Selectors\n got %v\nwant %v", got, want)
	}
}

// A strongswan.conf value extends to the end of its line, so two keys sharing
// one line make the second key part of the first value: "auth = pubkey  id = x"
// is discarded as "invalid value for: auth", which reads like an unsupported
// auth method rather than a syntax error. Cost an hour the first time.
func TestSwanctl_OneKeyPerLine(t *testing.T) {
	conf, err := ikev2.RenderSwanctl(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Count(trimmed, " = ") > 1 {
			t.Errorf("line %d has more than one key: %q", i+1, line)
		}
	}
}

// Route-based IPsec is the whole reason gotun needs no new classification axis:
// decrypted packets surface on a named interface, so -mark-iface and the
// home_nets forward rule apply unchanged. Without if_id charon installs
// policies and no interface, and both lose their anchor.
func TestSwanctl_IsRouteBased(t *testing.T) {
	conf, err := ikev2.RenderSwanctl(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"if_id_in = 0x61", "if_id_out = 0x61", "encap = yes", "mobike = yes"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func containsPrefix(in []netip.Prefix, want netip.Prefix) bool {
	for _, p := range in {
		if p == want {
			return true
		}
	}
	return false
}

func uuidOf(t *testing.T, profile string) string {
	t.Helper()
	i := strings.LastIndex(profile, "<key>PayloadUUID</key>")
	if i < 0 {
		t.Fatal("no PayloadUUID")
	}
	rest := profile[i:]
	start := strings.Index(rest, "<string>") + len("<string>")
	end := strings.Index(rest, "</string>")
	return rest[start:end]
}
