package ikev2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

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

// testCA mints a throwaway CA and a leaf, so the trust tests run on real
// certificates rather than on bytes that happen to parse.
func testCA(t *testing.T) (caPEM, leafPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gotun-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "vpn.example.net"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              []string{"vpn.example.net"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

// A self-signed gateway is rejected by a phone that has nothing to validate it
// against, and the failure is a generic connect error that says nothing about
// trust. A root delivered inside the same profile is trusted for that profile,
// so this payload is the whole of the trust setup.
func TestProfile_EmbedsTheCAAsATrustedRoot(t *testing.T) {
	caPEM, _ := testCA(t)
	c := testConfig()
	c.CAPEM = caPEM

	b, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "com.apple.security.root") {
		t.Fatalf("no root certificate payload:\n%s", got)
	}
	// The VPN payload must still be there: a profile that installs only a CA
	// looks like it worked and configures nothing.
	if !strings.Contains(got, "com.apple.vpn.managed") {
		t.Error("the VPN payload went missing")
	}

	// Apple's certificate payloads carry DER, not PEM. Handing them PEM
	// produces a profile that installs and then validates nothing, which reads
	// as a problem with the CA rather than with the encoding.
	start := strings.Index(got, "<data>")
	end := strings.Index(got, "</data>")
	if start < 0 || end < 0 {
		t.Fatal("no <data> element carrying the certificate")
	}
	raw := strings.Join(strings.Fields(got[start+len("<data>"):end]), "")
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("the payload is not base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the payload is not DER: %v", err)
	}
	if cert.Subject.CommonName != "gotun-test-ca" {
		t.Errorf("embedded the wrong certificate: %s", cert.Subject.CommonName)
	}
	if strings.Contains(got, "BEGIN CERTIFICATE") {
		t.Error("the profile carries PEM, which iOS will not use")
	}
}

// A leaf passed where a CA belongs would install, be trusted for nothing, and
// leave the same generic connect error.
func TestValidate_RejectsSomethingThatIsNotACA(t *testing.T) {
	_, leafPEM := testCA(t)
	c := testConfig()
	c.CAPEM = leafPEM
	err := c.Validate()
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("the error should say why, got: %v", err)
	}
}

func TestValidate_RejectsAnUnreadableCA(t *testing.T) {
	for _, bad := range [][]byte{
		[]byte("not pem at all"),
		[]byte("-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n"),
	} {
		c := testConfig()
		c.CAPEM = bad
		if err := c.Validate(); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// A first test against a gateway that is not reachable from everywhere needs a
// profile the person connects by hand. On-demand with an unconditional Connect
// rule and no probe makes the phone try on every network and hold traffic
// where it cannot reach the gateway, which breaks their internet the moment
// they leave the house.
func TestProfile_OnDemandCanBeShippedOff(t *testing.T) {
	c := testConfig()
	c.OnDemandDisabled = true
	b, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "<key>OnDemandEnabled</key>\n\t\t\t<integer>0</integer>") {
		t.Errorf("on-demand should be off:\n%s", got)
	}
	// Omitted rather than present-but-inert: a rule list that is not being
	// evaluated is the kind of thing somebody later reads as the behaviour.
	if strings.Contains(got, "OnDemandRules") {
		t.Error("the rules should not be emitted when on-demand is off")
	}
	// ...and the tunnel itself must still be fully configured.
	if !strings.Contains(got, "com.apple.vpn.managed") || !strings.Contains(got, "IKEv2") {
		t.Error("the VPN payload went missing")
	}
}

// The resolver a split tunnel pushes is configured and then never used unless
// the profile says which queries belong to it: iOS treats a non-default-route
// tunnel's DNS servers as supplemental, consulted only for the domains listed.
// Measured on a live phone -- charon pushed the address on every connect and
// zero queries ever arrived.
func TestProfile_DNSMatchDomainsDecideWhetherTheResolverIsUsedAtAll(t *testing.T) {
	c := testConfig()
	c.DNSMatchDomains = []string{""}
	b, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	if !strings.Contains(got, "<key>DNS</key>") {
		t.Fatalf("no DNS settings:\n%s", got)
	}
	// Placement, not just presence. Apple puts DNS at the payload level
	// because it applies to every VPN type, and iOS silently ignores an
	// unknown key nested inside the IKEv2 dictionary -- a profile with it in
	// the wrong place installs cleanly, looks right and changes nothing. That
	// is how this shipped once.
	if indentOf(t, got, "<key>DNS</key>") != indentOf(t, got, "<key>IKEv2</key>") {
		t.Errorf("DNS must be a sibling of IKEv2, not nested inside it:\n%s", got)
	}
	if !strings.Contains(got, "<string>"+c.VIPGateway.String()+"</string>") {
		t.Error("the resolver address is not the one the pool pushes")
	}
	// The empty string is the documented way to match every domain, and it has
	// to survive serialisation as an actually-empty element: <string></string>,
	// not a self-closed or whitespace-bearing one.
	i := strings.Index(got, "<key>SupplementalMatchDomains</key>")
	if i < 0 {
		t.Fatal("no SupplementalMatchDomains")
	}
	window := got[i:min(len(got), i+200)]
	if !strings.Contains(window, "<string></string>") {
		t.Errorf("the match-all empty string did not survive:\n%s", window)
	}
	if !strings.Contains(got, "<key>SupplementalMatchDomainsNoSearch</key>") {
		t.Error("an empty search domain would be meaningless; it must be suppressed")
	}
}

// A named list sends only those queries to the gateway, leaving everything else
// on the phone's own resolver.
func TestProfile_DNSMatchCanBeNarrowedToDomains(t *testing.T) {
	c := testConfig()
	c.DNSMatchDomains = []string{"ru", "lan"}
	b, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, d := range []string{"<string>ru</string>", "<string>lan</string>"} {
		if !strings.Contains(got, d) {
			t.Errorf("missing %s", d)
		}
	}
	if strings.Contains(got, "<string></string>") {
		t.Error("a narrowed list must not also match everything")
	}
}

// Nil emits nothing, which is the state the profile was in before: the
// resolver pushed by IKEv2 and never consulted.
func TestProfile_DNSSettingsCanBeOmitted(t *testing.T) {
	c := testConfig()
	c.DNSMatchDomains = nil
	b, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "<key>DNS</key>") {
		t.Error("no DNS settings were asked for")
	}
}

// indentOf reports how many tabs precede a line, which is how the structural
// placement of a key is checked without pulling in a plist parser.
func indentOf(t *testing.T, doc, key string) int {
	t.Helper()
	for _, line := range strings.Split(doc, "\n") {
		if strings.TrimSpace(line) == key {
			return len(line) - len(strings.TrimLeft(line, "\t"))
		}
	}
	t.Fatalf("%s not found", key)
	return -1
}
