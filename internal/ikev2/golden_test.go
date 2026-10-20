package ikev2_test

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/ikev2"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/prefixes"
)

// update rewrites the golden files instead of comparing against them. Every
// change it produces has to be read in the diff before it is committed -- that
// reading is the entire value of these tests.
var update = flag.Bool("update", false, "rewrite the golden files")

// These are characterization tests, not specifications. They assert nothing
// about what the output ought to be; they pin what it currently is, so that a
// refactor which was meant to change only how the document is built cannot
// quietly change what the document says.
//
// That distinction matters for this package more than most. A profile is
// consumed by a device nobody here can inspect, and a wrong one installs
// cleanly, looks right and changes nothing -- which is exactly how the DNS
// dictionary shipped at the wrong nesting level and went unnoticed until a
// live phone was measured. Line coverage of the writer was 100% at the time.
//
// The matrix exists because the interesting failures live in the combinations:
// which payloads appear, in what order, and at what depth.
func goldenConfig() ikev2.Config {
	return ikev2.Config{
		Server:      "vpn.example.net",
		GatewayID:   "vpn.example.net",
		ClientID:    "iphone",
		VIPSubnet:   netip.MustParsePrefix("10.231.17.0/24"),
		VIPGateway:  netip.MustParseAddr("10.231.17.1"),
		Pool:        netip.MustParsePrefix("10.231.17.16/28"),
		NonRoutable: policy.DefaultNonRoutable(),
		Families:    prefixes.Families{V4: true},
	}
}

// goldenCA is a committed fixture rather than a freshly minted certificate.
// A golden file that changes on every run is worse than no golden file: it
// fails constantly, gets re-blessed without being read, and the one time it
// reports something real nobody looks.
func goldenCA(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGolden_Profile(t *testing.T) {
	caPEM := goldenCA(t)

	cases := []struct {
		name string
		mut  func(*ikev2.Config)
	}{
		{name: "minimal", mut: func(*ikev2.Config) {}},
		{name: "with-ca", mut: func(c *ikev2.Config) { c.CAPEM = caPEM }},
		{name: "on-demand-off", mut: func(c *ikev2.Config) { c.OnDemandDisabled = true }},
		{
			name: "dns-match-all",
			mut:  func(c *ikev2.Config) { c.DNSMatchDomains = []string{""} },
		},
		{
			name: "dns-match-domains",
			mut:  func(c *ikev2.Config) { c.DNSMatchDomains = []string{"ru", "lan"} },
		},
		{
			name: "home-ssids-and-probe",
			mut: func(c *ikev2.Config) {
				c.HomeSSIDs = []string{"Home", "Home 5G"}
				c.ProbeURL = "http://vpn.example.net:8443/alive"
			},
		},
		{
			name: "dual-stack",
			mut:  func(c *ikev2.Config) { c.Families = prefixes.Families{V4: true, V6: true} },
		},
		{
			name: "dpd-medium-and-keepalive",
			mut: func(c *ikev2.Config) {
				c.DPDRate = ikev2.DPDMedium
				c.KeepAliveInterval = 60
			},
		},
		{
			name: "named-profile",
			mut: func(c *ikev2.Config) {
				c.ProfileName = "Home split tunnel"
				c.Identifier = "net.example.vpn"
			},
		},
		{
			// The shape actually deployed, which is the one a refactor must
			// not disturb.
			name: "production",
			mut: func(c *ikev2.Config) {
				c.CAPEM = caPEM
				c.DNSMatchDomains = []string{""}
				c.HomeSSIDs = []string{"Home", "Home 5G", "Home-Guest"}
				c.ProbeURL = "http://vpn.example.net:8443/alive"
				c.ProfileName = "gotun iphone"
			},
		},
		{
			// Escaping is easy to lose in a rewrite, and the symptom is a
			// profile iOS refuses to parse at all.
			name: "needs-escaping",
			mut: func(c *ikev2.Config) {
				c.HomeSSIDs = []string{`Ben & Jerry's <home>`, `"quoted"`}
				c.ProfileName = `A & B <vpn>`
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goldenConfig()
			tc.mut(&c)
			got, err := ikev2.EncodeProfile(c)
			if err != nil {
				t.Fatal(err)
			}
			compareGolden(t, filepath.Join("testdata", "profile", tc.name+".mobileconfig"), got)
		})
	}
}

func TestGolden_Swanctl(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ikev2.Config)
	}{
		{name: "shared", mut: func(*ikev2.Config) {}},
		{name: "dual-stack", mut: func(c *ikev2.Config) { c.Families = prefixes.Families{V4: true, V6: true} }},
		{
			name: "custom-proposals",
			mut: func(c *ikev2.Config) {
				c.IKEProposals = "aes256gcm16-prfsha384-ecp384"
				c.ESPProposals = "aes256gcm16-ecp384"
				c.DPDRate = ikev2.DPDLow
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goldenConfig()
			tc.mut(&c)
			got, err := ikev2.RenderSwanctl(c)
			if err != nil {
				t.Fatal(err)
			}
			compareGolden(t, filepath.Join("testdata", "swanctl", tc.name+".conf"), []byte(got))
		})
	}
}

func TestGolden_UserCredential(t *testing.T) {
	u := ikev2.User{
		Name:    "iphone",
		Created: time.Date(2026, 10, 19, 18, 18, 0, 0, time.UTC),
	}
	got, err := ikev2.RenderUser(u, "AAAAA-BBBBB-CCCCC-DDDDD")
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, filepath.Join("testdata", "swanctl", "user.conf"), []byte(got))
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run `go test ./internal/ikev2/ -update` and read the diff", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s changed.\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}
