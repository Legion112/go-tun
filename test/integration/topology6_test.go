//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

// labNonRoutable6 is the IPv6 counterpart of labNonRoutable, and it carries the
// same trap in a worse form.
//
// The production default excludes fc00::/7, and every network in this lab is
// ULA, i.e. inside fc00::/7. Left at the default, no IPv6 destination here is
// ever classified, nothing is marked, and every IPv6 test below passes without
// proving anything at all.
//
// fe80::/10 and ff00::/8 must stay: neighbour discovery is ICMPv6 to link-local
// and multicast addresses, so marking them does not break service discovery, it
// breaks address resolution and with it every IPv6 flow on the segment.
const labNonRoutable6 = "fe80::/10,::1/128,ff00::/8"

// The IPv6 plan mirrors the IPv4 numbering so the two can be read side by side.
// Docker takes ::1 of each subnet for the bridge, exactly as it takes .1, so
// nothing is ever assigned there.
const (
	lanNet6     = "fd00:10::/64"
	wgNet6      = "fd00:20::/64"
	ruNet6      = "fd00:200::/64"
	foreignNet6 = "fd00:30::/64"

	clientIP6      = "fd00:10::10"
	gotunLanIP6    = "fd00:10::2"
	gotunWgIP6     = "fd00:20::2"
	gotunRuIP6     = "fd00:200::2"
	exitWgIP6      = "fd00:20::3"
	exitForeignIP6 = "fd00:30::2"
	ispWgIP6       = "fd00:20::4"
	ispForeignIP6  = "fd00:30::3"
	ruDestIP6      = "fd00:200::10"
	foreignDestIP6 = "fd00:30::10"
)

// TestLabNonRoutable6ExcludesULA fails the moment someone "fixes" the lab by
// pasting the production IPv6 default into labNonRoutable6. Every lab network
// is ULA, so fc00::/7 in that list makes every IPv6 test here vacuous -- they
// would pass while classifying nothing.
func TestLabNonRoutable6ExcludesULA(t *testing.T) {
	ula := netip.MustParsePrefix("fc00::/7")
	var sawLinkLocal, sawMulticast bool
	for _, s := range strings.Split(labNonRoutable6, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			t.Fatalf("labNonRoutable6 entry %q: %v", s, err)
		}
		if p.Overlaps(ula) {
			t.Fatalf("%s overlaps ULA space; every lab network is ULA, so this makes"+
				" the IPv6 tests pass without classifying anything", p)
		}
		switch {
		case p.String() == "fe80::/10":
			sawLinkLocal = true
		case p.String() == "ff00::/8":
			sawMulticast = true
		}
	}
	if !sawLinkLocal || !sawMulticast {
		t.Fatal("link-local and multicast must stay excluded, or neighbour discovery gets marked")
	}
}

type topo6 struct {
	lab          *harness.Lab
	gotunPriv    string
	gotunPub     string
	exitPriv     string
	exitPub      string
	prefixesFile string
}

func requireIPv6Lab(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := harness.SupportsIPv6Networks(ctx); err != nil {
		t.Skipf("skipping IPv6 lab: %v", err)
	}
}

// setupTopo6 is setupTopo with both families live on every link. It stays a
// separate fixture rather than a flag on the original so the IPv4 labs keep
// running byte-for-byte as they did.
func setupTopo6(t *testing.T) *topo6 {
	t.Helper()
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}
	requireIPv6Lab(t, ctx)

	prefix := fmt.Sprintf("gotun6%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "lan", "10.10.0.0/24", harness.NetOpts{Subnet6: lanNet6}))
	must(t, lab.CreateNetwork(ctx, "wgnet", "10.20.0.0/24", harness.NetOpts{Subnet6: wgNet6}))
	must(t, lab.CreateNetwork(ctx, "ru", "10.200.0.0/24", harness.NetOpts{Subnet6: ruNet6}))
	must(t, lab.CreateNetwork(ctx, "foreign", "10.30.0.0/24", harness.NetOpts{Subnet6: foreignNet6}))

	must(t, lab.RunContainer(ctx, "client", image, "10.10.0.10", "lan", nil,
		harness.RunOpts{IP6: clientIP6}))
	must(t, lab.RunContainer(ctx, "gotun", image, "10.10.0.2", "lan", map[string]string{
		"wgnet": "10.20.0.2",
		"ru":    "10.200.0.2",
	}, harness.RunOpts{IP6: gotunLanIP6, Extra6: map[string]string{
		"wgnet": gotunWgIP6,
		"ru":    gotunRuIP6,
	}}))
	must(t, lab.RunContainer(ctx, "exit", image, "10.20.0.3", "wgnet", map[string]string{
		"foreign": "10.30.0.2",
	}, harness.RunOpts{IP6: exitWgIP6, Extra6: map[string]string{"foreign": exitForeignIP6}}))
	must(t, lab.RunContainer(ctx, "isp", image, "10.20.0.4", "wgnet", map[string]string{
		"foreign": "10.30.0.3",
	}, harness.RunOpts{IP6: ispWgIP6, Extra6: map[string]string{"foreign": ispForeignIP6}}))
	must(t, lab.RunContainer(ctx, "ru-dest", image, "10.200.0.10", "ru", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "RU"},
		IP6:        ruDestIP6,
	}))
	must(t, lab.RunContainer(ctx, "foreign-dest", image, "10.30.0.10", "foreign", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "FOREIGN"},
		IP6:        foreignDestIP6,
	}))

	nodes := map[string]string{
		"client": clientIP6, "gotun": gotunLanIP6, "exit": exitWgIP6,
		"isp": ispWgIP6, "ru-dest": ruDestIP6, "foreign-dest": foreignDestIP6,
	}
	for n, a6 := range nodes {
		must(t, lab.WaitReady(ctx, n))
		must(t, lab.WaitReadyV6(ctx, n, a6))
	}

	gotunPriv, gotunPub := genWGKeys(t, lab, "gotun")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")
	tp := &topo6{lab: lab, gotunPriv: gotunPriv, gotunPub: gotunPub, exitPriv: exitPriv, exitPub: exitPub}

	for _, n := range []string{"ru-dest", "foreign-dest"} {
		via4, via6 := "10.200.0.2", gotunRuIP6
		if n == "foreign-dest" {
			via4, via6 = "10.30.0.2", exitForeignIP6
		}
		must(t, lab.ExecOK(ctx, n, "ip", "route", "replace", "default", "via", via4))
		must(t, lab.ExecOK(ctx, n, "ip", "-6", "route", "replace", "default", "via", via6))
	}

	// The exit peer is dual-stack: it carries both families over one tunnel and
	// masquerades both on the way out, which is what makes the source-identity
	// assertions below mean something.
	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg-exit private-key /tmp/exit.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.10.0.0/24,10.99.0.0/30,10.200.0.0/24,fd00:10::/64,fd00:99::/126,fd00:200::/64 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip address replace fd00:99::2/126 dev wg-exit
ip link set wg-exit up
ip route replace 10.10.0.0/24 dev wg-exit
ip route replace 10.200.0.0/24 dev wg-exit
ip -6 route replace fd00:10::/64 dev wg-exit
ip -6 route replace fd00:200::/64 dev wg-exit
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting meta nfproto ipv4 oifname != "lo" masquerade || true
nft add rule inet exitnat postrouting meta nfproto ipv6 oifname != "lo" masquerade || true
`, exitPriv, gotunPub)))

	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru.txt")
	mustWrite(t, prefPath, "10.200.0.0/24\nfd00:200::/64\n")
	must(t, lab.Copy(ctx, "gotun", prefPath, "/tmp/ru.txt"))

	wgConf := filepath.Join(dir, "wg-exit.conf")
	mustWrite(t, wgConf, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.0.1/30, fd00:99::1/126
ListenPort = 51820

[Peer]
PublicKey = %s
Endpoint = 10.20.0.3:51820
AllowedIPs = 10.30.0.0/24,10.99.0.0/30,fd00:30::/64,fd00:99::/126
PersistentKeepalive = 5
`, gotunPriv, exitPub))
	must(t, lab.Copy(ctx, "gotun", wgConf, "/tmp/wg-exit.conf"))

	applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true")

	// ISP uplink, so fail-open has somewhere to fall back to, and so an IPv6
	// leak has a path that visibly is not the tunnel.
	must(t, lab.ExecOK(ctx, "isp", "ip", "route", "replace", "10.10.0.0/24", "via", "10.20.0.2"))
	must(t, lab.ExecOK(ctx, "isp", "ip", "-6", "route", "replace", lanNet6, "via", gotunWgIP6))
	must(t, lab.ExecOK(ctx, "isp", "bash", "-c", `
set -e
nft add table inet ispnat || true
nft 'add chain inet ispnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet ispnat postrouting meta nfproto ipv4 oifname != "lo" masquerade || true
nft add rule inet ispnat postrouting meta nfproto ipv6 oifname != "lo" masquerade || true
`))
	must(t, lab.ExecOK(ctx, "gotun", "ip", "route", "replace", "default", "via", "10.20.0.4"))
	must(t, lab.ExecOK(ctx, "gotun", "ip", "-6", "route", "replace", "default", "via", ispWgIP6))

	must(t, lab.ExecOK(ctx, "client", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "client", "ip", "-6", "route", "replace", "default", "via", gotunLanIP6))

	tp.prefixesFile = "/tmp/ru.txt"
	return tp
}

// applyTopo6 runs a real gotun apply inside the gotun container and returns its
// output, so tests can assert on the convergence line as well as on behaviour.
func applyTopo6(t *testing.T, tp *topo6, extra ...string) string {
	t.Helper()
	args := []string{"gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", labNonRoutable + "," + labNonRoutable6,
		"-endpoint", "10.20.0.3,fd00:20::3",
		"-lan", "10.10.0.0/24,10.20.0.0/24,10.200.0.0/24," + lanNet6 + "," + wgNet6 + "," + ruNet6,
		"-wg-config", "/tmp/wg-exit.conf",
		"-mark-iface", "eth0",
	}
	args = append(args, extra...)
	out, err := tp.lab.Exec(context.Background(), "gotun", args...)
	if err != nil {
		t.Fatalf("gotun apply failed: %v\n%s", err, out)
	}
	return out
}

// curl6 fetches an IPv6 URL. -g is required: curl reads the brackets as a glob
// otherwise.
func curl6(t *testing.T, tp *topo6, from, addr, path string) (string, error) {
	t.Helper()
	url := fmt.Sprintf("http://[%s]:8080%s", addr, path)
	return tp.lab.Exec(context.Background(), from, "curl", "-g", "-s", "--max-time", "5", url)
}

// peerAddr parses what labhttp's /peer handler echoed back. Comparing IPv6 as
// text is fragile -- the same address has many spellings -- so it is compared
// as a parsed address.
func peerAddr(t *testing.T, out string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("not an address: %q", out)
	}
	return a.Unmap()
}

// TestIPv6HappyPath_RUDirect_ForeignViaExit is the central claim of IPv6
// support, proved by egress identity rather than by reachability.
//
// Both destinations answer either way, so a body check would pass even with no
// classification at all. What distinguishes the two paths is the address the
// destination sees: a direct packet arrives with the client's own address,
// while a tunnelled one arrives masqueraded behind the exit.
func TestIPv6HappyPath_RUDirect_ForeignViaExit(t *testing.T) {
	tp := setupTopo6(t)

	ruBody, err := curl6(t, tp, "client", ruDestIP6, "/id")
	if err != nil || strings.TrimSpace(ruBody) != "RU" {
		t.Fatalf("IPv6 RU destination unreachable: %v %q", err, ruBody)
	}
	fgBody, err := curl6(t, tp, "client", foreignDestIP6, "/id")
	if err != nil || strings.TrimSpace(fgBody) != "FOREIGN" {
		t.Fatalf("IPv6 foreign destination unreachable: %v %q", err, fgBody)
	}

	ruPeer, err := curl6(t, tp, "client", ruDestIP6, "/peer")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := peerAddr(t, ruPeer), netip.MustParseAddr(clientIP6); got != want {
		t.Fatalf("the RU destination must see the client directly (%s), saw %s:"+
			" IPv6 direct traffic is not going direct", want, got)
	}

	fgPeer, err := curl6(t, tp, "client", foreignDestIP6, "/peer")
	if err != nil {
		t.Fatal(err)
	}
	got := peerAddr(t, fgPeer)
	if want := netip.MustParseAddr(exitForeignIP6); got != want {
		t.Fatalf("the foreign destination must see the exit (%s), saw %s:"+
			" IPv6 traffic is not going through the tunnel", want, got)
	}
	if got == netip.MustParseAddr(clientIP6) {
		t.Fatal("the foreign destination saw the client's own IPv6 address -- the policy is leaking")
	}
}

// TestDualStack_BothFamiliesClassifiedInOneTopology is the regression guard for
// the change as a whole: an IPv6 implementation that broke IPv4 would pass
// every test above.
func TestDualStack_BothFamiliesClassifiedInOneTopology(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	cases := []struct {
		name, from, dst, wantPeer string
	}{
		{"v4 RU direct", "client", "10.200.0.10", "10.10.0.10"},
		{"v4 foreign via exit", "client", "10.30.0.10", "10.30.0.2"},
	}
	for _, c := range cases {
		out, err := tp.lab.Exec(ctx, c.from, "curl", "-s", "--max-time", "5",
			fmt.Sprintf("http://%s:8080/peer", c.dst))
		if err != nil {
			t.Fatalf("%s: %v (%s)", c.name, err, out)
		}
		if got, want := peerAddr(t, out), netip.MustParseAddr(c.wantPeer); got != want {
			t.Fatalf("%s: destination saw %s, want %s", c.name, got, want)
		}
	}

	for _, c := range []struct{ name, dst, wantPeer string }{
		{"v6 RU direct", ruDestIP6, clientIP6},
		{"v6 foreign via exit", foreignDestIP6, exitForeignIP6},
	} {
		out, err := curl6(t, tp, "client", c.dst, "/peer")
		if err != nil {
			t.Fatalf("%s: %v (%s)", c.name, err, out)
		}
		if got, want := peerAddr(t, out), netip.MustParseAddr(c.wantPeer); got != want {
			t.Fatalf("%s: destination saw %s, want %s", c.name, got, want)
		}
	}
}

// TestIPv6IdempotentApply applies three times, not two. A single re-apply
// cannot tell a converged reconciler from one that oscillates between two
// states, which is exactly the shape a readback bug takes.
func TestIPv6IdempotentApply(t *testing.T) {
	tp := setupTopo6(t)

	second := applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true")
	if !strings.Contains(second, "gotun apply: 0 changes") {
		t.Fatalf("a converged dual-stack box must report 0 changes, got: %s", second)
	}
	third := applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true")
	if strings.TrimSpace(second) != strings.TrimSpace(third) {
		t.Fatalf("applies 2 and 3 differ, so the reconciler is oscillating:\n2: %s\n3: %s", second, third)
	}
}

// TestIPv6_TextPathConvergesLikeJSONPath simulates the router.
//
// OpenWrt ships nftables without JSON, so the gateway this is written for reads
// its live table through the text parser -- the one that cannot tell ip from
// ip6. If the two paths disagree about convergence, the box that churns is the
// real one, rebuilding a 17k-element table on every apply while a developer's
// JSON-capable machine reports everything is fine.
func TestIPv6_TextPathConvergesLikeJSONPath(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	if out := applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true"); !strings.Contains(out, "0 changes") {
		t.Fatalf("expected a converged starting point, got: %s", out)
	}

	// Shadow nft with a wrapper that refuses -j, the way a nojson build does.
	// /usr/local/sbin precedes /usr/sbin on root's PATH in this image.
	must(t, tp.lab.ExecOK(ctx, "gotun", "bash", "-c", `
set -e
cat >/usr/local/sbin/nft <<'EOF'
#!/bin/sh
for a in "$@"; do [ "$a" = "-j" ] && { echo "Error: JSON support not compiled in" >&2; exit 1; }; done
exec /usr/sbin/nft "$@"
EOF
chmod +x /usr/local/sbin/nft
`))
	// Prove the shim is actually in effect, or this test passes vacuously.
	if _, err := tp.lab.Exec(ctx, "gotun", "nft", "-j", "list", "table", "inet", "gotun"); err == nil {
		t.Fatal("the nojson shim is not in effect; this test would prove nothing")
	}

	out := applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true")
	if !strings.Contains(out, "gotun apply: 0 changes") {
		t.Fatalf("a converged box without JSON nft must also report 0 changes, got: %s\n"+
			"the router reads its table this way, so this is a full table rebuild on every apply", out)
	}
}

// TestIPv6FailClosed_BlackholesMarkedTraffic also checks that IPv4 is
// undisturbed: a fail-mode change for one family must not move the other.
func TestIPv6FailClosed_BlackholesMarkedTraffic(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "false")

	routes, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "route", "show", "table", "100")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(routes, "blackhole") {
		t.Fatalf("IPv6 table 100 must end in a blackhole, got: %q", routes)
	}

	// A blackholed IPv6 lookup reports EINVAL rather than printing the word
	// "blackhole", so the assertion is that the command fails -- the IPv4
	// phrasing does not carry over.
	if out, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "route", "get",
		foreignDestIP6, "from", gotunLanIP6, "mark", "0x1"); err == nil {
		t.Fatalf("a marked IPv6 lookup must hit the blackhole, got: %q", out)
	}

	if _, err := curl6(t, tp, "client", foreignDestIP6, "/id"); err == nil {
		t.Fatal("non-direct IPv6 must not reach the uplink when fail-closed")
	}
	ru, err := curl6(t, tp, "client", ruDestIP6, "/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("direct IPv6 must keep working while fail-closed: %v %q", err, ru)
	}
	v4, err := tp.lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(v4) != "RU" {
		t.Fatalf("IPv4 must be undisturbed by an IPv6 fail-mode change: %v %q", err, v4)
	}
}

// TestIPv6FailOpen_FallsBackToUplink establishes that the IPv4 fail-open design
// carries over: an empty owned table means the lookup misses and the RPDB
// continues to main.
//
// The egress-identity half is what makes it honest. FailOpen is documented as a
// SILENT fallback, detectable only by checking who the destination thinks you
// are -- so that is what is checked, rather than mere reachability.
func TestIPv6FailOpen_FallsBackToUplink(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	applyTopo6(t, tp, "-fail-mode", "open", "-tunnel-up", "false")

	routes, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "route", "show", "table", "100")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(routes) != "" {
		t.Fatalf("fail-open must leave the IPv6 owned table empty, got: %q", routes)
	}

	peer, err := curl6(t, tp, "client", foreignDestIP6, "/peer")
	if err != nil {
		t.Fatalf("fail-open must still reach the destination: %v", err)
	}
	got := peerAddr(t, peer)
	if want := netip.MustParseAddr(ispForeignIP6); got != want {
		t.Fatalf("fail-open must egress the ISP (%s), saw %s", want, got)
	}
	if got == netip.MustParseAddr(exitForeignIP6) {
		t.Fatal("traffic still went through the exit; this is not the fail-open path")
	}
}

// TestIPv6NoBypass_Classified replaces the old TestIPv6NoBypass, which asserted
// that IPv6 was disabled. The guard is now that IPv6 does not slip past the
// policy, and it needs both halves: "must fail" alone would also pass if IPv6
// were simply broken, which is precisely what the old version had baked in.
func TestIPv6NoBypass_Classified(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	out, _ := tp.lab.Exec(ctx, "client", "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6")
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("the client must have IPv6 enabled for this to mean anything, got %q", out)
	}
	addrs, err := tp.lab.Exec(ctx, "client", "ip", "-o", "-6", "addr", "show", "scope", "global")
	if err != nil || !strings.Contains(addrs, clientIP6) {
		t.Fatalf("client has no global IPv6 address: %v %q", err, addrs)
	}

	chain, err := tp.lab.Exec(ctx, "gotun", "nft", "list", "chain", "inet", "gotun", "prerouting")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(chain, "ip6 daddr") || !strings.Contains(chain, "mark-non-direct-v6") {
		t.Fatalf("a dual-stack kernel with no IPv6 classifier IS the bypass:\n%s", chain)
	}

	// Negative: with the tunnel down and fail-closed, non-direct IPv6 must not
	// find its way out.
	applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "false")
	if _, err := curl6(t, tp, "client", foreignDestIP6, "/id"); err == nil {
		t.Fatal("non-direct IPv6 escaped while the tunnel was down")
	}
	// Positive: and it works again once the tunnel is back, so the failure
	// above was the policy and not a broken lab.
	applyTopo6(t, tp, "-fail-mode", "closed", "-tunnel-up", "true")
	body, err := curl6(t, tp, "client", foreignDestIP6, "/id")
	if err != nil || strings.TrimSpace(body) != "FOREIGN" {
		t.Fatalf("bringing the tunnel back must restore IPv6: %v %q", err, body)
	}
}

// TestIPv6UnderlayEndpointNotMarked pins that the peer's IPv6 underlay address
// is excluded. Without it the IPv6 classifier marks the tunnel's own
// encapsulated packets and the tunnel eats itself.
func TestIPv6UnderlayEndpointNotMarked(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	chain, err := tp.lab.Exec(ctx, "gotun", "nft", "list", "chain", "inet", "gotun", "prerouting")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(chain, exitWgIP6) || !strings.Contains(chain, "exclude-endpoint-v6") {
		t.Fatalf("the IPv6 underlay endpoint must be excluded from marking:\n%s", chain)
	}
	got, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "route", "get", exitWgIP6)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "wg-exit") {
		t.Fatalf("the endpoint must not route into the tunnel it establishes: %q", got)
	}
}

// TestIPv6ClearRemovesEverything pins that teardown covers both families.
// Clearing IPv4 alone would leave the IPv6 rule steering at a table that had
// just been emptied, on a box the operator believes is clean.
func TestIPv6ClearRemovesEverything(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	must(t, tp.lab.ExecOK(ctx, "gotun", "gotun", "clear"))

	rules, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "rule", "show")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "fwmark 0x1") {
		t.Fatalf("the IPv6 fwmark rule survived clear: %q", rules)
	}
	routes, err := tp.lab.Exec(ctx, "gotun", "ip", "-6", "route", "show", "table", "100")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(routes) != "" {
		t.Fatalf("IPv6 table 100 survived clear: %q", routes)
	}
	if _, err := tp.lab.Exec(ctx, "gotun", "nft", "list", "table", "inet", "gotun"); err == nil {
		t.Fatal("the owned nft table survived clear")
	}
}

// TestDNSSplit_AAAAIsClassified closes the loop between the resolver and the
// classifier, which is the exact shape the original leak took.
//
// gotun-dns is deliberately qtype-blind, so it will happily hand a client an
// AAAA record for a .ru name. Before IPv6 was classified, the address in that
// record was steered by nothing at all: the client reached a "direct" site over
// IPv6 by whatever path the uplink offered, outside the policy entirely. This
// asserts both halves -- the AAAA comes back from the Direct upstream, and the
// address it names is then actually reached directly.
func TestDNSSplit_AAAAIsClassified(t *testing.T) {
	tp := setupTopo6(t)
	ctx := context.Background()

	// The source CIDR and the answer family are independent: gotun-dns reaches
	// both upstreams over IPv4, so even an AAAA query arrives from an IPv4
	// source. Each resolver therefore maps the same IPv4 source range to both
	// an A and an AAAA answer, and the qtype picks between them.
	labdnsCmd := `labdns -listen :53 ` +
		`-map 10.200.0.0/24=10.200.0.50 -map 10.30.0.0/24=10.30.0.50 ` +
		`-map 10.200.0.0/24=` + ruDestIP6 + ` -map 10.30.0.0/24=` + foreignDestIP6 +
		` >/tmp/labdns.log 2>&1 &`
	must(t, tp.lab.ExecOK(ctx, "ru-dest", "bash", "-c", labdnsCmd))
	must(t, tp.lab.ExecOK(ctx, "foreign-dest", "bash", "-c", labdnsCmd))
	time.Sleep(300 * time.Millisecond)

	must(t, tp.lab.ExecOK(ctx, "gotun", "bash", "-c",
		`gotun-dns -listen 10.10.0.2:53 -direct-upstream 10.200.0.10:53 -exit-upstream 10.30.0.10:53 -mark 0x1 >/tmp/gotun-dns.log 2>&1 &`))
	time.Sleep(300 * time.Millisecond)

	dumpLogs := func() {
		for _, pair := range [][2]string{
			{"gotun", "/tmp/gotun-dns.log"},
			{"ru-dest", "/tmp/labdns.log"},
			{"foreign-dest", "/tmp/labdns.log"},
		} {
			out, _ := tp.lab.Exec(ctx, pair[0], "cat", pair[1])
			t.Logf("%s %s:\n%s", pair[0], pair[1], out)
		}
	}

	// A .ru name resolves over the Direct upstream, so the answer is the one
	// the RU resolver gives.
	aaaa, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=3", "+tries=1",
		"@10.10.0.2", "lavka.yandex.ru", "AAAA")
	if err != nil {
		dumpLogs()
		t.Fatalf("AAAA query failed: %v", err)
	}
	got := strings.TrimSpace(aaaa)
	if got == "" {
		dumpLogs()
		t.Fatal("no AAAA answer; labdns is still replying with an A record to an AAAA query")
	}
	if want := netip.MustParseAddr(ruDestIP6); peerAddr(t, got) != want {
		dumpLogs()
		t.Fatalf("AAAA for a .ru name must come from the Direct upstream (%s), got %s", want, got)
	}

	// And the address that answer names is genuinely reached directly.
	peer, err := curl6(t, tp, "client", got, "/peer")
	if err != nil {
		t.Fatalf("reaching the AAAA answer failed: %v", err)
	}
	if want := netip.MustParseAddr(clientIP6); peerAddr(t, peer) != want {
		t.Fatalf("the AAAA destination saw %s, want the client's own address %s:"+
			" the resolver said direct but the packet did not go direct",
			peerAddr(t, peer), want)
	}

	// A non-.ru name still resolves over the Exit upstream, proving the split
	// itself is unaffected by answering AAAA.
	ex, err := tp.lab.Exec(ctx, "client", "dig", "+short", "+time=3", "+tries=1",
		"@10.10.0.2", "example.com", "AAAA")
	if err != nil {
		dumpLogs()
		t.Fatalf("AAAA query for a foreign name failed: %v", err)
	}
	if want := netip.MustParseAddr(foreignDestIP6); peerAddr(t, strings.TrimSpace(ex)) != want {
		dumpLogs()
		t.Fatalf("AAAA for a foreign name must come from the Exit upstream (%s), got %s", want, ex)
	}
}
