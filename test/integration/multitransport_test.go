//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

// The laptop's WireGuard /30 and the phone's IKEv2 pool both have to stay out
// of the classifier, for the reason every inbound transport does: without it
// the gateway marks traffic addressed to its own tunnel-side address and routes
// it at the exit, so the resolver on that address answers nothing.
//
// Neither may be passed to -lan either. -lan feeds home_nets, so listing them
// would make the isolation rules drop each client's traffic to its own gateway.
const multiNonRoutable = labNonRoutable + "," + ikev2VIPSubnet + ",10.98.0.0/30"

// multiRoamIface is the laptop's inbound WireGuard device. Named without a
// hyphen like the phone's, because netifd creates it from a UCI section and
// those names cannot contain one.
const multiRoamIface = "wgroam"

// TestMultiTransport_EveryPathGetsSmartRoutingAtOnce is the shape the gateway
// actually runs in: a phone on IKEv2, a laptop on WireGuard and a desktop on
// the home LAN, all at the same time, all getting the same RU/non-RU decision.
//
// Each of the three reaches the classifier differently -- an xfrm interface, a
// WireGuard interface, and a bridge -- and gotun has to treat them as three
// inbound devices rather than as one. Before -clients-iface took a list, the
// isolation rule existed for whichever device happened to be named first, and
// clients on the others got the geo split *and* unrestricted access to the home
// LAN. That combination works, so nothing reported it.
//
// Running them in sequence would not test this. The transports share one
// classifier, one routing table and one exit hop, so the question is whether
// all three hold simultaneously -- which is why every path is exercised again
// at the end, after the others have been used.
func TestMultiTransport_EveryPathGetsSmartRoutingAtOnce(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunmulti%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "home", "10.10.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "inet", "10.40.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "wgnet", "10.20.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ru", "10.200.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "foreign", "10.30.0.0/24"))

	must(t, lab.RunContainer(ctx, "flint", image, "10.10.0.2", "home", map[string]string{
		"inet":  "10.40.0.2",
		"wgnet": "10.20.0.2",
		"ru":    "10.200.0.2",
	}))
	// Two remote clients on the same WAN, each using a different transport to
	// reach the same gateway address.
	must(t, lab.RunContainer(ctx, "phone", image, "10.40.0.10", "inet", nil))
	must(t, lab.RunContainer(ctx, "laptop", image, "10.40.0.11", "inet", nil))
	// And one client that is simply inside the house, with no tunnel at all.
	must(t, lab.RunContainer(ctx, "home-pc", image, "10.10.0.10", "home", nil))
	must(t, lab.RunContainer(ctx, "home-nas", image, "10.10.0.20", "home", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "NAS"},
	}))
	must(t, lab.RunContainer(ctx, "exit", image, "10.20.0.3", "wgnet", map[string]string{
		"foreign": "10.30.0.2",
	}))
	must(t, lab.RunContainer(ctx, "ru-dest", image, "10.200.0.10", "ru", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "RU"},
	}))
	must(t, lab.RunContainer(ctx, "foreign-dest", image, "10.30.0.10", "foreign", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "FOREIGN"},
	}))

	for _, n := range []string{
		"flint", "phone", "laptop", "home-pc", "home-nas", "exit", "ru-dest", "foreign-dest",
	} {
		must(t, lab.WaitReady(ctx, n))
	}
	requireXfrmInterface(t, lab, "flint")

	must(t, lab.ExecOK(ctx, "home-pc", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "home-nas", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.200.0.2"))
	must(t, lab.ExecOK(ctx, "foreign-dest", "ip", "route", "replace", "default", "via", "10.30.0.2"))
	must(t, lab.ExecOK(ctx, "phone", "ip", "route", "replace", "default", "via", "10.40.0.2"))
	must(t, lab.ExecOK(ctx, "laptop", "ip", "route", "replace", "default", "via", "10.40.0.2"))

	flintPriv, flintPub := genWGKeys(t, lab, "flint")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")
	roamIfPriv, roamIfPub := genWGKeys(t, lab, "flint")
	laptopPriv, laptopPub := genWGKeys(t, lab, "laptop")

	// The exit must carry every client subnet in AllowedIPs, or replies have
	// nowhere to go and the tunnel looks healthy while connections hang.
	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg-exit private-key /tmp/exit.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.10.0.0/24,%s,10.98.0.0/30,10.99.0.0/30,10.200.0.0/24 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip link set wg-exit up
ip route replace 10.10.0.0/24 dev wg-exit
ip route replace %s dev wg-exit
ip route replace 10.98.0.0/30 dev wg-exit
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting oifname != "lo" masquerade || true
`, exitPriv, flintPub, ikev2VIPSubnet, ikev2VIPSubnet)))

	wanIface := ifaceForAddr(t, lab, "flint", "10.40.0.2")
	homeIface := ifaceForAddr(t, lab, "flint", "10.10.0.2")

	// Both inbound devices created outside gotun, the way netifd and charon
	// create them: gotun holds the credential for neither.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
ip link add %[1]s type xfrm dev %[2]s if_id %[3]s
ip link set %[1]s up
ip address replace %[4]s/24 dev %[1]s

ip link add dev %[5]s type wireguard
echo '%[6]s' > /tmp/wgroam.key
wg set %[5]s private-key /tmp/wgroam.key listen-port 51821
wg set %[5]s peer %[7]s allowed-ips 10.98.0.2/32
ip address replace 10.98.0.1/30 dev %[5]s
ip link set %[5]s up
`, ikev2ClientsIface, wanIface, ikev2IfID, ikev2GatewayVIP,
		multiRoamIface, roamIfPriv, laptopPub)))

	writeSwanctlGateway(t, lab, "flint", ikev2Selectors())
	writeSwanctlClient(t, lab, "phone")
	startCharon(t, lab, "flint")
	startCharon(t, lab, "phone")

	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru.txt")
	mustWrite(t, prefPath, "10.200.0.0/24\n")
	must(t, lab.Copy(ctx, "flint", prefPath, "/tmp/ru.txt"))

	wgExit := filepath.Join(dir, "wg-exit.conf")
	mustWrite(t, wgExit, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.0.1/30
ListenPort = 51820

[Peer]
PublicKey = %s
Endpoint = 10.20.0.3:51820
AllowedIPs = 10.30.0.0/24,10.99.0.0/30
PersistentKeepalive = 5
`, flintPriv, exitPub))
	must(t, lab.Copy(ctx, "flint", wgExit, "/tmp/wg-exit.conf"))

	// Both inbound devices named, and both in the ingress guard. Naming only
	// one of them is the bug this test exists for; omitting one from
	// -mark-iface is the other, and Compile now refuses that outright.
	must(t, lab.ExecOK(ctx, "flint", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", multiNonRoutable,
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24",
		"-clients-iface", ikev2ClientsIface+","+multiRoamIface,
		"-mark-iface", homeIface+","+ikev2ClientsIface+","+multiRoamIface,
		"-wg-config", "/tmp/wg-exit.conf",
		"-tunnel-up", "true",
	))

	// Host firewall, standing in for the OpenWrt zones. Both remote transports
	// get the same treatment: established plus DNS, nothing else, because
	// gotun's isolation is a forward hook rule and the router's own address is
	// reached through input.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
nft add table inet hostfw
nft 'add chain inet hostfw input { type filter hook input priority 0 ; policy accept ; }'
for dev in %s %s; do
  nft add rule inet hostfw input iifname "$dev" ct state established,related accept
  nft add rule inet hostfw input iifname "$dev" udp dport 53 accept
  nft add rule inet hostfw input iifname "$dev" tcp dport 53 accept
  nft add rule inet hostfw input iifname "$dev" drop
done
nft 'add chain inet hostfw forward { type filter hook forward priority 0 ; policy accept ; }'
nft 'add rule inet hostfw forward tcp flags syn / syn,rst tcp option maxseg size set rt mtu'
`, ikev2ClientsIface, multiRoamIface)))

	// One resolver for every path, on 0.0.0.0 so each client can reach it at
	// the gateway address its own transport gives it: the phone at the xfrm
	// address, the laptop at its /30 gateway, the desktop at the LAN address.
	labdnsCmd := `labdns -listen :53 -map 10.200.0.0/24=10.200.0.50 -map 10.30.0.0/24=10.30.0.50 >/tmp/labdns.log 2>&1 &`
	must(t, lab.ExecOK(ctx, "ru-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "foreign-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c",
		`gotun-dns -listen 0.0.0.0:53 -direct-upstream 10.200.0.10:53 -exit-upstream 10.30.0.10:53 -mark 0x1 >/tmp/gotun-dns.log 2>&1 &`))
	time.Sleep(300 * time.Millisecond)

	// The laptop: a dumb full-tunnel WireGuard client. The underlay stays
	// on-link so the default route out the tunnel cannot swallow the handshake.
	must(t, lab.ExecOK(ctx, "laptop", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev %[1]s type wireguard
echo '%[2]s' > /tmp/laptop.key
wg set %[1]s private-key /tmp/laptop.key
wg set %[1]s peer %[3]s allowed-ips 0.0.0.0/0 endpoint 10.40.0.2:51821 persistent-keepalive 5
ip address replace 10.98.0.2/30 dev %[1]s
ip link set %[1]s up
ip route replace 10.40.0.0/24 dev $(ip -o -4 addr show | awk '/10\.40\.0\.11\//{print $2; exit}' | cut -d@ -f1)
ip route replace default dev %[1]s
`, multiRoamIface, laptopPriv, roamIfPub)))

	must(t, lab.ExecOK(ctx, "phone", "swanctl", "--initiate", "--child", "home"))

	// --- assertions ---

	// 1: both tunnels establish, over the same WAN, to the same gateway.
	waitIKESA(t, lab, "phone", 30*time.Second)
	waitHandshake(t, lab, "laptop", multiRoamIface, roamIfPub)

	// 2: every path gets the same decision, proved by source identity at the
	// destination rather than by which reply came back. The three sources are
	// what make this a test of three inbound devices rather than of one.
	paths := []struct {
		client  string
		ruPeer  string // what the RU destination must see: the direct path
		dnsAddr string
	}{
		{client: "phone", ruPeer: "", dnsAddr: ikev2GatewayVIP}, // VIP, checked by subnet
		{client: "laptop", ruPeer: "10.98.0.2", dnsAddr: "10.98.0.1"},
		{client: "home-pc", ruPeer: "10.10.0.10", dnsAddr: "10.10.0.2"},
	}
	for _, p := range paths {
		assertBody(t, lab, p.client, "http://10.200.0.10:8080/id", "RU")
		got := mustGet(t, lab, p.client, "http://10.200.0.10:8080/peer")
		if p.ruPeer == "" {
			if !vipSubnetContains(t, got) {
				t.Errorf("%s: RU dest must see the client's own VIP, got %q", p.client, got)
			}
		} else if got != p.ruPeer {
			t.Errorf("%s: RU dest must see %s direct through the router, got %q",
				p.client, p.ruPeer, got)
		}

		assertBody(t, lab, p.client, "http://10.30.0.10:8080/id", "FOREIGN")
		if got := mustGet(t, lab, p.client, "http://10.30.0.10:8080/peer"); got != "10.30.0.2" {
			t.Errorf("%s: foreign dest must see the exit, got %q", p.client, got)
		}
	}

	// 3: split DNS over all three paths, each at the gateway address its own
	// transport hands it.
	for _, p := range paths {
		ru, err := lab.Exec(ctx, p.client, "dig", "+short", "+time=3", "+tries=1",
			"@"+p.dnsAddr, "lavka.yandex.ru", "A")
		if err != nil || strings.TrimSpace(ru) != "10.200.0.50" {
			t.Errorf("%s: want RU geo answer 10.200.0.50 from %s, got %q (%v)",
				p.client, p.dnsAddr, ru, err)
		}
		ex, err := lab.Exec(ctx, p.client, "dig", "+short", "+time=3", "+tries=1",
			"@"+p.dnsAddr, "example.com", "A")
		if err != nil || strings.TrimSpace(ex) != "10.30.0.50" {
			t.Errorf("%s: want foreign geo answer 10.30.0.50 from %s, got %q (%v)",
				p.client, p.dnsAddr, ex, err)
		}
	}

	// 4: the requirement this whole design exists for, and the one a single
	// isolation rule used to satisfy for only one transport. BOTH remote
	// clients must be off the home LAN.
	for _, c := range []string{"phone", "laptop"} {
		if _, err := lab.Exec(ctx, c, "curl", "-s", "--max-time", "3", "http://10.10.0.20:8080/id"); err == nil {
			t.Errorf("%s must not reach home-nas", c)
		}
	}
	// ...while the client that is actually inside the house keeps it.
	assertBody(t, lab, "home-pc", "http://10.10.0.20:8080/id", "NAS")

	// 5: the isolation is per device in the live table, not just in the model.
	tbl, err := lab.Exec(ctx, "flint", "nft", "list", "table", "inet", "gotun")
	if err != nil {
		t.Fatalf("nft list table inet gotun: %v", err)
	}
	for _, dev := range []string{ikev2ClientsIface, multiRoamIface} {
		want := fmt.Sprintf(`iifname "%s"`, dev)
		if !strings.Contains(tbl, want) {
			t.Errorf("no isolation rule for %s in the live table:\n%s", dev, tbl)
		}
	}

	// 6: still simultaneous. Everything above ran in sequence, so the last
	// question is whether using one path disturbed the others -- a shared
	// classifier, one routing table and one exit hop make that worth asking
	// rather than assuming.
	ikeSAs, err := lab.Exec(ctx, "phone", "swanctl", "--list-sas")
	if err != nil || !strings.Contains(ikeSAs, "ESTABLISHED") {
		t.Errorf("the IKEv2 SA did not survive the WireGuard client's traffic: %v\n%s", err, ikeSAs)
	}
	hs, err := lab.Exec(ctx, "laptop", "wg", "show", multiRoamIface, "latest-handshakes")
	if err != nil || strings.Contains(hs, "\t0") {
		t.Errorf("the WireGuard session did not survive: %v\n%s", err, hs)
	}
	for _, p := range paths {
		assertBody(t, lab, p.client, "http://10.30.0.10:8080/id", "FOREIGN")
		assertBody(t, lab, p.client, "http://10.200.0.10:8080/id", "RU")
	}
}
