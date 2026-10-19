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

// phoneNonRoutable keeps the inbound peer's own /30 out of the classifier. The
// lab replaces the production non-routable list, which would otherwise cover it
// as RFC1918, so without this the gateway marks traffic to its own tunnel-side
// address and routes it at the exit.
//
// Note what is NOT here: the peer subnet must never be passed to -lan either.
// -lan feeds home_nets, so listing it would make the isolation rule drop the
// peer's traffic to itself.
const phoneNonRoutable = labNonRoutable + ",10.98.0.0/30"

// TestPhoneDeploy_SmartRoutingWithoutLANAccess is the end-to-end target for a
// phone tunnelling in to the router: it must get split routing and split DNS,
// and it must reach neither the home LAN nor the router's own services beyond
// DNS.
//
// It differs from TestLANDeploy_PortForwardHomeIsolation in the three ways that
// matter on a Flint 2 rather than a Pi:
//
//  1. gotun runs ON the router, so there is no DNAT hop -- the peer dials the
//     router's WAN address directly.
//  2. The inbound interface is created outside gotun, the way netifd creates it,
//     and is named "wgphone" -- no hyphen, because UCI section names cannot
//     contain one, so the hardcoded "wg-clients" can never be the live name.
//     gotun is told about it with -clients-iface and holds no key for it.
//  3. Restricting the router's own services is done by a host firewall stanza
//     standing in for the OpenWrt zone, because gotun's isolation is a forward
//     hook rule and the router's address is reached through input. Neither half
//     is sufficient alone, which is the whole reason this test exists.
func TestPhoneDeploy_SmartRoutingWithoutLANAccess(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunphone%d", time.Now().UnixNano()%1_000_000)
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

	// flint is the router: home LAN, WAN, the exit underlay and the RU path.
	must(t, lab.RunContainer(ctx, "flint", image, "10.10.0.2", "home", map[string]string{
		"inet":  "10.40.0.2",
		"wgnet": "10.20.0.2",
		"ru":    "10.200.0.2",
	}))
	must(t, lab.RunContainer(ctx, "phone", image, "10.40.0.10", "inet", nil))
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

	for _, n := range []string{"flint", "phone", "home-pc", "home-nas", "exit", "ru-dest", "foreign-dest"} {
		must(t, lab.WaitReady(ctx, n))
	}

	must(t, lab.ExecOK(ctx, "home-pc", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "home-nas", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.200.0.2"))
	must(t, lab.ExecOK(ctx, "foreign-dest", "ip", "route", "replace", "default", "via", "10.30.0.2"))
	must(t, lab.ExecOK(ctx, "phone", "ip", "route", "replace", "default", "via", "10.40.0.2"))

	flintPriv, flintPub := genWGKeys(t, lab, "flint")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")
	phoneIfPriv, phoneIfPub := genWGKeys(t, lab, "flint")
	phonePriv, phonePub := genWGKeys(t, lab, "phone")

	// Exit hop. AllowedIPs must carry the peer's /30 as well as the home LAN, or
	// replies to the phone have nowhere to go and the tunnel looks healthy while
	// connections hang.
	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg-exit private-key /tmp/exit.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.10.0.0/24,10.98.0.0/30,10.99.0.0/30,10.200.0.0/24 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip link set wg-exit up
ip route replace 10.10.0.0/24 dev wg-exit
ip route replace 10.98.0.0/30 dev wg-exit
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting oifname != "lo" masquerade || true
`, exitPriv, flintPub)))

	// The inbound interface, created the way netifd would: outside gotun, with a
	// name that has no hyphen, and with the key held by the box rather than by
	// the classifier.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wgphone type wireguard || true
echo '%s' > /tmp/wgphone.key
wg set wgphone private-key /tmp/wgphone.key listen-port 51821
wg set wgphone peer %s allowed-ips 10.98.0.2/32
ip address replace 10.98.0.1/30 dev wgphone
ip link set wgphone up
`, phoneIfPriv, phonePub)))

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

	homeIf := ifaceForAddr(t, lab, "flint", "10.10.0.2")

	// The classifier must cover the peer interface. Leaving it out is the live
	// br-guest/br-iot bug: the peer would get no split routing at all and
	// nothing would report it.
	must(t, lab.ExecOK(ctx, "flint", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", phoneNonRoutable,
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24",
		"-clients-iface", "wgphone",
		"-mark-iface", homeIf+",wgphone",
		"-wg-config", "/tmp/wg-exit.conf",
		"-tunnel-up", "true",
	))

	// Host firewall, standing in for the OpenWrt zone. gotun classifies; it does
	// not firewall the box it runs on, and the guest and iot zones on the real
	// router already have exactly this shape: input REJECT plus Allow-DNS.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", `
set -e
nft add table inet hostfw
nft 'add chain inet hostfw input { type filter hook input priority 0 ; policy accept ; }'
nft add rule inet hostfw input iifname "wgphone" ct state established,related accept
nft add rule inet hostfw input iifname "wgphone" udp dport 53 accept
nft add rule inet hostfw input iifname "wgphone" tcp dport 53 accept
nft add rule inet hostfw input iifname "wgphone" drop
`))

	// A service on the router's own LAN address, to prove the peer cannot reach
	// the router itself -- the half gotun's forward-hook isolation cannot cover.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c",
		`labhttp -listen 10.10.0.2:18080 -body ROUTER >/tmp/router-http.log 2>&1 &`))

	// Split DNS on the tunnel-side address, which is what a phone's DNS = line
	// would point at.
	labdnsCmd := `labdns -listen :53 -map 10.200.0.0/24=10.200.0.50 -map 10.30.0.0/24=10.30.0.50 >/tmp/labdns.log 2>&1 &`
	must(t, lab.ExecOK(ctx, "ru-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "foreign-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c",
		`gotun-dns -listen 10.98.0.1:53 -direct-upstream 10.200.0.10:53 -exit-upstream 10.30.0.10:53 -mark 0x1 >/tmp/gotun-dns.log 2>&1 &`))
	time.Sleep(300 * time.Millisecond)

	// The phone: a dumb full-tunnel client. No geo logic, no split on the device.
	// The underlay stays on-link so the default route out wgphone cannot swallow
	// the handshake.
	must(t, lab.ExecOK(ctx, "phone", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wgphone type wireguard || true
echo '%s' > /tmp/phone.key
wg set wgphone private-key /tmp/phone.key
wg set wgphone peer %s allowed-ips 0.0.0.0/0 endpoint 10.40.0.2:51821 persistent-keepalive 5
ip address replace 10.98.0.2/30 dev wgphone
ip link set wgphone up
ip route replace 10.40.0.0/24 dev $(ip -o -4 addr show | awk '/10\.40\.0\.10\//{print $2; exit}' | cut -d@ -f1)
ip route replace default dev wgphone
`, phonePriv, phoneIfPub)))

	// --- assertions ---

	// 1: the tunnel comes up over the WAN, with no ping to help it -- ICMP to the
	// router is dropped by the zone, so keepalive has to carry the handshake.
	waitHandshake(t, lab, "phone", "wgphone", phoneIfPub)

	// 2: split routing, proved by source identity at the destination rather than
	// by which reply came back.
	ru, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("phone → RU dest: %v %q", err, ru)
	}
	ruPeer, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/peer")
	if err != nil || strings.TrimSpace(ruPeer) != "10.98.0.2" {
		t.Fatalf("RU dest must see the peer direct through the router, got %q (%v)", ruPeer, err)
	}
	foreign, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/id")
	if err != nil || strings.TrimSpace(foreign) != "FOREIGN" {
		t.Fatalf("phone → foreign dest: %v %q", err, foreign)
	}
	frPeer, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/peer")
	if err != nil || strings.TrimSpace(frPeer) != "10.30.0.2" {
		t.Fatalf("foreign dest must see the exit, got %q (%v)", frPeer, err)
	}

	// 3: no LAN access, which is the requirement this whole design exists for.
	if _, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "3", "http://10.10.0.20:8080/id"); err == nil {
		t.Fatal("phone must not reach home-nas")
	}

	// 4: no router access either. The router is part of the LAN, and this is the
	// half that lives outside gotun.
	if _, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "3", "http://10.10.0.2:18080/"); err == nil {
		t.Fatal("phone must not reach the router's own LAN address")
	}

	// 5: DNS to the gateway still works, and splits. This is why the input hook
	// cannot simply be closed.
	ruAns, err := lab.Exec(ctx, "phone", "dig", "+short", "+time=3", "+tries=1", "@10.98.0.1", "lavka.yandex.ru", "A")
	if err != nil || strings.TrimSpace(ruAns) != "10.200.0.50" {
		dumpPhoneDNSLogs(t, lab)
		t.Fatalf("want RU geo answer 10.200.0.50, got %q (%v)", ruAns, err)
	}
	exAns, err := lab.Exec(ctx, "phone", "dig", "+short", "+time=3", "+tries=1", "@10.98.0.1", "example.com", "A")
	if err != nil || strings.TrimSpace(exAns) != "10.30.0.50" {
		dumpPhoneDNSLogs(t, lab)
		t.Fatalf("want foreign geo answer 10.30.0.50, got %q (%v)", exAns, err)
	}

	// 6: the home LAN is unaffected -- isolation is one-way, not a partition.
	nas, err := lab.Exec(ctx, "home-pc", "curl", "-s", "--max-time", "5", "http://10.10.0.20:8080/id")
	if err != nil || strings.TrimSpace(nas) != "NAS" {
		t.Fatalf("home-pc → home-nas: %v %q", err, nas)
	}
	homeForeign, err := lab.Exec(ctx, "home-pc", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/id")
	if err != nil || strings.TrimSpace(homeForeign) != "FOREIGN" {
		t.Fatalf("home-pc split routing must still work: %v %q", err, homeForeign)
	}
}

// ifaceForAddr returns the device name carrying addr, because container
// interface order is not guaranteed and -mark-iface takes names.
func ifaceForAddr(t *testing.T, lab *harness.Lab, container, addr string) string {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "bash", "-c",
		fmt.Sprintf(`ip -o -4 addr show | awk '/%s\//{print $2; exit}' | cut -d@ -f1`,
			strings.ReplaceAll(addr, ".", `\.`)))
	if err != nil {
		t.Fatalf("iface for %s on %s: %v", addr, container, err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		t.Fatalf("no interface carries %s on %s", addr, container)
	}
	return name
}

// waitHandshake polls rather than pinging first: the peer zone drops ICMP to the
// router, so persistent-keepalive is what has to bring the session up.
func waitHandshake(t *testing.T, lab *harness.Lab, container, iface, peerPub string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := lab.Exec(ctx, container, "wg", "show", iface, "latest-handshakes")
		if err == nil {
			last = out
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 && f[0] == peerPub && f[1] != "0" {
					return
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("no handshake with %s on %s within 20s, last: %q", peerPub, iface, last)
}

func dumpPhoneDNSLogs(t *testing.T, lab *harness.Lab) {
	t.Helper()
	ctx := context.Background()
	for _, pair := range [][2]string{
		{"flint", "/tmp/gotun-dns.log"},
		{"ru-dest", "/tmp/labdns.log"},
		{"foreign-dest", "/tmp/labdns.log"},
	} {
		out, _ := lab.Exec(ctx, pair[0], "cat", pair[1])
		t.Logf("%s %s:\n%s", pair[0], pair[1], out)
	}
}
