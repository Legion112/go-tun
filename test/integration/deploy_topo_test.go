//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/test/integration/harness"
)

// IP plan (never use .1 — Docker bridge gateway):
//
//	client-net 10.50.0.0/24   client .10, ru-inet .2
//	home-wan   10.51.0.0/24   ru-inet .2, home-router .3
//	ru-dest    10.52.0.0/24   ru-inet .2, ru-dest .10
//	ru-ext     10.53.0.0/24   ru-inet .2, ext-inet .3
//	ext-dest   10.54.0.0/24   ext-inet .2, non-ru .10
//	hop-net    10.55.0.0/24   ext-inet .2, remote-hop .3
//	home-lan   10.56.0.0/24   home-router .2, pi .3, home-nas .10
const (
	deployHomeRouterWAN = "10.51.0.3"
	deployPiLAN         = "10.56.0.3"
	deployRemoteHop     = "10.55.0.3"
	deployRUDest        = "10.52.0.10"
	deployNonRU         = "10.54.0.10"
	deployHomeNAS       = "10.56.0.10"
	deployClientsPort   = 51821
)

// TestDeployTopo_EgressIdentity is the high-fidelity deployment lab:
// remote client on RU Internet → home-router DNAT → Pi; RU egress identity =
// home-router; non-RU egress identity = remote-hop; physical RU→external uplink remains.
func TestDeployTopo_EgressIdentity(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotundeploy%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "client-net", "10.50.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "home-wan", "10.51.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ru-dest-net", "10.52.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ru-ext", "10.53.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ext-dest", "10.54.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "hop-net", "10.55.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "home-lan", "10.56.0.0/24"))

	must(t, lab.RunContainer(ctx, "client", image, "10.50.0.10", "client-net", nil))
	must(t, lab.RunContainer(ctx, "ru-inet", image, "10.50.0.2", "client-net", map[string]string{
		"home-wan":    "10.51.0.2",
		"ru-dest-net": "10.52.0.2",
		"ru-ext":      "10.53.0.2",
	}))
	must(t, lab.RunContainer(ctx, "home-router", image, "10.51.0.3", "home-wan", map[string]string{
		"home-lan": "10.56.0.2",
	}))
	must(t, lab.RunContainer(ctx, "pi", image, "10.56.0.3", "home-lan", nil))
	must(t, lab.RunContainer(ctx, "home-nas", image, "10.56.0.10", "home-lan", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "NAS"},
	}))
	must(t, lab.RunContainer(ctx, "ru-dest", image, "10.52.0.10", "ru-dest-net", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "RU"},
	}))
	must(t, lab.RunContainer(ctx, "ext-inet", image, "10.53.0.3", "ru-ext", map[string]string{
		"ext-dest": "10.54.0.2",
		"hop-net":  "10.55.0.2",
	}))
	must(t, lab.RunContainer(ctx, "non-ru", image, "10.54.0.10", "ext-dest", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "FOREIGN"},
	}))
	must(t, lab.RunContainer(ctx, "remote-hop", image, "10.55.0.3", "hop-net", nil))

	for _, n := range []string{"client", "ru-inet", "home-router", "pi", "home-nas", "ru-dest", "ext-inet", "non-ru", "remote-hop"} {
		must(t, lab.WaitReady(ctx, n))
	}

	// --- explicit routes on every router-like node ---
	must(t, lab.ExecOK(ctx, "ru-inet", "bash", "-c", `
set -e
ip route replace 10.54.0.0/24 via 10.53.0.3
ip route replace 10.55.0.0/24 via 10.53.0.3
ip route replace 10.56.0.0/24 via 10.51.0.3
`))
	must(t, lab.ExecOK(ctx, "ext-inet", "bash", "-c", `
set -e
ip route replace 10.50.0.0/24 via 10.53.0.2
ip route replace 10.51.0.0/24 via 10.53.0.2
ip route replace 10.52.0.0/24 via 10.53.0.2
ip route replace 10.56.0.0/24 via 10.53.0.2
`))
	must(t, lab.ExecOK(ctx, "home-router", "bash", "-c", `
set -e
ip route replace default via 10.51.0.2
# Client WG addresses arrive from Pi LAN; without this, strict rp_filter drops them.
ip route replace 10.98.0.0/30 via 10.56.0.3
sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null
WAN_IF=$(ip -o -4 addr show | awk '/10\.51\.0\.3\//{print $2; exit}' | cut -d@ -f1)
LAN_IF=$(ip -o -4 addr show | awk '/10\.56\.0\.2\//{print $2; exit}' | cut -d@ -f1)
test -n "$WAN_IF" && test -n "$LAN_IF"
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority -100 ; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
nft add rule ip nat prerouting udp dport 51821 dnat to 10.56.0.3:51821
nft add rule ip nat postrouting oifname "$WAN_IF" masquerade
nft add table inet filter
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }'
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward iifname "$WAN_IF" oifname "$LAN_IF" udp dport 51821 ip daddr 10.56.0.3 accept
nft add rule inet filter forward iifname "$LAN_IF" oifname "$WAN_IF" accept
`))
	must(t, lab.ExecOK(ctx, "client", "ip", "route", "replace", "default", "via", "10.50.0.2"))
	must(t, lab.ExecOK(ctx, "pi", "ip", "route", "replace", "default", "via", "10.56.0.2"))
	must(t, lab.ExecOK(ctx, "home-nas", "ip", "route", "replace", "default", "via", "10.56.0.2"))
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.52.0.2"))
	must(t, lab.ExecOK(ctx, "non-ru", "ip", "route", "replace", "default", "via", "10.54.0.2"))
	must(t, lab.ExecOK(ctx, "remote-hop", "bash", "-c", `
set -e
ip route replace default via 10.55.0.2
ip route replace 10.50.0.0/24 via 10.55.0.2
ip route replace 10.51.0.0/24 via 10.55.0.2
ip route replace 10.56.0.0/24 via 10.55.0.2
`))

	piPriv, piPub := genWGKeys(t, lab, "pi")
	clientsPriv, clientsPub := genWGKeys(t, lab, "pi")
	hopPriv, hopPub := genWGKeys(t, lab, "remote-hop")
	cliPriv, cliPub := genWGKeys(t, lab, "client")

	// remote-hop: exit WG + SNAT toward non-RU
	must(t, lab.ExecOK(ctx, "remote-hop", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/hop.key
wg set wg-exit private-key /tmp/hop.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.98.0.0/30,10.56.0.0/24,10.50.0.0/24 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip link set wg-exit up
ip route replace 10.98.0.0/30 dev wg-exit
ip route replace 10.56.0.0/24 dev wg-exit
nft add table inet hopnat
nft 'add chain inet hopnat postrouting { type nat hook postrouting priority 100 ; }'
nft add rule inet hopnat postrouting oifname != "lo" masquerade
`, hopPriv, piPub)))

	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru.txt")
	mustWrite(t, prefPath, "10.52.0.0/24\n")
	must(t, lab.Copy(ctx, "pi", prefPath, "/tmp/ru.txt"))

	wgExit := filepath.Join(dir, "wg-exit.conf")
	mustWrite(t, wgExit, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.0.1/30
ListenPort = 51820

[Peer]
PublicKey = %s
Endpoint = %s:51820
AllowedIPs = 10.54.0.0/24,10.99.0.0/30
PersistentKeepalive = 5
`, piPriv, hopPub, deployRemoteHop))
	must(t, lab.Copy(ctx, "pi", wgExit, "/tmp/wg-exit.conf"))

	wgClients := filepath.Join(dir, "wg-clients.conf")
	mustWrite(t, wgClients, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.98.0.1/30
ListenPort = %d

[Peer]
PublicKey = %s
AllowedIPs = 10.98.0.2/32
`, clientsPriv, deployClientsPort, cliPub))
	must(t, lab.Copy(ctx, "pi", wgClients, "/tmp/wg-clients.conf"))

	must(t, lab.ExecOK(ctx, "pi", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", labNonRoutable,
		"-endpoint", deployRemoteHop,
		// home LAN + clients WG subnet (return path must not be marked into table 100)
		"-lan", "10.56.0.0/24,10.98.0.0/30",
		"-wg-config", "/tmp/wg-exit.conf",
		"-wg-clients-config", "/tmp/wg-clients.conf",
		"-tunnel-up", "true",
		// Masquerade the direct class onto the Pi LAN so the home-router sees a
		// LAN-sourced flow. This used to be a hand-rolled nft rule in this test;
		// gotun owns it now, so the RU-egress assertion below only passes if
		// gotun's own rule fires -- the home-router has no route back to
		// 10.98.0.0/30.
		"-direct-snat", "true",
	))

	// Pi LAN probe for port-forward / direct-LAN negatives
	must(t, lab.ExecOK(ctx, "pi", "bash", "-c",
		`labhttp -listen 10.56.0.3:18080 -body PILAN >/tmp/pilan-http.log 2>&1 &`))
	time.Sleep(200 * time.Millisecond)

	// client inbound WG via home-router WAN (port-forward).
	// Do not route home-LAN via tunnel yet — asserts 1–2 prove physical path is blocked.
	must(t, lab.ExecOK(ctx, "client", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-clients type wireguard || true
echo '%s' > /tmp/cli.key
wg set wg-clients private-key /tmp/cli.key
wg set wg-clients peer %s allowed-ips 10.52.0.0/24,10.54.0.0/24,10.55.0.0/24,10.98.0.0/30 endpoint %s:%d persistent-keepalive 5
ip address replace 10.98.0.2/30 dev wg-clients
ip link set wg-clients up
ip route replace 10.52.0.0/24 dev wg-clients
ip route replace 10.54.0.0/24 dev wg-clients
ip route replace 10.55.0.0/24 dev wg-clients
`, cliPriv, clientsPub, deployHomeRouterWAN, deployClientsPort)))

	// --- assertions ---

	// 1: ingress via home-router WAN + cannot hit Pi LAN IP directly (physical path)
	_, _ = lab.Exec(ctx, "client", "ping", "-c", "1", "-W", "2", "10.98.0.1")
	hs, err := lab.Exec(ctx, "client", "wg", "show", "wg-clients", "latest-handshakes")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if !strings.Contains(hs, clientsPub) {
		t.Fatalf("expected handshake via home-router WAN, got %q", hs)
	}
	fields := strings.Fields(hs)
	if len(fields) < 2 || fields[len(fields)-1] == "0" {
		t.Fatalf("expected non-zero handshake timestamp, got %q", hs)
	}
	if _, err := lab.Exec(ctx, "client", "curl", "-s", "--connect-timeout", "2", "--max-time", "3",
		"http://"+deployPiLAN+":18080/"); err == nil {
		t.Fatal("client must not reach Pi LAN IP directly")
	}

	// 2: port-forward only — A weak (router WAN), B important (no open path to Pi services except DNAT)
	if _, err := lab.Exec(ctx, "client", "curl", "-s", "--connect-timeout", "2", "--max-time", "3",
		"http://"+deployHomeRouterWAN+":9/"); err == nil {
		t.Fatal("non-forwarded home-router WAN port should fail")
	}
	if _, err := lab.Exec(ctx, "client", "curl", "-s", "--connect-timeout", "2", "--max-time", "3",
		"http://"+deployPiLAN+":18080/"); err == nil {
		t.Fatal("client must not reach Pi LAN listener without WG DNAT path")
	}

	// 3: RU via gotun appears from home-router WAN
	ruID, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://"+deployRUDest+":8080/id")
	if err != nil || strings.TrimSpace(ruID) != "RU" {
		t.Fatalf("RU id: %v %q", err, ruID)
	}
	ruPeer, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://"+deployRUDest+":8080/peer")
	if err != nil {
		t.Fatalf("RU peer: %v", err)
	}
	if strings.TrimSpace(ruPeer) != deployHomeRouterWAN {
		t.Fatalf("RU destination must see home-router WAN %s, got %q", deployHomeRouterWAN, ruPeer)
	}
	if strings.TrimSpace(ruPeer) == deployRemoteHop {
		t.Fatal("RU destination must not see remote-hop")
	}
	// gotun's own snat-direct rule is what made the assertion above possible:
	// the client's WG source is 10.98.0.2 and the home-router has no route back
	// to it, so an un-masqueraded flow could never have completed.
	snatOut, err := lab.Exec(ctx, "pi", "nft", "list", "chain", "inet", "gotun", "postrouting")
	if err != nil {
		t.Fatalf("nft list postrouting: %v", err)
	}
	if !nftCounterHit(snatOut, "snat-direct", "") {
		t.Fatalf("snat-direct counter must increase for forwarded direct traffic; nft:\n%s", snatOut)
	}
	// Traffic toward the Pi's own LAN must NOT be masqueraded, or LAN hosts would
	// see the gateway instead of the client.
	pilanPeer, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://10.56.0.3:18080/")
	if err == nil && strings.Contains(pilanPeer, "PILAN") {
		lanNft, lerr := lab.Exec(ctx, "pi", "nft", "list", "chain", "inet", "gotun", "postrouting")
		if lerr == nil && !strings.Contains(lanNft, `comment "snat-skip-lan"`) {
			t.Fatal("expected a snat-skip-lan guard so LAN-destined traffic keeps the client source")
		}
	}

	// 4: non-RU via gotun appears from remote-hop
	frID, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://"+deployNonRU+":8080/id")
	if err != nil || strings.TrimSpace(frID) != "FOREIGN" {
		t.Fatalf("non-RU id: %v %q", err, frID)
	}
	frPeer, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "5", "http://"+deployNonRU+":8080/peer")
	if err != nil {
		t.Fatalf("non-RU peer: %v", err)
	}
	if strings.TrimSpace(frPeer) != deployRemoteHop {
		t.Fatalf("non-RU destination must see remote-hop %s, got %q", deployRemoteHop, frPeer)
	}

	// 5: physical uplink still exists (from ru-inet, no tunnel)
	uplink, err := lab.Exec(ctx, "ru-inet", "curl", "-s", "--max-time", "5", "http://"+deployNonRU+":8080/id")
	if err != nil || strings.TrimSpace(uplink) != "FOREIGN" {
		t.Fatalf("RU→external physical path must work without tunnel: %v %q", err, uplink)
	}

	// 6: home isolation (route home-LAN via tunnel; gotun home_nets must drop)
	must(t, lab.ExecOK(ctx, "client", "bash", "-c", fmt.Sprintf(`
set -e
wg set wg-clients peer %s allowed-ips 10.52.0.0/24,10.54.0.0/24,10.55.0.0/24,10.56.0.0/24,10.98.0.0/30
ip route replace 10.56.0.0/24 dev wg-clients
`, clientsPub)))
	if _, err := lab.Exec(ctx, "client", "curl", "-s", "--max-time", "3", "http://"+deployHomeNAS+":8080/id"); err == nil {
		t.Fatal("tunneled client must not reach home-nas")
	}

	// 7: endpoint exclusion — route smoke + forwarded underlay hits exclude-endpoint counter
	rt, err := lab.Exec(ctx, "pi", "ip", "route", "get", deployRemoteHop)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rt, "dev wg-exit") {
		t.Fatalf("endpoint underlay must not use wg-exit: %q", rt)
	}
	// Locally generated WG packets skip prerouting; probe via client tunnel so Pi prerouting sees daddr=endpoint.
	_, _ = lab.Exec(ctx, "client", "ping", "-c", "3", "-W", "2", deployRemoteHop)
	nftOut, err := lab.Exec(ctx, "pi", "nft", "list", "chain", "inet", "gotun", "prerouting")
	if err != nil {
		t.Fatalf("nft list: %v", err)
	}
	if !excludeEndpointCounterHit(nftOut, deployRemoteHop) {
		t.Fatalf("exclude-endpoint counter must increase for forwarded underlay to %s; nft:\n%s", deployRemoteHop, nftOut)
	}
}

func excludeEndpointCounterHit(nftList, endpointIP string) bool {
	return nftCounterHit(nftList, "exclude-endpoint", endpointIP)
}

// nftCounterHit reports whether a rule carrying the given comment (and, when
// mustContain is non-empty, that substring) has a non-zero packet counter.
func nftCounterHit(nftList, comment, mustContain string) bool {
	lines := strings.Split(nftList, "\n")
	for _, line := range lines {
		if !strings.Contains(line, comment) {
			continue
		}
		if mustContain != "" && !strings.Contains(line, mustContain) {
			continue
		}
		// e.g. counter packets 2 bytes 168
		idx := strings.Index(line, "counter packets ")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("counter packets "):]
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err == nil && n > 0 {
			return true
		}
	}
	return false
}
