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

// TestLANDeploy_PortForwardHomeIsolation proves the Pi home-router deployment invariants:
// 1) WAN reaches gotun only via router DNAT of the WG UDP port
// 2) home-pc uses gotun's LAN IP (not WAN)
// 3) WAN peer over the tunnel cannot reach home-LAN hosts (prefix isolation)
func TestLANDeploy_PortForwardHomeIsolation(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunlan%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	// home: Pi LAN; inet/dmz: WAN side of router → gotun; exit nets unchanged
	must(t, lab.CreateNetwork(ctx, "home", "10.10.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "inet", "10.40.0.0/24")) // wan-peer ↔ router
	must(t, lab.CreateNetwork(ctx, "dmz", "10.41.0.0/24"))  // router ↔ gotun WAN
	must(t, lab.CreateNetwork(ctx, "wgnet", "10.20.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "ru", "10.200.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "foreign", "10.30.0.0/24"))

	must(t, lab.RunContainer(ctx, "home-pc", image, "10.10.0.10", "home", nil))
	must(t, lab.RunContainer(ctx, "home-nas", image, "10.10.0.20", "home", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "NAS"},
	}))
	must(t, lab.RunContainer(ctx, "home-nas2", image, "10.10.0.21", "home", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "NAS2"},
	}))
	must(t, lab.RunContainer(ctx, "gotun", image, "10.10.0.2", "home", map[string]string{
		"dmz":   "10.41.0.3",
		"wgnet": "10.20.0.2",
		"ru":    "10.200.0.2",
	}))
	must(t, lab.RunContainer(ctx, "router", image, "10.40.0.2", "inet", map[string]string{
		"dmz": "10.41.0.2",
	}))
	must(t, lab.RunContainer(ctx, "wan-peer", image, "10.40.0.10", "inet", nil))
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

	for _, n := range []string{"home-pc", "home-nas", "home-nas2", "gotun", "router", "wan-peer", "exit", "ru-dest", "foreign-dest"} {
		must(t, lab.WaitReady(ctx, n))
	}

	must(t, lab.ExecOK(ctx, "home-nas", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "home-nas2", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.200.0.2"))
	must(t, lab.ExecOK(ctx, "foreign-dest", "ip", "route", "replace", "default", "via", "10.30.0.2"))

	// Router: DNAT WG UDP/51821 → gotun DMZ; forward filter allows only that new flow (+ established).
	must(t, lab.ExecOK(ctx, "router", "bash", "-c", `
set -e
WAN_IF=$(ip -o -4 addr show | awk '/10\.40\.0\.2\//{print $2; exit}' | cut -d@ -f1)
DMZ_IF=$(ip -o -4 addr show | awk '/10\.41\.0\.2\//{print $2; exit}' | cut -d@ -f1)
test -n "$WAN_IF" && test -n "$DMZ_IF"

nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority -100 ; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
nft add rule ip nat prerouting udp dport 51821 dnat to 10.41.0.3:51821
nft add rule ip nat postrouting oifname != "lo" masquerade

# Consumer-NAT-like forward: established return OK; new WAN→DMZ only WG UDP to gotun.
nft add table inet filter
nft 'add chain inet filter forward { type filter hook forward priority 0 ; policy drop ; }'
nft add rule inet filter forward ct state established,related accept
nft add rule inet filter forward iifname "$WAN_IF" oifname "$DMZ_IF" udp dport 51821 ip daddr 10.41.0.3 accept
`))

	gotunPriv, gotunPub := genWGKeys(t, lab, "gotun")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")
	clientsPriv, clientsPub := genWGKeys(t, lab, "gotun")
	wanPriv, wanPub := genWGKeys(t, lab, "wan-peer")

	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg-exit private-key /tmp/exit.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.10.0.0/24,10.99.0.0/30,10.200.0.0/24 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip link set wg-exit up
ip route replace 10.10.0.0/24 dev wg-exit
ip route replace 10.200.0.0/24 dev wg-exit
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting oifname != "lo" masquerade || true
`, exitPriv, gotunPub)))

	dir := t.TempDir()
	prefPath := filepath.Join(dir, "ru.txt")
	mustWrite(t, prefPath, "10.200.0.0/24\n")
	must(t, lab.Copy(ctx, "gotun", prefPath, "/tmp/ru.txt"))

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
`, gotunPriv, exitPub))
	must(t, lab.Copy(ctx, "gotun", wgExit, "/tmp/wg-exit.conf"))

	wgClients := filepath.Join(dir, "wg-clients.conf")
	mustWrite(t, wgClients, fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.98.0.1/30
ListenPort = 51821

[Peer]
PublicKey = %s
AllowedIPs = 10.98.0.2/32
`, clientsPriv, wanPub))
	must(t, lab.Copy(ctx, "gotun", wgClients, "/tmp/wg-clients.conf"))

	must(t, lab.ExecOK(ctx, "gotun", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", labNonRoutable,
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24",
		"-wg-config", "/tmp/wg-exit.conf",
		"-wg-clients-config", "/tmp/wg-clients.conf",
		"-tunnel-up", "true",
	))

	// Temporary DMZ listener on gotun — used only to prove WAN cannot route to DMZ except WG DNAT.
	must(t, lab.ExecOK(ctx, "gotun", "bash", "-c",
		`labhttp -listen 10.41.0.3:18080 -body DMZ >/tmp/dmz-http.log 2>&1 &`))
	time.Sleep(200 * time.Millisecond)

	// home-pc: gateway is gotun LAN IP only
	must(t, lab.ExecOK(ctx, "home-pc", "ip", "route", "replace", "default", "via", "10.10.0.2"))

	// wan-peer: underlay via router; WG to router WAN:51821 (port-forward)
	must(t, lab.ExecOK(ctx, "wan-peer", "ip", "route", "replace", "default", "via", "10.40.0.2"))
	must(t, lab.ExecOK(ctx, "wan-peer", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-clients type wireguard || true
echo '%s' > /tmp/wan.key
wg set wg-clients private-key /tmp/wan.key
wg set wg-clients peer %s allowed-ips 10.10.0.0/24,10.98.0.0/30 endpoint 10.40.0.2:51821 persistent-keepalive 5
ip address replace 10.98.0.2/30 dev wg-clients
ip link set wg-clients up
ip route replace 10.10.0.0/24 dev wg-clients
`, wanPriv, clientsPub)))

	// --- assertions ---

	// 1: handshake via port-forward (positive: WAN → router:51821 DNAT → gotun DMZ WG)
	_, _ = lab.Exec(ctx, "wan-peer", "ping", "-c", "1", "-W", "2", "10.98.0.1")
	hs, err := lab.Exec(ctx, "wan-peer", "wg", "show", "wg-clients", "latest-handshakes")
	if err != nil {
		t.Fatalf("wg handshake check: %v", err)
	}
	if !strings.Contains(hs, clientsPub) {
		t.Fatalf("expected handshake with clients peer via port-forward, got %q", hs)
	}
	fields := strings.Fields(hs)
	if len(fields) < 2 || fields[len(fields)-1] == "0" {
		t.Fatalf("expected completed handshake (non-zero timestamp), got %q", hs)
	}

	// A (weak): nothing listening on router WAN itself — not the WAN-firewall property.
	if _, err := lab.Exec(ctx, "wan-peer", "curl", "-s", "--connect-timeout", "2", "--max-time", "3", "http://10.40.0.2:9/"); err == nil {
		t.Fatal("non-forwarded router WAN port should fail")
	}
	// B (important): WAN must not reach gotun DMZ by routing through the router (only WG DNAT allowed).
	if _, err := lab.Exec(ctx, "wan-peer", "curl", "-s", "--connect-timeout", "2", "--max-time", "3", "http://10.41.0.3:18080/"); err == nil {
		t.Fatal("wan-peer must not reach gotun DMZ listener through router (port-forward-only boundary)")
	}

	// 2: home-pc uses gotun LAN, not WAN/dmz
	rt, err := lab.Exec(ctx, "home-pc", "ip", "route", "get", "10.30.0.10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rt, "via 10.10.0.2") {
		t.Fatalf("home-pc must use gotun LAN gateway, got %q", rt)
	}
	if strings.Contains(rt, "10.41.0.2") || strings.Contains(rt, "10.40.0.") {
		t.Fatalf("home-pc must not hairpin via WAN path: %q", rt)
	}

	// 3a/3b: WAN peer cannot reach two home-LAN hosts (prefix isolation)
	if _, err := lab.Exec(ctx, "wan-peer", "curl", "-s", "--max-time", "3", "http://10.10.0.20:8080/id"); err == nil {
		t.Fatal("wan-peer must not reach home-nas")
	}
	if _, err := lab.Exec(ctx, "wan-peer", "curl", "-s", "--max-time", "3", "http://10.10.0.21:8080/id"); err == nil {
		t.Fatal("wan-peer must not reach home-nas2 (prefix isolation)")
	}

	// 4: home-pc reaches home-nas on LAN
	nas, err := lab.Exec(ctx, "home-pc", "curl", "-s", "--max-time", "5", "http://10.10.0.20:8080/id")
	if err != nil || strings.TrimSpace(nas) != "NAS" {
		t.Fatalf("home-pc → home-nas: %v %q", err, nas)
	}

	// 5: home-pc RU / foreign split still works
	ru, err := lab.Exec(ctx, "home-pc", "curl", "-s", "--max-time", "5", "http://10.200.0.10:8080/id")
	if err != nil || strings.TrimSpace(ru) != "RU" {
		t.Fatalf("home-pc RU: %v %q", err, ru)
	}
	foreign, err := lab.Exec(ctx, "home-pc", "curl", "-s", "--max-time", "5", "http://10.30.0.10:8080/id")
	if err != nil || strings.TrimSpace(foreign) != "FOREIGN" {
		t.Fatalf("home-pc foreign: %v %q", err, foreign)
	}
}
