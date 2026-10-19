//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/prefixes"
	"github.com/legion/go-tun/test/integration/harness"
)

// The IKEv2/IPsec counterpart of TestPhoneDeploy_SmartRoutingWithoutLANAccess.
//
// It exists alongside the WireGuard version rather than replacing it. An iPhone
// using Apple's in-kernel IKEv2 client gets NAT-keepalive hardware offload and
// coarse DPD, which is where phone VPN battery actually goes; a WireGuard
// NetworkExtension cannot have either. Both transports will be deployed, so
// both are tested.
//
// See docs/ikev2-phone.md for the decisions this pins.

const (
	// ikev2IfID ties the xfrm interface to the CHILD_SA. charon only ever sees
	// the number; the interface name is ours.
	ikev2IfID = "0x61"
	// ikev2ClientsIface is the xfrm interface decrypted client packets surface
	// on. Route-based IPsec exists in this lab purely so that name exists:
	// policy-based IPsec surfaces them on the physical WAN device instead, and
	// gotun's whole inbound model -- -mark-iface and the home_nets forward
	// rule -- is interface-named.
	ikev2ClientsIface = "ipsec0"

	// The VIP subnet is deliberately an odd /24. It is routed into the tunnel
	// by an explicit selector, so a client sitting on a network that used the
	// same prefix would lose that network.
	ikev2VIPSubnet  = "10.231.17.0/24"
	ikev2GatewayVIP = "10.231.17.1"
	ikev2PoolAddrs  = "10.231.17.16/28"

	ikev2PSK = "labsecret"
)

// ikev2NonRoutable keeps the VIP subnet out of the classifier, for the same
// reason the WireGuard test keeps the peer /30 out: without it the gateway
// marks traffic addressed to its own tunnel-side address and routes it at the
// exit, so gotun-dns answers nothing.
//
// As in the WireGuard test, the VIP subnet must never be passed to -lan. -lan
// feeds home_nets, so listing it would make the isolation rule drop the
// client's traffic to the resolver.
const ikev2NonRoutable = labNonRoutable + "," + ikev2VIPSubnet

// ikev2LabPrivate is what this lab treats as "private space the client keeps
// on-link". In production it is RFC1918 plus CGNAT, link-local and reserved
// space; here it is the client's own access network plus the block the VIP pool
// lives in.
//
// The second entry is not padding. It is what forces the VIP subnet to be
// punched back in as an explicit selector, which is the trap the production
// configuration walks into: the gateway's tunnel-side address is itself inside
// RFC1918, so the very list that keeps the client's LAN off the tunnel also
// cuts the address gotun-dns listens on.
//
// The home LAN is deliberately NOT here, so it stays inside the negotiated
// selectors and the no-LAN-access assertion exercises gotun's forward-hook
// isolation for real. In production RFC1918 exclusion means the home LAN is not
// in the selectors at all, and the gateway's inbound XFRM policy drops anything
// outside them -- a stronger guarantee than WireGuard gives, where the client
// chooses its own AllowedIPs and only the nft rule stands in the way.
func ikev2LabPrivate() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.40.0.0/24"),
		netip.MustParsePrefix("10.231.0.0/16"),
	}
}

// ikev2Selectors is the gateway's local_ts: everything except private space,
// with the VIP subnet restored.
//
// **Prefixes, not ranges, and that is a measured decision.** A traffic selector
// is a range on the wire and the same set is 4 ranges against 31 prefixes, so
// ranges look obviously better. They are not: charon's own client rounds each
// received range up to its smallest covering prefix when it installs routes, so
// "11.0.0.0-100.63.255.255" becomes a 0.0.0.0/1 route that swallows the
// client's own LAN. Measured in this lab -- with range selectors a host on the
// client's access network becomes unreachable while the tunnel is up, which is
// the requirement failing silently. Prefixes install exactly.
//
// Punching the VIP subnet out of the cut before complementing, rather than
// appending it afterwards, is what keeps the result seamless.
func ikev2Selectors(private ...netip.Prefix) []netip.Prefix {
	vip := netip.MustParsePrefix(ikev2VIPSubnet)
	cut := append(ikev2LabPrivate(), private...)
	cut = prefixes.RangePrefixes(prefixes.Subtract(cut, []netip.Prefix{vip}))
	return prefixes.RangePrefixes(prefixes.Complement(cut, prefixes.Families{V4: true}))
}

func TestIKEv2Phone_SplitRoutingWithoutLANAccess(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunike%d", time.Now().UnixNano()%1_000_000)
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
	// cafe-printer stands for every device on whatever network the phone is
	// sitting on. Requirement: it stays reachable while the tunnel is up.
	must(t, lab.RunContainer(ctx, "cafe-printer", image, "10.40.0.20", "inet", nil, harness.RunOpts{
		Entrypoint: []string{"labhttp"},
		Cmd:        []string{"-listen", ":8080", "-body", "PRINTER"},
	}))
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
		"flint", "phone", "cafe-printer", "home-pc", "home-nas",
		"exit", "ru-dest", "foreign-dest",
	} {
		must(t, lab.WaitReady(ctx, n))
	}

	requireXfrmInterface(t, lab, "flint")

	must(t, lab.ExecOK(ctx, "home-pc", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "home-nas", "ip", "route", "replace", "default", "via", "10.10.0.2"))
	must(t, lab.ExecOK(ctx, "ru-dest", "ip", "route", "replace", "default", "via", "10.200.0.2"))
	must(t, lab.ExecOK(ctx, "foreign-dest", "ip", "route", "replace", "default", "via", "10.30.0.2"))
	must(t, lab.ExecOK(ctx, "phone", "ip", "route", "replace", "default", "via", "10.40.0.2"))

	flintPriv, flintPub := genWGKeys(t, lab, "flint")
	exitPriv, exitPub := genWGKeys(t, lab, "exit")

	// Exit hop. AllowedIPs must carry the VIP subnet as well as the home LAN,
	// or replies to the phone have nowhere to go and the tunnel looks healthy
	// while connections hang.
	must(t, lab.ExecOK(ctx, "exit", "bash", "-c", fmt.Sprintf(`
set -e
ip link add dev wg-exit type wireguard || true
echo '%s' > /tmp/exit.key
wg set wg-exit private-key /tmp/exit.key listen-port 51820
wg set wg-exit peer %s allowed-ips 10.10.0.0/24,%s,10.99.0.0/30,10.200.0.0/24 endpoint 10.20.0.2:51820 persistent-keepalive 5
ip address replace 10.99.0.2/30 dev wg-exit
ip link set wg-exit up
ip route replace 10.10.0.0/24 dev wg-exit
ip route replace %s dev wg-exit
nft add table inet exitnat || true
nft 'add chain inet exitnat postrouting { type nat hook postrouting priority 100 ; }' || true
nft add rule inet exitnat postrouting oifname != "lo" masquerade || true
`, exitPriv, flintPub, ikev2VIPSubnet, ikev2VIPSubnet)))

	wanIface := ifaceForAddr(t, lab, "flint", "10.40.0.2")
	homeIface := ifaceForAddr(t, lab, "flint", "10.10.0.2")

	// The inbound interface, created the way netifd's proto xfrm would: outside
	// gotun, with gotun holding no credential for it.
	//
	// The address is a /24 rather than a /32 on purpose. charon installs no
	// route for an xfrm interface, so with a /32 the pool is not on-link and
	// every reply to the client fails source lookup with "network is
	// unreachable" -- while the SA stays ESTABLISHED and the handshake counters
	// look perfect.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
ip link add %s type xfrm dev %s if_id %s
ip link set %s up
ip address replace %s/24 dev %s
`, ikev2ClientsIface, wanIface, ikev2IfID, ikev2ClientsIface, ikev2GatewayVIP, ikev2ClientsIface)))

	selectors := ikev2Selectors()
	writeSwanctlGateway(t, lab, "flint", selectors)
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

	// The classifier must cover the xfrm interface. Leaving it out of
	// -mark-iface gives the phone no split routing at all and reports nothing.
	// Note what is NOT listed: the WAN device. ESP arrives there as UDP/4500 and
	// must never reach the classifier.
	must(t, lab.ExecOK(ctx, "flint", "gotun", "apply",
		"-prefixes", "/tmp/ru.txt",
		"-non-routable", ikev2NonRoutable,
		"-endpoint", "10.20.0.3",
		"-lan", "10.10.0.0/24",
		"-clients-iface", ikev2ClientsIface,
		"-mark-iface", homeIface+","+ikev2ClientsIface,
		"-wg-config", "/tmp/wg-exit.conf",
		"-tunnel-up", "true",
	))

	// Host firewall, standing in for the OpenWrt zone. gotun classifies; it does
	// not firewall the box it runs on, and it does not clamp MSS either.
	//
	// The clamp is load-bearing here rather than decorative: the client's
	// packets cross ESP-in-UDP and then wg-exit, two encapsulations whose
	// overheads stack, and ICMP is unaffected by the result -- so without it
	// latency checks pass while large TCP responses stall.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
nft add table inet hostfw
nft 'add chain inet hostfw input { type filter hook input priority 0 ; policy accept ; }'
nft add rule inet hostfw input iifname "%[1]s" ct state established,related accept
nft add rule inet hostfw input iifname "%[1]s" udp dport 53 accept
nft add rule inet hostfw input iifname "%[1]s" tcp dport 53 accept
nft add rule inet hostfw input iifname "%[1]s" drop
nft 'add chain inet hostfw forward { type filter hook forward priority 0 ; policy accept ; }'
nft 'add rule inet hostfw forward tcp flags syn / syn,rst tcp option maxseg size set rt mtu'
`, ikev2ClientsIface)))

	// Probe counters, to answer "which interface did the kernel think this
	// arrived on" with a number rather than an argument.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
nft add table inet probe
nft 'add chain inet probe pre { type filter hook prerouting priority -149 ; }'
nft add rule inet probe pre iifname "%s" counter comment "from-clients-iface"
nft add rule inet probe pre iifname "%s" udp dport 4500 counter comment "esp-on-wan"
`, ikev2ClientsIface, wanIface)))

	// A service on the router's own LAN address, to prove the client cannot
	// reach the router itself -- the half gotun's forward-hook isolation cannot
	// cover, because the router's own address is reached through input.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c",
		`labhttp -listen 10.10.0.2:18080 -body ROUTER >/tmp/router-http.log 2>&1 &`))

	// Split DNS on the VIP-side gateway address, which is what the pool's
	// INTERNAL_IP4_DNS attribute hands the phone.
	labdnsCmd := `labdns -listen :53 -map 10.200.0.0/24=10.200.0.50 -map 10.30.0.0/24=10.30.0.50 >/tmp/labdns.log 2>&1 &`
	must(t, lab.ExecOK(ctx, "ru-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "foreign-dest", "bash", "-c", labdnsCmd))
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(
		`gotun-dns -listen %s:53 -direct-upstream 10.200.0.10:53 -exit-upstream 10.30.0.10:53 -mark 0x1 >/tmp/gotun-dns.log 2>&1 &`,
		ikev2GatewayVIP)))
	time.Sleep(300 * time.Millisecond)

	must(t, lab.ExecOK(ctx, "phone", "swanctl", "--initiate", "--child", "home"))

	// --- assertions ---

	// 1: the SA comes up over the WAN with no ping to help it, and it is
	// UDP-encapsulated. encap=yes is not lab convenience: the real path crosses
	// the MTS GPON router's NAT and then the Flint's, so production is always
	// encapsulated and a lab running raw ESP would be testing a path that does
	// not exist.
	sas := waitIKESA(t, lab, "phone", 30*time.Second)
	if !strings.Contains(sas, "TUNNEL-in-UDP") {
		t.Fatalf("CHILD_SA must be UDP-encapsulated, got:\n%s", sas)
	}

	// 2: the client installed exactly the selectors the gateway narrowed to.
	// This is the requirement itself -- it catches a local_ts that silently
	// stayed 0.0.0.0/0 (full tunnel, the client's own LAN lost) as well as one
	// narrowed to the wrong thing.
	assertNegotiatedSelectors(t, lab, "phone", selectors)

	// 3: the other half of the requirement. A host on the client's own access
	// network must stay on-link, and it must see the client's real address --
	// reachability alone would also be satisfied by hairpinning through the
	// tunnel and back out.
	got, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.40.0.20:8080/id")
	if err != nil || strings.TrimSpace(got) != "PRINTER" {
		t.Fatalf("a host on the phone's own access network must stay reachable: %v %q", err, got)
	}
	peer, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "5", "http://10.40.0.20:8080/peer")
	if err != nil || strings.TrimSpace(peer) != "10.40.0.10" {
		t.Fatalf("private traffic must stay off the tunnel, printer saw %q (%v)", peer, err)
	}

	// 4: the classifier is scoped to the xfrm interface and not to the WAN
	// device. Static, so it is checked before any traffic: the WireGuard
	// analogue of this is -endpoint exclusion, and the reason none is needed
	// here is that the peer's address is dynamic and ESP never reaches the
	// classifier at all.
	tbl, err := lab.Exec(ctx, "flint", "nft", "list", "table", "inet", "gotun")
	if err != nil {
		t.Fatalf("nft list table inet gotun: %v", err)
	}
	if !strings.Contains(tbl, ikev2ClientsIface) {
		t.Errorf("classifier does not mention %s:\n%s", ikev2ClientsIface, tbl)
	}
	if strings.Contains(tbl, `"`+wanIface+`"`) {
		t.Errorf("classifier must not be scoped to the WAN device %s:\n%s", wanIface, tbl)
	}

	// 5: split routing, proved by source identity at the destination rather than
	// by which reply came back.
	assertBody(t, lab, "phone", "http://10.200.0.10:8080/id", "RU")
	ruPeer := mustGet(t, lab, "phone", "http://10.200.0.10:8080/peer")
	if !vipSubnetContains(t, ruPeer) {
		t.Errorf("RU dest must see the client's VIP direct through the router, got %q", ruPeer)
	}
	assertBody(t, lab, "phone", "http://10.30.0.10:8080/id", "FOREIGN")
	if frPeer := mustGet(t, lab, "phone", "http://10.30.0.10:8080/peer"); frPeer != "10.30.0.2" {
		t.Errorf("foreign dest must see the exit, got %q", frPeer)
	}

	// 6: the premise of route-based IPsec, as a number rather than an argument.
	// Decrypted packets arrived on the xfrm interface; ESP arrived on the WAN
	// device. It has to come after assertion 5, because until something has
	// actually crossed the tunnel both counters read zero for the honest
	// reason.
	assertCounter(t, lab, "flint", "from-clients-iface", true)
	assertCounter(t, lab, "flint", "esp-on-wan", true)

	// 7: DNS to the gateway's VIP address works and splits. This is what the
	// punched-back selector buys: without it the phone resolves through
	// whatever resolver the network it is sitting on advertises, and every
	// GeoDNS answer is quietly wrong while the tunnel stays healthy.
	ruAns, err := lab.Exec(ctx, "phone", "dig", "+short", "+time=3", "+tries=1",
		"@"+ikev2GatewayVIP, "lavka.yandex.ru", "A")
	if err != nil || strings.TrimSpace(ruAns) != "10.200.0.50" {
		dumpIKEv2Logs(t, lab)
		t.Fatalf("want RU geo answer 10.200.0.50, got %q (%v)", ruAns, err)
	}
	exAns, err := lab.Exec(ctx, "phone", "dig", "+short", "+time=3", "+tries=1",
		"@"+ikev2GatewayVIP, "example.com", "A")
	if err != nil || strings.TrimSpace(exAns) != "10.30.0.50" {
		dumpIKEv2Logs(t, lab)
		t.Fatalf("want foreign geo answer 10.30.0.50, got %q (%v)", exAns, err)
	}

	// 8: no home LAN and no router services. The home LAN IS inside the
	// negotiated selectors here, so the packet really does arrive on the xfrm
	// interface and gotun's forward-hook isolation is what drops it.
	if _, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "3", "http://10.10.0.20:8080/id"); err == nil {
		t.Error("phone must not reach home-nas")
	}
	if _, err := lab.Exec(ctx, "phone", "curl", "-s", "--max-time", "3", "http://10.10.0.2:18080/"); err == nil {
		t.Error("phone must not reach the router's own LAN address")
	}

	// 9: a large transfer survives both classes. ESP-in-UDP inside wg-exit is
	// two stacked encapsulations, and the symptom of getting that wrong is
	// invisible to every other assertion in this test.
	assertBulk(t, lab, "phone", "http://10.200.0.10:8080/bulk?bytes=1048576", 1<<20)
	assertBulk(t, lab, "phone", "http://10.30.0.10:8080/bulk?bytes=1048576", 1<<20)

	// 10: the home LAN is unaffected -- isolation is one-way, not a partition.
	assertBody(t, lab, "home-pc", "http://10.10.0.20:8080/id", "NAS")
	assertBody(t, lab, "home-pc", "http://10.30.0.10:8080/id", "FOREIGN")

	// 11: fail-open at the client. Tearing the SA down is what an iPhone does
	// when DPD gives up, and the requirement is that it degrades to plain
	// internet rather than to no internet.
	//
	// Source identity is what separates the two outcomes: reaching the RU
	// destination at all proves traffic is not being held, and seeing the
	// client's real address rather than its VIP proves it went direct.
	must(t, lab.ExecOK(ctx, "phone", "swanctl", "--terminate", "--ike", "home"))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := lab.Exec(ctx, "phone", "ip", "route", "show", "table", "220")
		if strings.TrimSpace(out) == "" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if out, _ := lab.Exec(ctx, "phone", "ip", "route", "show", "table", "220"); strings.TrimSpace(out) != "" {
		t.Errorf("tunnel routes outlived the SA, so a dead tunnel is a kill switch:\n%s", out)
	}
	assertBody(t, lab, "phone", "http://10.200.0.10:8080/id", "RU")
	if p := mustGet(t, lab, "phone", "http://10.200.0.10:8080/peer"); p != "10.40.0.10" {
		t.Errorf("after fail-open the RU dest must see the real address, got %q", p)
	}
}

// requireXfrmInterface skips rather than loading the module.
//
// `ip link add type xfrm` needs CONFIG_XFRM_INTERFACE, which is a module on a
// stock kernel. Loading it is host kernel state -- not host *network namespace*
// state, so it would not break the isolation invariant -- but doing it silently
// from a test would still be the lab reaching outside itself, so the operator
// gets told instead.
func requireXfrmInterface(t *testing.T, lab *harness.Lab, container string) {
	t.Helper()
	ctx := context.Background()
	err := lab.ExecOK(ctx, container, "bash", "-c",
		`ip link add gotunprobe type xfrm dev lo if_id 0x1 && ip link del gotunprobe`)
	if err != nil {
		t.Skipf("no xfrm interface support in this kernel (run: sudo modprobe xfrm_interface): %v", err)
	}
}

// writeSwanctlGateway renders the road-warrior gateway configuration.
//
// Every key sits on its own line because strongswan.conf values extend to the
// end of the line: "local { auth = psk  id = flint }" parses auth as
// "psk  id = flint }" and the connection is discarded with "invalid value for:
// auth", which reads like an unsupported auth method rather than a syntax
// error.
//
// PSK rather than certificates plus EAP-MSCHAPv2, which is what the phone
// profile will actually ship. The datapath this test measures is identical
// either way, and the auth path cannot be proven here regardless -- a
// strongSwan client is not an iOS one. Certificates are a deploy-time check
// against the real phone; see docs/ikev2-phone.md.
func writeSwanctlGateway(t *testing.T, lab *harness.Lab, container string, selectors []netip.Prefix) {
	t.Helper()
	ts := make([]string, 0, len(selectors))
	for _, p := range selectors {
		ts = append(ts, p.String())
	}
	conf := fmt.Sprintf(`connections {
  phone {
    version = 2
    local_addrs = 10.40.0.2
    pools = phone_pool
    encap = yes
    proposals = aes256gcm16-prfsha384-ecp256
    local-1 {
      auth = psk
      id = flint
    }
    remote-1 {
      auth = psk
      id = phone
    }
    children {
      phone {
        if_id_in = %s
        if_id_out = %s
        local_ts = %s
        esp_proposals = aes256gcm16-ecp256
        mode = tunnel
        start_action = none
      }
    }
  }
}
pools {
  phone_pool {
    addrs = %s
    dns = %s
  }
}
secrets {
  ike-phone {
    id = phone
    secret = %s
  }
}
`, ikev2IfID, ikev2IfID, strings.Join(ts, ","), ikev2PoolAddrs, ikev2GatewayVIP, ikev2PSK)
	writeSwanctlConf(t, lab, container, conf)
}

// writeSwanctlClient renders a dumb full-tunnel client: it proposes 0.0.0.0/0
// and accepts whatever the gateway narrows that to, which is exactly what an
// iOS client does and the reason the split lives on the gateway.
func writeSwanctlClient(t *testing.T, lab *harness.Lab, container string) {
	t.Helper()
	conf := fmt.Sprintf(`connections {
  home {
    version = 2
    remote_addrs = 10.40.0.2
    vips = 0.0.0.0
    encap = yes
    proposals = aes256gcm16-prfsha384-ecp256
    local-1 {
      auth = psk
      id = phone
    }
    remote-1 {
      auth = psk
      id = flint
    }
    children {
      home {
        remote_ts = 0.0.0.0/0
        esp_proposals = aes256gcm16-ecp256
        start_action = none
      }
    }
  }
}
secrets {
  ike-home {
    id = flint
    secret = %s
  }
}
`, ikev2PSK)
	writeSwanctlConf(t, lab, container, conf)
}

func writeSwanctlConf(t *testing.T, lab *harness.Lab, container, conf string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "swanctl.conf")
	mustWrite(t, path, conf)
	must(t, lab.Copy(context.Background(), container, path, "/etc/swanctl/swanctl.conf"))
}

// startCharon runs the daemon and loads the configuration.
//
// charon logs to syslog by default, and there is no syslog in a container, so
// without the filelog stanza a failed negotiation leaves behind no explanation
// at all.
func startCharon(t *testing.T, lab *harness.Lab, container string) {
	t.Helper()
	ctx := context.Background()
	must(t, lab.ExecOK(ctx, container, "bash", "-c",
		`printf 'charon {\n  filelog {\n    stderr {\n      default = 2\n    }\n  }\n}\n' > /etc/strongswan.d/zz-lab.conf`))
	must(t, lab.ExecOK(ctx, container, "bash", "-c",
		`/usr/lib/ipsec/charon > /tmp/charon.log 2>&1 &`))

	// Wait for vici rather than sleeping: swanctl against a daemon that has not
	// finished loading plugins fails in a way that reads like a config error.
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if err := lab.ExecOK(ctx, container, "swanctl", "--stats"); err == nil {
			last = nil
			break
		} else {
			last = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if last != nil {
		out, _ := lab.Exec(ctx, container, "cat", "/tmp/charon.log")
		t.Fatalf("charon on %s never came up: %v\n%s", container, last, out)
	}
	if err := lab.ExecOK(ctx, container, "swanctl", "--load-all"); err != nil {
		out, _ := lab.Exec(ctx, container, "cat", "/tmp/charon.log")
		t.Fatalf("swanctl --load-all on %s: %v\n%s", container, err, out)
	}
}

func waitIKESA(t *testing.T, lab *harness.Lab, container string, within time.Duration) string {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(within)
	var last string
	for time.Now().Before(deadline) {
		out, err := lab.Exec(ctx, container, "swanctl", "--list-sas")
		if err == nil {
			last = out
			if strings.Contains(out, "ESTABLISHED") && strings.Contains(out, "INSTALLED") {
				return out
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	log, _ := lab.Exec(ctx, container, "cat", "/tmp/charon.log")
	t.Fatalf("no established CHILD_SA on %s within %s, last:\n%s\ncharon log:\n%s",
		container, within, last, log)
	return ""
}

// assertNegotiatedSelectors compares the client's view of the narrowed traffic
// selectors against what the gateway was configured to offer.
//
// The client's side is read rather than the gateway's on purpose: the gateway
// echoing back its own configuration would prove nothing about what the peer
// accepted, and what the peer accepted is the requirement.
func assertNegotiatedSelectors(t *testing.T, lab *harness.Lab, container string, want []netip.Prefix) {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "swanctl", "--list-sas")
	if err != nil {
		t.Fatalf("swanctl --list-sas: %v", err)
	}
	// Both the IKE_SA and the CHILD_SA print a "remote" line -- the first is
	// "remote 'flint' @ 10.40.0.2[4500]", the second the selector list -- so
	// the fields are filtered by whether they parse as a prefix rather than by
	// which line they came from.
	var got []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "remote" {
			continue
		}
		for _, field := range f[1:] {
			if _, err := netip.ParsePrefix(field); err == nil {
				got = append(got, field)
			}
		}
	}
	if len(got) == 0 {
		t.Fatalf("no negotiated remote selectors in:\n%s", out)
	}

	wantStr := make([]string, 0, len(want))
	for _, p := range want {
		wantStr = append(wantStr, p.String())
	}
	sort.Strings(got)
	sort.Strings(wantStr)
	if strings.Join(got, " ") != strings.Join(wantStr, " ") {
		t.Fatalf("negotiated selectors differ\n got (%d): %v\nwant (%d): %v",
			len(got), got, len(wantStr), wantStr)
	}

	// Routes, not just selectors: the kernel form is what actually steers
	// packets, and a client that accepted the selectors but installed a
	// rounded-up route would pass the comparison above and still swallow the
	// client's own LAN.
	routes, err := lab.Exec(context.Background(), container, "ip", "route", "show", "table", "220")
	if err != nil {
		t.Fatalf("ip route show table 220: %v", err)
	}
	var installed []string
	for _, line := range strings.Split(strings.TrimSpace(routes), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			installed = append(installed, f[0])
		}
	}
	sort.Strings(installed)
	if strings.Join(installed, " ") != strings.Join(wantStr, " ") {
		t.Errorf("installed routes are not the selectors\n got (%d): %v\nwant (%d): %v",
			len(installed), installed, len(wantStr), wantStr)
	}
}

func assertCounter(t *testing.T, lab *harness.Lab, container, comment string, nonZero bool) {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "nft", "list", "table", "inet", "probe")
	if err != nil {
		t.Fatalf("nft list table inet probe: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `comment "`+comment+`"`) {
			continue
		}
		zero := strings.Contains(line, "packets 0 ")
		if nonZero && zero {
			t.Errorf("counter %q never fired: %s", comment, strings.TrimSpace(line))
		}
		if !nonZero && !zero {
			t.Errorf("counter %q fired and should not have: %s", comment, strings.TrimSpace(line))
		}
		return
	}
	t.Errorf("no counter commented %q in:\n%s", comment, out)
}

func mustGet(t *testing.T, lab *harness.Lab, container, url string) string {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "curl", "-s", "--max-time", "5", url)
	if err != nil {
		t.Fatalf("%s GET %s: %v", container, url, err)
	}
	return strings.TrimSpace(out)
}

func assertBody(t *testing.T, lab *harness.Lab, container, url, want string) {
	t.Helper()
	if got := mustGet(t, lab, container, url); got != want {
		t.Errorf("%s GET %s: got %q want %q", container, url, got, want)
	}
}

// assertBulk fetches a large body and checks the byte count, which is the only
// way to ask the MTU question. curl is told to write just the size so a
// megabyte never crosses the Docker exec boundary.
func assertBulk(t *testing.T, lab *harness.Lab, container, url string, want int) {
	t.Helper()
	out, err := lab.Exec(context.Background(), container, "curl", "-s", "-o", "/dev/null",
		"--max-time", "30", "-w", "%{size_download}", url)
	if err != nil {
		t.Errorf("%s bulk GET %s: %v", container, url, err)
		return
	}
	if strings.TrimSpace(out) != fmt.Sprint(want) {
		t.Errorf("%s bulk GET %s: downloaded %q bytes, want %d -- stacked encapsulation MTU",
			container, url, strings.TrimSpace(out), want)
	}
}

func vipSubnetContains(t *testing.T, addr string) bool {
	t.Helper()
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return netip.MustParsePrefix(ikev2VIPSubnet).Contains(a)
}

func dumpIKEv2Logs(t *testing.T, lab *harness.Lab) {
	t.Helper()
	ctx := context.Background()
	for _, pair := range [][2]string{
		{"flint", "/tmp/charon.log"},
		{"phone", "/tmp/charon.log"},
		{"flint", "/tmp/gotun-dns.log"},
		{"ru-dest", "/tmp/labdns.log"},
		{"foreign-dest", "/tmp/labdns.log"},
	} {
		out, _ := lab.Exec(ctx, pair[0], "cat", pair[1])
		t.Logf("%s %s:\n%s", pair[0], pair[1], out)
	}
}

// TestIKEv2Phone_MOBIKESurvivesAccessNetworkChange is Wi-Fi to LTE, which is
// the single most common thing a phone does and the one a site-to-site tunnel
// never has to handle.
//
// The discriminator is the SA's own number. A session that survived the move
// stays #1; one that silently tore down and reconnected comes back as #2, and
// every other symptom -- traffic flowing, the interface up, the gateway content
// -- looks identical either way. Reachability alone would pass on a tunnel that
// drops for twenty seconds on every train platform.
func TestIKEv2Phone_MOBIKESurvivesAccessNetworkChange(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotunmbk%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	// Two access networks: the Wi-Fi the phone starts on and the cellular one
	// it roams to. The gateway sits on both, and the phone keeps dialling the
	// same address throughout -- it is the phone's own address that changes,
	// which is exactly what MOBIKE's UPDATE_SA_ADDRESSES is for.
	must(t, lab.CreateNetwork(ctx, "inet", "10.40.0.0/24"))
	must(t, lab.CreateNetwork(ctx, "inet2", "10.41.0.0/24"))

	must(t, lab.RunContainer(ctx, "flint", image, "10.40.0.2", "inet", map[string]string{
		"inet2": "10.41.0.2",
	}))
	must(t, lab.RunContainer(ctx, "phone", image, "10.40.0.10", "inet", map[string]string{
		"inet2": "10.41.0.10",
	}))
	for _, n := range []string{"flint", "phone"} {
		must(t, lab.WaitReady(ctx, n))
	}
	requireXfrmInterface(t, lab, "flint")

	wanIface := ifaceForAddr(t, lab, "flint", "10.40.0.2")
	wifiIface := ifaceForAddr(t, lab, "phone", "10.40.0.10")
	cellIface := ifaceForAddr(t, lab, "phone", "10.41.0.10")

	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
ip link add %s type xfrm dev %s if_id %s
ip link set %s up
ip address replace %s/24 dev %s
`, ikev2ClientsIface, wanIface, ikev2IfID, ikev2ClientsIface, ikev2GatewayVIP, ikev2ClientsIface)))

	// A service on the gateway's tunnel-side address is enough to prove the
	// tunnel carries traffic, and it keeps this lab to two containers.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(
		`labhttp -listen %s:8080 -body GATEWAY >/tmp/vip-http.log 2>&1 &`, ikev2GatewayVIP)))
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", fmt.Sprintf(`
set -e
nft add table inet probe
nft 'add chain inet probe pre { type filter hook prerouting priority -149 ; }'
nft add rule inet probe pre iifname "%s" counter comment "from-clients-iface"
`, ikev2ClientsIface)))

	// The second access network has to count as private too, or the phone
	// would route its own new subnet into the tunnel the moment it roamed.
	writeSwanctlGateway(t, lab, "flint", ikev2Selectors(netip.MustParsePrefix("10.41.0.0/24")))
	writeSwanctlClient(t, lab, "phone")
	startCharon(t, lab, "flint")
	startCharon(t, lab, "phone")

	// Start on Wi-Fi alone: the cellular interface exists but carries no
	// address charon could choose, which is the state a phone is actually in.
	must(t, lab.ExecOK(ctx, "phone", "bash", "-c", fmt.Sprintf(`
set -e
ip link set %s down
ip route replace default via 10.40.0.2
`, cellIface)))

	must(t, lab.ExecOK(ctx, "phone", "swanctl", "--initiate", "--child", "home"))
	before := waitIKESA(t, lab, "phone", 30*time.Second)
	if !strings.Contains(before, "peer supports MOBIKE") && !strings.Contains(before, "10.40.0.10") {
		t.Logf("initial SA:\n%s", before)
	}
	saBefore := saSerial(t, before)

	assertBody(t, lab, "phone", "http://"+ikev2GatewayVIP+":8080/id", "GATEWAY")
	assertCounter(t, lab, "flint", "from-clients-iface", true)

	// Roam. Bringing the new interface up before taking the old one down is the
	// order a phone uses, and it is the order that gives charon an address to
	// move to rather than a window with none.
	must(t, lab.ExecOK(ctx, "phone", "bash", "-c", fmt.Sprintf(`
set -e
ip link set %s up
ip route replace default via 10.41.0.2
ip link set %s down
`, cellIface, wifiIface)))

	// MOBIKE is not instantaneous: charon notices the address change from a
	// netlink event and then exchanges UPDATE_SA_ADDRESSES.
	var after string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := lab.Exec(ctx, "phone", "swanctl", "--list-sas")
		if err == nil && strings.Contains(out, "10.41.0.10") && strings.Contains(out, "ESTABLISHED") {
			after = out
			break
		}
		after = out
		time.Sleep(time.Second)
	}
	if !strings.Contains(after, "10.41.0.10") {
		log, _ := lab.Exec(ctx, "phone", "cat", "/tmp/charon.log")
		t.Fatalf("the SA never moved to the new access network:\n%s\ncharon log:\n%s", after, log)
	}

	// The assertion that separates roaming from reconnecting.
	if got := saSerial(t, after); got != saBefore {
		log, _ := lab.Exec(ctx, "phone", "cat", "/tmp/charon.log")
		t.Errorf("SA was re-established (#%s -> #%s) rather than migrated; MOBIKE did not"+
			" carry the move\ncharon log:\n%s", saBefore, got, log)
	}

	// The gateway has to agree about where the phone now is, or its replies go
	// to the address the phone just left.
	gw, err := lab.Exec(ctx, "flint", "swanctl", "--list-sas")
	if err != nil {
		t.Fatalf("gateway swanctl --list-sas: %v", err)
	}
	if !strings.Contains(gw, "10.41.0.10") {
		t.Errorf("gateway still believes the phone is on the old network:\n%s", gw)
	}

	// And the decrypted packets still surface on the same interface, which is
	// what keeps gotun's classification valid across a roam: -mark-iface and
	// the home_nets rule are both interface-named.
	assertBody(t, lab, "phone", "http://"+ikev2GatewayVIP+":8080/id", "GATEWAY")
	assertCounter(t, lab, "flint", "from-clients-iface", true)
}

// saSerial extracts the "#N" the daemon gives an IKE_SA. It increments on every
// new SA, so an unchanged value is evidence the session was migrated rather
// than rebuilt.
func saSerial(t *testing.T, listSAs string) string {
	t.Helper()
	for _, line := range strings.Split(listSAs, "\n") {
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "#") {
				return strings.TrimSuffix(strings.TrimPrefix(f, "#"), ",")
			}
		}
	}
	t.Fatalf("no established SA serial in:\n%s", listSAs)
	return ""
}

// TestIKEv2Generated_ConfigIsAcceptedByCharon runs the shipping generator and
// feeds its output to a real daemon.
//
// The unit tests pin what `gotun ikev2` writes; they cannot tell whether charon
// agrees that it is a configuration. That gap matters more than usual here,
// because the production selector list is 53 entries on one `local_ts` line and
// nothing documents a limit -- on the file format, on charon, or on iOS. Two of
// those three can be answered here.
//
// It also exercises the certificate path the deployed profile uses, which the
// PSK lab deliberately does not.
func TestIKEv2Generated_ConfigIsAcceptedByCharon(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Fatalf("docker daemon not reachable: %v", err)
	}
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Fatalf("image %s missing; run make docker-build: %v", image, err)
	}

	prefix := fmt.Sprintf("gotungen%d", time.Now().UnixNano()%1_000_000)
	lab, err := harness.NewLab(ctx, prefix)
	if err != nil {
		t.Fatalf("docker lab: %v", err)
	}
	t.Cleanup(func() { lab.Close(context.Background()) })

	must(t, lab.CreateNetwork(ctx, "inet", "10.40.0.0/24"))
	must(t, lab.RunContainer(ctx, "flint", image, "10.40.0.2", "inet", nil))
	must(t, lab.WaitReady(ctx, "flint"))

	// Production-shaped: the real non-routable defaults, both families, and a
	// public probe host -- not the lab's artificial private list.
	out, err := lab.Exec(ctx, "flint", "gotun", "ikev2",
		"-server", "vpn.example.net",
		"-vip-subnet", ikev2VIPSubnet,
		"-vip-gateway", ikev2GatewayVIP,
		"-pool", ikev2PoolAddrs,
		"-probe-url", "http://vpn.example.net:8443/alive",
		"-client-id", "iphone",
		"-if-id", ikev2IfID,
		"-out-swanctl", "/etc/swanctl/swanctl.conf",
		"-out-profile", "/tmp/phone.mobileconfig",
	)
	if err != nil {
		t.Fatalf("gotun ikev2: %v\n%s", err, out)
	}
	if !strings.Contains(out, "traffic selectors") {
		t.Errorf("unexpected output:\n%s", out)
	}

	// A throwaway PKI, because the generated configuration authenticates the
	// gateway with a certificate and charon refuses a connection whose
	// credential is absent.
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", `
set -e
pki --gen --type ecdsa --size 256 --outform pem > /etc/swanctl/private/ca.key
pki --self --ca --in /etc/swanctl/private/ca.key --type ecdsa --dn "CN=gotun-lab-ca" \
  --outform pem > /etc/swanctl/x509ca/ca.pem
pki --gen --type ecdsa --size 256 --outform pem > /etc/swanctl/private/gw.key
pki --pub --in /etc/swanctl/private/gw.key --type ecdsa \
  | pki --issue --cacert /etc/swanctl/x509ca/ca.pem --cakey /etc/swanctl/private/ca.key \
      --dn "CN=vpn.example.net" --san vpn.example.net --flag serverAuth \
      --outform pem > /etc/swanctl/x509/gotun-gw.pem
`))

	must(t, lab.ExecOK(ctx, "flint", "bash", "-c",
		`printf 'charon {\n  filelog {\n    stderr {\n      default = 1\n    }\n  }\n}\n' > /etc/strongswan.d/zz-lab.conf`))
	must(t, lab.ExecOK(ctx, "flint", "bash", "-c", `/usr/lib/ipsec/charon > /tmp/charon.log 2>&1 &`))
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := lab.ExecOK(ctx, "flint", "swanctl", "--stats"); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	loaded, err := lab.Exec(ctx, "flint", "swanctl", "--load-all")
	if err != nil {
		log, _ := lab.Exec(ctx, "flint", "cat", "/tmp/charon.log")
		t.Fatalf("swanctl --load-all: %v\n%s\ncharon log:\n%s", err, loaded, log)
	}
	for _, want := range []string{
		"loaded connection 'phone'",
		"successfully loaded 1 connections, 0 unloaded",
		"loaded pool 'phone-pool'",
	} {
		if !strings.Contains(loaded, want) {
			t.Errorf("load output missing %q:\n%s", want, loaded)
		}
	}

	// Accepted is not the same as kept. charon could have parsed the line and
	// retained a truncated list, which would narrow the tunnel silently, so the
	// selectors are read back out of the loaded connection.
	conns, err := lab.Exec(ctx, "flint", "swanctl", "--list-conns")
	if err != nil {
		t.Fatalf("swanctl --list-conns: %v", err)
	}
	for _, want := range []string{
		ikev2VIPSubnet, // the punched-back resolver subnet
		"2000::/3",     // the single IPv6 selector
		"11.0.0.0/8",   // a representative v4 gap
	} {
		if !strings.Contains(conns, want) {
			t.Errorf("loaded connection does not carry selector %s:\n%s", want, conns)
		}
	}
	// The private space the phone has to keep on-link must not be in there.
	for _, mustNot := range []string{"192.168.0.0/16", "10.0.0.0/8", "0.0.0.0/0"} {
		if strings.Contains(conns, mustNot) {
			t.Errorf("loaded connection tunnels private space %s:\n%s", mustNot, conns)
		}
	}
}
