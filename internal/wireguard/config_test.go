package wireguard_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/wireguard"
)

func wgSpec() policy.WireGuardSpec {
	return policy.WireGuardSpec{
		Interface:  "wg-exit",
		PrivateKey: "PRIVKEY",
		ListenPort: 51820,
		Address:    netip.MustParsePrefix("10.99.0.1/30"),
		Managed:    true,
		Up:         true,
		Peer: policy.WireGuardPeer{
			PublicKey:           "PEERPUB",
			Endpoint:            "10.20.0.3:51820",
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.30.0.0/24"), netip.MustParsePrefix("10.99.0.0/30")},
			PersistentKeepalive: 5,
		},
	}
}

func matchingDump() string {
	// iface: private-key public-key listen-port fwmark
	// peer:  public-key psk endpoint allowed-ips handshake rx tx keepalive
	return "PRIVKEY\tLOCALPUB\t51820\toff\n" +
		"PEERPUB\t(none)\t10.20.0.3:51820\t10.30.0.0/24,10.99.0.0/30\t0\t0\t0\t5\n"
}

func TestReconcile_SemanticMatchNoChanges(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip link show dev wg-exit"] = "2: wg-exit: <POINTOPOINT,UP,LOWER_UP>"
	r.Outputs["wg show wg-exit dump"] = matchingDump()
	r.Outputs["ip -4 addr show dev wg-exit"] = "inet 10.99.0.1/30 scope global wg-exit"
	n, err := wireguard.Reconcile(r, wgSpec())
	if err != nil {
		t.Fatal(err)
	}
	// Semantic match still ensures AllowedIPs routes (2 non-default prefixes).
	if n != 2 {
		t.Fatalf("want 2 route refreshes, got %d; calls=%v", n, r.Calls)
	}
	for _, c := range r.Calls {
		if strings.Contains(c, "wg set") || strings.HasPrefix(c, "wg set") {
			t.Fatalf("semantic match must not reconfigure: %v", r.Calls)
		}
	}
}

func TestReconcile_EndpointChangeForcesReapply(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip link show dev wg-exit"] = "2: wg-exit: <POINTOPOINT,UP,LOWER_UP>"
	dump := "PRIVKEY\tLOCALPUB\t51820\toff\n" +
		"PEERPUB\t(none)\t10.20.0.9:51820\t10.30.0.0/24,10.99.0.0/30\t0\t0\t0\t5\n"
	r.Outputs["wg show wg-exit dump"] = dump
	r.Outputs["ip -4 addr show dev wg-exit"] = "inet 10.99.0.1/30 scope global wg-exit"
	n, err := wireguard.Reconcile(r, wgSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("endpoint change must force reapply")
	}
}

func TestReconcile_AllowedIPsChangeForcesReapply(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip link show dev wg-exit"] = "2: wg-exit: <POINTOPOINT,UP,LOWER_UP>"
	dump := "PRIVKEY\tLOCALPUB\t51820\toff\n" +
		"PEERPUB\t(none)\t10.20.0.3:51820\t10.30.0.0/24\t0\t0\t0\t5\n"
	r.Outputs["wg show wg-exit dump"] = dump
	r.Outputs["ip -4 addr show dev wg-exit"] = "inet 10.99.0.1/30 scope global wg-exit"
	n, err := wireguard.Reconcile(r, wgSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("AllowedIPs change must force reapply")
	}
}

func TestReconcile_ListenPortChangeForcesReapply(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.Outputs["ip link show dev wg-exit"] = "2: wg-exit: <POINTOPOINT,UP,LOWER_UP>"
	dump := "PRIVKEY\tLOCALPUB\t51821\toff\n" +
		"PEERPUB\t(none)\t10.20.0.3:51820\t10.30.0.0/24,10.99.0.0/30\t0\t0\t0\t5\n"
	r.Outputs["wg show wg-exit dump"] = dump
	r.Outputs["ip -4 addr show dev wg-exit"] = "inet 10.99.0.1/30 scope global wg-exit"
	n, err := wireguard.Reconcile(r, wgSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("listen-port change must force reapply")
	}
}
