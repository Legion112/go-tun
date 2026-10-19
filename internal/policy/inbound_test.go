package policy_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/policy"
)

// These tests pin the inbound-client decisions the way ipv6_test.go pins the
// IPv6 ones: the behaviour a phone tunnelling in through the router depends on,
// stated once so a later change has to argue with a name rather than with a
// comment.
//
// Three of the four fail against the tree as it stands. That is deliberate --
// they were written from the live router, where `nft list table inet gotun`
// contains exactly `set ru_nets` and `chain prerouting`: no home_nets, no
// forward chain, so nothing isolates an inbound peer from the home LAN today.

// Isolation must not depend on gotun holding the inbound private key.
//
// On OpenWrt netifd owns the WireGuard device and gotun holds no key by design,
// so InboundWireGuard is empty on exactly the deployment that needs isolation
// most: a phone arriving from the WAN. Gating the rule on PrivateKey means the
// isolation silently does not exist there.
func TestCompile_InboundIsolationWithoutManagedKeys(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"wgphone"}

	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}

	var haveHome bool
	for _, set := range st.Nft.Sets {
		if set.Name == policy.HomeNetsSetName {
			haveHome = true
		}
	}
	if !haveHome {
		t.Errorf("want %s set for an unmanaged clients iface, sets=%+v",
			policy.HomeNetsSetName, st.Nft.Sets)
	}

	var haveIsolate bool
	for _, ch := range st.Nft.Chains {
		if ch.Hook != "forward" {
			continue
		}
		for _, r := range ch.Rules {
			if r.Description == "isolate-inbound-from-home" &&
				r.IIfName == "wgphone" &&
				r.DropDstSet == policy.HomeNetsSetName {
				haveIsolate = true
			}
		}
	}
	if !haveIsolate {
		t.Errorf("want isolate rule on iif wgphone, chains=%+v", st.Nft.Chains)
	}

	// gotun must not try to own a device it has no key for.
	if st.WireGuardClients.Managed {
		t.Errorf("clients wg must stay unmanaged without a private key: %+v", st.WireGuardClients)
	}
}

// The clients interface name must be configurable even when gotun does manage
// the device, for the same reason -tunnel-iface is: the name that exists on the
// box is not ours to choose.
func TestCompile_ClientsInterfaceOverridesDefaultWhenManaged(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"wgphone"}
	p.InboundWireGuard = policy.WireGuardConfig{
		PrivateKey: "CLIENTPRIV",
		ListenPort: 51821,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.98.0.1/30")},
		Peer: policy.WireGuardPeer{
			PublicKey:  "PHONE",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.98.0.2/32")},
		},
	}

	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.WireGuardClients.Interface != "wgphone" {
		t.Errorf("clients iface: want wgphone, got %q", st.WireGuardClients.Interface)
	}
	for _, ch := range st.Nft.Chains {
		for _, r := range ch.Rules {
			if r.Description == "isolate-inbound-from-home" && r.IIfName != "wgphone" {
				t.Errorf("isolate rule on stale iface %q", r.IIfName)
			}
		}
	}
}

// A clients interface absent from MarkIIfNames gets no split routing at all,
// and nothing reports it. This is not hypothetical: the live router runs
// -mark-iface br-lan while br-guest and br-iot are up, so clients on those
// bridges are unclassified right now. Adding a tunnel interface and forgetting
// it here would put every phone flow out the ISP while looking healthy.
func TestCompile_RejectsClientsIfaceMissingFromMarkIfaces(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"wgphone"}
	p.MarkIIfNames = []string{"br-lan"}

	_, err := policy.Compile(p)
	if err == nil {
		t.Fatal("want error when the clients iface is not in MarkIIfNames")
	}
	if !strings.Contains(err.Error(), "wgphone") {
		t.Errorf("error should name the interface, got: %v", err)
	}
}

// Scope boundary, pinned because it is the requirement's sharp edge rather than
// a bug: home_nets isolation is a *forward* hook rule, so it covers inbound
// peer -> LAN host and nothing else. Traffic addressed to the router's own LAN
// address goes to input, not forward, and is therefore untouched -- the peer can
// still reach dnsmasq, SSH and LuCI on 192.168.8.1.
//
// That cuts both ways, which is why this is a decision and not a defect: the
// same gap is what keeps the peer's DNS working, and DNS to the gateway is
// load-bearing for GeoDNS. Restricting the router's own services belongs to the
// host firewall, where the guest and iot zones already do it with
// input=REJECT plus an Allow-DNS rule. gotun classifies; it does not firewall
// the box it runs on.
func TestCompile_InboundIsolationIsForwardOnlyByDesign(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"wgphone"}

	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range st.Nft.Chains {
		for _, r := range ch.Rules {
			if r.Description != "isolate-inbound-from-home" {
				continue
			}
			if ch.Hook != "forward" {
				t.Errorf("isolation belongs in forward, found in %q", ch.Hook)
			}
		}
		if ch.Hook == "input" {
			t.Errorf("gotun must not own an input chain (host firewall's job): %+v", ch)
		}
	}
}

// A gateway carries more than one inbound transport at a time, and they are not
// interchangeable: a phone on IKEv2 arrives on an xfrm interface while a laptop
// on WireGuard arrives on a netifd-created one.
//
// Isolating only the first leaves the second with the geo split *and*
// unrestricted access to the home LAN. That combination works, which is why
// nothing reports it.
func TestCompile_IsolatesEveryInboundInterface(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"ipsec0", "wgphone"}
	p.LANs = append(p.LANs, netip.MustParsePrefix("fd00:10::/64"))
	p.IPv6 = policy.IPv6On
	p.MarkIIfNames = []string{"br-lan", "ipsec0", "wgphone"}

	st, err := policy.Compile(p)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string][]policy.Family{}
	for _, ch := range st.Nft.Chains {
		if ch.Hook != "forward" {
			continue
		}
		for _, r := range ch.Rules {
			if r.Description == "isolate-inbound-from-home" {
				got[r.IIfName] = append(got[r.IIfName], r.Family)
			}
		}
	}
	for _, dev := range p.ClientsInterfaces {
		fams := got[dev]
		if len(fams) != 2 {
			t.Errorf("%s: want an isolation rule per family, got %v", dev, fams)
		}
	}
	// And the ingress guard has to cover them, or the rules above protect
	// clients who were never classified in the first place.
	for _, ch := range st.Nft.Chains {
		for _, r := range ch.Rules {
			if len(r.IIfNames) == 0 {
				continue
			}
			for _, dev := range p.ClientsInterfaces {
				if !slices.Contains(r.IIfNames, dev) {
					t.Errorf("ingress guard %v omits %s", r.IIfNames, dev)
				}
			}
		}
	}
}

// A name carrying a comma is a list that was never split. It renders as an nft
// rule matching an interface that cannot exist, so isolation applies to nothing
// while apply reports success -- and the ingress-guard check cannot catch it,
// because with -mark-iface empty there is no guard to compare against.
func TestCompile_RejectsAnInterfaceNameThatIsAList(t *testing.T) {
	cases := []struct {
		name  string
		ifs   []string
		marks []string
	}{
		{name: "comma, no ingress guard", ifs: []string{"ipsec0,wgphone"}},
		{
			name:  "comma, with an ingress guard",
			ifs:   []string{"ipsec0,wgphone"},
			marks: []string{"br-lan", "ipsec0", "wgphone"},
		},
		{name: "space", ifs: []string{"ipsec0 wgphone"}},
		{name: "empty entry", ifs: []string{"ipsec0", ""}},
		{name: "longer than IFNAMSIZ", ifs: []string{"ipsec0123456789abc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(true)
			p.ClientsInterfaces = tc.ifs
			p.MarkIIfNames = tc.marks
			if _, err := policy.Compile(p); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// gotun can own exactly one inbound WireGuard device, and which of several it
// owns is not something to guess. The combination does not arise on the real
// router -- there netifd owns the device and gotun holds no key -- so refusing
// it removes an implicit "the first one" rule nobody would find.
func TestCompile_RejectsManagedInboundWithSeveralClientsInterfaces(t *testing.T) {
	p := testPolicy(true)
	p.ClientsInterfaces = []string{"wgphone", "ipsec0"}
	p.MarkIIfNames = []string{"br-lan", "wgphone", "ipsec0"}
	p.InboundWireGuard = policy.WireGuardConfig{
		PrivateKey: "CLIENTPRIV",
		ListenPort: 51821,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.98.0.1/30")},
		Peer:       policy.WireGuardPeer{PublicKey: "PHONE"},
	}
	_, err := policy.Compile(p)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "one inbound WireGuard device") {
		t.Errorf("error should explain why, got: %v", err)
	}
}
