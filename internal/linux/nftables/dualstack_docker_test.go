package nftables

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/test/integration/harness"
)

// dualStackSpec compiles a policy that exercises every rule shape in both
// families: excludes, endpoint exclusion, the classifier, home isolation and
// SNAT.
func dualStackSpec(t *testing.T) policy.NftSpec {
	t.Helper()
	st, err := policy.Compile(policy.Policy{
		DirectPrefixes: []netip.Prefix{
			netip.MustParsePrefix("10.200.0.0/24"),
			netip.MustParsePrefix("10.200.2.0/24"),
			netip.MustParsePrefix("2a02:6b8::/32"),
			netip.MustParsePrefix("fd00:200::/64"),
		},
		TunnelInterface: "wg-exit",
		TunnelEndpoints: []netip.Addr{
			netip.MustParseAddr("10.20.0.3"),
			netip.MustParseAddr("fd00:20::3"),
		},
		LANs: []netip.Prefix{
			netip.MustParsePrefix("10.10.0.0/24"),
			netip.MustParsePrefix("fd00:10::/64"),
		},
		LANIfaces:         []string{"eth0"},
		MarkIIfNames:      []string{"eth0"},
		FailMode:          policy.FailClosed,
		TunnelUp:          false,
		DirectSNAT:        true,
		DirectSNAT6:       true,
		TunnelCarriesIPv6: true,
		InboundWireGuard: policy.WireGuardConfig{
			PrivateKey: "CLIENTPRIV",
			ListenPort: 51821,
			Peer:       policy.WireGuardPeer{PublicKey: "WANPEER"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return st.Nft
}

// TestDualStack_RealNftRoundTrip_JSONAndTextAgree loads a dual-stack table into
// a real nft, lists it back both ways, and feeds each listing through its own
// matcher.
//
// This is the cheapest test for the most expensive failure mode. The two
// readback paths have opposite blind spots -- the JSON parser used to discard
// every ip6 daddr match, while the text parser cannot tell ip from ip6 at all
// -- so a dual-stack table could read as converged on one kind of box and as
// permanent drift on another. Drift here is not cosmetic: reconciliation is
// delete-and-rewrite, so a false mismatch reloads the whole table, all ~17k
// elements of it, on every single apply, and resets the counters the live
// verification depends on. OpenWrt ships nftables without JSON, so the box that
// matters most is the one on the weaker path.
func TestDualStack_RealNftRoundTrip_JSONAndTextAgree(t *testing.T) {
	if os.Getenv("GOTUN_INTEGRATION") == "" {
		t.Skip("set GOTUN_INTEGRATION=1 to run (make test-nft-real)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Skipf("docker daemon not reachable: %v", err)
	}
	const image = "gotun:lab"
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Skip("gotun:lab image missing; run make docker-build")
	}

	spec := dualStackSpec(t)
	script := RenderFullTable(spec)
	for _, want := range []string{
		"type ipv6_addr",
		"ip6 daddr",
		`comment "mark-non-direct-v6"`,
		`comment "exclude-endpoint-v6"`,
		"meta nfproto ipv6",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("rendered script is missing %q:\n%s", want, script)
		}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gotun.nft"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	// Loading it at all proves the IPv6 syntax is valid and that the elements
	// are acceptable to an ipv6_addr interval set.
	inner := `set -e
nft -f /work/gotun.nft
echo '===JSON==='
nft -j list table inet gotun
echo '===TEXT==='
nft list table inet gotun
`
	stdout, stderr, err := harness.RunOneShot(ctx, harness.OneShot{
		Image:       image,
		Privileged:  true,
		NetworkMode: "none",
		Binds:       []string{dir + ":/work:ro"},
		Cmd:         []string{"bash", "-c", inner},
	})
	if err != nil {
		t.Fatalf("nft -f failed: %v\nstderr: %s\nstdout: %s\nscript:\n%s", err, stderr, stdout, script)
	}

	jsonPart, textPart, ok := splitMarked(stdout)
	if !ok {
		t.Fatalf("could not split the two listings:\n%s", stdout)
	}

	if !semanticMatchJSON(jsonPart, spec) {
		t.Fatalf("real nft JSON did not match the spec -- every apply would rebuild the table.\nJSON: %s", jsonPart)
	}
	liveText, err := parseNftText(textPart)
	if err != nil {
		t.Fatalf("parsing real nft text: %v\n%s", err, textPart)
	}
	if !semanticMatch(liveText, spec) {
		t.Fatalf("real nft text did not match the spec -- the router would rebuild the table on every apply.\ntext:\n%s", textPart)
	}

	// The set type has to survive the round trip, or a future ipv4_addr /
	// ipv6_addr mix-up would be invisible.
	for _, want := range []string{"type ipv6_addr", "ru_nets6"} {
		if !strings.Contains(textPart, want) {
			t.Fatalf("text listing is missing %q:\n%s", want, textPart)
		}
	}

	// Both parsers must agree, and must both say "no". Agreement alone is not
	// enough: a matcher that has gone blind to IPv6 agrees with itself
	// perfectly while accepting anything.
	mutations := []struct {
		name string
		mut  func(s *policy.NftSpec)
	}{
		{"v6 LAN exclude changed", func(s *policy.NftSpec) {
			setExclude(s, policy.FamilyV6, netip.MustParsePrefix("fd00:99::/64"))
		}},
		{"v6 endpoint changed", func(s *policy.NftSpec) {
			setExcludeAddr(s, policy.FamilyV6, netip.MustParseAddr("fd00:20::9"))
		}},
		{"v6 set element changed", func(s *policy.NftSpec) {
			setElement(s, "ru_nets6", 0, netip.MustParsePrefix("2a03::/32"))
		}},
		{"v6 set element removed", func(s *policy.NftSpec) { dropElement(s, "ru_nets6") }},
		{"v4 set element removed", func(s *policy.NftSpec) { dropElement(s, "ru_nets") }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			mutated := dualStackSpec(t)
			m.mut(&mutated)
			gotJSON := semanticMatchJSON(jsonPart, mutated)
			live, err := parseNftText(textPart)
			if err != nil {
				t.Fatal(err)
			}
			gotText := semanticMatch(live, mutated)
			if gotJSON != gotText {
				t.Fatalf("the two readback paths disagree (json=%v text=%v):"+
					" the same live table would converge on one box and churn on the other",
					gotJSON, gotText)
			}
			if gotJSON {
				t.Fatal("a changed spec must read as drift on both paths")
			}
		})
	}
}

func splitMarked(out string) (jsonPart, textPart string, ok bool) {
	_, rest, ok := strings.Cut(out, "===JSON===")
	if !ok {
		return "", "", false
	}
	jsonPart, textPart, ok = strings.Cut(rest, "===TEXT===")
	return jsonPart, textPart, ok
}

func setExclude(s *policy.NftSpec, fam policy.Family, p netip.Prefix) {
	for ci := range s.Chains {
		for ri := range s.Chains[ci].Rules {
			r := &s.Chains[ci].Rules[ri]
			if r.Family == fam && len(r.ExcludePrefixes) > 0 {
				r.ExcludePrefixes[0] = p
				return
			}
		}
	}
}

func setExcludeAddr(s *policy.NftSpec, fam policy.Family, a netip.Addr) {
	for ci := range s.Chains {
		for ri := range s.Chains[ci].Rules {
			r := &s.Chains[ci].Rules[ri]
			if r.Family == fam && len(r.ExcludeAddrs) > 0 {
				r.ExcludeAddrs[0] = a
				return
			}
		}
	}
}

func setElement(s *policy.NftSpec, set string, i int, p netip.Prefix) {
	for si := range s.Sets {
		if s.Sets[si].Name == set && i < len(s.Sets[si].Elements) {
			s.Sets[si].Elements[i] = p
			return
		}
	}
}

func dropElement(s *policy.NftSpec, set string) {
	for si := range s.Sets {
		if s.Sets[si].Name == set && len(s.Sets[si].Elements) > 0 {
			s.Sets[si].Elements = s.Sets[si].Elements[1:]
			return
		}
	}
}
