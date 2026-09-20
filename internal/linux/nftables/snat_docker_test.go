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

// TestDirectSNAT_RealNftRoundTrip renders the direct-SNAT table, loads it into a
// real nft inside an isolated container, lists it back as JSON, and feeds that
// through the drift matcher.
//
// This is the only test that can catch a mismatch between hand-written JSON
// fixtures and what nft actually emits. Such a mismatch is expensive rather than
// loud: semanticMatchJSON would return false on every apply, so each one would
// delete and rebuild the whole table -- reloading ~12k set elements and resetting
// the counters the live verification depends on. It also proves the rule is valid
// nft syntax in an inet nat chain.
func TestDirectSNAT_RealNftRoundTrip(t *testing.T) {
	if os.Getenv("GOTUN_INTEGRATION") == "" {
		t.Skip("set GOTUN_INTEGRATION=1 to run (make test-integration)")
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

	st, err := policy.Compile(policy.Policy{
		DirectPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")},
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.20.0.3"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		LANIfaces:       []string{"eth0"},
		FailMode:        policy.FailClosed,
		TunnelUp:        false,
		DirectSNAT:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := RenderFullTable(st.Nft)
	if !strings.Contains(script, "masquerade") {
		t.Fatalf("rendered script has no masquerade:\n%s", script)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gotun.nft"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	// Load it for real, then ask nft to hand the table back as JSON.
	inner := `set -e
nft -f /work/gotun.nft
nft -j list table inet gotun
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

	// The real nft output must satisfy the matcher, or every apply churns.
	if !semanticMatchJSON(stdout, st.Nft) {
		t.Fatalf("real nft JSON did not match the spec -- every apply would rebuild the table.\nJSON: %s", stdout)
	}
}
