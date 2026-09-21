package nftables_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/testutil"
	"github.com/legion/go-tun/test/integration/harness"
)

// TestLargeRUSet_DockerNftApply loads the full RU set into nftables inside an
// isolated Docker container (--network none). Requires GOTUN_LARGE_SET=1 and
// a local MMDB at data/geo/GeoIP2-City.mmdb. Host netns is never modified.
func TestLargeRUSet_DockerNftApply(t *testing.T) {
	if os.Getenv("GOTUN_LARGE_SET") == "" {
		t.Skip("set GOTUN_LARGE_SET=1 to run (make test-large-set)")
	}
	// IPv4 only for now; the dual-stack large-set test arrives with the
	// family-aware compiler.
	prefs := testutil.LoadRUv4FromMMDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := harness.DaemonOK(ctx); err != nil {
		t.Skipf("docker daemon not reachable: %v", err)
	}
	const image = "gotun:lab"
	if err := harness.ImageExists(ctx, image); err != nil {
		t.Skip("gotun:lab image missing; run make docker-build")
	}

	st, err := policy.Compile(policy.Policy{
		DirectPrefixes:  prefs,
		TunnelInterface: "wg-exit",
		TunnelEndpoints:  []netip.Addr{netip.MustParseAddr("10.20.0.3")},
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		FailMode:        policy.FailClosed,
		TunnelUp:        false,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := nftables.RenderFullTable(st.Nft)

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "gotun.nft")
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	inner := `set -e
nft -f /work/gotun.nft
nft -j list set inet gotun ru_nets
`
	start := time.Now()
	stdout, stderr, err := harness.RunOneShot(ctx, harness.OneShot{
		Image:       image,
		Privileged:  true,
		NetworkMode: "none",
		Binds:       []string{dir + ":/work:ro"},
		Cmd:         []string{"bash", "-c", inner},
	})
	if err != nil {
		t.Fatalf("docker nft apply: %v\nstderr=%s\nstdout=%s", err, stderr, truncate(stdout, 2000))
	}
	elapsed := time.Since(start)

	n, err := countElemsFromDockerJSON([]byte(stdout))
	if err != nil {
		t.Fatalf("parse nft json: %v\nout=%s", err, truncate(stdout, 2000))
	}
	if n != len(prefs) {
		t.Fatalf("nft set elements: got %d want %d", n, len(prefs))
	}
	t.Logf("loaded %d RU prefixes into nft in %s (script %d bytes)", n, elapsed, len(script))
}

func countElemsFromDockerJSON(out []byte) (int, error) {
	// stdout may contain only the json object from nft -j
	out = bytes.TrimSpace(out)
	var root struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &root); err != nil {
		// try find first {
		i := bytes.IndexByte(out, '{')
		if i < 0 {
			return 0, err
		}
		if err2 := json.Unmarshal(out[i:], &root); err2 != nil {
			return 0, fmt.Errorf("%v / %w", err, err2)
		}
	}
	n := 0
	for _, raw := range root.Nftables {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			continue
		}
		setRaw, ok := wrap["set"]
		if !ok {
			continue
		}
		var setObj struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(setRaw, &setObj); err != nil {
			continue
		}
		n += len(setObj.Elem)
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
