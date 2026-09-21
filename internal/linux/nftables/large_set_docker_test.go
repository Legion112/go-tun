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
	prefs := testutil.LoadAllRUfromMMDB(t)
	var v4, v6 int
	for _, p := range prefs {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}

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
		TunnelEndpoints: []netip.Addr{netip.MustParseAddr("10.20.0.3")},
		LANs: []netip.Prefix{
			netip.MustParsePrefix("10.10.0.0/24"),
			netip.MustParsePrefix("fd00:10::/64"),
		},
		FailMode:          policy.FailClosed,
		TunnelUp:          false,
		TunnelCarriesIPv6: true,
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

	// Both sets go in through one nft -f, which is how the gateway loads them:
	// a single transaction, so the two families can never be half-applied.
	// Listing both back is what catches an IPv6 interval set the kernel
	// accepted but stored differently.
	inner := `set -e
nft -f /work/gotun.nft
nft -j list set inet gotun ru_nets
nft -j list set inet gotun ru_nets6
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

	// Two JSON documents come back, one per list command; count each.
	parts := splitJSONDocs(stdout)
	if len(parts) != 2 {
		t.Fatalf("want two set listings, got %d\nout=%s", len(parts), truncate(stdout, 2000))
	}
	got4, err := countElemsFromDockerJSON([]byte(parts[0]))
	if err != nil {
		t.Fatalf("parse ru_nets json: %v\nout=%s", err, truncate(parts[0], 2000))
	}
	got6, err := countElemsFromDockerJSON([]byte(parts[1]))
	if err != nil {
		t.Fatalf("parse ru_nets6 json: %v\nout=%s", err, truncate(parts[1], 2000))
	}
	if got4 != v4 || got6 != v6 {
		t.Fatalf("nft set elements: got v4=%d v6=%d want v4=%d v6=%d", got4, got6, v4, v6)
	}
	t.Logf("loaded %d RU prefixes (v4=%d v6=%d) into nft in %s (script %d bytes)",
		len(prefs), got4, got6, elapsed, len(script))
}

// splitJSONDocs separates the concatenated top-level objects nft prints when
// several list commands run in one shell.
func splitJSONDocs(out string) []string {
	var docs []string
	depth, start := 0, -1
	for i, c := range out {
		switch c {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				docs = append(docs, out[start:i+1])
				start = -1
			}
		}
	}
	return docs
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
