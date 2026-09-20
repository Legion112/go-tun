package apply_test

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/apply"
	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/policy"
)

func basePolicy() policy.Policy {
	return policy.Policy{
		DirectPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")},
		TunnelInterface: "wg-exit",
		TunnelEndpoint:  netip.MustParseAddr("10.10.0.2"),
		LANs:            []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		FailMode:        policy.FailClosed,
		TunnelUp:        false, // blackhole — no need for real wg keys in unit tests
	}
}

func TestReconcile_FirstApplyMakesChanges(t *testing.T) {
	r := linux.NewRecordingRunner()
	res, err := apply.Reconcile(r, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes == 0 {
		t.Fatal("expected changes on first apply")
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "nft") {
		t.Fatalf("expected nft calls, got %v", r.Calls)
	}
	if !strings.Contains(joined, "ip rule") && !strings.Contains(joined, "rule add") {
		t.Fatalf("expected ip rule calls, got %v", r.Calls)
	}
}

func TestReconcile_SecondApplySemanticNoop(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	r.AlreadyApplied = true
	r.Calls = nil
	res, err := apply.Reconcile(r, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes != 0 {
		t.Fatalf("expected 0 semantic changes on second apply, got %d; calls=%v", res.Changes, r.Calls)
	}
}

func TestReconcile_PartialFailureStops(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "ip route"
	_, err := apply.Reconcile(r, basePolicy())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "routing") {
		t.Fatalf("want routing error, got %v", err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "nft") {
		t.Fatalf("expected nft before failure, calls=%v", r.Calls)
	}
}

func TestSwapSetElements_UsesTransaction(t *testing.T) {
	r := linux.NewRecordingRunner()
	_, err := nftables.SwapSetElements(r, "inet", "gotun", "ru_nets", []string{"10.200.0.0/24", "10.200.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Calls, "\n")
	if !strings.Contains(joined, "flush set") || !strings.Contains(joined, "<<STDIN>>") {
		t.Fatalf("expected atomic nft -f transaction, got %v", r.Calls)
	}
}

func TestReconcile_NftSingleTransaction(t *testing.T) {
	r := linux.NewRecordingRunner()
	// Pretend table already exists with wrong contents so Reconcile must replace.
	r.Outputs["nft -j list table inet gotun"] = `{"nftables":[{"table":{"family":"inet","name":"gotun"}},{"set":{"name":"ru_nets","elem":["1.2.3.0/24"]}}]}`
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	var nftApply string
	for i, c := range r.Calls {
		if strings.Contains(c, "nft") && strings.Contains(c, "-f") && strings.Contains(c, "<<STDIN>>") {
			if i+1 < len(r.Calls) && strings.HasPrefix(r.Calls[i+1], "STDIN:") {
				nftApply = r.Calls[i+1]
			}
		}
	}
	if nftApply == "" {
		t.Fatalf("expected single nft -f apply, calls=%v", r.Calls)
	}
	if !strings.Contains(nftApply, "delete table inet gotun") {
		t.Fatalf("expected delete+add in one transaction, got %s", nftApply)
	}
	if !strings.Contains(nftApply, "add table inet gotun") {
		t.Fatalf("expected add table in same transaction, got %s", nftApply)
	}
	// Must not issue a separate delete-table CLI call.
	for _, c := range r.Calls {
		if strings.HasPrefix(c, "nft delete table") {
			t.Fatalf("delete table must be inside nft -f, not a separate call: %v", r.Calls)
		}
	}
}

func TestCompileIncludesEndpointInNftScript(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range r.Calls {
		if strings.Contains(c, "<<STDIN>>") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected nft -f with stdin script")
	}
}

func directSNATPolicy() policy.Policy {
	p := basePolicy()
	p.DirectSNAT = true
	// Must match the interface name in linux.RecordingRunner's sampleNftListJSON
	// fixture, or the semantic match fails and this reports a spurious change.
	p.LANIfaces = []string{"eth0"}
	return p
}

func TestReconcile_DirectSNATSecondApplySemanticNoop(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.AlreadyApplied = true
	res, err := apply.Reconcile(r, directSNATPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes != 0 {
		t.Fatalf("expected 0 semantic changes on second apply with direct SNAT, got %d; calls=%v",
			res.Changes, r.Calls)
	}
}

func TestReconcile_DirectSNATInSingleTransaction(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, directSNATPolicy()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.Calls, "\n")
	var stdin string
	for _, c := range r.Calls {
		if strings.HasPrefix(c, "STDIN:") && strings.Contains(c, "add table inet gotun") {
			stdin = c
		}
	}
	if stdin == "" {
		t.Fatalf("no nft batch found in:\n%s", joined)
	}
	for _, want := range []string{"add chain inet gotun postrouting", "masquerade", "snat-skip-lan"} {
		if !strings.Contains(stdin, want) {
			t.Fatalf("nft batch missing %q:\n%s", want, stdin)
		}
	}
}

// The breakdown must account for the whole total, or it misleads exactly when it
// is being relied on: an apply that reports changes but attributes none of them.
func TestReconcile_ComponentsAccountForTheTotal(t *testing.T) {
	r := linux.NewRecordingRunner()
	res, err := apply.Reconcile(r, basePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes == 0 {
		t.Fatal("a first apply against an empty box must report changes")
	}
	sum := 0
	for _, c := range res.Components {
		sum += c.Changes
	}
	if sum != res.Changes {
		t.Fatalf("components sum to %d but total is %d: %v", sum, res.Changes, res.Components)
	}
	if !strings.Contains(res.Summary(), "nftables=") {
		t.Fatalf("summary should name the subsystem that changed, got %q", res.Summary())
	}
}

// A failing subsystem must still be named and still carry its partial count, so a
// mid-way abort says how far the apply got.
func TestReconcile_FailedComponentIsStillReported(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "nft"
	res, err := apply.Reconcile(r, basePolicy())
	if err == nil {
		t.Fatal("expected the nft failure to surface")
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Fatalf("error should name the subsystem, got %v", err)
	}
	last := res.Components[len(res.Components)-1]
	if last.Name != "nftables" {
		t.Fatalf("the failing subsystem should be the last recorded, got %q", last.Name)
	}
	for _, c := range res.Components {
		if c.Name == "routing" {
			t.Fatal("subsystems after the failure must not be recorded")
		}
	}
}

// Nothing may pass "-" or /dev/stdin to a command that reads piped input. Both
// work on a desktop and neither exists on a stock OpenWrt root, where the result
// is that every nft write and every private-key load fails -- so this would look
// perfectly healthy in CI and take the gateway out entirely.
func TestReconcile_PipedInputUsesProcfsPath(t *testing.T) {
	r := linux.NewRecordingRunner()
	if _, err := apply.Reconcile(r, basePolicy()); err != nil {
		t.Fatal(err)
	}
	piped := 0
	for _, c := range r.Calls {
		if !strings.Contains(c, "<<STDIN>>") {
			continue
		}
		piped++
		for _, bad := range []string{" -f -", "/dev/stdin"} {
			if strings.Contains(c, bad) {
				t.Errorf("%q passes %q; use linux.StdinPath", c, bad)
			}
		}
		// The literal, not linux.StdinPath: comparing against the constant would
		// make this pass for whatever the constant happens to say.
		if !strings.Contains(c, "/proc/self/fd/0") {
			t.Errorf("%q pipes input but names no readable path", c)
		}
	}
	if piped == 0 {
		t.Fatal("expected at least one piped command (the nft batch)")
	}
}

// Clear is the rollback path, so a failure has to surface. It used to return nil
// unconditionally, which made "exit 0" no evidence that anything was removed.
func TestClear_FailureIsReported(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "nft delete table"
	if err := apply.Clear(r); err == nil {
		t.Fatal("a failed teardown must not report success")
	}
}

// Every subsystem is still attempted after one fails; a teardown that stops at
// the first error leaves the box half-configured.
func TestClear_ContinuesPastAFailure(t *testing.T) {
	r := linux.NewRecordingRunner()
	r.FailOn = "nft delete table"
	_ = apply.Clear(r)
	joined := strings.Join(r.Calls, "\n")
	for _, want := range []string{"ip rule del priority", "nft delete table", "ip link del dev wg-exit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("teardown skipped %q:\n%s", want, joined)
		}
	}
}

// The ip rule must go first: with a fail-closed policy still in table 100,
// removing the tunnel ahead of the rule black-holes marked traffic for the rest
// of the teardown, which is the opposite of what a rollback is for.
func TestClear_RemovesTheRuleBeforeTheTunnel(t *testing.T) {
	r := linux.NewRecordingRunner()
	if err := apply.Clear(r); err != nil {
		t.Fatal(err)
	}
	rule, link := -1, -1
	for i, c := range r.Calls {
		if rule < 0 && strings.HasPrefix(c, "ip rule del priority") {
			rule = i
		}
		if link < 0 && strings.HasPrefix(c, "ip link del dev wg-exit") {
			link = i
		}
	}
	if rule < 0 || link < 0 {
		t.Fatalf("expected both a rule delete and a link delete: %v", r.Calls)
	}
	if rule > link {
		t.Fatalf("the ip rule must be removed before the tunnel: %v", r.Calls)
	}
}

// A box that was never set up, or was already torn down, must clear cleanly.
func TestClear_AbsentObjectsAreNotFailures(t *testing.T) {
	r := linux.NewRecordingRunner()
	// The real wording, which differs per tool -- a single invented message would
	// not exercise the absence checks each one actually needs.
	absent := map[string]string{
		"ip rule del priority 100":    "RTNETLINK answers: No such file or directory",
		"ip route flush table 100":    "RTNETLINK answers: No such file or directory",
		"nft delete table inet gotun": "Error: No such file or directory",
		"ip link del dev wg-exit":     `Cannot find device "wg-exit"`,
		"ip link del dev wg-clients":  `Cannot find device "wg-clients"`,
	}
	for k, msg := range absent {
		r.Errors[k] = errors.New(msg)
	}
	if err := apply.Clear(r); err != nil {
		t.Fatalf("clearing an already-clean box must succeed: %v", err)
	}
}

// The property that makes -dry-run trustworthy: a full reconcile through the dry
// runner issues no writes to the host at all. Asserted over the real command
// surface rather than a sample, so a future subsystem that reaches for some new
// verb is caught here instead of on the router.
func TestReconcile_DryRunIssuesNoWrites(t *testing.T) {
	inner := linux.NewRecordingRunner()
	var out bytes.Buffer
	d := &linux.DryRunner{Inner: inner, Out: &out}

	if _, err := apply.Reconcile(d, directSNATPolicy()); err != nil {
		t.Fatal(err)
	}
	if d.Writes == 0 {
		t.Fatal("an empty box needs changes, so some writes should have been withheld")
	}
	for _, c := range inner.Calls {
		if strings.HasPrefix(c, "STDIN:") {
			t.Fatalf("a piped script reached the host: %q", c)
		}
		for _, verb := range []string{" add ", " del ", " delete ", " replace ", " flush ", " set ", " -f ", " -w "} {
			if strings.Contains(c+" ", verb) {
				t.Errorf("mutating command reached the host: %q", c)
			}
		}
	}
	if !strings.Contains(out.String(), "DRY-RUN:") {
		t.Fatal("expected the withheld commands to be printed")
	}
}
