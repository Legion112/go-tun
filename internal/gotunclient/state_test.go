package gotunclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func strp(s string) *string { return &s }

// The crux of the tri-state: unset must survive a round trip as nil and stay
// distinguishable from an explicit empty value, because restoring an unset
// property means resetting it while "" could mean a real value.
func TestState_RoundTripPreservesUnsetAsNull(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	in := &State{
		Version: StateVersion, ConnectionID: "c", Device: "wlan0",
		Saved:   NMProps{Method: "auto", Routes: nil, DNS: nil, RouteMetric: nil},
		SavedAt: time.Now().UTC(),
	}
	if err := SaveState(p, in); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"routes": null`) {
		t.Fatalf("unset should marshal to null:\n%s", raw)
	}
	out, err := LoadState(p)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if out.Saved.Routes != nil || out.Saved.DNS != nil || out.Saved.RouteMetric != nil {
		t.Fatalf("unset became set: %+v", out.Saved)
	}
}

func TestState_EmptyStringStaysDistinctFromUnset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	in := &State{Version: StateVersion, ConnectionID: "c", Saved: NMProps{Method: "auto", Routes: strp("")}}
	if err := SaveState(p, in); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	out, err := LoadState(p)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if out.Saved.Routes == nil {
		t.Fatal(`"" must not collapse into unset`)
	}
}

func TestSaveState_Mode0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if err := SaveState(p, &State{Version: StateVersion, ConnectionID: "c"}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestSaveState_CreatesParentDirAndLeavesNoTmp(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "dir", "state.json")
	if err := SaveState(p, &State{Version: StateVersion, ConnectionID: "c"}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not survive a successful save")
	}
}

func TestLoadState_WrongVersionErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	b, _ := json.Marshal(map[string]any{"version": 99, "connection_id": "c"})
	os.WriteFile(p, b, 0o600)
	if _, err := LoadState(p); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadState_MissingConnectionIDErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	b, _ := json.Marshal(map[string]any{"version": StateVersion})
	os.WriteFile(p, b, 0o600)
	if _, err := LoadState(p); err == nil || !strings.Contains(err.Error(), "connection_id") {
		t.Fatalf("err = %v", err)
	}
}

func TestRemoveState_MissingFileIsNoError(t *testing.T) {
	if err := RemoveState(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("RemoveState: %v", err)
	}
}

func TestStateExists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if StateExists(p) {
		t.Fatal("should not exist yet")
	}
	SaveState(p, &State{Version: StateVersion, ConnectionID: "c"})
	if !StateExists(p) {
		t.Fatal("should exist now")
	}
}

// TestLoadState_AcceptsVersion1 is the other half of the migration guarantee:
// a machine enabled under the pre-IPv6 binary must still be disable-able by
// this one. Rejecting the old version would strand the user's original
// NetworkManager settings inside a file the new binary refuses to read.
func TestLoadState_AcceptsVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	v1 := `{
  "version": 1,
  "connection_id": "MTS_GPON_2F34",
  "device": "wlan0",
  "saved": {"method": "auto", "ipv6_ignore_auto_dns": false},
  "enabled_gateway": "192.168.8.162"
}`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatalf("a version 1 state file must still load: %v", err)
	}
	if st.Saved.IPv6 != nil {
		t.Fatal("a pre-IPv6 snapshot must leave IPv6 nil, or disable would clear properties it never captured")
	}
	if st.IPv6Managed {
		t.Fatal("a pre-IPv6 enable never managed IPv6")
	}
}

// TestLoadState_RejectsFutureVersion keeps the upper bound meaningful.
func TestLoadState_RejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	future := fmt.Sprintf(`{"version": %d, "connection_id": "x"}`, StateVersion+1)
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("a newer state file must not be silently accepted")
	}
}

// TestSaveLoadState_IPv6RoundTrip keeps the new block on disk.
func TestSaveLoadState_IPv6RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	routes := "::/0 fd00:8::162"
	in := &State{
		Version:         StateVersion,
		ConnectionID:    "conn",
		EnabledGateway6: "fd00:8::162",
		IPv6Managed:     true,
		Saved: NMProps{
			Method: "auto",
			IPv6:   &NMPropsV6{Method: "auto", NeverDefault: true, Routes: &routes},
		},
	}
	if err := SaveState(path, in); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Saved.IPv6 == nil || !got.Saved.IPv6.NeverDefault || got.Saved.IPv6.Routes == nil {
		t.Fatalf("IPv6 snapshot did not round trip: %+v", got.Saved.IPv6)
	}
	if *got.Saved.IPv6.Routes != routes || !got.IPv6Managed {
		t.Fatalf("IPv6 snapshot changed in transit: %+v", got.Saved.IPv6)
	}
}
