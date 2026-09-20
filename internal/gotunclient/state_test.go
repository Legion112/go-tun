package gotunclient

import (
	"encoding/json"
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
