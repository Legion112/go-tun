package gotunclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StateVersion is bumped when the on-disk shape changes incompatibly.
const StateVersion = 1

// NMProps is a snapshot of the connection properties gotun-client reads and restores.
//
// A nil pointer means nmcli reported the property as unset. Restoring an unset
// property means assigning the empty string, which resets it to its default --
// so the tri-state matters: "" and unset are not interchangeable.
type NMProps struct {
	Method        string  `json:"method"`
	Gateway       *string `json:"gateway"`
	DNS           *string `json:"dns"`
	IgnoreAutoDNS bool    `json:"ignore_auto_dns"`
	NeverDefault  bool    `json:"never_default"`
	Routes        *string `json:"routes"`
	RouteMetric   *string `json:"route_metric"`
	IPv6IgnoreDNS bool    `json:"ipv6_ignore_auto_dns"`
}

// State is persisted so disable can restore NM settings without re-deriving them.
type State struct {
	Version        int       `json:"version"`
	ConnectionID   string    `json:"connection_id"`
	Device         string    `json:"device"`
	Saved          NMProps   `json:"saved"`
	EnabledGateway string    `json:"enabled_gateway"`
	EnabledDNS     string    `json:"enabled_dns"`
	Mode           string    `json:"mode"`
	SelfPath       string    `json:"self_path"`
	SavedAt        time.Time `json:"saved_at"`
	Confirmed      bool      `json:"confirmed"`
	ArmUnit        string    `json:"arm_unit,omitempty"`
}

func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Version != StateVersion {
		return nil, fmt.Errorf("state %s: version %d unsupported (want %d)", path, s.Version, StateVersion)
	}
	if s.ConnectionID == "" {
		return nil, fmt.Errorf("state %s: missing connection_id", path)
	}
	return &s, nil
}

func SaveState(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func RemoveState(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// StateExists reports whether a state file is present.
func StateExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
