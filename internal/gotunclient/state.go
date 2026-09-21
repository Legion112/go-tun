package gotunclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// StateVersion is what this binary writes. It is bumped when the on-disk
	// shape changes incompatibly.
	StateVersion = 2
	// minLoadableStateVersion is the oldest version still readable.
	//
	// Version 1 predates IPv6 support and simply has no ipv6 block, which
	// leaves NMProps.IPv6 nil and makes disable emit exactly the arguments it
	// emitted before -- so a machine that was enabled under the old binary can
	// still be disabled by the new one. That property is the whole reason the
	// IPv6 snapshot is a nil-able pointer rather than an inline struct: a
	// zero-valued struct would not read as "never captured", it would read as
	// "ipv6.routes was unset", and restoring it would clear static IPv6 routes
	// that gotun never touched.
	minLoadableStateVersion = 1
)

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

	// IPv6 is nil when the snapshot predates IPv6 support, or when the profile
	// reported no ipv6.method. Nil means "never captured", which is not the
	// same as "captured as unset" -- see minLoadableStateVersion. The existing
	// fields above keep their names and positions so a version 1 file still
	// unmarshals into them.
	IPv6 *NMPropsV6 `json:"ipv6,omitempty"`
}

// NMPropsV6 is the IPv6 half of the snapshot.
type NMPropsV6 struct {
	Method       string  `json:"method"`
	DNS          *string `json:"dns"`
	NeverDefault bool    `json:"never_default"`
	Routes       *string `json:"routes"`
	RouteMetric  *string `json:"route_metric"`
}

// State is persisted so disable can restore NM settings without re-deriving them.
type State struct {
	Version        int     `json:"version"`
	ConnectionID   string  `json:"connection_id"`
	Device         string  `json:"device"`
	Saved          NMProps `json:"saved"`
	EnabledGateway string  `json:"enabled_gateway"`
	EnabledDNS     string  `json:"enabled_dns"`
	// EnabledGateway6 and IPv6Managed record whether this enable took charge of
	// the IPv6 half, so disable and status can tell "we left IPv6 alone" from
	// "we pointed it at the gateway".
	EnabledGateway6 string    `json:"enabled_gateway6,omitempty"`
	IPv6Managed     bool      `json:"ipv6_managed,omitempty"`
	Mode            string    `json:"mode"`
	SelfPath        string    `json:"self_path"`
	SavedAt         time.Time `json:"saved_at"`
	Confirmed       bool      `json:"confirmed"`
	ArmUnit         string    `json:"arm_unit,omitempty"`
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
	if s.Version < minLoadableStateVersion || s.Version > StateVersion {
		return nil, fmt.Errorf("state %s: version %d unsupported (want %d..%d)",
			path, s.Version, minLoadableStateVersion, StateVersion)
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
