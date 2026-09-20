package gotunclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

// ApplyMode selects how far a change is written.
//
// The three tiers exist so the risky form is never the first one tried: device
// changes only NM's in-memory state, temporary survives until NM restarts, and
// persistent is written to the profile on disk.
type ApplyMode string

const (
	// ApplyDevice reapplies in memory via D-Bus. No link bounce, so an SSH
	// session over the affected interface survives. Lost on NM restart.
	ApplyDevice ApplyMode = "device"
	// ApplyTemporary edits the profile in memory only. Bounces the link.
	ApplyTemporary ApplyMode = "temporary"
	// ApplyPersistent writes the profile to disk. Bounces the link and
	// survives a reboot -- so a bad config needs disable or a console.
	ApplyPersistent ApplyMode = "persistent"
)

func ParseApplyMode(s string) (ApplyMode, error) {
	switch ApplyMode(s) {
	case ApplyDevice, ApplyTemporary, ApplyPersistent:
		return ApplyMode(s), nil
	}
	return "", fmt.Errorf("unknown -apply-mode %q (want device, temporary or persistent)", s)
}

// Defaults for the home-lab deployment this was built for.
const (
	DefaultGateway   = "192.168.8.162"
	DefaultDNS       = "192.168.8.1"
	DefaultStatePath = "/var/lib/gotun-client/state.json"
	DefaultProbe     = "1.1.1.1"

	rollbackUnit = "gotun-client-rollback"
)

// EnableOptions configures Enable.
type EnableOptions struct {
	Gateway      netip.Addr
	DNS          netip.Addr
	Probe        netip.Addr
	ExtraLANs    []netip.Prefix
	StatePath    string
	ConnectionID string
	Mode         ApplyMode
	Force        bool
	// DryRun suppresses state-file writes and post-apply verification. The
	// Runner still filters mutating commands, but file writes and assertions
	// are not Runner calls, so they need their own gate.
	DryRun         bool
	ConfirmTimeout time.Duration
	SettleTimeout  time.Duration
	SelfPath       string
	// Detach re-runs this command under a transient systemd unit when the
	// apply mode bounces the link. Without it, the SSH session that issued
	// the command dies mid-apply and takes the process with it, leaving the
	// host half-configured with nothing left running to verify or roll back.
	Detach bool
	// Args is the original argv (after the subcommand), replayed on re-exec.
	Args []string
}

const enableUnit = "gotun-client-enable"

// bouncesLink reports whether a mode tears the interface down.
func (m ApplyMode) bouncesLink() bool { return m != ApplyDevice }

// detach re-executes this enable under a transient systemd unit so it outlives
// the calling SSH session. Returns true when the work was handed off.
func detach(r linux.Runner, w io.Writer, o EnableOptions) (bool, error) {
	if !o.Detach || !o.Mode.bouncesLink() || o.DryRun {
		return false, nil
	}
	if _, err := r.Run("sh", "-c", "test -d /run/systemd/system && command -v systemd-run >/dev/null"); err != nil {
		fmt.Fprintf(w, "WARNING: systemd unavailable, running inline; an SSH drop will kill this apply.\n")
		return false, nil
	}
	args := []string{
		"--collect",
		"--unit=" + enableUnit,
		"--description=gotun-client enable",
		o.SelfPath, "enable", "-detach=false",
	}
	args = append(args, o.Args...)
	if err := run(r, "systemd-run", args...); err != nil {
		return false, fmt.Errorf("detach via systemd-run: %w", err)
	}
	fmt.Fprintf(w, "detached as %s.service (this link will bounce)\n", enableUnit)
	fmt.Fprintf(w, "  follow:  journalctl -fu %s\n", enableUnit)
	fmt.Fprintf(w, "  result:  gotun-client status\n")
	return true, nil
}

// sleepFunc is replaced in tests so settle does not really sleep.
var sleepFunc = time.Sleep

// buildEnableArgs returns the argv after "nmcli connection modify <con>".
//
// ipv4.gateway is deliberately never written: NetworkManager only materialises
// it alongside static ipv4.addresses, so under method=auto it is inert. The
// working knobs are never-default plus an explicit default in ipv4.routes.
func buildEnableArgs(o EnableOptions) []string {
	return []string{
		"ipv4.never-default", "yes",
		// One argv element: "<dest> <nexthop>". Appended with + so any
		// pre-existing static route survives.
		"+ipv4.routes", "0.0.0.0/0 " + o.Gateway.String(),
		"ipv4.ignore-auto-dns", "yes",
		"ipv4.dns", o.DNS.String(),
		"ipv6.ignore-auto-dns", "yes",
	}
}

// buildRestoreArgs returns the argv that puts saved back. Properties that were
// unset are assigned the empty string, which resets them to their default.
func buildRestoreArgs(saved NMProps) []string {
	return []string{
		"ipv4.never-default", nmBoolArg(saved.NeverDefault),
		"ipv4.routes", nmArg(saved.Routes),
		"ipv4.route-metric", nmArg(saved.RouteMetric),
		"ipv4.ignore-auto-dns", nmBoolArg(saved.IgnoreAutoDNS),
		"ipv4.dns", nmArg(saved.DNS),
		"ipv6.ignore-auto-dns", nmBoolArg(saved.IPv6IgnoreDNS),
	}
}

// applyProps writes props to the connection according to mode.
func applyProps(r linux.Runner, mode ApplyMode, conn ActiveConn, args []string) error {
	switch mode {
	case ApplyDevice:
		// device modify takes the same property list and reapplies in place.
		return run(r, "nmcli", append([]string{"device", "modify", conn.Device}, args...)...)
	case ApplyTemporary:
		if err := run(r, "nmcli", append([]string{"connection", "modify", "--temporary", conn.ID}, args...)...); err != nil {
			return err
		}
		return run(r, "nmcli", "connection", "up", conn.ID)
	case ApplyPersistent:
		if err := run(r, "nmcli", append([]string{"connection", "modify", conn.ID}, args...)...); err != nil {
			return err
		}
		return run(r, "nmcli", "connection", "up", conn.ID)
	}
	return fmt.Errorf("unknown apply mode %q", mode)
}

// revertProps undoes an apply. device mode has a dedicated escape hatch:
// reapply re-reads the stored profile, so nothing has to be reconstructed.
func revertProps(r linux.Runner, mode ApplyMode, conn ActiveConn, saved NMProps) error {
	if mode == ApplyDevice {
		return run(r, "nmcli", "device", "reapply", conn.Device)
	}
	args := buildRestoreArgs(saved)
	target := []string{"connection", "modify", conn.ID}
	if mode == ApplyTemporary {
		target = []string{"connection", "modify", "--temporary", conn.ID}
	}
	if err := run(r, "nmcli", append(target, args...)...); err != nil {
		return err
	}
	return run(r, "nmcli", "connection", "up", conn.ID)
}

func run(r linux.Runner, name string, args ...string) error {
	_, err := r.Run(name, args...)
	return err
}

// Enable points the host's IPv4 default route at the gotun gateway and its DNS
// at the configured resolver, snapshotting the previous NM settings first and
// rolling back on any verification failure.
func Enable(r linux.Runner, w io.Writer, o EnableOptions) error {
	if !o.Gateway.IsValid() || !o.Gateway.Is4() {
		return fmt.Errorf("invalid -gateway %q", o.Gateway)
	}
	if !o.DNS.IsValid() || !o.DNS.Is4() {
		return fmt.Errorf("invalid -dns %q", o.DNS)
	}
	if o.SettleTimeout <= 0 {
		o.SettleTimeout = 20 * time.Second
	}
	if !o.Probe.IsValid() {
		o.Probe = netip.MustParseAddr(DefaultProbe)
	}

	if handed, err := detach(r, w, o); err != nil || handed {
		return err
	}

	conn, err := DetectActiveConn(r, o.ConnectionID)
	if err != nil {
		return err
	}

	cur, err := ReadNMProps(r, conn.ID)
	if err != nil {
		return err
	}
	switch cur.Method {
	case "auto", "manual":
	default:
		return fmt.Errorf("ipv4.method=%q on %q is not supported (want auto or manual)", cur.Method, conn.ID)
	}

	protected, err := protectedSet(o.ExtraLANs)
	if err != nil {
		return err
	}

	st := &State{
		Version:        StateVersion,
		ConnectionID:   conn.ID,
		Device:         conn.Device,
		Saved:          cur,
		EnabledGateway: o.Gateway.String(),
		EnabledDNS:     o.DNS.String(),
		Mode:           string(o.Mode),
		SelfPath:       o.SelfPath,
		SavedAt:        time.Now().UTC(),
	}

	if StateExists(o.StatePath) {
		if !o.Force {
			return fmt.Errorf("already enabled: state file %s exists (use -force to re-apply, or disable first)", o.StatePath)
		}
		// Re-snapshotting here would record the *enabled* config as the
		// original, which would quietly turn disable into a no-op.
		prev, err := LoadState(o.StatePath)
		if err != nil {
			return fmt.Errorf("-force: cannot read existing state %s: %w", o.StatePath, err)
		}
		fmt.Fprintf(w, "state file exists, -force: reusing snapshot from %s\n", prev.SavedAt.Format(time.RFC3339))
		st.Saved = prev.Saved
	}

	if cur.Routes != nil && !o.Force {
		return fmt.Errorf("ipv4.routes on %q is already set (%s); re-run with -force once you have checked it can be restored",
			conn.ID, *cur.Routes)
	}

	// The snapshot must reach disk before anything is mutated.
	if o.DryRun {
		fmt.Fprintf(w, "DRY-RUN: would write state to %s:\n%s\n", o.StatePath, mustStateJSON(st))
	} else if err := SaveState(o.StatePath, st); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	// Arm before the change, so a bounce that never comes back still reverts.
	if o.ConfirmTimeout > 0 {
		if err := armRollback(r, st, o.StatePath, o.ConfirmTimeout); err != nil {
			_ = RemoveState(o.StatePath)
			return fmt.Errorf("arm auto-rollback: %w", err)
		}
		st.ArmUnit = rollbackUnit
		if !o.DryRun {
			if err := SaveState(o.StatePath, st); err != nil {
				return fmt.Errorf("save state: %w", err)
			}
		}
	} else {
		fmt.Fprintf(w, "WARNING: -confirm-timeout 0: no automatic rollback is armed.\n")
	}

	fail := func(cause error) error {
		if rbErr := revertProps(r, o.Mode, conn, st.Saved); rbErr != nil {
			// Do not disarm: the timer is now the last line of defence.
			return fmt.Errorf("%v; ROLLBACK ALSO FAILED, host may be unreachable: %w", cause, rbErr)
		}
		_ = disarmRollback(r, st)
		_ = RemoveState(o.StatePath)
		return fmt.Errorf("%v (rolled back)", cause)
	}

	if err := applyProps(r, o.Mode, conn, buildEnableArgs(o)); err != nil {
		if o.DryRun {
			return fmt.Errorf("apply failed: %w", err)
		}
		return fail(fmt.Errorf("apply failed: %w", err))
	}
	if o.DryRun {
		fmt.Fprintf(w, "\nDRY-RUN: nothing was applied, so verification is skipped.\n")
		fmt.Fprintf(w, "         protected LANs would be: %s\n", formatPrefixes(protected))
		return nil
	}
	if err := settle(r, conn.Device, o.SettleTimeout); err != nil {
		return fail(err)
	}
	// Drop stale PMTU/redirect exceptions so the assertions below read the FIB
	// rather than a cached per-destination answer.
	_ = FlushRouteCache(r)
	if err := verifyEnabled(r, protected, o.Gateway, o.Probe); err != nil {
		return fail(err)
	}

	fmt.Fprintf(w, "enabled: %s (%s) default via %s, dns %s, mode %s\n", conn.ID, conn.Device, o.Gateway, o.DNS, o.Mode)
	fmt.Fprintf(w, "protected LANs: %s\n", formatPrefixes(protected))
	if o.ConfirmTimeout > 0 {
		fmt.Fprintf(w, "\nARMED: settings revert automatically in %s\n", o.ConfirmTimeout)
		fmt.Fprintf(w, "  confirm: gotun-client confirm -state %s\n", o.StatePath)
		fmt.Fprintf(w, "  revert:  gotun-client disable -state %s\n", o.StatePath)
	}
	return nil
}

// verifyEnabled is the post-apply gate: the default route must have moved, no
// protected LAN may hairpin through the gateway, and there must be exactly one
// default route.
func verifyEnabled(r linux.Runner, protected []netip.Prefix, gw, probe netip.Addr) error {
	if err := AssertDefaultViaGateway(r, probe, gw); err != nil {
		return err
	}
	if err := AssertSingleDefaultRoute(r); err != nil {
		return err
	}
	return AssertLANsOnLink(r, protected, gw)
}

// settle waits for NM to finish reactivating the device and for a default route
// to exist again. Without it, verification races the reassociation.
func settle(r linux.Runner, dev string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		ok, err := deviceConnected(r, dev)
		if err == nil && ok {
			out, rErr := r.Run("ip", "-4", "route", "show", "default")
			if rErr == nil && strings.TrimSpace(out) != "" {
				return nil
			}
			last = fmt.Errorf("device %s connected but no default route yet", dev)
		} else if err != nil {
			last = err
		} else {
			last = fmt.Errorf("device %s not connected yet", dev)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("device %s did not settle within %s: %v", dev, timeout, last)
		}
		sleepFunc(500 * time.Millisecond)
	}
}

// armRollback schedules an unconditional disable via a transient systemd unit.
// The countdown is held by PID 1, so it survives this process exiting, the SSH
// session dropping, and kill -9.
func armRollback(r linux.Runner, st *State, statePath string, d time.Duration) error {
	if st.SelfPath == "" {
		return fmt.Errorf("cannot arm rollback: executable path unknown")
	}
	secs := strconv.Itoa(int(d.Seconds()))
	return run(r, "systemd-run",
		"--collect",
		"--on-active="+secs+"s",
		"--unit="+rollbackUnit,
		"--description=gotun-client armed rollback",
		st.SelfPath, "disable", "-state", statePath)
}

func disarmRollback(r linux.Runner, st *State) error {
	if st.ArmUnit == "" {
		return nil
	}
	if err := run(r, "systemctl", "stop", st.ArmUnit+".timer"); err != nil {
		return err
	}
	// A completed or cancelled transient unit can linger in a failed state.
	_, _ = r.Run("systemctl", "reset-failed", st.ArmUnit+".timer", st.ArmUnit+".service")
	return nil
}

// Disable restores the snapshot in the state file and removes it.
func Disable(r linux.Runner, w io.Writer, statePath string) error {
	st, err := LoadState(statePath)
	if err != nil {
		return fmt.Errorf("load state %s: %w", statePath, err)
	}
	conn := ActiveConn{ID: st.ConnectionID, Device: st.Device}
	mode, err := ParseApplyMode(st.Mode)
	if err != nil {
		mode = ApplyPersistent
	}

	if err := revertProps(r, mode, conn, st.Saved); err != nil {
		// Keep the state file: a retry must still be possible.
		return fmt.Errorf("restore %q: %w (state kept at %s for retry)", conn.ID, err, statePath)
	}
	if err := settle(r, conn.Device, 20*time.Second); err != nil {
		return fmt.Errorf("restore %q: %w (state kept at %s for retry)", conn.ID, err, statePath)
	}
	_ = FlushRouteCache(r)

	if gw, perr := netip.ParseAddr(st.EnabledGateway); perr == nil {
		probe := netip.MustParseAddr(DefaultProbe)
		if res, rerr := RouteGet(r, probe); rerr == nil && res.Via == gw {
			return fmt.Errorf("restore %q applied but off-LAN traffic still routes via %s (state kept at %s)", conn.ID, gw, statePath)
		}
	}

	_ = disarmRollback(r, st)
	if err := RemoveState(statePath); err != nil {
		return fmt.Errorf("remove state: %w", err)
	}
	fmt.Fprintf(w, "disabled: %s (%s) restored\n", conn.ID, conn.Device)
	return nil
}

// Confirm cancels the armed rollback and marks the state confirmed.
func Confirm(r linux.Runner, w io.Writer, statePath string) error {
	st, err := LoadState(statePath)
	if err != nil {
		return fmt.Errorf("load state %s: %w", statePath, err)
	}
	if st.Confirmed {
		fmt.Fprintf(w, "already confirmed at %s\n", st.SavedAt.Format(time.RFC3339))
		return nil
	}
	if err := disarmRollback(r, st); err != nil {
		return fmt.Errorf("disarm rollback: %w", err)
	}
	st.Confirmed = true
	st.ArmUnit = ""
	if err := SaveState(statePath, st); err != nil {
		return err
	}
	fmt.Fprintf(w, "confirmed: automatic rollback cancelled; %s stays enabled\n", st.ConnectionID)
	return nil
}

// detectPrefixes is replaced in tests so the protected set does not depend on
// whatever interfaces the machine running the tests happens to have.
var detectPrefixes = DetectOnLinkPrefixes

// mustStateJSON renders a state for dry-run output.
func mustStateJSON(st *State) string {
	b, err := json.MarshalIndent(st, "  ", "  ")
	if err != nil {
		return fmt.Sprintf("<unrenderable: %v>", err)
	}
	return "  " + string(b)
}

func protectedSet(extras []netip.Prefix) ([]netip.Prefix, error) {
	onLink, err := detectPrefixes()
	if err != nil {
		return nil, fmt.Errorf("detect on-link prefixes: %w", err)
	}
	return MergePrefixes(onLink, extras...), nil
}

func formatPrefixes(ps []netip.Prefix) string {
	var parts []string
	for _, p := range ps {
		parts = append(parts, p.String())
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}
