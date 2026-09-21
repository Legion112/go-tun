package gotunclient

import (
	"encoding/json"
	"errors"
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
	// DefaultProbe6 is only ever an argument to "ip -6 route get", which is a
	// FIB lookup -- no packet is sent to it, so using a public literal here
	// reveals nothing. It keeps the existing Cloudflare choice rather than
	// bringing in another third party.
	DefaultProbe6 = "2606:4700:4700::1111"

	rollbackUnit = "gotun-client-rollback"
)

// EnableOptions configures Enable.
type EnableOptions struct {
	Gateway netip.Addr
	DNS     netip.Addr
	Probe   netip.Addr
	// Gateway6 is the gotun box's IPv6 address. Zero leaves the IPv6 half
	// unmanaged, which means IPv6 keeps egressing the ISP uplink -- the same
	// leak the gateway's -ipv6-fallback=direct describes, seen from the client.
	Gateway6 netip.Addr
	// DNS6 is written to ipv6.dns. Zero writes nothing: ipv6.ignore-auto-dns
	// already stops the ISP's IPv6 resolver competing, and the pinned IPv4
	// resolver answers AAAA queries perfectly well.
	DNS6 netip.Addr
	// Probe6 is an off-LAN IPv6 address used to assert the default route
	// moved. It is only ever an argument to "ip -6 route get", which is a FIB
	// lookup -- no packet is sent to it.
	Probe6 netip.Addr
	// ManageV6 is the -ipv6 flag. When false, gotun does not touch the IPv6
	// half at all.
	ManageV6 bool
	// StrictV6 turns IPv6 verification failures into errors that roll the
	// enable back, instead of warnings.
	StrictV6     bool
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
// The IPv6 half mirrors the IPv4 reasoning exactly, and stops short in the same
// place: ipv6.method is never written either. Flipping a profile from disabled,
// ignore or link-local to auto would turn IPv6 ON for someone who had switched
// it off, and "IPv6 on by default" has to mean "gotun manages the IPv6 you
// have", never "gotun gives you IPv6". ipv6.gateway is skipped for the same
// inertness reason as ipv4.gateway.
//
// With Gateway6 unset the argv is byte-for-byte what it was before IPv6
// support, which is what keeps an IPv4-only client unaffected.
func buildEnableArgs(o EnableOptions) []string {
	args := []string{
		"ipv4.never-default", "yes",
		// One argv element: "<dest> <nexthop>". Appended with + so any
		// pre-existing static route survives.
		"+ipv4.routes", "0.0.0.0/0 " + o.Gateway.String(),
		"ipv4.ignore-auto-dns", "yes",
		"ipv4.dns", o.DNS.String(),
		"ipv6.ignore-auto-dns", "yes",
	}
	if o.Gateway6.IsValid() {
		args = append(args,
			"ipv6.never-default", "yes",
			"+ipv6.routes", "::/0 "+o.Gateway6.String(),
		)
	}
	if o.DNS6.IsValid() {
		args = append(args, "ipv6.dns", o.DNS6.String())
	}
	return args
}

// buildRestoreArgs returns the argv that puts saved back. Properties that were
// unset are assigned the empty string, which resets them to their default.
// The IPv6 block is emitted only when the snapshot actually captured one. A
// nil IPv6 means the state file predates IPv6 support, or the profile had no
// ipv6.method to record -- either way there is nothing to put back, and
// assigning empty strings would clear static IPv6 routes gotun never touched.
func buildRestoreArgs(saved NMProps) []string {
	args := []string{
		"ipv4.never-default", nmBoolArg(saved.NeverDefault),
		"ipv4.routes", nmArg(saved.Routes),
		"ipv4.route-metric", nmArg(saved.RouteMetric),
		"ipv4.ignore-auto-dns", nmBoolArg(saved.IgnoreAutoDNS),
		"ipv4.dns", nmArg(saved.DNS),
		"ipv6.ignore-auto-dns", nmBoolArg(saved.IPv6IgnoreDNS),
	}
	if v6 := saved.IPv6; v6 != nil {
		args = append(args,
			"ipv6.never-default", nmBoolArg(v6.NeverDefault),
			"ipv6.routes", nmArg(v6.Routes),
			"ipv6.route-metric", nmArg(v6.RouteMetric),
			"ipv6.dns", nmArg(v6.DNS),
		)
	}
	return args
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
	if !o.Probe6.IsValid() {
		o.Probe6 = netip.MustParseAddr(DefaultProbe6)
	}
	if o.Gateway6.IsValid() && !o.Gateway6.Is6() {
		return fmt.Errorf("invalid -gateway6 %q: must be an IPv6 address", o.Gateway6)
	}
	if o.DNS6.IsValid() && !o.DNS6.Is6() {
		return fmt.Errorf("invalid -dns6 %q: must be an IPv6 address", o.DNS6)
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

	// Decide about the IPv6 half before anything is written.
	//
	// Every path that declines leaves IPv6 pointing at the ISP uplink, which
	// is a silent leak rather than a visible failure, so each one says so.
	var v6Notes []string
	if !o.ManageV6 {
		o.Gateway6, o.DNS6 = netip.Addr{}, netip.Addr{}
	} else if !cur.ManagesIPv6() {
		method := "unset"
		if cur.IPv6 != nil && cur.IPv6.Method != "" {
			method = cur.IPv6.Method
		}
		v6Notes = append(v6Notes, fmt.Sprintf(
			"ipv6.method=%s on %s, so there is no IPv6 to manage; leaving it alone", method, conn.ID))
		o.Gateway6, o.DNS6 = netip.Addr{}, netip.Addr{}
	} else if !o.Gateway6.IsValid() {
		gw6, err := DetectGateway6(r, conn.Device, o.Gateway)
		if err != nil {
			if o.StrictV6 {
				return fmt.Errorf("-ipv6-strict: %w", err)
			}
			v6Notes = append(v6Notes, fmt.Sprintf(
				"could not find the gateway's IPv6 address (%v); IPv6 traffic will egress"+
					" the ISP DIRECTLY and is not classified by gotun."+
					" Pass -gateway6, or -ipv6=false to stop trying", err))
		} else {
			o.Gateway6 = gw6
		}
	}
	if o.Gateway6.IsValid() && cur.IPv6 != nil && cur.IPv6.Routes != nil && !o.Force {
		// Unlike ipv4.routes this does not abort the enable. Plenty of hosts
		// carry a static IPv6 route legitimately, and refusing the whole
		// operation over the IPv6 half would hand the user no tunnel at all.
		v6Notes = append(v6Notes, fmt.Sprintf(
			"ipv6.routes is already set to %q; leaving IPv6 alone (use -force to take it over)", *cur.IPv6.Routes))
		o.Gateway6 = netip.Addr{}
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
		IPv6Managed:    o.Gateway6.IsValid(),
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
		if prev.Saved.IPv6 == nil && o.Gateway6.IsValid() {
			// The reused snapshot predates IPv6 support, so disable would have
			// nothing to put the IPv6 properties back to. Taking IPv6 over now
			// would leave it stuck pointing at a gateway that may be gone.
			if o.StrictV6 {
				return fmt.Errorf("-ipv6-strict: the reused snapshot predates IPv6 support;" +
					" run disable then enable to manage the IPv6 half")
			}
			fmt.Fprintf(w, "IPv6: the reused snapshot predates IPv6 support, so IPv6 stays DIRECT"+
				" for this apply. Run disable then enable to manage it.\n")
			o.Gateway6 = netip.Addr{}
			st.IPv6Managed = false
		}
	}

	if cur.Routes != nil && !o.Force {
		return fmt.Errorf("ipv4.routes on %q is already set (%s); re-run with -force once you have checked it can be restored",
			conn.ID, *cur.Routes)
	}

	// Reported only once the enable is actually going ahead. Printing these
	// alongside a refusal would leave the user reading an IPv6 warning about
	// an apply that never happened.
	for _, n := range v6Notes {
		fmt.Fprintf(w, "IPv6: %s\n", n)
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
	warnings, err := verifyEnabled(r, verifyTargets{
		Protected: protected,
		Gateway:   o.Gateway,
		Probe:     o.Probe,
		Gateway6:  o.Gateway6,
		Probe6:    o.Probe6,
		Strict6:   o.StrictV6,
	})
	if err != nil {
		return fail(err)
	}
	for _, warn := range warnings {
		fmt.Fprintf(w, "WARNING: %s\n", warn)
	}

	fmt.Fprintf(w, "enabled: %s (%s) default via %s, dns %s, mode %s\n", conn.ID, conn.Device, o.Gateway, o.DNS, o.Mode)
	if o.Gateway6.IsValid() {
		fmt.Fprintf(w, "IPv6: default via %s\n", o.Gateway6)
	} else if _, v6 := HostFamilies(r); v6 {
		fmt.Fprintf(w, "IPv6: NOT TUNNELED -- IPv6 traffic egresses the ISP directly."+
			" Clients prefer IPv6 when both families resolve, so this is most traffic.\n")
	}
	fmt.Fprintf(w, "protected LANs: %s\n", formatPrefixes(protected))
	if o.ConfirmTimeout > 0 {
		fmt.Fprintf(w, "\nARMED: settings revert automatically in %s\n", o.ConfirmTimeout)
		fmt.Fprintf(w, "  confirm: gotun-client confirm -state %s\n", o.StatePath)
		fmt.Fprintf(w, "  revert:  gotun-client disable -state %s\n", o.StatePath)
	}
	return nil
}

// verifyTargets is what verifyEnabled checks against. A struct rather than a
// growing positional list, now that both families are involved.
type verifyTargets struct {
	Protected []netip.Prefix
	Gateway   netip.Addr
	Probe     netip.Addr
	Gateway6  netip.Addr // zero skips the IPv6 assertions
	Probe6    netip.Addr
	Strict6   bool
}

// verifyEnabled is the post-apply gate: the default route must have moved, no
// protected LAN may hairpin through the gateway, and there must be exactly one
// default route.
//
// IPv4 failures are fatal and roll the enable back. IPv6 failures are warnings
// unless Strict6, and the asymmetry is deliberate: rolling back a working IPv4
// tunnel because NetworkManager would not move the IPv6 default would leave the
// user with no tunnel at all, where degrading the IPv6 half leaves them with
// the IPv4 one and a loud notice. The realistic cause is the kernel's own RA
// handling racing NM over the IPv6 default route, which is a host-level
// condition rather than something this apply did wrong.
func verifyEnabled(r linux.Runner, t verifyTargets) ([]string, error) {
	if err := AssertDefaultViaGateway(r, t.Probe, t.Gateway); err != nil {
		return nil, err
	}
	if err := AssertSingleDefaultRoute(r); err != nil {
		return nil, err
	}
	if err := AssertLANsOnLink(r, t.Protected, t.Gateway); err != nil {
		return nil, err
	}
	if !t.Gateway6.IsValid() {
		return nil, nil
	}

	var warns []string
	note := func(format string, a ...any) error {
		msg := fmt.Sprintf(format, a...)
		if t.Strict6 {
			return fmt.Errorf("-ipv6-strict: %s", msg)
		}
		warns = append(warns, msg)
		return nil
	}
	if err := AssertDefaultViaGateway(r, t.Probe6, t.Gateway6); err != nil {
		if err := note("the IPv6 default route did not move to %s (%v);"+
			" IPv6 traffic egresses the ISP DIRECTLY and is not classified by gotun."+
			" Re-run with -ipv6=false to stop managing it", t.Gateway6, err); err != nil {
			return nil, err
		}
	}
	if err := AssertSingleDefaultRoute6(r); err != nil && !errors.Is(err, ErrNoDefaultRoute6) {
		if err := note("IPv6 default routes: %v", err); err != nil {
			return nil, err
		}
	}
	return warns, nil
}

// settle waits for NM to finish reactivating the device and for a default route
// to exist again. Without it, verification races the reassociation.
func settle(r linux.Runner, dev string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		ok, err := deviceConnected(r, dev)
		if err == nil && ok {
			// Either family counts: a v6-only network is a supported shape,
			// and waiting for an IPv4 default there would always time out.
			if v4, v6 := HostFamilies(r); v4 || v6 {
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
