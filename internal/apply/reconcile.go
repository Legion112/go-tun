package apply

import (
	"errors"
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/linux/nftables"
	"github.com/legion/go-tun/internal/linux/routing"
	"github.com/legion/go-tun/internal/linux/sysctl"
	"github.com/legion/go-tun/internal/policy"
	"github.com/legion/go-tun/internal/wireguard"
)

// Result summarizes a reconcile.
type Result struct {
	Changes int
	State   policy.DesiredKernelState
	// Components breaks Changes down per subsystem, in the order they ran. A bare
	// total says an apply did not converge but not where, which is the hard part
	// to diagnose on a box you cannot easily instrument.
	Components []ComponentChanges
}

// ComponentChanges is one subsystem's contribution to a reconcile.
type ComponentChanges struct {
	Name    string
	Changes int
}

// Summary renders the non-zero components as "nftables=1 routing=2".
func (r Result) Summary() string {
	var parts []string
	for _, c := range r.Components {
		if c.Changes != 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", c.Name, c.Changes))
		}
	}
	return strings.Join(parts, " ")
}

// Reconcile applies Policy to the kernel via DesiredKernelState.
// Order: sysctl → nft → wireguard → ip rules/routes
// (WireGuard before routes so table 100 can reference wg-exit).
// On mid-way failure, returns error without rolling back prior subsystems.
func Reconcile(r linux.Runner, p policy.Policy) (Result, error) {
	st, err := policy.Compile(p)
	if err != nil {
		return Result{}, err
	}
	res := Result{State: st}
	step := func(name string, c int, err error) error {
		res.Changes += c
		res.Components = append(res.Components, ComponentChanges{Name: name, Changes: c})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}

	c, err := sysctl.Reconcile(r, st.Sysctls)
	if err := step("sysctl", c, err); err != nil {
		return res, err
	}
	c, err = nftables.Reconcile(r, st.Nft)
	if err := step("nftables", c, err); err != nil {
		return res, err
	}
	c, err = wireguard.Reconcile(r, st.WireGuard)
	if err := step("wireguard", c, err); err != nil {
		return res, err
	}
	c, err = wireguard.Reconcile(r, st.WireGuardClients)
	if err := step("wireguard-clients", c, err); err != nil {
		return res, err
	}
	c, err = routing.Reconcile(r, st.IPRules, st.Routes)
	if err := step("routing", c, err); err != nil {
		return res, err
	}

	return res, nil
}

// Clear removes gotun-owned kernel objects.
//
// Every subsystem is attempted even when an earlier one fails, but failures are
// reported rather than swallowed. This is the rollback path, so "exit 0" has to
// mean something: previously it was returned unconditionally and was no evidence
// at all that anything had been removed.
//
// The ip rule goes first. Nothing else matters until traffic has stopped being
// steered into table 100, and tearing the tunnel down ahead of the rule would
// black-hole marked traffic for the rest of the teardown under a fail-closed
// policy -- the opposite of what a rollback is for.
func Clear(r linux.Runner) error {
	return errors.Join(
		routing.Clear(r, policy.DefaultRulePriority, policy.DefaultTableID),
		nftables.Clear(r, policy.OwnedNftFamily, policy.OwnedNftTable),
		wireguard.Clear(r, policy.DefaultTunnelIface),
		wireguard.Clear(r, policy.DefaultClientsIface),
	)
}
