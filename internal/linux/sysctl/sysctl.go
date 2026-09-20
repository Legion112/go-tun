package sysctl

import (
	"fmt"
	"strings"

	"github.com/legion/go-tun/internal/linux"
	"github.com/legion/go-tun/internal/policy"
)

// Reconcile applies desired sysctls. Returns the number of keys changed.
//
// Everything goes through the Runner rather than direct file I/O so that a dry
// run can intercept it -- but nothing here may assume bash, which a router does
// not have. With bash the read probe failed on every key, so convergence was
// unreachable and every apply reported changes; worse, when a write also failed
// the confirming read was another bash call, so it failed too and the error
// aborted the whole apply before nft, wireguard and routing had run at all.
//
// /bin/sh and sysctl(8) are both present on every target, verified on the
// gateway itself.
func Reconcile(r linux.Runner, specs []policy.SysctlSpec) (int, error) {
	changes := 0
	for _, s := range specs {
		if cur, ok := readKey(r, s.Key); ok && cur == s.Value {
			continue
		}
		if err := writeKey(r, s.Key, s.Value); err != nil {
			// A write can report failure after taking effect, so only a readback
			// settles it.
			if cur, ok := readKey(r, s.Key); ok && cur == s.Value {
				changes++
				continue
			}
			return changes, fmt.Errorf("%s: %w", s.Key, err)
		}
		changes++
	}
	return changes, nil
}

func procPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

// readKey prefers the proc file, which is authoritative and needs no key parsing,
// and falls back to sysctl(8) for a kernel without procfs mounted there.
func readKey(r linux.Runner, key string) (string, bool) {
	if out, err := r.Run("sh", "-c", "cat "+procPath(key)); err == nil {
		return strings.TrimSpace(out), true
	}
	if out, err := r.Run("sysctl", "-n", key); err == nil {
		return strings.TrimSpace(out), true
	}
	return "", false
}

func writeKey(r linux.Runner, key, value string) error {
	if _, err := r.Run("sh", "-c", fmt.Sprintf("echo %s > %s", value, procPath(key))); err == nil {
		return nil
	}
	_, err := r.Run("sysctl", "-w", key+"="+value)
	return err
}
