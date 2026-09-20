package sysctl_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/linux/sysctl"
	"github.com/legion/go-tun/internal/policy"
)

// fakeRunner answers from a handler, so a test can make the same command behave
// differently across calls -- which linux.RecordingRunner's static output map
// cannot express.
type fakeRunner struct {
	handle func(call string) (string, error)
	calls  []string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	return f.handle(call)
}

func (f *fakeRunner) RunWithInput(name, stdin string, args ...string) (string, error) {
	return f.Run(name, args...)
}

func forwardSpec() []policy.SysctlSpec {
	return []policy.SysctlSpec{{Key: "net.ipv4.ip_forward", Value: "1"}}
}

var errNoSuchCommand = errors.New("not found")

// The router has no bash. Naming it anywhere means the read probe never succeeds,
// so convergence is unreachable and every apply reports changes -- and a failed
// write then aborts the apply before nft, wireguard and routing run.
func TestReconcile_NeverInvokesBash(t *testing.T) {
	r := &fakeRunner{handle: func(string) (string, error) { return "1", nil }}
	if _, err := sysctl.Reconcile(r, forwardSpec()); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "bash") {
			t.Fatalf("no target is guaranteed to have bash: %q", c)
		}
	}
	if len(r.calls) == 0 {
		t.Fatal("expected at least a read probe")
	}
}

func TestReconcile_AlreadyCorrectReportsNoChanges(t *testing.T) {
	r := &fakeRunner{handle: func(call string) (string, error) {
		if call == "sh -c cat /proc/sys/net/ipv4/ip_forward" {
			return "1\n", nil
		}
		return "", errNoSuchCommand
	}}
	n, err := sysctl.Reconcile(r, forwardSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a converged key must report 0 changes, got %d: %v", n, r.calls)
	}
}

// Busybox is enough: with no shell at all, sysctl(8) alone must get there.
func TestReconcile_WorksWithSysctlOnly(t *testing.T) {
	r := &fakeRunner{handle: func(call string) (string, error) {
		switch {
		case strings.HasPrefix(call, "sh "):
			return "", errNoSuchCommand
		case call == "sysctl -n net.ipv4.ip_forward":
			return "1\n", nil
		}
		return "", errNoSuchCommand
	}}
	n, err := sysctl.Reconcile(r, forwardSpec())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a converged key must report 0 changes even without a shell, got %d: %v", n, r.calls)
	}
}

func TestReconcile_WritesThroughSysctlWhenNoShell(t *testing.T) {
	r := &fakeRunner{handle: func(call string) (string, error) {
		switch {
		case strings.HasPrefix(call, "sh "):
			return "", errNoSuchCommand
		case call == "sysctl -n net.ipv4.conf.all.send_redirects":
			return "1\n", nil // not the desired value, so it must be written
		case call == "sysctl -w net.ipv4.conf.all.send_redirects=0":
			return "net.ipv4.conf.all.send_redirects = 0", nil
		}
		return "", errNoSuchCommand
	}}
	n, err := sysctl.Reconcile(r, []policy.SysctlSpec{
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 change, got %d: %v", n, r.calls)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "sysctl -w net.ipv4.conf.all.send_redirects=0") {
		t.Fatalf("expected the sysctl write: %v", r.calls)
	}
}

// A write can report failure after having taken effect. Only a readback settles
// it, and getting this wrong aborts the apply before the subsystems that matter.
func TestReconcile_WriteThatTookEffectIsNotFatal(t *testing.T) {
	reads := 0
	r := &fakeRunner{handle: func(call string) (string, error) {
		switch {
		case strings.HasPrefix(call, "sh -c cat "):
			reads++
			if reads == 1 {
				return "1\n", nil // wrong value, so a write is attempted
			}
			return "0\n", nil // the write landed despite reporting failure
		case strings.HasPrefix(call, "sh -c echo "), strings.HasPrefix(call, "sysctl -w"):
			return "", errNoSuchCommand
		}
		return "", errNoSuchCommand
	}}
	n, err := sysctl.Reconcile(r, []policy.SysctlSpec{
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
	})
	if err != nil {
		t.Fatalf("a write that actually landed must not fail the apply: %v", err)
	}
	if n != 1 {
		t.Fatalf("the key did change, so it should be counted; got %d", n)
	}
}

func TestReconcile_GenuineWriteFailureNamesTheKey(t *testing.T) {
	r := &fakeRunner{handle: func(call string) (string, error) {
		if strings.HasPrefix(call, "sh -c cat ") {
			return "1\n", nil // never reaches the desired value
		}
		return "", fmt.Errorf("permission denied")
	}}
	_, err := sysctl.Reconcile(r, []policy.SysctlSpec{
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
	})
	if err == nil {
		t.Fatal("a write that did not take effect must surface")
	}
	if !strings.Contains(err.Error(), "net.ipv4.conf.all.send_redirects") {
		t.Fatalf("the error should name the key, got %v", err)
	}
}

// The proc path is derived from the key, and a wrong derivation writes to a file
// that does not exist while looking like a normal failure.
func TestReconcile_ReadsTheProcPathForTheKey(t *testing.T) {
	var saw string
	r := &fakeRunner{handle: func(call string) (string, error) {
		if strings.HasPrefix(call, "sh -c cat ") {
			saw = strings.TrimPrefix(call, "sh -c cat ")
			return "0\n", nil
		}
		return "", errNoSuchCommand
	}}
	if _, err := sysctl.Reconcile(r, []policy.SysctlSpec{
		{Key: "net.ipv4.conf.br-lan.send_redirects", Value: "0"},
	}); err != nil {
		t.Fatal(err)
	}
	if saw != "/proc/sys/net/ipv4/conf/br-lan/send_redirects" {
		t.Fatalf("wrong proc path: %q", saw)
	}
}
