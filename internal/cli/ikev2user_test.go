package cli

import (
	"errors"
	"strings"
	"testing"
)

// fakeRunner records what was run and replies from a script.
type fakeRunner struct {
	calls []string
	reply func(name string, args ...string) (string, error)
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))
	if f.reply != nil {
		return f.reply(name, args...)
	}
	return "", nil
}

func (f *fakeRunner) RunWithInput(name, _ string, args ...string) (string, error) {
	return f.Run(name, args...)
}

// Revocation is two steps, and the second is the one that is easy to forget.
// Reloading stops the credential being accepted for new sessions; it does
// nothing to an established one, because the generated connection does not
// reauthenticate and so rekeys without consulting the secret.
func TestApplyRevoke_ReloadsAndThenTerminatesTheLiveSession(t *testing.T) {
	r := &fakeRunner{}
	if err := ApplyRevoke(r, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("want two commands, got %v", r.calls)
	}
	if r.calls[0] != "swanctl --load-all" {
		t.Errorf("first command should reload, got %q", r.calls[0])
	}
	if r.calls[1] != "swanctl --terminate --ike alice" {
		t.Errorf("second command should tear the session down, got %q", r.calls[1])
	}
}

// A user who is not connected has no SA, and charon says so with an error.
// Treating that as a failure would make every revocation of an offline user
// look broken.
func TestApplyRevoke_NoLiveSessionIsSuccess(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--terminate" {
			return "no matching SAs to terminate found", errors.New("exit status 1")
		}
		return "", nil
	}}
	if err := ApplyRevoke(r, "alice"); err != nil {
		t.Fatalf("an offline user is still revoked: %v", err)
	}
}

// If the session cannot be torn down, the credential is gone but the tunnel is
// not. Reporting success there is the exact failure this whole path exists to
// prevent, so it has to be an error that says what is still true.
func TestApplyRevoke_FailsLoudlyWhenTheSessionSurvives(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--terminate" {
			return "daemon unreachable", errors.New("exit status 2")
		}
		return "", nil
	}}
	err := ApplyRevoke(r, "alice")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "survive") {
		t.Errorf("the error should say the session survives, got: %v", err)
	}
}

// A failed reload means the credential is still accepted, so the terminate must
// not even be attempted -- tearing the session down there would look like a
// successful revocation while the user simply reconnects.
func TestApplyRevoke_StopsIfTheReloadFailed(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--load-all" {
			return "unable to connect to daemon", errors.New("exit status 1")
		}
		return "", nil
	}}
	err := ApplyRevoke(r, "alice")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "can still connect") {
		t.Errorf("the error should say the credential is still live, got: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "--terminate") {
			t.Error("must not terminate after a failed reload")
		}
	}
}
