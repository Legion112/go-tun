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

// rawSAs is real `swanctl --list-sas --raw` output, captured from the lab.
// Invented fixtures are the usual way a parser passes its tests and fails on a
// daemon: note that the child-sas block repeats uniqueid, and that local-id
// sits on the same line as remote-id.
const rawSAs = `list-sa event {users {uniqueid=2 version=2 state=ESTABLISHED local-host=10.60.0.2 local-port=4500 local-id=vpn.lab remote-host=10.60.0.11 remote-port=4500 remote-id=bob initiator-spi=96e4433f53753ea4 responder-spi=fe6a07367e47c0b9 nat-remote=yes nat-any=yes encr-alg=AES_CBC encr-keysize=128 established=9 rekey-time=14057 remote-vips=[10.70.0.18] child-sas {users-2 {name=users uniqueid=2 reqid=2 state=INSTALLED mode=TUNNEL protocol=ESP}}}}
list-sa event {users {uniqueid=1 version=2 state=ESTABLISHED local-host=10.60.0.2 local-port=4500 local-id=vpn.lab remote-host=10.60.0.10 remote-port=4500 remote-id=alice initiator-spi=e7a4eb7dfa91c0b3 responder-spi=165838dac924eba4 nat-remote=yes nat-any=yes established=11 rekey-time=14049 remote-vips=[10.70.0.17] child-sas {users-1 {name=users uniqueid=1 reqid=1 state=INSTALLED}}}}`

// Identity is what the daemon already knows, and it is why neither a per-user
// connection nor a pinned address is needed to tell people apart.
func TestParseSAs_ReadsIdentityAddressAndID(t *testing.T) {
	got := parseSAs(rawSAs)
	if len(got) != 2 {
		t.Fatalf("want 2 SAs, got %d: %+v", len(got), got)
	}
	byName := map[string]liveSA{}
	for _, sa := range got {
		byName[sa.Identity] = sa
	}
	for name, want := range map[string]liveSA{
		"alice": {UniqueID: "1", Identity: "alice", Host: "10.60.0.10", VIPs: []string{"10.70.0.17"}},
		"bob":   {UniqueID: "2", Identity: "bob", Host: "10.60.0.11", VIPs: []string{"10.70.0.18"}},
	} {
		sa := byName[name]
		if sa.UniqueID != want.UniqueID || sa.Host != want.Host ||
			strings.Join(sa.VIPs, ",") != strings.Join(want.VIPs, ",") {
			t.Errorf("%s: got %+v want %+v", name, sa, want)
		}
	}
}

// The gateway's own identity must never be mistaken for a user's: terminating
// by it would be a no-op at best and the wrong session at worst.
func TestParseSAs_IgnoresTheLocalIdentity(t *testing.T) {
	for _, sa := range parseSAs(rawSAs) {
		if sa.Identity == "vpn.lab" {
			t.Fatalf("the gateway's own id was read as a user: %+v", sa)
		}
	}
}

func TestParseSAs_EmptyWhenNobodyIsConnected(t *testing.T) {
	if got := parseSAs(""); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// Revocation is two steps, and the second is the one that is easy to forget.
// Reloading stops the credential being accepted for new sessions; it does
// nothing to an established one, because the generated connection does not
// reauthenticate and so rekeys without consulting the secret.
func TestApplyRevoke_ReloadsThenTerminatesThatPersonsSession(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--list-sas" {
			return rawSAs, nil
		}
		return "", nil
	}}
	if err := ApplyRevoke(r, "alice"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 3 {
		t.Fatalf("want reload, list and terminate, got %v", r.calls)
	}
	if r.calls[0] != "swanctl --load-all" {
		t.Errorf("first command should reload, got %q", r.calls[0])
	}
	// alice is uniqueid 1; terminating 2 would cut off bob.
	if r.calls[2] != "swanctl --terminate --ike-id 1" {
		t.Errorf("should terminate only alice's session, got %q", r.calls[2])
	}
}

// One credential can be in use from two devices at once -- charon's default
// uniqueness policy allows it -- so leaving the second session up would be a
// revocation that half happened.
func TestApplyRevoke_TerminatesEverySessionOfThatIdentity(t *testing.T) {
	twoDevices := strings.ReplaceAll(rawSAs, "remote-id=bob", "remote-id=alice")
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--list-sas" {
			return twoDevices, nil
		}
		return "", nil
	}}
	if err := ApplyRevoke(r, "alice"); err != nil {
		t.Fatal(err)
	}
	var terminated []string
	for _, c := range r.calls {
		if strings.Contains(c, "--terminate") {
			terminated = append(terminated, c)
		}
	}
	if len(terminated) != 2 {
		t.Fatalf("want both of alice's sessions terminated, got %v", terminated)
	}
}

// A user who is not connected has no SA. Treating that as a failure would make
// every revocation of an offline user look broken.
func TestApplyRevoke_NoLiveSessionIsSuccess(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--list-sas" {
			return "", nil
		}
		return "", nil
	}}
	if err := ApplyRevoke(r, "alice"); err != nil {
		t.Fatalf("an offline user is still revoked: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "--terminate") {
			t.Errorf("nothing to terminate, but ran %q", c)
		}
	}
}

// If the session cannot be torn down, the credential is gone but the tunnel is
// not. Reporting success there is the exact failure this path exists to
// prevent, so it has to be an error that says what is still true.
func TestApplyRevoke_FailsLoudlyWhenTheSessionSurvives(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		switch args[0] {
		case "--list-sas":
			return rawSAs, nil
		case "--terminate":
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

// Likewise if the sessions cannot even be listed: the credential is revoked and
// whatever is up stays up, which the operator has to be told.
func TestApplyRevoke_FailsWhenSessionsCannotBeListed(t *testing.T) {
	r := &fakeRunner{reply: func(_ string, args ...string) (string, error) {
		if args[0] == "--list-sas" {
			return "", errors.New("exit status 1")
		}
		return "", nil
	}}
	if err := ApplyRevoke(r, "alice"); err == nil {
		t.Fatal("want an error")
	} else if !strings.Contains(err.Error(), "survive") {
		t.Errorf("got: %v", err)
	}
}

// A failed reload means the credential is still accepted, so nothing else must
// be attempted -- tearing the session down there would look like a successful
// revocation while the user simply reconnects.
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
	if len(r.calls) != 1 {
		t.Errorf("nothing should follow a failed reload, got %v", r.calls)
	}
}
