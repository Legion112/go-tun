package ikev2_test

import (
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/legion/go-tun/internal/ikev2"
)

func testStore(t *testing.T) ikev2.Store {
	t.Helper()
	return ikev2.Store{Dir: filepath.Join(t.TempDir(), "conf.d")}
}

func mustAdd(t *testing.T, s ikev2.Store, name string) (ikev2.User, string) {
	t.Helper()
	u, secret, err := s.Add(testConfig(), name)
	if err != nil {
		t.Fatalf("add %s: %v", name, err)
	}
	return u, secret
}

// Addresses are assigned lowest-free and then belong to that user. Predictable
// from the files alone is the point: an operator reading a firewall log has to
// be able to say who it was without a database.
func TestStore_AssignsTheLowestFreeAddressAndKeepsIt(t *testing.T) {
	s := testStore(t)
	alice, _ := mustAdd(t, s, "alice")
	bob, _ := mustAdd(t, s, "bob")

	// Pool is 10.231.17.16/28: .16 is the network and .31 the broadcast, so the
	// first usable is .17.
	if alice.VIP.String() != "10.231.17.17" {
		t.Errorf("alice got %v, want 10.231.17.17", alice.VIP)
	}
	if bob.VIP.String() != "10.231.17.18" {
		t.Errorf("bob got %v, want 10.231.17.18", bob.VIP)
	}

	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alice" || got[1].Name != "bob" {
		t.Fatalf("list: %+v", got)
	}
	if got[0].VIP != alice.VIP || got[1].VIP != bob.VIP {
		t.Errorf("list lost the addresses: %+v", got)
	}
	if got[0].Created.IsZero() {
		t.Error("list lost the creation time")
	}
}

// The network and broadcast addresses are skipped because charon would hand
// them out and some clients refuse to use them -- a user who simply never
// works, with nothing to point at.
func TestStore_SkipsTheNetworkAndBroadcastAddresses(t *testing.T) {
	s := testStore(t)
	c := testConfig()
	c.Pool = netip.MustParsePrefix("10.231.17.16/30") // .16 net, .17, .18, .19 bcast
	for _, name := range []string{"a", "b"} {
		if _, _, err := s.Add(c, name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}
	users, _ := s.List()
	for _, u := range users {
		if u.VIP.String() == "10.231.17.16" || u.VIP.String() == "10.231.17.19" {
			t.Errorf("%s got the network or broadcast address %v", u.Name, u.VIP)
		}
	}
	if _, _, err := s.Add(c, "c"); err == nil {
		t.Error("want pool exhaustion with only two usable addresses")
	} else if !strings.Contains(err.Error(), "full") {
		t.Errorf("exhaustion error should say so, got: %v", err)
	}
}

// Revoking holds the address back rather than freeing it. Handing it to the
// next person would make every log entry from before the revocation attribute
// the old user's traffic to the new one -- the one thing a fixed address was
// for.
func TestStore_RevokedAddressIsNotHandedToSomeoneElse(t *testing.T) {
	s := testStore(t)
	alice, _ := mustAdd(t, s, "alice")

	if _, err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(); len(got) != 0 {
		t.Errorf("alice is still active: %+v", got)
	}
	tombs, err := s.ListRevoked()
	if err != nil {
		t.Fatal(err)
	}
	if len(tombs) != 1 || tombs[0].VIP != alice.VIP || tombs[0].Revoked.IsZero() {
		t.Fatalf("want one tombstone holding %v, got %+v", alice.VIP, tombs)
	}

	carol, _ := mustAdd(t, s, "carol")
	if carol.VIP == alice.VIP {
		t.Errorf("carol was handed alice's revoked address %v", carol.VIP)
	}

	// The name is held back too, so a reissue cannot quietly inherit the
	// history.
	if _, _, err := s.Add(testConfig(), "alice"); err == nil {
		t.Error("want a refusal when reissuing a revoked name")
	} else if !strings.Contains(err.Error(), "purge") {
		t.Errorf("the refusal should say how to release it, got: %v", err)
	}

	// Purge is the deliberate step that makes the address reusable.
	if _, err := s.Purge("alice"); err != nil {
		t.Fatal(err)
	}
	again, _ := mustAdd(t, s, "alice")
	if again.VIP != alice.VIP {
		t.Errorf("after purge the address should be free again, got %v want %v", again.VIP, alice.VIP)
	}
}

// The tombstone must not be a credential, and must not be loadable by charon.
func TestStore_TombstoneCarriesNoCredentialAndNoConfig(t *testing.T) {
	s := testStore(t)
	_, secret := mustAdd(t, s, "alice")
	if _, err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") {
			t.Errorf("a .conf survived revocation and charon would still load it: %s", e.Name())
		}
		if !strings.HasSuffix(e.Name(), ".revoked") {
			continue
		}
		found = true
		b, err := os.ReadFile(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		body := string(b)
		if strings.Contains(body, secret) {
			t.Error("the tombstone contains the revoked secret")
		}
		for _, bad := range []string{"secrets {", "connections {", "pools {"} {
			if strings.Contains(body, bad) {
				t.Errorf("the tombstone contains %q, which charon could act on", bad)
			}
		}
	}
	if !found {
		t.Error("no tombstone was written")
	}
}

// The file is the credential, so its mode is part of the contract.
func TestStore_UserFileIsNotReadableByOthers(t *testing.T) {
	s := testStore(t)
	mustAdd(t, s, "alice")
	info, err := os.Stat(filepath.Join(s.Dir, "gotun-user-alice.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != fs.FileMode(0o600) {
		t.Errorf("mode is %04o, want 0600", perm)
	}
}

// Reissuing in place would leave the old secret working until the next reload,
// which is a revocation that silently did not happen.
func TestStore_RefusesToOverwriteAnExistingUser(t *testing.T) {
	s := testStore(t)
	mustAdd(t, s, "alice")
	if _, _, err := s.Add(testConfig(), "alice"); err == nil {
		t.Fatal("want a refusal")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("got: %v", err)
	}
}

// A pool that moved under existing users leaves them holding addresses the
// gateway no longer routes, and the symptom is one person's tunnel failing for
// no visible reason.
func TestStore_RefusesWhenThePoolMovedUnderExistingUsers(t *testing.T) {
	s := testStore(t)
	mustAdd(t, s, "alice")

	c := testConfig()
	c.VIPSubnet = netip.MustParsePrefix("10.231.18.0/24")
	c.VIPGateway = netip.MustParseAddr("10.231.18.1")
	c.Pool = netip.MustParsePrefix("10.231.18.16/28")
	if _, _, err := s.Add(c, "bob"); err == nil {
		t.Fatal("want a refusal")
	} else if !strings.Contains(err.Error(), "outside the pool") {
		t.Errorf("got: %v", err)
	}
}

// A file without the headers is not ours. Guessing would be worse than
// failing: inventing an address for it hands a second user one already in use.
func TestStore_RefusesToGuessAtAForeignFile(t *testing.T) {
	s := testStore(t)
	mustAdd(t, s, "alice")
	if err := os.WriteFile(filepath.Join(s.Dir, "gotun-user-mystery.conf"),
		[]byte("connections {\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("want an error for a file with no gotun headers")
	}
}

func TestValidateUserName(t *testing.T) {
	for _, ok := range []string{"alice", "bob2", "a", "my-phone", "my.phone", "a_b"} {
		if err := ikev2.ValidateUserName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	// Each of these is either an invalid IKE identity or an unsafe path
	// component, and one of them is a directory traversal.
	for _, bad := range []string{"", "Alice", "../etc/passwd", "a/b", "a b", "-lead", ".lead",
		strings.Repeat("a", 32)} {
		if err := ikev2.ValidateUserName(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// The secret has to survive being read off a screen and typed into a phone, so
// the alphabet omits the characters people get wrong, and it has to be worth
// generating rather than guessing.
func TestGenerateSecret(t *testing.T) {
	const want = 4*5 + 3 // four groups of five, hyphenated
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		s, err := ikev2.GenerateSecret()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != want {
			t.Fatalf("length %d, want %d: %q", len(s), want, s)
		}
		if seen[s] {
			t.Fatalf("generated %q twice in 200 draws", s)
		}
		seen[s] = true
		for _, r := range strings.ReplaceAll(s, "-", "") {
			if !strings.ContainsRune("ABCDEFGHJKMNPQRSTUVWXYZ23456789", r) {
				t.Fatalf("%q contains %q, which is outside the typeable alphabet", s, r)
			}
		}
		for _, lookalike := range []string{"I", "L", "O", "0", "1"} {
			if strings.Contains(s, lookalike) {
				t.Fatalf("%q contains the misread-prone %q", s, lookalike)
			}
		}
	}
}

// Per-user snippets pin three things, and all three are load-bearing: the
// single-address pool fixes the address, the connection-level identity is what
// makes that pool reachable only by them, and the connection name is what
// `swanctl --terminate --ike <name>` and `--list-sas` attribution rely on.
func TestRenderUser_PinsAddressIdentityAndName(t *testing.T) {
	s := testStore(t)
	u, secret := mustAdd(t, s, "alice")
	b, err := os.ReadFile(filepath.Join(s.Dir, "gotun-user-alice.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	for _, want := range []string{
		"connections {\n  alice {",          // the SA is named after the user
		"pools = pool-alice",                // ...using their own pool
		"addrs = " + u.VIP.String() + "/32", // ...of exactly one address
		"id = alice",                        // and only they may use it
		"secret = \"" + secret + "\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "id = %any") {
		t.Error("a per-user connection must not accept any identity")
	}
}

// Both gateway shapes have to agree about what is tunnelled. They are rendered
// by the same function for that reason; this is the test that would catch
// someone splitting them again.
func TestRenderUser_AgreesWithTheSharedShapeOnSelectors(t *testing.T) {
	c := testConfig()
	shared, err := ikev2.RenderSwanctl(c)
	if err != nil {
		t.Fatal(err)
	}
	perUser, err := ikev2.RenderUser(c, ikev2.User{
		Name: "alice", VIP: netip.MustParseAddr("10.231.17.17"),
	}, "SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if a, b := localTS(t, shared), localTS(t, perUser); a != b {
		t.Errorf("the two shapes tunnel different things\n shared: %s\nper-user: %s", a, b)
	}
}

func localTS(t *testing.T, conf string) string {
	t.Helper()
	for _, line := range strings.Split(conf, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "local_ts = ") {
			return strings.TrimPrefix(s, "local_ts = ")
		}
	}
	t.Fatalf("no local_ts in:\n%s", conf)
	return ""
}

// Nothing the user receives may carry the password: the profile is AirDropped
// to a phone and then sits in Downloads.
func TestStore_SecretNeverReachesTheProfile(t *testing.T) {
	s := testStore(t)
	_, secret := mustAdd(t, s, "alice")

	c := testConfig()
	c.ClientID = "alice"
	profile, err := ikev2.EncodeProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile), secret) {
		t.Fatal("the profile contains the password")
	}
	// Nor is it recoverable from the store afterwards.
	users, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if strings.Contains(u.Name, secret) || strings.Contains(u.VIP.String(), secret) {
			t.Fatal("the secret leaked into the listing")
		}
	}
}
