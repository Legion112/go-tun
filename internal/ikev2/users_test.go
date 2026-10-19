package ikev2_test

import (
	"io/fs"
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
	u, secret, err := s.Add(name)
	if err != nil {
		t.Fatalf("add %s: %v", name, err)
	}
	return u, secret
}

// The listing survives a round trip, which is all the state this tool keeps:
// who exists and when they were issued. Who is *connected* comes from the
// daemon instead, which is the whole reason no address needs pinning.
func TestStore_ListRoundTripsWhatAddWrote(t *testing.T) {
	s := testStore(t)
	mustAdd(t, s, "alice")
	mustAdd(t, s, "bob")

	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alice" || got[1].Name != "bob" {
		t.Fatalf("list: %+v", got)
	}
	for _, u := range got {
		if u.Created.IsZero() {
			t.Errorf("%s lost its creation time", u.Name)
		}
	}
}

// Revoking deletes the credential outright. Nothing is held back, because
// nothing per-user remains to hold: the address a person gets comes from the
// shared pool, and the identity-to-address pair charon records at connect time
// is what attributes an old log entry.
func TestStore_RemoveDeletesTheCredentialAndAllowsReissue(t *testing.T) {
	s := testStore(t)
	_, first := mustAdd(t, s, "alice")

	if _, err := s.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.List(); len(got) != 0 {
		t.Errorf("alice is still listed: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "gotun-user-alice.conf")); !os.IsNotExist(err) {
		t.Errorf("the credential file survived revocation: %v", err)
	}
	if _, err := s.Remove("alice"); err == nil {
		t.Error("revoking twice should report that there is no such user")
	}

	// Reissuing is allowed and must mint a new secret, or a revoked password
	// would come back with the name.
	_, second := mustAdd(t, s, "alice")
	if first == second {
		t.Error("reissuing handed back the revoked password")
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
	if _, _, err := s.Add("alice"); err == nil {
		t.Fatal("want a refusal")
	} else if !strings.Contains(err.Error(), "already exists") {
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

// The per-user file is a credential and nothing else. A whole connection per
// user would be needed only to pin a per-user address, and it duplicated the
// 52-entry selector list per person for an answer charon already gives.
func TestRenderUser_IsOnlyACredential(t *testing.T) {
	s := testStore(t)
	_, secret := mustAdd(t, s, "alice")
	b, err := os.ReadFile(filepath.Join(s.Dir, "gotun-user-alice.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	for _, want := range []string{"secrets {", "eap-alice {", "id = alice",
		`secret = "` + secret + `"`} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet is missing %q:\n%s", want, got)
		}
	}
	// Anything beyond the secret is shared configuration that must not be
	// duplicated per person: two copies drift, and a selector list that drifted
	// would tunnel different things for different people.
	for _, unwanted := range []string{"connections {", "pools {", "local_ts", "if_id_in"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("snippet contains %q, which belongs to the shared configuration", unwanted)
		}
	}
}

// Selectors live in exactly one place now, so the shared configuration is the
// only thing that can decide what is tunnelled. This is the test that would
// catch somebody putting a connection back into a per-user file.
func TestRenderSwanctl_IsTheOnlyPlaceSelectorsAppear(t *testing.T) {
	c := testConfig()
	shared, err := ikev2.RenderSwanctl(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shared, "local_ts = ") {
		t.Fatal("the shared configuration has no selectors")
	}
	// And it carries no credential, so it can live in a repository.
	for _, line := range strings.Split(shared, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "secret =") {
			t.Errorf("the shared configuration contains a live secret: %q", line)
		}
	}
	// eap_id = %any is what lets users be issued and withdrawn without
	// touching this file at all.
	if !strings.Contains(shared, "eap_id = %any") {
		t.Error("the shared connection must accept whichever identity has a secret")
	}
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
		if strings.Contains(u.Name, secret) {
			t.Fatal("the secret leaked into the listing")
		}
	}
}
