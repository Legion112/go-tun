package ikev2

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Store is a directory of per-user swanctl snippets, one file each.
//
// One file per user rather than one file with N stanzas, because revocation is
// then a delete rather than an edit: nothing has to parse and rewrite a
// configuration that currently authenticates people. swanctl's own
// `include conf.d/*.conf` does the assembly.
//
// Each file carries a whole connection, not just a secret. That is what buys a
// fixed virtual IP: strongSwan's pools are per-connection and not
// identity-aware, so one shared connection with several pools hands out
// whichever address is free rather than the user's own. A connection per user
// with a single-address pool pins it -- and names the SA after the user, so
// `swanctl --list-sas` attributes traffic for free.
type Store struct{ Dir string }

// User is one named credential. The secret is deliberately absent: it exists
// in the gateway's own file and in whatever the person typed into their phone,
// and nowhere else.
type User struct {
	Name    string
	VIP     netip.Addr
	Created time.Time
	// Revoked is set on a tombstone. It exists so an address is not handed to
	// somebody else: reusing a revoked user's address would make every log
	// entry from before the revocation attribute their traffic to whoever came
	// next, which is the one thing a fixed address was for.
	Revoked time.Time
}

const (
	userFilePrefix = "gotun-user-"
	userFileSuffix = ".conf"
	// revokedSuffix deliberately does not match swanctl's include glob, so a
	// tombstone is invisible to charon.
	revokedSuffix = ".revoked"

	// Header keys, so List can report what Add decided without re-deriving it.
	hdrName    = "# gotun-user: "
	hdrVIP     = "# gotun-vip: "
	hdrCreated = "# gotun-created: "
	hdrRevoked = "# gotun-revoked: "
)

// userNamePattern is both an IKE identity and part of a filename, which is why
// it is this narrow. It also has to survive being typed into an iPhone's
// username field.
var userNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,30}$`)

// ValidateUserName rejects a name that cannot safely be both an identity and a
// path component.
func ValidateUserName(name string) error {
	if !userNamePattern.MatchString(name) {
		return fmt.Errorf("ikev2: user name %q must be 1-31 characters of a-z, 0-9, dot,"+
			" underscore or hyphen, starting with a letter or digit", name)
	}
	return nil
}

func (s Store) path(name string) string {
	return filepath.Join(s.Dir, userFilePrefix+name+userFileSuffix)
}

func (s Store) tombstonePath(name string) string {
	return filepath.Join(s.Dir, userFilePrefix+name+revokedSuffix)
}

// List returns the users in the directory, ordered by name.
func (s Store) List() ([]User, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return collect(s.Dir, entries, userFileSuffix)
}

// ListRevoked returns the tombstones: users who are gone but whose addresses
// are still held back.
func (s Store) ListRevoked() ([]User, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return collect(s.Dir, entries, revokedSuffix)
}

func collect(dir string, entries []os.DirEntry, suffix string) ([]User, error) {
	var out []User
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, userFilePrefix) || !strings.HasSuffix(n, suffix) {
			continue
		}
		u, err := readUserHeader(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func readUserHeader(path string) (User, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return User{}, err
	}
	var u User
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, hdrName):
			u.Name = strings.TrimSpace(strings.TrimPrefix(line, hdrName))
		case strings.HasPrefix(line, hdrVIP):
			u.VIP, _ = netip.ParseAddr(strings.TrimSpace(strings.TrimPrefix(line, hdrVIP)))
		case strings.HasPrefix(line, hdrCreated):
			u.Created, _ = time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(line, hdrCreated)))
		case strings.HasPrefix(line, hdrRevoked):
			u.Revoked, _ = time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(line, hdrRevoked)))
		}
	}
	if u.Name == "" || !u.VIP.IsValid() {
		return User{}, fmt.Errorf("ikev2: %s is not a gotun user file (no name or VIP header);"+
			" refusing to guess, because getting this wrong would hand a second user"+
			" an address already in use", path)
	}
	return u, nil
}

// Add creates a user: a fixed virtual IP, a generated secret, and the gateway
// snippet that authenticates them. It returns the secret exactly once -- it is
// never stored anywhere but the gateway file.
func (s Store) Add(c Config, name string) (User, string, error) {
	if err := ValidateUserName(name); err != nil {
		return User{}, "", err
	}
	if err := c.Validate(); err != nil {
		return User{}, "", err
	}
	c.withDefaults()

	existing, err := s.List()
	if err != nil {
		return User{}, "", err
	}
	revoked, err := s.ListRevoked()
	if err != nil {
		return User{}, "", err
	}
	for _, u := range existing {
		if u.Name == name {
			return User{}, "", fmt.Errorf("ikev2: user %q already exists (%s); revoke it first"+
				" -- reissuing in place would leave the old secret working until the next reload",
				name, s.path(name))
		}
		// A pool that moved under existing users is the one way this quietly
		// breaks: their files keep addresses the gateway no longer routes, and
		// the symptom is one person's tunnel failing for no visible reason.
		if !c.Pool.Contains(u.VIP) {
			return User{}, "", fmt.Errorf("ikev2: existing user %q holds %v, which is outside"+
				" the pool %v being used now; the pool cannot move while users exist",
				u.Name, u.VIP, c.Pool)
		}
	}

	for _, u := range revoked {
		if u.Name == name {
			return User{}, "", fmt.Errorf("ikev2: %q was revoked on %s and the name is held back"+
				" with address %v; reissuing it would attribute their old traffic to the new"+
				" credential. Use a different name, or `user purge %s` to release it",
				name, u.Revoked.Format("2006-01-02"), u.VIP, name)
		}
	}

	vip, err := allocateVIP(c, append(existing, revoked...))
	if err != nil {
		return User{}, "", err
	}
	secret, err := GenerateSecret()
	if err != nil {
		return User{}, "", err
	}

	u := User{Name: name, VIP: vip, Created: time.Now().UTC().Truncate(time.Second)}
	snippet, err := RenderUser(c, u, secret)
	if err != nil {
		return User{}, "", err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return User{}, "", err
	}
	// 0600 because this file is the credential. Written with O_EXCL so a
	// concurrent add cannot silently win and leave two users sharing an
	// address.
	f, err := os.OpenFile(s.path(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return User{}, "", err
	}
	if _, err := f.WriteString(snippet); err != nil {
		f.Close()
		return User{}, "", err
	}
	if err := f.Close(); err != nil {
		return User{}, "", err
	}
	return u, secret, nil
}

// Remove deletes a user's gateway snippet and leaves a tombstone holding their
// address.
//
// It does not reload charon or tear down the live session; see the CLI, which
// does both, because a revoke that only edited a file is not a revoke.
func (s Store) Remove(name string) (User, error) {
	if err := ValidateUserName(name); err != nil {
		return User{}, err
	}
	u, err := readUserHeader(s.path(name))
	if err != nil {
		if os.IsNotExist(err) {
			return User{}, fmt.Errorf("ikev2: no such user %q", name)
		}
		return User{}, err
	}
	u.Revoked = time.Now().UTC().Truncate(time.Second)

	// The tombstone carries the headers and nothing else. It is written before
	// the credential is deleted, so a crash in between leaves the address held
	// rather than silently free.
	tomb := fmt.Sprintf("%s%s\n%s%s\n%s%s\n%s%s\n"+
		"#\n# Revoked. This file holds %v back so it is not handed to someone else,\n"+
		"# which would attribute this user's earlier traffic to whoever came next.\n"+
		"# It carries no credential. Release the address with: gotun ikev2 user purge %s\n",
		hdrName, u.Name, hdrVIP, u.VIP,
		hdrCreated, u.Created.UTC().Format(timeLayout),
		hdrRevoked, u.Revoked.Format(timeLayout),
		u.VIP, u.Name)
	if err := os.WriteFile(s.tombstonePath(name), []byte(tomb), 0o644); err != nil {
		return User{}, err
	}
	if err := os.Remove(s.path(name)); err != nil {
		return User{}, err
	}
	return u, nil
}

// Purge releases a revoked name and its address for reuse.
//
// Separate from Remove and never automatic: it is the point at which old log
// entries stop being attributable, so it should be a decision rather than a
// side effect.
func (s Store) Purge(name string) (User, error) {
	if err := ValidateUserName(name); err != nil {
		return User{}, err
	}
	u, err := readUserHeader(s.tombstonePath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return User{}, fmt.Errorf("ikev2: no revoked user %q", name)
		}
		return User{}, err
	}
	return u, os.Remove(s.tombstonePath(name))
}

// allocateVIP picks the lowest free address in the pool.
//
// Lowest-free rather than random, so the mapping is predictable from the files
// alone and an operator reading a firewall log can tell who it was. The
// gateway's own tunnel-side address is skipped, as is anything an existing user
// already holds -- an address is assigned once and then belongs to that user
// until they are revoked.
func allocateVIP(c Config, existing []User) (netip.Addr, error) {
	taken := map[netip.Addr]string{}
	for _, u := range existing {
		taken[u.VIP] = u.Name
	}
	pool := c.Pool.Masked()
	for addr := pool.Addr(); pool.Contains(addr); addr = addr.Next() {
		if !addr.IsValid() {
			break
		}
		if addr == c.VIPGateway {
			continue
		}
		// The pool's own network and broadcast addresses are skipped for IPv4.
		// charon would hand them out, and some clients will not use them.
		if addr.Is4() && (addr == pool.Addr() || addr == lastAddrOfPrefix(pool)) {
			continue
		}
		if _, dup := taken[addr]; dup {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("ikev2: pool %v is full (%d addresses held, including"+
		" revoked users); widen -pool, or release a revoked name with `user purge`",
		c.Pool, len(existing))
}

func lastAddrOfPrefix(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= p.Bits() {
				b[i] |= 1 << (7 - bit)
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// secretAlphabet omits characters that are misread when someone reads a
// password off a screen and types it into a phone: I, L, O, 0 and 1.
const secretAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// secretGroups x secretGroupLen characters, hyphenated. 20 characters over a
// 31-symbol alphabet is a little under 100 bits, against an online-only attack
// surface: the secret is only ever offered inside an established IKE_SA, so
// there is no offline guessing to outrun.
const (
	secretGroups   = 4
	secretGroupLen = 5
)

// GenerateSecret returns a typeable high-entropy EAP secret.
func GenerateSecret() (string, error) {
	var b strings.Builder
	for g := 0; g < secretGroups; g++ {
		if g > 0 {
			b.WriteByte('-')
		}
		for i := 0; i < secretGroupLen; i++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(secretAlphabet))))
			if err != nil {
				return "", fmt.Errorf("ikev2: generating a secret: %w", err)
			}
			b.WriteByte(secretAlphabet[n.Int64()])
		}
	}
	return b.String(), nil
}
