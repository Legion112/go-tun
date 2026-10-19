package ikev2

import (
	"crypto/rand"
	"fmt"
	"math/big"
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
// then a delete: nothing has to parse and rewrite a configuration that is
// currently authenticating other people. swanctl's own
// `include conf.d/*.conf` does the assembly.
//
// Each file is nothing but a credential -- a `secrets` stanza. The connection,
// the pool and the traffic selectors are shared and come from
// `gotun ikev2`, because charon already knows which identity owns which
// session: `swanctl --list-sas` prints the EAP identity next to the assigned
// address, so neither a per-user connection nor a pinned address is needed to
// answer "who is this" or to end one person's session.
type Store struct{ Dir string }

// User is one named credential. The secret is deliberately absent: it exists
// in the gateway's own file and in whatever the person typed into their phone,
// and nowhere else.
type User struct {
	Name    string
	Created time.Time
}

const (
	userFilePrefix = "gotun-user-"
	userFileSuffix = ".conf"

	// Header keys, so List can report what Add recorded without parsing
	// swanctl.conf syntax.
	hdrName    = "# gotun-user: "
	hdrCreated = "# gotun-created: "
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

// List returns the users in the directory, ordered by name.
func (s Store) List() ([]User, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []User
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, userFilePrefix) || !strings.HasSuffix(n, userFileSuffix) {
			continue
		}
		u, err := readUserHeader(filepath.Join(s.Dir, n))
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
		case strings.HasPrefix(line, hdrCreated):
			u.Created, _ = time.Parse(time.RFC3339, strings.TrimSpace(strings.TrimPrefix(line, hdrCreated)))
		}
	}
	if u.Name == "" {
		return User{}, fmt.Errorf("ikev2: %s has no gotun-user header, so it is not a file"+
			" this tool wrote; refusing to treat it as a user", path)
	}
	return u, nil
}

// Add creates a user: a generated secret and the snippet that authenticates
// them. It returns the secret exactly once -- it is never stored anywhere but
// the gateway file.
func (s Store) Add(name string) (User, string, error) {
	if err := ValidateUserName(name); err != nil {
		return User{}, "", err
	}
	if _, err := os.Stat(s.path(name)); err == nil {
		return User{}, "", fmt.Errorf("ikev2: user %q already exists (%s); revoke it first"+
			" -- reissuing in place would leave the old secret working until the next reload",
			name, s.path(name))
	} else if !os.IsNotExist(err) {
		return User{}, "", err
	}

	secret, err := GenerateSecret()
	if err != nil {
		return User{}, "", err
	}
	u := User{Name: name, Created: time.Now().UTC().Truncate(time.Second)}
	snippet, err := RenderUser(u, secret)
	if err != nil {
		return User{}, "", err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return User{}, "", err
	}
	// 0600 because this file is the credential. O_EXCL so a concurrent add
	// cannot silently win and leave one of the two passwords unusable.
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

// Remove deletes a user's credential.
//
// It does not reload charon or tear down the live session; see the CLI, which
// does both, because a revoke that only deleted a file is not a revoke.
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
	return u, os.Remove(s.path(name))
}

// RenderUser emits one user's credential, and nothing else.
//
// Nothing else is the point. A per-user connection would be needed to pin a
// per-user address, and a pinned address was the only way to attribute an old
// packet log to a person -- but it also duplicates the whole traffic-selector
// list per user, and charon already records the identity and the address it
// handed out, together, at connect time. Logging that pair is the cheap way to
// the same answer.
func RenderUser(u User, secret string) (string, error) {
	if err := ValidateUserName(u.Name); err != nil {
		return "", err
	}
	if secret == "" {
		return "", fmt.Errorf("ikev2: user %q has no secret", u.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n%s%s\n", hdrName, u.Name, hdrCreated, u.Created.UTC().Format(timeLayout))
	fmt.Fprintf(&b, `#
# Generated by gotun ikev2 user add. THIS FILE IS A CREDENTIAL: mode 0600, and
# it does not belong in a repository or a backup that others can read.
#
# Revoking %s means deleting this file AND reloading AND terminating the live
# session. The first two alone do not revoke anything: the connection does not
# reauthenticate, so an established session rekeys without consulting the
# secret and survives indefinitely. Measured; see docs/ikev2-phone.md.
#
#   gotun ikev2 user revoke %s
#
secrets {
  eap-%s {
    id = %s
    secret = "%s"
  }
}
`, u.Name, u.Name, u.Name, u.Name, secret)
	return b.String(), nil
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
