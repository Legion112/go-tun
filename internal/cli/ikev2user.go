package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/legion/go-tun/internal/ikev2"
	"github.com/legion/go-tun/internal/linux"
)

// DefaultUserDir is where swanctl's own `include conf.d/*.conf` picks snippets
// up, so a file written here is live after a reload and needs no edit to
// swanctl.conf.
const DefaultUserDir = "/etc/swanctl/conf.d"

func runIKEv2User(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gotun ikev2 user <add|list|revoke|purge> <name> [flags]")
	}
	switch args[0] {
	case "add":
		return runUserAdd(args[1:])
	case "list":
		return runUserList(args[1:])
	case "revoke":
		return runUserRevoke(args[1:])
	case "purge":
		return runUserPurge(args[1:])
	default:
		return fmt.Errorf("unknown ikev2 user command %q (want add, list, revoke or purge)", args[0])
	}
}

// userName pulls the positional name off the front, so the name reads as an
// argument rather than as a flag.
func userName(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, errors.New("a user name is required")
	}
	return args[0], args[1:], nil
}

func runUserAdd(args []string) error {
	name, rest, err := userName(args)
	if err != nil {
		return fmt.Errorf("usage: gotun ikev2 user add <name> [flags]: %w", err)
	}
	fs := flag.NewFlagSet("ikev2 user add", flag.ContinueOnError)
	f := registerIKEv2Flags(fs)
	dir := fs.String("dir", DefaultUserDir, "directory of per-user swanctl snippets")
	outProfile := fs.String("out-profile", "", "output path for this user's iOS profile;"+
		" empty means <name>.mobileconfig in the working directory")
	apply := fs.String("apply", "true",
		"reload charon so the new user can connect immediately (true|false)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	cfg, err := f.config()
	if err != nil {
		return err
	}
	// The profile's identity has to be the user, not the shared -client-id, or
	// the phone announces a name the gateway has no connection for.
	cfg.ClientID = name
	if strings.TrimSpace(*f.name) == "" || *f.name == "gotun" {
		cfg.ProfileName = "gotun " + name
	}

	store := ikev2.Store{Dir: *dir}
	u, secret, err := store.Add(cfg, name)
	if err != nil {
		return err
	}

	profilePath := strings.TrimSpace(*outProfile)
	if profilePath == "" {
		profilePath = name + ".mobileconfig"
	}
	profile, err := ikev2.EncodeProfile(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(profilePath, profile, 0o600); err != nil {
		return err
	}

	fmt.Printf("gotun ikev2: user %s added, address %s\n", u.Name, u.VIP)
	fmt.Printf("gotun ikev2: gateway snippet → %s (mode 0600)\n",
		filepath.Join(*dir, "gotun-user-"+name+".conf"))
	fmt.Printf("gotun ikev2: iOS profile → %s\n", profilePath)

	// Printed, never written anywhere but the gateway snippet. Deliberately on
	// stdout rather than into the profile: a .mobileconfig carrying the
	// password is a credential in a file that gets AirDropped to a phone and
	// then sits in Downloads, and iOS keeps it in the keychain after the first
	// connect anyway.
	fmt.Printf("\n  password for %s:  %s\n\n", u.Name, secret)
	fmt.Fprintln(os.Stderr, "gotun ikev2: that password is shown once and stored nowhere else."+
		" Type it into the phone's VPN password field; iOS keeps it in the keychain afterwards.")

	if truthy(*apply) {
		if out, err := reloadSwanctl(linux.ExecRunner{}); err != nil {
			fmt.Fprintf(os.Stderr, "gotun ikev2: the user is on disk but charon was not reloaded:"+
				" %v\n%s\nRun: swanctl --load-all\n", err, out)
			return err
		}
		fmt.Println("gotun ikev2: charon reloaded; the user can connect now")
	}
	return nil
}

func runUserList(args []string) error {
	fs := flag.NewFlagSet("ikev2 user list", flag.ContinueOnError)
	dir := fs.String("dir", DefaultUserDir, "directory of per-user swanctl snippets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := ikev2.Store{Dir: *dir}
	users, err := store.List()
	if err != nil {
		return err
	}
	revoked, err := store.ListRevoked()
	if err != nil {
		return err
	}
	if len(users) == 0 && len(revoked) == 0 {
		fmt.Printf("gotun ikev2: no users in %s\n", *dir)
		return nil
	}
	// No secrets here, and none recoverable: they exist in the gateway snippet
	// and in whatever the person typed into their phone, and nowhere else.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tADDRESS\tADDED\tSTATE")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\t%s\tactive\n", u.Name, u.VIP, stamp(u.Created))
	}
	// Revoked names are listed because their addresses are still held: without
	// them "the pool is full" would have no visible explanation.
	for _, u := range revoked {
		fmt.Fprintf(w, "%s\t%s\t%s\trevoked %s\n", u.Name, u.VIP, stamp(u.Created), stamp(u.Revoked))
	}
	return w.Flush()
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02 15:04")
}

func runUserPurge(args []string) error {
	name, rest, err := userName(args)
	if err != nil {
		return fmt.Errorf("usage: gotun ikev2 user purge <name> [flags]: %w", err)
	}
	fs := flag.NewFlagSet("ikev2 user purge", flag.ContinueOnError)
	dir := fs.String("dir", DefaultUserDir, "directory of per-user swanctl snippets")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	u, err := ikev2.Store{Dir: *dir}.Purge(name)
	if err != nil {
		return err
	}
	fmt.Printf("gotun ikev2: released %s and its address %s for reuse\n", u.Name, u.VIP)
	fmt.Fprintf(os.Stderr, "gotun ikev2: log entries from before %s was revoked are no longer"+
		" attributable once %s is handed to someone else.\n", u.Name, u.VIP)
	return nil
}

func runUserRevoke(args []string) error {
	name, rest, err := userName(args)
	if err != nil {
		return fmt.Errorf("usage: gotun ikev2 user revoke <name> [flags]: %w", err)
	}
	fs := flag.NewFlagSet("ikev2 user revoke", flag.ContinueOnError)
	dir := fs.String("dir", DefaultUserDir, "directory of per-user swanctl snippets")
	apply := fs.String("apply", "true",
		"reload charon and tear down the user's live session (true|false)."+
			" false leaves a revocation that has not taken effect")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	store := ikev2.Store{Dir: *dir}
	u, err := store.Remove(name)
	if err != nil {
		return err
	}
	fmt.Printf("gotun ikev2: removed %s (%s) from %s\n", u.Name, u.VIP, *dir)

	if !truthy(*apply) {
		// Said loudly, because the file being gone looks like the job is done.
		fmt.Fprintf(os.Stderr, "gotun ikev2: NOT APPLIED. %s can still connect until charon is"+
			" reloaded, and any session they already have keeps working indefinitely --"+
			" the connection does not reauthenticate, so it rekeys without consulting the"+
			" secret. Run:\n  swanctl --load-all\n  swanctl --terminate --ike %s\n",
			u.Name, u.Name)
		return nil
	}
	return ApplyRevoke(linux.ExecRunner{}, u.Name)
}

// ApplyRevoke makes a revocation take effect, which takes two steps rather than
// one.
//
// Reloading stops the credential being accepted for NEW sessions. It does
// nothing to an established one: the generated connection does not
// reauthenticate, so the IKE_SA rekeys without consulting the secret and the
// tunnel survives for as long as the peer keeps it alive. Measured in
// TestIKEv2Users_NamedCredentialsAreFixedAndRevocable.
func ApplyRevoke(r linux.Runner, name string) error {
	out, err := reloadSwanctl(r)
	if err != nil {
		return fmt.Errorf("gotun ikev2: reload failed, so %s can still connect: %w\n%s",
			name, err, out)
	}
	fmt.Println("gotun ikev2: charon reloaded; the credential is no longer accepted")

	// A user who is not currently connected has no SA, and charon says so with
	// an error. That is success here, not failure.
	out, err = r.Run("swanctl", "--terminate", "--ike", name)
	switch {
	case err == nil:
		fmt.Printf("gotun ikev2: terminated %s's live session\n", name)
	case strings.Contains(strings.ToLower(out+err.Error()), "no matching"):
		fmt.Printf("gotun ikev2: %s had no live session\n", name)
	default:
		return fmt.Errorf("gotun ikev2: %s's credential is revoked but their live session could"+
			" not be torn down, and it will survive indefinitely: %w\n%s", name, err, out)
	}
	return nil
}

func reloadSwanctl(r linux.Runner) (string, error) {
	return r.Run("swanctl", "--load-all")
}
