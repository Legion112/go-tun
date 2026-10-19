package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
		return fmt.Errorf("usage: gotun ikev2 user <add|list|revoke> <name> [flags]")
	}
	switch args[0] {
	case "add":
		return runUserAdd(args[1:])
	case "list":
		return runUserList(args[1:])
	case "revoke":
		return runUserRevoke(args[1:])
	default:
		return fmt.Errorf("unknown ikev2 user command %q (want add, list or revoke)", args[0])
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
	// The profile's identity has to be the user: it is what the phone sends as
	// its EAP identity, and therefore which secret the gateway looks up.
	cfg.ClientID = name
	if strings.TrimSpace(*f.name) == "" || *f.name == "gotun" {
		cfg.ProfileName = "gotun " + name
	}

	u, secret, err := ikev2.Store{Dir: *dir}.Add(name)
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

	fmt.Printf("gotun ikev2: user %s added\n", u.Name)
	fmt.Printf("gotun ikev2: credential → %s (mode 0600)\n",
		filepath.Join(*dir, "gotun-user-"+name+".conf"))
	fmt.Printf("gotun ikev2: iOS profile → %s\n", profilePath)

	// Printed, never written anywhere but the gateway snippet. Deliberately not
	// into the profile: a .mobileconfig carrying the password is a credential
	// in a file that gets AirDropped to a phone and then sits in Downloads,
	// and iOS keeps it in the keychain after the first connect anyway.
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
	users, err := ikev2.Store{Dir: *dir}.List()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Printf("gotun ikev2: no users in %s\n", *dir)
		return nil
	}

	// Who is connected comes from the daemon rather than from any state this
	// tool keeps: charon already records the EAP identity of every SA next to
	// the address it handed out, which is the whole reason no address needs
	// pinning. Best effort, because listing users is useful on a box where
	// charon is not running.
	live := map[string][]liveSA{}
	if sas, err := listSAs(linux.ExecRunner{}); err == nil {
		for _, sa := range sas {
			live[sa.Identity] = append(live[sa.Identity], sa)
		}
	}

	// No secrets here, and none recoverable: they exist in the gateway snippet
	// and in whatever the person typed into their phone, and nowhere else.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tADDED\tCONNECTED FROM\tADDRESS")
	for _, u := range users {
		sas := live[u.Name]
		if len(sas) == 0 {
			fmt.Fprintf(w, "%s\t%s\t-\t-\n", u.Name, stamp(u.Created))
			continue
		}
		for _, sa := range sas {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Name, stamp(u.Created), sa.Host,
				strings.Join(sa.VIPs, ","))
		}
	}
	return w.Flush()
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02 15:04")
}

func runUserRevoke(args []string) error {
	name, rest, err := userName(args)
	if err != nil {
		return fmt.Errorf("usage: gotun ikev2 user revoke <name> [flags]: %w", err)
	}
	fs := flag.NewFlagSet("ikev2 user revoke", flag.ContinueOnError)
	dir := fs.String("dir", DefaultUserDir, "directory of per-user swanctl snippets")
	apply := fs.String("apply", "true",
		"reload charon and tear down the user's live sessions (true|false)."+
			" false leaves a revocation that has not taken effect")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	u, err := ikev2.Store{Dir: *dir}.Remove(name)
	if err != nil {
		return err
	}
	fmt.Printf("gotun ikev2: removed %s's credential from %s\n", u.Name, *dir)

	if !truthy(*apply) {
		// Said loudly, because the file being gone looks like the job is done.
		fmt.Fprintf(os.Stderr, "gotun ikev2: NOT APPLIED. %s can still connect until charon is"+
			" reloaded, and any session they already have keeps working indefinitely --"+
			" the connection does not reauthenticate, so it rekeys without consulting the"+
			" secret. Run:\n  swanctl --load-all\n"+
			"  swanctl --list-sas --raw   # find the uniqueid whose remote-id is %s\n"+
			"  swanctl --terminate --ike-id <id>\n", u.Name, u.Name)
		return nil
	}
	return ApplyRevoke(linux.ExecRunner{}, u.Name)
}

// liveSA is one IKE_SA as the daemon reports it.
type liveSA struct {
	UniqueID string
	Identity string // the peer's EAP identity: the user name
	Host     string // the public address they are connecting from
	VIPs     []string
}

var (
	reUniqueID   = regexp.MustCompile(`\buniqueid=([0-9]+)`)
	reRemoteID   = regexp.MustCompile(`\bremote-id=([^\s}]+)`)
	reRemoteHost = regexp.MustCompile(`\bremote-host=([^\s}]+)`)
	reRemoteVIPs = regexp.MustCompile(`\bremote-vips=\[([^\]]*)\]`)
)

// listSAs asks the daemon who is connected.
//
// --raw rather than the human listing, because the human one spreads an SA over
// several lines and puts the identity on a different one from the id needed to
// terminate it. The raw form is one line per SA with both on it.
func listSAs(r linux.Runner) ([]liveSA, error) {
	out, err := r.Run("swanctl", "--list-sas", "--raw")
	if err != nil {
		return nil, err
	}
	return parseSAs(out), nil
}

func parseSAs(raw string) []liveSA {
	var out []liveSA
	for _, line := range strings.Split(raw, "\n") {
		id := reUniqueID.FindStringSubmatch(line)
		peer := reRemoteID.FindStringSubmatch(line)
		if id == nil || peer == nil {
			continue
		}
		sa := liveSA{UniqueID: id[1], Identity: peer[1]}
		if h := reRemoteHost.FindStringSubmatch(line); h != nil {
			sa.Host = h[1]
		}
		if v := reRemoteVIPs.FindStringSubmatch(line); v != nil && v[1] != "" {
			sa.VIPs = strings.Fields(strings.ReplaceAll(v[1], ",", " "))
		}
		out = append(out, sa)
	}
	return out
}

// ApplyRevoke makes a revocation take effect, which takes two steps rather than
// one.
//
// Reloading stops the credential being accepted for NEW sessions. It does
// nothing to an established one: the generated connection does not
// reauthenticate, so the IKE_SA rekeys without consulting the secret and the
// tunnel survives for as long as the peer keeps it alive. Measured in
// TestIKEv2Users_NamedCredentialsAreRevocable.
func ApplyRevoke(r linux.Runner, name string) error {
	out, err := reloadSwanctl(r)
	if err != nil {
		return fmt.Errorf("gotun ikev2: reload failed, so %s can still connect: %w\n%s",
			name, err, out)
	}
	fmt.Println("gotun ikev2: charon reloaded; the credential is no longer accepted")

	sas, err := listSAs(r)
	if err != nil {
		return fmt.Errorf("gotun ikev2: %s's credential is revoked but their live sessions could"+
			" not be listed, so any they have will survive indefinitely: %w", name, err)
	}
	// Every session, not the first: the default uniqueness policy lets one
	// credential be used from two devices at once, and leaving the second one
	// up is a revocation that half happened.
	var found int
	for _, sa := range sas {
		if sa.Identity != name {
			continue
		}
		found++
		if out, err := r.Run("swanctl", "--terminate", "--ike-id", sa.UniqueID); err != nil {
			return fmt.Errorf("gotun ikev2: %s's credential is revoked but session %s could not"+
				" be torn down, and it will survive indefinitely: %w\n%s",
				name, sa.UniqueID, err, out)
		}
		fmt.Printf("gotun ikev2: terminated %s's session %s from %s\n", name, sa.UniqueID, sa.Host)
	}
	if found == 0 {
		fmt.Printf("gotun ikev2: %s had no live session\n", name)
	}
	return nil
}

func reloadSwanctl(r linux.Runner) (string, error) {
	return r.Run("swanctl", "--load-all")
}
