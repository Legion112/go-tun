package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/policy"
)

// runCheck validates a configuration and reports what it resolves to, without
// touching the system.
//
// It exists because `/etc/init.d/gotun start` cannot be trusted: rc.common
// discards start_service's return value, so a refused start prints its reason
// and still exits 0. An operator reaching for their primary recovery command
// gets "success" having started nothing, and diagnoses the next incident from
// that. check is the command that answers honestly, which is why gotun.init
// runs it as a pre-flight rather than leaving it as a convenience -- being on
// the start path is also what stops it rotting.
func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	f := registerWatchFlagsOnly(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Refused rather than ignored: `gotun check /etc/gotun/gotun.conf` is the
	// obvious thing to type, and silently checking the defaults instead would
	// report a healthy configuration nobody has.
	if fs.NArg() > 0 {
		return fmt.Errorf("gotun check: unexpected argument %q; did you mean -config %s",
			fs.Arg(0), fs.Arg(0))
	}
	if err := loadConfigInto(fs, *f.configPath, deployconf.WatchFlags); err != nil {
		return err
	}

	o, err := f.options()
	if err != nil {
		return err
	}
	p, err := Validate(o)
	if err != nil {
		return err
	}
	st, err := policy.Compile(p)
	if err != nil {
		return err
	}

	where := *f.configPath
	if where == "" {
		where = "the flags given"
	}
	fmt.Printf("gotun check: %s is usable\n", where)

	// The effective flag values, which is the question an operator actually
	// has: not what the file says, but what the service will run with once the
	// file, the flags and the defaults have been reconciled.
	names := make([]string, 0, len(deployconf.WatchFlags))
	for _, name := range deployconf.WatchFlags {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if g := fs.Lookup(name); g != nil {
			fmt.Printf("  -%s %s\n", name, g.Value.String())
		}
	}

	// And the two numbers that distinguish a configuration that works from one
	// that looks fine. An empty direct set does not degrade gracefully: it
	// tunnels everything, including the traffic that has to stay local.
	fmt.Printf("  %d direct prefixes, table %d, mark 0x%x\n",
		len(p.DirectPrefixes), p.Table, p.Mark)
	if len(p.DirectPrefixes) == 0 {
		fmt.Fprintln(os.Stderr, "gotun check: the direct set is EMPTY, so everything would be"+
			" tunnelled, including traffic that must stay local")
	}
	fmt.Printf("  %s, %s, %s\n",
		plural(len(st.Nft.Sets), "nft set"),
		plural(len(st.Routes), "route"),
		plural(len(st.IPRules), "ip rule"))
	return nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
