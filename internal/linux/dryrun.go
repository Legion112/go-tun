package linux

import (
	"fmt"
	"io"
	"strings"
)

// DryRunner forwards read-only commands to Inner and prints mutating ones instead
// of running them.
//
// The classification is an allow-list: a command it does not positively recognise
// as read-only is printed, never run. The inverse -- letting unknown commands
// through -- is how a "dry run" ends up changing a household router's
// forwarding, and no amount of convenience is worth that. gotun's command surface
// is small and fixed, so enumerating the reads costs little.
//
// Reads still go to the real host, so what gets printed reflects the actual
// current state rather than a guess: a converged box prints nothing.
type DryRunner struct {
	Inner Runner
	Out   io.Writer
	// Writes counts the commands that were withheld.
	Writes int
}

func (d *DryRunner) Run(name string, args ...string) (string, error) {
	return d.RunWithInput(name, "", args...)
}

func (d *DryRunner) RunWithInput(name, stdin string, args ...string) (string, error) {
	if isReadOnly(name, args) {
		return d.Inner.RunWithInput(name, stdin, args...)
	}
	d.Writes++
	fmt.Fprintf(d.Out, "DRY-RUN: %s %s\n", name, strings.Join(args, " "))
	if stdin != "" {
		for _, line := range strings.Split(strings.TrimRight(stdin, "\n"), "\n") {
			fmt.Fprintf(d.Out, "DRY-RUN |   %s\n", line)
		}
	}
	return "", nil
}

// isReadOnly recognises exactly the reads gotun issues. Anything else, including
// a command that is in fact harmless, is treated as a write.
func isReadOnly(name string, args []string) bool {
	switch name {
	case "nft":
		// "nft -j list ..." and "nft list ..."; "-f" is a write.
		for _, a := range args {
			if a == "-f" {
				return false
			}
			if a == "list" {
				return true
			}
		}
		return false
	case "wg":
		return len(args) > 0 && args[0] == "show"
	case "sysctl":
		return len(args) > 0 && args[0] == "-n"
	case "sh":
		// Only the proc read probe. Anything with a redirect is a write.
		return len(args) == 2 && args[0] == "-c" &&
			strings.HasPrefix(args[1], "cat /proc/sys/") && !strings.ContainsAny(args[1], ">|;&")
	case "ip":
		// ip OBJECT [COMMAND]; the commands gotun reads with are show and get.
		for _, a := range args {
			switch a {
			case "show", "list", "lst", "get":
				return true
			}
		}
		return false
	}
	return false
}
