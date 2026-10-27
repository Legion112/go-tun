package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// printVersion reports what the binary was built from. Once binaries are
// downloaded rather than built in place, "which gotun is on the router" has
// no other answer: the file name says the architecture and nothing else.
//
// Nothing is injected at link time. The go command stamps the module version
// from the git tag at HEAD, or a pseudo-version between tags, and records the
// commit, so a release build and a `make build` report the same way. An
// uncommitted tree already shows as "+dirty" in the version itself.
func printVersion(w io.Writer) {
	version, revision := "(devel)", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" {
			version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
			}
		}
	}
	fmt.Fprintf(w, "gotun %s %s/%s %s", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if revision != "" {
		fmt.Fprintf(w, " rev %s", revision)
	}
	fmt.Fprintln(w)
}
