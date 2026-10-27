package cli

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// The architecture is the part that matters on a router: a binary built for
// the wrong one fails with "not found" from the shell, which says nothing.
func TestPrintVersion_NamesPlatformAndToolchain(t *testing.T) {
	var buf bytes.Buffer
	printVersion(&buf)
	out := buf.String()

	for _, want := range []string{"gotun ", runtime.GOOS + "/" + runtime.GOARCH, runtime.Version()} {
		if !strings.Contains(out, want) {
			t.Errorf("version output %q lacks %q", out, want)
		}
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Errorf("version output should be exactly one line, got %q", out)
	}
}

func TestRun_VersionTakesNoFlagsAndSucceeds(t *testing.T) {
	for _, arg := range []string{"version", "-version", "--version"} {
		if err := Run([]string{arg}); err != nil {
			t.Errorf("Run(%q) = %v", arg, err)
		}
	}
}
