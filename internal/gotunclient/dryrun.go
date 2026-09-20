package gotunclient

import (
	"fmt"
	"io"
	"strings"

	"github.com/legion/go-tun/internal/linux"
)

// DryRunner forwards read-only commands to Inner and prints mutating ones
// instead of running them. Read-only calls still go through so detection and
// property reads reflect the real host.
type DryRunner struct {
	Inner linux.Runner
	Out   io.Writer
}

func (d DryRunner) Run(name string, args ...string) (string, error) {
	return d.RunWithInput(name, "", args...)
}

func (d DryRunner) RunWithInput(name, stdin string, args ...string) (string, error) {
	if isMutating(name, args) {
		fmt.Fprintf(d.Out, "DRY-RUN: %s %s\n", name, strings.Join(args, " "))
		return "", nil
	}
	return d.Inner.RunWithInput(name, stdin, args...)
}

// isMutating reports whether a command would change host state. It is a
// deny-list of the verbs this CLI actually issues, so an unrecognised read-only
// command still passes through.
func isMutating(name string, args []string) bool {
	switch name {
	case "systemd-run", "setsid", "nohup", "kill":
		return true
	case "systemctl":
		if len(args) == 0 {
			return false
		}
		switch args[0] {
		case "show", "status", "is-active", "is-enabled", "is-failed", "list-timers", "cat":
			return false
		}
		return true
	case "nmcli":
		if len(args) < 2 {
			return false
		}
		switch args[0] {
		case "connection", "c", "con":
			switch args[1] {
			case "modify", "up", "down", "add", "delete", "reload", "clone", "edit", "load":
				return true
			}
		case "device", "d", "dev":
			switch args[1] {
			case "modify", "connect", "disconnect", "reapply", "delete", "set":
				return true
			}
		case "general", "networking", "radio":
			return args[1] != "status" && args[1] != "permissions" && args[1] != "hostname"
		}
		return false
	case "ip":
		if len(args) == 0 {
			return false
		}
		// `ip route get`/`show` are reads; add/del/flush/replace are not.
		for _, a := range args {
			switch a {
			case "add", "del", "delete", "change", "replace", "append", "flush":
				return true
			}
		}
		return strings.Contains(strings.Join(args, " "), "rule")
	}
	return false
}
