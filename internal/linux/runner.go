package linux

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// StdinPath is the path to pass to a command that reads a file but should read
// what we piped it instead.
//
// Neither of the obvious spellings is portable enough. "nft -f -" makes nft open
// /dev/stdin, and "wg set ... private-key /dev/stdin" does the same, but that
// path does not exist on a stock OpenWrt root: there is no /dev/std* symlink
// farm, so every nft write and every key load fails. /proc/self/fd/0 is created
// by procfs itself and is present anywhere /proc is mounted, which includes
// every target here.
//
// Passing a path rather than writing a temp file is deliberate for the private
// key: a temp file would put it on disk, however briefly.
const StdinPath = "/proc/self/fd/0"

// Runner executes external commands (nft, ip, sysctl, wg).
type Runner interface {
	Run(name string, args ...string) (stdout string, err error)
	RunWithInput(name string, stdin string, args ...string) (stdout string, err error)
}

// ExecRunner runs real commands on the host/netns.
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) (string, error) {
	return ExecRunner{}.RunWithInput(name, "", args...)
}

func (ExecRunner) RunWithInput(name string, stdin string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// RecordingRunner records commands and can return scripted results.
type RecordingRunner struct {
	Calls     []string
	Outputs   map[string]string
	Errors    map[string]error
	FailOn    string
	CallCount int
	// SemanticApplied tracks whether a full desired state was already applied (for idempotency tests).
	AlreadyApplied bool
}

func NewRecordingRunner() *RecordingRunner {
	return &RecordingRunner{
		Outputs: map[string]string{},
		Errors:  map[string]error{},
	}
}

func (r *RecordingRunner) key(name string, args []string) string {
	return name + " " + strings.Join(args, " ")
}

func (r *RecordingRunner) Run(name string, args ...string) (string, error) {
	return r.RunWithInput(name, "", args...)
}

func (r *RecordingRunner) RunWithInput(name string, stdin string, args ...string) (string, error) {
	key := r.key(name, args)
	if stdin != "" {
		key += " <<STDIN>>"
	}
	r.Calls = append(r.Calls, key)
	if stdin != "" {
		r.Calls = append(r.Calls, "STDIN:"+stdin)
	}
	r.CallCount++
	if r.FailOn != "" && strings.Contains(key, r.FailOn) {
		return "", fmt.Errorf("injected failure: %s", key)
	}
	if err, ok := r.Errors[key]; ok {
		return r.Outputs[key], err
	}
	// Simulate existing state after first successful apply
	if r.AlreadyApplied {
		if name == "nft" && len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "table" {
			return sampleNftListJSON(), nil
		}
		if name == "nft" && len(args) >= 2 && args[0] == "list" {
			return sampleNftList(), nil
		}
		// Production shells out to sh, never bash (a router has no bash); accept
		// both so an older caller is still simulated.
		if (name == "sh" || name == "bash") && len(args) >= 2 && args[0] == "-c" {
			cmd := args[1]
			if strings.Contains(cmd, "cat /proc/sys/net/ipv4/ip_forward") ||
				strings.Contains(cmd, "cat /proc/sys/net/ipv6/conf/all/disable_ipv6") ||
				strings.Contains(cmd, "cat /proc/sys/net/ipv6/conf/default/disable_ipv6") {
				return "1", nil
			}
			// send_redirects converges to 0, not 1.
			if strings.Contains(cmd, "send_redirects") && strings.Contains(cmd, "cat /proc/sys/") {
				return "0", nil
			}
		}
		if name == "sysctl" && len(args) >= 2 && args[0] == "-n" {
			switch args[1] {
			case "net.ipv4.ip_forward":
				return "1", nil
			case "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6":
				return "1", nil
			}
			if strings.Contains(args[1], "send_redirects") {
				return "0", nil
			}
		}
		if name == "ip" && len(args) >= 1 && args[0] == "rule" {
			return "100: from all fwmark 0x1 lookup 100", nil
		}
		if name == "ip" && len(args) >= 1 && args[0] == "route" {
			return "blackhole default metric 100", nil
		}
	}
	if out, ok := r.Outputs[key]; ok {
		return out, nil
	}
	return "", nil
}

func sampleNftList() string {
	return `table inet gotun {
  set ru_nets {
    type ipv4_addr
    flags interval
    elements = { 10.200.0.0/24 }
  }
  chain prerouting {
    type filter hook prerouting priority mangle + 1; policy accept;
    meta nfproto ipv6 drop comment "drop-ipv6"
    ip daddr 10.10.0.0/24 return comment "exclude-lan"
    ip daddr 10.10.0.2 return comment "exclude-endpoint"
    ip daddr != @ru_nets meta mark set 0x1 comment "mark-non-direct"
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip daddr 10.10.0.0/24 return comment "snat-skip-lan"
    meta nfproto ipv4 oifname "eth0" fib saddr type != local counter packets 0 bytes 0 masquerade comment "snat-direct"
  }
}`
}

func sampleNftListJSON() string {
	return `{"nftables":[
{"metainfo":{"version":"1"}},
{"table":{"family":"inet","name":"gotun"}},
{"set":{"family":"inet","name":"ru_nets","table":"gotun","type":"ipv4_addr","flags":["interval"],"elem":["10.200.0.0/24"]}},
{"chain":{"family":"inet","table":"gotun","name":"prerouting","type":"filter","hook":"prerouting","prio":-149,"policy":"accept"}},
{"rule":{"family":"inet","table":"gotun","chain":"prerouting","comment":"drop-ipv6","expr":[]}},
{"rule":{"family":"inet","table":"gotun","chain":"prerouting","comment":"exclude-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"family":"inet","table":"gotun","chain":"prerouting","comment":"exclude-endpoint","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"10.10.0.2"}}]}},
{"rule":{"family":"inet","table":"gotun","chain":"prerouting","comment":"mark-non-direct","expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}},
{"chain":{"family":"inet","table":"gotun","name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"rule":{"family":"inet","table":"gotun","chain":"postrouting","comment":"snat-skip-lan","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"10.10.0.0","len":24}}}}]}},
{"rule":{"family":"inet","table":"gotun","chain":"postrouting","comment":"snat-direct","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"match":{"op":"!=","left":{"fib":{"result":"type","flags":["saddr"]}},"right":"local"}},{"counter":{"packets":0,"bytes":0}},{"masquerade":null}]}}
]}`
}

// WriteTempFile is a helper for backends that need a file path.
func WriteTempFile(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
