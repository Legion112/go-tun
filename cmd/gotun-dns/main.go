package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/dnsproxy"
	"github.com/legion/go-tun/internal/policy"
)

func main() {
	configPath := flag.String("config", "",
		"read settings from this /etc/gotun/gotun-dns.conf-style file. A flag passed"+
			" explicitly wins over the file, and a setting the file omits keeps its default"+
			" here rather than being overridden with an empty value")
	listen := flag.String("listen", "127.0.0.2:53",
		"UDP/TCP listen address. Not :53, because this resolver is never the only one on a"+
			" box: it answers the subset of names that must be resolved through the tunnel,"+
			" and something else -- dnsmasq, here -- has to forward to it. Binding the"+
			" wildcard would fight whatever owns :53 and serves DHCP")
	directUp := flag.String("direct-upstream", "77.88.8.8:53", "upstream for Direct path (.ru); unmarked dial")
	exitUp := flag.String("exit-upstream", "1.1.1.1:53", "upstream for Exit path; dialed with SO_MARK")
	markStr := flag.String("mark", fmt.Sprintf("0x%x", policy.DefaultMark), "SO_MARK for Exit path (must match gotun apply)")
	timeout := flag.Duration("timeout", 3*time.Second, "upstream query timeout")
	flag.Parse()

	if err := loadConfig(flag.CommandLine, *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "gotun-dns: %v\n", err)
		os.Exit(2)
	}

	mark, err := parseMark(*markStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotun-dns: mark: %v\n", err)
		os.Exit(2)
	}

	fwd, err := dnsproxy.NewForwarder(
		dnsproxy.DefaultRUClassifier(),
		dnsproxy.Upstream{Direct: *directUp, Exit: *exitUp},
		dnsproxy.DialConfig{Timeout: *timeout, Mark: mark},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotun-dns: %v\n", err)
		os.Exit(1)
	}

	log.Printf("gotun-dns listen=%s direct-upstream=%s exit-upstream=%s mark=0x%x",
		*listen, *directUp, *exitUp, mark)
	log.Printf("gotun-dns requires CAP_NET_BIND_SERVICE for :53 (if non-root) and CAP_NET_ADMIN (or CAP_NET_RAW) for SO_MARK")

	srv := &dnsproxy.Server{Listen: *listen, Forwarder: fwd}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// loadConfig fills in the flags the operator did not pass. An empty path is not
// an error: the file is optional and every setting has a default.
func loadConfig(fs *flag.FlagSet, path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	conf, err := deployconf.Load(path, deployconf.GotunDNSConf)
	if err != nil {
		return err
	}
	return conf.Into(fs, deployconf.DNSFlags)
}

func parseMark(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}
