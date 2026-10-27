package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/legion/go-tun/internal/deployconf"
	"github.com/legion/go-tun/internal/dnsproxy"
	"github.com/legion/go-tun/internal/dnswatch"
)

type dnsWatchFlags struct {
	configPath, filter, resolver, fallback, serversFile, pidGlob *string
	cfg                                                          dnswatch.Config
}

func registerDNSWatchFlags(fs *flag.FlagSet) *dnsWatchFlags {
	f := &dnsWatchFlags{
		configPath: fs.String("config", "",
			"read the GOTUN_DNS_* settings from this gotun-dns.conf, the same file gotun-dns reads"),
		filter: fs.String("filter", "",
			"blocking resolver in front of gotun-dns, e.g. AdGuard Home at 127.0.0.1:3053. It is"+
				" the first hop while it answers and is dropped from the list while it does not."+
				" Empty means there is none"),
		resolver: fs.String("resolver", dnsproxy.DefaultListen, "gotun-dns's listen address"),
		fallback: fs.String("fallback", dnsproxy.DefaultDirectUpstream,
			"last resort, never removed. A local resolver: its answer to a foreign name is"+
				" geo-localised but connects, where a foreign resolver's direct answer may not"),
		serversFile: fs.String("servers-file", dnswatch.DefaultServersFile,
			"the dnsmasq --servers-file to keep current (uci: dhcp.@dnsmasq[0].serversfile)"),
		pidGlob: fs.String("dnsmasq-pidfiles", dnswatch.DefaultPidGlob,
			"pid files of the dnsmasq processes to SIGHUP after a change"),
	}
	fs.DurationVar(&f.cfg.Interval, "interval", dnswatch.DefaultInterval, "how often to probe each hop")
	fs.DurationVar(&f.cfg.Timeout, "timeout", dnswatch.DefaultTimeout, "per-query probe timeout")
	fs.IntVar(&f.cfg.FailAfter, "fail-after", dnswatch.DefaultFailAfter,
		"consecutive failed probes before a hop is removed")
	fs.IntVar(&f.cfg.RecoverAfter, "recover-after", dnswatch.DefaultRecoverAfter,
		"consecutive answered probes before a hop is put back")
	return f
}

// runDNSWatch keeps dnsmasq's upstream list down to the hops that answer, so
// that a dead ad blocker costs ad blocking rather than every lookup.
func runDNSWatch(args []string) error {
	fs := flag.NewFlagSet("dnswatch", flag.ContinueOnError)
	f := registerDNSWatchFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("dnswatch takes no arguments, got %q", fs.Args())
	}
	if path := strings.TrimSpace(*f.configPath); path != "" {
		conf, err := deployconf.Load(path, deployconf.GotunDNSConf)
		if err != nil {
			return ConfigError{Err: err}
		}
		if err := conf.Into(fs, deployconf.DNSWatchFlags); err != nil {
			return ConfigError{Err: err}
		}
	}
	cfg := f.cfg
	cfg.Filter = strings.TrimSpace(*f.filter)
	cfg.Resolver = strings.TrimSpace(*f.resolver)
	cfg.Fallback = strings.TrimSpace(*f.fallback)
	cfg.ServersFile = strings.TrimSpace(*f.serversFile)
	cfg.PidGlob = strings.TrimSpace(*f.pidGlob)
	if err := cfg.Validate(); err != nil {
		return ConfigError{Err: err}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return dnswatch.New(cfg, dnswatch.DNSProbe, log.New(os.Stderr, "", log.LstdFlags)).Run(ctx)
}
