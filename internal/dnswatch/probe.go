package dnswatch

import (
	"context"
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
)

// DNSProbe asks addr for name's A record over UDP. NXDOMAIN counts as an
// answer: the hop is up and said so. SERVFAIL does not -- that is what a
// resolver says when the thing behind it is broken.
func DNSProbe(ctx context.Context, addr, name string) error {
	timeout := DefaultTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	t := dns.NewTransport()
	t.ReadTimeout = timeout
	t.WriteTimeout = timeout
	c := &dns.Client{Transport: t}

	r, _, err := c.Exchange(ctx, dns.NewMsg(name, dns.TypeA), "udp", addr)
	if err != nil {
		return err
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return nil
	}
	return fmt.Errorf("%s answered rcode %d for %s", addr, r.Rcode, name)
}
