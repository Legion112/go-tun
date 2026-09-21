package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// labdns simulates a geo-based DNS server: answers depend on the query source
// IP. A and AAAA are both served, each from the -map entries of its own family,
// so one source CIDR can be given both by repeating -map.
// Optional -truncate-udp returns TC=1 on UDP and the full answer on TCP.

type geoRule struct {
	net  netip.Prefix
	addr netip.Addr
}

func main() {
	listen := flag.String("listen", ":53", "listen address")
	truncateUDP := flag.Bool("truncate-udp", false, "set TC on UDP replies; full answer on TCP")
	var maps flagStrings
	flag.Var(&maps, "map", "sourceCIDR=answerIP (repeatable); the answer's family picks the "+
		"record type, e.g. -map 10.200.0.0/24=10.200.0.50 -map fd00:200::/64=fd00:200::50")
	flag.Parse()
	if len(maps) == 0 {
		fmt.Fprintln(os.Stderr, "labdns: at least one -map CIDR=IP is required")
		os.Exit(2)
	}
	rules, err := parseMaps(maps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "labdns: %v\n", err)
		os.Exit(2)
	}

	h := &geoHandler{rules: rules, truncateUDP: *truncateUDP}
	log.Printf("labdns listen=%s truncate-udp=%v maps=%v", *listen, *truncateUDP, maps)
	if err := h.listenAndServe(*listen); err != nil {
		log.Fatal(err)
	}
}

type geoHandler struct {
	rules       []geoRule
	truncateUDP bool
}

func (h *geoHandler) listenAndServe(addr string) error {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		udp.Close()
		return err
	}
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- serveUDP(udp, h.handle)
	}()
	go func() {
		defer wg.Done()
		errCh <- serveTCP(tcp, h.handle)
	}()
	err = <-errCh
	udp.Close()
	tcp.Close()
	wg.Wait()
	return err
}

type queryHandler func(raw []byte, src netip.Addr, udp bool) []byte

func serveUDP(pc net.PacketConn, h queryHandler) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		src := addrIP(addr)
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go func() {
			out := h(raw, src, true)
			if out != nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}()
	}
}

func serveTCP(ln net.Listener, h queryHandler) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var lenBuf [2]byte
			if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
				return
			}
			l := int(lenBuf[0])<<8 | int(lenBuf[1])
			if l <= 0 || l > 65535 {
				return
			}
			raw := make([]byte, l)
			if _, err := io.ReadFull(c, raw); err != nil {
				return
			}
			out := h(raw, addrIP(c.RemoteAddr()), false)
			if out == nil {
				return
			}
			lenBuf[0] = byte(len(out) >> 8)
			lenBuf[1] = byte(len(out))
			_, _ = c.Write(lenBuf[:])
			_, _ = c.Write(out)
		}(c)
	}
}

func (h *geoHandler) handle(raw []byte, src netip.Addr, udp bool) []byte {
	req := new(dns.Msg)
	req.Data = raw
	if err := req.Unpack(); err != nil {
		return nil
	}
	m := req.Copy()
	dnsutil.SetReply(m, req)
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return pack(m)
	}
	// The qtype decides which family to answer with. Ignoring it and always
	// returning an A record meant an AAAA query got an answer of the wrong
	// type, which a resolver treats as a malformed reply rather than as "no
	// such record".
	_, wantV6 := req.Question[0].(*dns.AAAA)

	ans, ok := h.lookup(src, wantV6)
	if !ok {
		if h.hasAnyRule(src) {
			// A rule covers this source, just not for this family. That is
			// NOERROR with an empty answer -- the correct way to say "no
			// record of this type" -- and a dual-stack client then falls back
			// to the other family instead of treating the name as missing.
			return pack(m)
		}
		m.Rcode = dns.RcodeNameError
		return pack(m)
	}
	name := req.Question[0].Header().Name
	hdr := dns.Header{Name: name, Class: dns.ClassINET, TTL: 60}
	if wantV6 {
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: rdata.AAAA{Addr: ans}}}
	} else {
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: rdata.A{Addr: ans}}}
	}
	if h.truncateUDP && udp {
		m.Truncated = true
		m.Answer = nil
	}
	return pack(m)
}

// lookup finds the answer for a source address, restricted to the family the
// query asked for.
func (h *geoHandler) lookup(src netip.Addr, wantV6 bool) (netip.Addr, bool) {
	if !src.IsValid() {
		return netip.Addr{}, false
	}
	for _, rule := range h.rules {
		if rule.net.Contains(src) && rule.addr.Is6() == wantV6 {
			return rule.addr, true
		}
	}
	return netip.Addr{}, false
}

// hasAnyRule reports whether any rule covers this source, regardless of family.
func (h *geoHandler) hasAnyRule(src netip.Addr) bool {
	if !src.IsValid() {
		return false
	}
	for _, rule := range h.rules {
		if rule.net.Contains(src) {
			return true
		}
	}
	return false
}

func pack(m *dns.Msg) []byte {
	m.Data = nil
	if err := m.Pack(); err != nil {
		return nil
	}
	return m.Data
}

func addrIP(addr net.Addr) netip.Addr {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

func parseMaps(vals []string) ([]geoRule, error) {
	var out []geoRule
	for _, v := range vals {
		cidr, ip, ok := strings.Cut(v, "=")
		if !ok {
			return nil, fmt.Errorf("bad -map %q (want CIDR=IP)", v)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		if a.Is4In6() {
			return nil, fmt.Errorf("answer must be plain IPv4 or IPv6, not 4-in-6: %s", a)
		}
		out = append(out, geoRule{net: p, addr: a})
	}
	return out, nil
}

type flagStrings []string

func (f *flagStrings) String() string { return strings.Join(*f, ",") }
func (f *flagStrings) Set(v string) error {
	*f = append(*f, v)
	return nil
}
