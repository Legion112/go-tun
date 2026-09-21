package gotunclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/legion/go-tun/internal/linux"
)

// Verified-good probe endpoints. The RU echo resolves into ru_nets (so gotun
// sends it direct out the ISP) and the foreign one does not (so it takes the
// tunnel). Both were confirmed to answer over the harder direct path.
const (
	DefaultRUEchoURL      = "https://yandex.ru/internet/api/v0/ip"
	DefaultForeignEchoURL = "https://api.ipify.org"
	DefaultLargeURL       = "https://speed.cloudflare.com/__down?bytes=10000000"
	DefaultLargeBytes     = 10000000

	// DefaultDirectURL is served from inside ru_nets, so it exercises the
	// DIRECT class. The tunnel-class probe above cannot see a broken direct
	// path -- a gateway whose direct class ran at 5 KB/s once passed every
	// other check in this tool.
	DefaultDirectURL = "https://mirror.yandex.ru/debian/dists/stable/Release"
	// DefaultMinDirectSpeed is a floor, not a benchmark. The failure this
	// guards against is ~1000x below it, so a loose floor separates "broken"
	// from "slow link" without being flaky.
	DefaultMinDirectSpeed = 100 * 1024
)

// Check is one verification result.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	Gateway   netip.Addr
	Probe     netip.Addr
	ExtraLANs []netip.Prefix

	RUEchoURL      string
	ForeignEchoURL string
	RUIP           netip.Addr
	ForeignIP      netip.Addr
	ExpectRUEgress string
	ExpectFgnEgres string

	LargeURL   string
	LargeBytes int64

	// DirectURL is fetched to measure the direct (non-tunnel) class.
	DirectURL string
	// DirectIP pins DirectURL's host, so the probe cannot silently drift onto
	// an address outside the direct set.
	DirectIP       netip.Addr
	MinDirectSpeed int64

	DNSNames []string

	SkipEgress bool
	SkipLarge  bool
	SkipDirect bool
	Timeout    time.Duration
}

var ipRE = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// ip6RE is necessarily loose -- it will match fragments of surrounding text --
// so every hit is validated with netip.ParseAddr before being believed.
var ip6RE = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b`)

// dialNetwork picks the transport for a pinned check.
//
// The unpinned case stays "tcp4" on purpose. The existing egress checks are an
// IPv4 proof, and letting them silently drift onto IPv6 would change what a
// passing check means rather than adding coverage.
func dialNetwork(pin netip.Addr) string {
	switch {
	case pin.Is4() || pin.Is4In6():
		return "tcp4"
	case pin.Is6():
		return "tcp6"
	default:
		return "tcp4"
	}
}

// Verify runs the client-side proof matrix and reports each check. It returns a
// non-nil error when any check failed, so it works as a single exit-code gate.
func Verify(r linux.Runner, w io.Writer, o VerifyOptions) error {
	if o.Timeout <= 0 {
		o.Timeout = 25 * time.Second
	}
	if !o.Probe.IsValid() {
		o.Probe = netip.MustParseAddr(DefaultProbe)
	}
	var checks []Check

	add := func(name string, err error, okDetail string) {
		if err != nil {
			checks = append(checks, Check{Name: name, OK: false, Detail: err.Error()})
			return
		}
		checks = append(checks, Check{Name: name, OK: true, Detail: okDetail})
	}

	// Routing. Flush first so a stale PMTU/redirect exception cannot make a
	// hairpinned prefix read as on-link.
	_ = FlushRouteCache(r)

	protected, err := protectedSet(o.ExtraLANs)
	if err != nil {
		return err
	}
	add("lan-on-link", AssertLANsOnLink(r, protected, o.Gateway), formatPrefixes(protected))
	add("default-via-gateway", AssertDefaultViaGateway(r, o.Probe, o.Gateway), "via "+o.Gateway.String())
	add("single-default-route", AssertSingleDefaultRoute(r), "exactly one")

	// Egress identity: the response body of an echo endpoint is the public IP
	// the destination saw. Pinning the destination IP is what makes this a
	// proof -- otherwise a CDN can hand back a differently-classified address.
	if !o.SkipEgress {
		if o.ForeignEchoURL != "" {
			got, err := echoEgressRetry(o.ForeignEchoURL, o.ForeignIP, o.Timeout, 2)
			switch {
			case err != nil:
				add("egress-foreign", err, "")
			case o.ExpectFgnEgres != "" && got != o.ExpectFgnEgres:
				add("egress-foreign", fmt.Errorf("saw %s, expected %s (traffic did not take the tunnel)", got, o.ExpectFgnEgres), "")
			default:
				add("egress-foreign", nil, got)
			}
		}
		if o.RUEchoURL != "" {
			got, err := echoEgressRetry(o.RUEchoURL, o.RUIP, o.Timeout, 2)
			switch {
			case err != nil:
				add("egress-ru", err, "")
			case o.ExpectRUEgress != "" && got != o.ExpectRUEgress:
				add("egress-ru", fmt.Errorf("saw %s, expected %s (RU traffic should egress direct)", got, o.ExpectRUEgress), "")
			default:
				add("egress-ru", nil, got)
			}
		}
	}

	// A full-MSS transfer over the tunnel: this is what catches an MTU/MSS
	// black hole, which otherwise looks like a hang rather than an error.
	if !o.SkipLarge && o.LargeURL != "" {
		n, dur, err := download(o.LargeURL, 90*time.Second)
		switch {
		case err != nil:
			add("large-transfer", err, "")
		case o.LargeBytes > 0 && n < o.LargeBytes:
			add("large-transfer", fmt.Errorf("got %d of %d bytes in %s (MTU/MSS black hole?)", n, o.LargeBytes, dur.Round(time.Millisecond)), "")
		default:
			add("large-transfer", nil, fmt.Sprintf("%d bytes in %s", n, dur.Round(time.Millisecond)))
		}
	}

	// Direct-class throughput. Separate from the check above because the two
	// classes take entirely different paths and only one of them was covered.
	if !o.SkipDirect && o.DirectURL != "" {
		n, dur, err := downloadPinned(o.DirectURL, o.DirectIP, 45*time.Second)
		switch {
		case err != nil:
			add("large-transfer-direct", err, "")
		case n == 0:
			add("large-transfer-direct", fmt.Errorf("no data from %s", o.DirectURL), "")
		default:
			speed := int64(float64(n) / dur.Seconds())
			if o.MinDirectSpeed > 0 && speed < o.MinDirectSpeed {
				add("large-transfer-direct", fmt.Errorf(
					"%d bytes in %s = %d B/s, below the %d B/s floor -- the direct class is degraded (hairpin without SNAT?)",
					n, dur.Round(time.Millisecond), speed, o.MinDirectSpeed), "")
			} else {
				add("large-transfer-direct", nil, fmt.Sprintf("%d bytes in %s (%d B/s)",
					n, dur.Round(time.Millisecond), speed))
			}
		}
	}

	for _, name := range o.DNSNames {
		addrs, err := net.LookupHost(name)
		if err != nil {
			add("dns:"+name, err, "")
			continue
		}
		add("dns:"+name, nil, strings.Join(addrs, " "))
	}

	failed := 0
	for _, c := range checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(w, "%s  %-22s %s\n", mark, c.Name, c.Detail)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	fmt.Fprintf(w, "\nall %d checks passed\n", len(checks))
	return nil
}

// pinnedClient dials pin instead of resolving the URL's host, while leaving the
// Host header and TLS SNI intact -- the equivalent of curl --resolve.
func pinnedClient(pin netip.Addr, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if pin.IsValid() {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(pin.String(), port)
			}
			return dialer.DialContext(ctx, dialNetwork(pin), addr)
		},
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// echoEgressRetry retries once. A single transient timeout against a public
// endpoint would otherwise report a routing failure that does not exist, and a
// check that cries wolf stops being trusted.
func echoEgressRetry(rawURL string, pin netip.Addr, timeout time.Duration, attempts int) (string, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		got, err := echoEgress(rawURL, pin, timeout)
		if err == nil {
			return got, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("%d attempts: %w", attempts, lastErr)
}

// echoEgress fetches an IP-echo endpoint and returns the address it reports.
func echoEgress(rawURL string, pin netip.Addr, timeout time.Duration) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	client := pinnedClient(pin, timeout)
	resp, err := client.Get(u.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: http %d", u.Host, resp.StatusCode)
	}
	m := ipRE.Find(body)
	if m == nil {
		return "", fmt.Errorf("%s: no IPv4 address in response %q", u.Host, strings.TrimSpace(string(body)))
	}
	return string(m), nil
}

func download(rawURL string, timeout time.Duration) (int64, time.Duration, error) {
	return downloadPinned(rawURL, netip.Addr{}, timeout)
}

func downloadPinned(rawURL string, pin netip.Addr, timeout time.Duration) (int64, time.Duration, error) {
	client := pinnedClient(pin, timeout)
	start := time.Now()
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	return n, time.Since(start), err
}
