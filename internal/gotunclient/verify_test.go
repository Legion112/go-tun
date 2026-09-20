package gotunclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The RU echo answers with a quoted string; the foreign one with a bare IP.
// Both must yield the address.
func TestEchoEgress_ExtractsQuotedAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\"94.29.32.94\"\n")
	}))
	defer srv.Close()
	got, err := echoEgress(srv.URL, netip.Addr{}, 5*time.Second)
	if err != nil {
		t.Fatalf("echoEgress: %v", err)
	}
	if got != "94.29.32.94" {
		t.Fatalf("got %q", got)
	}
}

func TestEchoEgress_ExtractsBareAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "185.80.130.211")
	}))
	defer srv.Close()
	got, err := echoEgress(srv.URL, netip.Addr{}, 5*time.Second)
	if err != nil {
		t.Fatalf("echoEgress: %v", err)
	}
	if got != "185.80.130.211" {
		t.Fatalf("got %q", got)
	}
}

func TestEchoEgress_NoAddressInBodyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>blocked by captive portal</html>")
	}))
	defer srv.Close()
	_, err := echoEgress(srv.URL, netip.Addr{}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no IPv4 address") {
		t.Fatalf("err = %v", err)
	}
}

func TestEchoEgress_NonOKStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := echoEgress(srv.URL, netip.Addr{}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v", err)
	}
}

// A single transient failure must not be reported as a routing problem.
func TestEchoEgressRetry_SucceedsOnSecondAttempt(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			http.Error(w, "flaky", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "94.29.32.94")
	}))
	defer srv.Close()
	got, err := echoEgressRetry(srv.URL, netip.Addr{}, 5*time.Second, 2)
	if err != nil {
		t.Fatalf("retry should have recovered: %v", err)
	}
	if got != "94.29.32.94" {
		t.Fatalf("got %q", got)
	}
}

func TestEchoEgressRetry_ReportsAttemptCountWhenAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := echoEgressRetry(srv.URL, netip.Addr{}, 5*time.Second, 2)
	if err == nil || !strings.Contains(err.Error(), "2 attempts") {
		t.Fatalf("err = %v", err)
	}
}

func TestDownload_CountsBytes(t *testing.T) {
	body := strings.Repeat("x", 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()
	n, _, err := download(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if n != int64(len(body)) {
		t.Fatalf("got %d bytes, want %d", n, len(body))
	}
}

// A pin must override the URL's host without changing the Host header, so a
// name-based vhost still answers -- this is the curl --resolve equivalent that
// makes the egress check a proof rather than an observation.
func TestPinnedClient_PreservesHostHeader(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		fmt.Fprint(w, "1.2.3.4")
	}))
	defer srv.Close()

	// Point a bogus hostname at the test server's real address.
	addrPort, err := netip.ParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("parse test server addr: %v", err)
	}
	client := pinnedClient(addrPort.Addr(), 5*time.Second)
	url := fmt.Sprintf("http://example.invalid:%d/", addrPort.Port())
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(gotHost, "example.invalid") {
		t.Fatalf("Host header = %q, want the original hostname", gotHost)
	}
}

func TestVerify_ReportsFailuresAndReturnsError(t *testing.T) {
	restoreDetect(t)
	r := statusRunner(t)
	onLinkAll(r)
	// Default route still points at the ISP router, not the gotun gateway.
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaFlint
	var out strings.Builder
	err := Verify(r, &out, VerifyOptions{
		Gateway:    netip.MustParseAddr(testGW),
		Probe:      netip.MustParseAddr("1.1.1.1"),
		SkipEgress: true,
		SkipLarge:  true,
	})
	if err == nil {
		t.Fatal("want a non-nil error so the exit code is a usable gate")
	}
	if !strings.Contains(out.String(), "FAIL  default-via-gateway") {
		t.Fatalf("output should mark the failing check:\n%s", out.String())
	}
}

func TestVerify_AllPassingReturnsNil(t *testing.T) {
	restoreDetect(t)
	r := statusRunner(t)
	onLinkAll(r)
	r.Outputs["ip -4 route get 1.1.1.1"] = routeGetViaGotun
	var out strings.Builder
	err := Verify(r, &out, VerifyOptions{
		Gateway:    netip.MustParseAddr(testGW),
		Probe:      netip.MustParseAddr("1.1.1.1"),
		SkipEgress: true,
		SkipLarge:  true,
	})
	if err != nil {
		t.Fatalf("want pass, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "all 3 checks passed") {
		t.Fatalf("output:\n%s", out.String())
	}
}
