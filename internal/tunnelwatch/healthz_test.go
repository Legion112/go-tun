package tunnelwatch

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func get(t *testing.T, h http.Handler, method, path string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Result()
}

// The probe's whole job is to be a discriminator, so the two answers have to
// come from the watchdog's acted-upon belief rather than from the fact that a
// web server is running.
func TestAliveHandler_ReflectsTheActedUponBelief(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want int
		body string
	}{
		{
			name: "carrying traffic",
			snap: Snapshot{TunnelUp: true, Verdict: Healthy},
			want: http.StatusOK,
			body: "up",
		},
		{
			name: "route withdrawn",
			snap: Snapshot{TunnelUp: false, Verdict: Unhealthy, Reason: "probe failed"},
			want: http.StatusServiceUnavailable,
			body: "down",
		},
		{
			// A single failure does not withdraw the route, so the two
			// deliberately disagree for a while. The phone must follow the
			// route, not the probe: flapping it direct on one bad check would
			// leak on every transient.
			name: "unhealthy but not yet failed over",
			snap: Snapshot{TunnelUp: true, Verdict: Unhealthy, Reason: "probe failed (1/3)"},
			want: http.StatusOK,
			body: "up",
		},
		{
			// Acting on Unknown is how a watchdog turns a working network into
			// a broken one. Here it would be worse than inert: a 503 would send
			// the phone direct because of uncertainty.
			name: "inconclusive",
			snap: Snapshot{TunnelUp: true, Verdict: Unknown, Reason: "probe cancelled"},
			want: http.StatusOK,
			body: "up",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := AliveHandler(func() Snapshot { return tc.snap })
			resp := get(t, h, http.MethodGet, AlivePath)
			if resp.StatusCode != tc.want {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.want)
			}
			buf := make([]byte, 64)
			n, _ := resp.Body.Read(buf)
			if got := strings.TrimSpace(string(buf[:n])); got != tc.body {
				t.Errorf("body %q, want %q", got, tc.body)
			}
		})
	}
}

// The endpoint is published to the internet through every NAT in front of the
// gateway, so the body must not describe the transport to whoever asks. The
// reason is already in the log.
func TestAliveHandler_SaysNothingBeyondUpOrDown(t *testing.T) {
	h := AliveHandler(func() Snapshot {
		return Snapshot{TunnelUp: false, Verdict: Unhealthy, Reason: "probe to 1.1.1.1:443 via xray0 failed"}
	})
	resp := get(t, h, http.MethodGet, AlivePath)
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	for _, leak := range []string{"xray0", "1.1.1.1", "probe"} {
		if strings.Contains(body, leak) {
			t.Errorf("body leaks %q: %q", leak, body)
		}
	}
}

// iOS matches the rule only on a 200 fetched without a redirect, so anything
// clever here -- a redirect to a status page, a 204, a cached answer -- turns
// the rule off rather than failing visibly.
func TestAliveHandler_IsPlainAndUncacheable(t *testing.T) {
	h := AliveHandler(func() Snapshot { return Snapshot{TunnelUp: true} })
	resp := get(t, h, http.MethodGet, AlivePath)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("must not redirect, got Location %q", loc)
	}
	if resp := get(t, h, http.MethodPost, AlivePath); resp.StatusCode == http.StatusOK {
		t.Error("POST must not read as alive")
	}
	if resp := get(t, h, http.MethodGet, "/"); resp.StatusCode == http.StatusOK {
		t.Error("only the probe path answers")
	}
}

// A watchdog that has not probed yet must not read as down. Otherwise every
// restart sends the phone direct for one probe interval, which is a leak caused
// by a deploy rather than by a failure.
func TestWatcher_SnapshotBeforeTheFirstProbeIsUp(t *testing.T) {
	w := New(nil, nil, nil, Config{Iface: "wg-exit", Target: "1.1.1.1:443"}, discardLogger())
	s := w.Snapshot()
	if !s.TunnelUp {
		t.Error("a watcher that has not probed yet must report the belief the initial apply installed")
	}
	if s.Verdict != Unknown {
		t.Errorf("verdict before the first probe should be unknown, got %s", s.Verdict)
	}
}

func TestProbeURLHint(t *testing.T) {
	if got := ProbeURLHint("vpn.example.net", ":8443"); got != "http://vpn.example.net:8443/alive" {
		t.Errorf("got %q", got)
	}
	if got := ProbeURLHint("vpn.example.net", "nonsense"); got != "" {
		t.Errorf("want empty for an unparseable address, got %q", got)
	}
}
