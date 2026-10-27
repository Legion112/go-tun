package dnswatch

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

var live = Config{
	Filter:   "127.0.0.1:3053",
	Resolver: "127.0.0.2:53",
	Fallback: "77.88.8.8:53",
}

func TestChain_DropsOnlyWhatIsDown(t *testing.T) {
	for _, c := range []struct {
		name             string
		filter, resolver bool
		want             []string
	}{
		{"healthy", true, true, []string{"127.0.0.1:3053", "127.0.0.2:53", "77.88.8.8:53"}},
		{"filter down", false, true, []string{"127.0.0.2:53", "77.88.8.8:53"}},
		// The filter's only upstream is the resolver, so it goes too.
		{"resolver down", true, false, []string{"77.88.8.8:53"}},
		{"both down", false, false, []string{"77.88.8.8:53"}},
	} {
		if got := Chain(live, c.filter, c.resolver); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestChain_WithoutAFilterIsTodaysList(t *testing.T) {
	c := live
	c.Filter = ""
	if got := Chain(c, false, true); !slices.Equal(got, []string{"127.0.0.2:53", "77.88.8.8:53"}) {
		t.Errorf("got %v", got)
	}
}

func TestServerLine_SpeaksDnsmasq(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.2:53":   "127.0.0.2",
		"127.0.0.1:3053": "127.0.0.1#3053",
		"[::1]:5353":     "::1#5353",
		// A wildcard listen is reached over loopback from the same box.
		":53":        "127.0.0.1",
		"0.0.0.0:53": "127.0.0.1",
		"[::]:53":    "::1",
	} {
		got, err := ServerLine(in)
		if err != nil || got != want {
			t.Errorf("ServerLine(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"127.0.0.2", "dns.example:53", "127.0.0.1:0", "127.0.0.1:x"} {
		if _, err := ServerLine(bad); err == nil {
			t.Errorf("ServerLine(%q) accepted", bad)
		}
	}
}

func TestTracker_Hysteresis(t *testing.T) {
	tr := tracker{up: true}
	if tr.observe(false, 2, 3) {
		t.Fatal("one failure took it down")
	}
	if !tr.observe(false, 2, 3) || tr.up {
		t.Fatal("two failures did not take it down")
	}
	tr.observe(true, 2, 3)
	tr.observe(false, 2, 3) // a relapse restarts the count
	tr.observe(true, 2, 3)
	if tr.observe(true, 2, 3) {
		t.Fatal("recovered on a broken streak")
	}
	if !tr.observe(true, 2, 3) || !tr.up {
		t.Fatal("three successes did not bring it back")
	}
}

// fakeHops answers probes from a table the test flips.
type fakeHops map[string]bool

func (f fakeHops) probe(_ context.Context, addr, _ string) error {
	if f[addr] {
		return nil
	}
	return errors.New("down")
}

func newTestWatcher(t *testing.T, hops fakeHops) (*Watcher, string, *int) {
	t.Helper()
	cfg := live
	cfg.ServersFile = filepath.Join(t.TempDir(), "dnsmasq.servers")
	w := New(cfg, hops.probe, log.New(io.Discard, "", 0))
	hups := 0
	w.hup = func() error { hups++; return nil }
	return w, cfg.ServersFile, &hups
}

func servers(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if s, ok := strings.CutPrefix(l, "server="); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestWatcher_FailsOverAndBack(t *testing.T) {
	hops := fakeHops{"127.0.0.1:3053": true, "127.0.0.2:53": true}
	w, file, hups := newTestWatcher(t, hops)
	ctx := context.Background()

	step := func() {
		if err := w.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	step()
	if got := servers(t, file); !slices.Equal(got, []string{"127.0.0.1#3053", "127.0.0.2", "77.88.8.8"}) {
		t.Fatalf("healthy: %v", got)
	}
	if *hups != 1 {
		t.Fatalf("hups=%d after the first write", *hups)
	}
	step()
	if *hups != 1 {
		t.Fatal("signalled dnsmasq with nothing changed; a SIGHUP clears its cache")
	}

	hops["127.0.0.1:3053"] = false
	step()
	if got := servers(t, file); got[0] != "127.0.0.1#3053" {
		t.Fatalf("one failed probe already removed the filter: %v", got)
	}
	step()
	if got := servers(t, file); !slices.Equal(got, []string{"127.0.0.2", "77.88.8.8"}) {
		t.Fatalf("filter down: %v", got)
	}

	hops["127.0.0.1:3053"] = true
	step()
	step()
	step()
	if got := servers(t, file); !slices.Equal(got, []string{"127.0.0.1#3053", "127.0.0.2", "77.88.8.8"}) {
		t.Fatalf("filter back: %v", got)
	}
}

// gotun-dns answering .ru but not the tunnel is not healthy: everything
// foreign would time out at it before reaching the fallback.
func TestWatcher_ResolverMustAnswerBothPaths(t *testing.T) {
	w, file, _ := newTestWatcher(t, nil)
	w.probe = func(_ context.Context, addr, name string) error {
		if addr == "127.0.0.2:53" && name == DefaultExitCanary {
			return errors.New("SERVFAIL")
		}
		return nil
	}
	for range 2 {
		if err := w.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := servers(t, file); !slices.Equal(got, []string{"77.88.8.8"}) {
		t.Fatalf("got %v", got)
	}
}

func TestWatcher_RepairsAFileSomeoneElseChanged(t *testing.T) {
	w, file, _ := newTestWatcher(t, fakeHops{"127.0.0.1:3053": true, "127.0.0.2:53": true})
	if err := os.WriteFile(file, []byte("server=8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := w.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := servers(t, file); len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestWatcher_StoppingLeavesTheFullList(t *testing.T) {
	w, file, _ := newTestWatcher(t, fakeHops{}) // everything down
	w.cfg.Interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := servers(t, file); !slices.Equal(got, []string{"127.0.0.1#3053", "127.0.0.2", "77.88.8.8"}) {
		t.Fatalf("got %v", got)
	}
}

// The real probe, against a real socket: an answer and NXDOMAIN count, SERVFAIL
// and silence do not.
func TestDNSProbe(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := &dns.Msg{Data: append([]byte(nil), buf[:n]...)}
			if req.Unpack() != nil {
				continue
			}
			name := req.Question[0].Header().Name
			if name == "silent." {
				continue
			}
			m := req.Copy()
			dnsutil.SetReply(m, req)
			switch name {
			case "missing.":
				m.Rcode = dns.RcodeNameError
			case "broken.":
				m.Rcode = dns.RcodeServerFailure
			}
			m.Data = nil
			if m.Pack() == nil {
				_, _ = pc.WriteTo(m.Data, from)
			}
		}
	}()
	addr := pc.LocalAddr().String()
	for name, wantOK := range map[string]bool{
		"fine.": true, "missing.": true, "broken.": false, "silent.": false,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		err := DNSProbe(ctx, addr, name)
		cancel()
		if (err == nil) != wantOK {
			t.Errorf("%s: err=%v, want ok=%v", name, err, wantOK)
		}
	}
}
