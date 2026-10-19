package tunnelwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// AlivePath is the probe endpoint. It is what a phone's On-Demand
// URLStringProbe points at.
const AlivePath = "/alive"

// AliveHandler answers the phone's on-demand probe with the watchdog's belief
// about the exit hop.
//
// This is the piece that makes client-side fail-open mean something. An
// endpoint that answers 200 whenever the web server is up tells the phone to
// connect into a tunnel whose exit may be dead, and gotun's route-level
// fail-open then sends that traffic out the local uplink -- silently, which the
// deploy notes already name as the one symptom you have to go looking for.
// Keyed on the watchdog instead, a dead exit hop becomes a VPN icon that is
// visibly off.
//
// Three deliberate properties:
//
//   - **The body says only "up" or "down".** This endpoint is published to the
//     internet through every NAT in front of the gateway, so a stranger can
//     read it. The reason belongs in the log, where it is already written.
//   - **The status keys on TunnelUp, not on the latest verdict.** An
//     inconclusive check is not evidence -- acting on Unknown is how a watchdog
//     turns a working network into a broken one -- and a 503 there would push
//     the phone direct because of uncertainty rather than because of a failure.
//   - **No caching.** iOS needs a 200 with no redirect; a cached 200 would keep
//     the phone dialling a tunnel that died minutes ago.
func AliveHandler(snapshot func() Snapshot) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(AlivePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		s := snapshot()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !s.TunnelUp {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("down\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("up\n"))
	})
	return mux
}

// ServeAlive runs the probe endpoint until ctx is done.
//
// It never fails the caller: a watchdog that refused to start because a probe
// port was taken would trade the thing that matters for the thing that reports
// on it. A bind failure is logged and the loop carries on, which the phone sees
// as an unreachable probe and therefore as "go direct" -- the safe reading.
func ServeAlive(ctx context.Context, addr string, snapshot func() Snapshot, logf func(string, ...any)) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logf("health endpoint not listening on %s: %v (the phone will read this as"+
			" 'gateway unreachable' and stay direct)", addr, err)
		return
	}
	srv := &http.Server{
		Handler:           AliveHandler(snapshot),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	logf("health endpoint listening on %s%s", addr, AlivePath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logf("health endpoint stopped: %v", err)
	}
}

// ProbeURLHint is the URL to put in the phone's profile, given the public
// address the gateway is reachable at.
func ProbeURLHint(publicHost string, addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	return fmt.Sprintf("http://%s%s", net.JoinHostPort(publicHost, port), AlivePath)
}
