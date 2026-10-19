package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	listen := flag.String("listen", ":8080", "listen address")
	body := flag.String("body", "", "response body for GET / and GET /id")
	flag.Parse()
	if *body == "" {
		fmt.Fprintln(os.Stderr, "labhttp: -body is required")
		os.Exit(2)
	}

	mux := http.NewServeMux()
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(*body))
	}
	mux.HandleFunc("/", h)
	mux.HandleFunc("/id", h)
	mux.HandleFunc("/peer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		_, _ = w.Write([]byte(host))
	})

	// /bulk exists for the MTU question, which an identity check cannot ask.
	// Two stacked tunnels (ESP-in-UDP inside a 1400-byte tun) drop large
	// segments while ICMP and short replies stay perfect, so a test that only
	// fetches /id passes on a path where nothing real works.
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, r *http.Request) {
		n := 1 << 20
		if q := r.URL.Query().Get("bytes"); q != "" {
			v, err := strconv.Atoi(q)
			if err != nil || v < 0 {
				http.Error(w, "bad bytes", http.StatusBadRequest)
				return
			}
			n = v
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := make([]byte, 32<<10)
		for i := range buf {
			buf[i] = byte('a' + i%26)
		}
		for n > 0 {
			chunk := buf
			if n < len(chunk) {
				chunk = chunk[:n]
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
			n -= len(chunk)
		}
	})

	log.Printf("labhttp listening on %s body=%q", *listen, *body)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}
