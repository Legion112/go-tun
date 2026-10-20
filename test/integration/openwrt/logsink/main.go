// logsink replaces OpenWrt's logd inside the deploy lab.
//
// logd cannot be used here. It opens the kernel ring buffer and blocks reading
// it; in a container that buffer belongs to the host and is quiet, so logd
// never reaches its own event loop and never accepts on /dev/log. Every syslog
// writer then blocks in connect() -- including procd, which stops answering its
// ubus "service" object, at which point `/etc/init.d/x start` hangs forever and
// the whole lab is unusable. Whether logd wedges depends on the host's kernel
// log state, so keeping it would make the lab pass or hang depending on the
// machine -- green here, hung in CI.
//
// So the image removes logd and runs this instead. It appends what it receives
// to a file, which is easier to assert on than `logread` and is what carries
// procd's own messages and each service's stdout and stderr, since procd routes
// those to syslog and never to the container's stdout.
//
// The socket is a datagram socket because that is what syslog(3) reaches for
// first, and because a datagram sink cannot wedge a writer the way logd did:
// there is no connect to block in and no accept to go missing.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	sock := flag.String("socket", "/dev/log", "unix datagram socket to receive syslog on")
	out := flag.String("out", "/var/log/messages", "file to append messages to")
	flag.Parse()

	// A stale socket file from a previous run makes Listen fail with "address
	// already in use" even though nothing holds it.
	if err := os.Remove(*sock); err != nil && !os.IsNotExist(err) {
		log.Fatalf("logsink: remove %s: %v", *sock, err)
	}

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("logsink: open %s: %v", *out, err)
	}
	defer f.Close()

	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: *sock, Net: "unixgram"})
	if err != nil {
		log.Fatalf("logsink: listen %s: %v", *sock, err)
	}
	// Services run as other users than root, and they still have to be able to
	// log; the socket is created with the process umask, which is stricter.
	if err := os.Chmod(*sock, 0o666); err != nil {
		log.Fatalf("logsink: chmod %s: %v", *sock, err)
	}
	fmt.Fprintf(os.Stderr, "logsink: receiving on %s, appending to %s\n", *sock, *out)

	buf := make([]byte, 64*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			msg := buf[:n]
			f.Write(msg)
			if msg[n-1] != '\n' {
				f.Write([]byte{'\n'})
			}
		}
		if err != nil {
			log.Fatalf("logsink: read: %v", err)
		}
	}
}
