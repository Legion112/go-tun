package dnsproxy

// Path selects which upstream egress policy to use for a query.
type Path int

const (
	// PathDirect resolves without the tunnel (RU-side perspective).
	PathDirect Path = iota
	// PathExit resolves via the WireGuard exit hop (SO_MARK).
	PathExit
)

func (p Path) String() string {
	switch p {
	case PathDirect:
		return "direct"
	case PathExit:
		return "exit"
	default:
		return "unknown"
	}
}

// Classifier decides Direct vs Exit for a DNS question name.
type Classifier interface {
	Classify(name string) Path
}

// Defaults gotun-dns listens and resolves direct names with. They are here
// rather than in its main because `gotun dnswatch` watches the one and falls
// back to the other, and two copies of an address can disagree.
const (
	DefaultListen         = "127.0.0.2:53"
	DefaultDirectUpstream = "77.88.8.8:53"
)
