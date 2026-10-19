package ikev2

import (
	"fmt"
	"net/netip"
	"strings"
)

// renderConnection emits the one road-warrior connection.
//
// One connection for everybody, accepting any identity that has a secret. A
// connection per user would be needed only to pin each person a fixed address,
// and that is not needed to tell them apart: charon prints the EAP identity of
// every SA next to the address it handed out, so `--list-sas` answers "who is
// this" and `--terminate --ike-id` ends exactly one person's session. The
// per-user form also duplicated the whole 52-entry selector list per user.
//
// Every key sits on its own line, which is not style. A strongswan.conf value
// extends to the end of its line, so `local-1 { auth = pubkey  id = x }`
// parses auth as "pubkey  id = x }" and the connection is discarded with
// "invalid value for: auth" -- an error that reads like an unsupported auth
// method rather than a syntax mistake.
func renderConnection(c Config, ts []string) string {
	var b strings.Builder
	b.WriteString("connections {\n  phone {\n")
	b.WriteString("    version = 2\n")
	b.WriteString("    pools = phone-pool\n")
	// encap forces UDP 4500 rather than leaving it to NAT detection. The real
	// path crosses two NATs, so production is always encapsulated; a gateway
	// that negotiated raw ESP when it happened to see no NAT would be a
	// different path from the one that was tested.
	b.WriteString("    encap = yes\n")
	fmt.Fprintf(&b, "    proposals = %s\n", c.IKEProposals)
	// MOBIKE is what survives Wi-Fi to LTE, which is the single most common
	// thing a phone does. It is on by default; it is named here so that
	// turning it off is a visible decision.
	b.WriteString("    mobike = yes\n")
	fmt.Fprintf(&b, "    dpd_delay = %s\n", dpdDelay(c.DPDRate))
	b.WriteString("    send_cert = always\n")
	b.WriteString("    local-1 {\n")
	b.WriteString("      auth = pubkey\n")
	fmt.Fprintf(&b, "      certs = %s\n", c.ServerCert)
	fmt.Fprintf(&b, "      id = %s\n", c.GatewayID)
	b.WriteString("    }\n")
	// EAP-MSCHAPv2 rather than a PSK: iOS stores the password in the keychain
	// after the first connect, so On-Demand needs no prompt, and there is no
	// shared secret to end up in a generated profile.
	//
	// eap_id = %any accepts whichever identity has a secret, which is what
	// makes `gotun ikev2 user add` able to issue and withdraw people without
	// touching this connection at all.
	b.WriteString("    remote-1 {\n")
	b.WriteString("      auth = eap-mschapv2\n")
	b.WriteString("      eap_id = %any\n")
	b.WriteString("    }\n")
	b.WriteString("    children {\n")
	b.WriteString("      phone {\n")
	// if_id is what makes this route-based. Without it charon installs XFRM
	// policies and no interface, decrypted packets surface on the physical WAN
	// device, and gotun's inbound model -- -mark-iface and the home_nets
	// forward rule, both interface-named -- has nothing to attach to.
	fmt.Fprintf(&b, "        if_id_in = %s\n", c.IfID)
	fmt.Fprintf(&b, "        if_id_out = %s\n", c.IfID)
	fmt.Fprintf(&b, "        local_ts = %s\n", strings.Join(ts, ","))
	fmt.Fprintf(&b, "        esp_proposals = %s\n", c.ESPProposals)
	b.WriteString("        mode = tunnel\n")
	b.WriteString("        start_action = none\n")
	b.WriteString("      }\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n}\n\n")
	return b.String()
}

// renderPool emits the pool a connection hands addresses out of.
//
// The resolver address has to be inside the selectors the same call produced,
// or the phone resolves through whatever network it is attached to and every
// GeoDNS answer is quietly wrong while the tunnel stays healthy. Validate
// refuses a configuration where it is not.
func renderPool(c Config, name, addrs string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pools {\n  %s {\n    addrs = %s\n    dns = %s\n  }\n}\n\n",
		name, addrs, c.VIPGateway)
	return b.String()
}

// RenderSwanctl emits the gateway half: one road-warrior connection, the
// virtual-IP pool, and the narrowed traffic selectors.
//
// Credentials are not here. `gotun ikev2 user add` writes one file per person
// into the same conf.d directory, each carrying nothing but a secret, so
// issuing and withdrawing people never touches this file.
func RenderSwanctl(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	c.withDefaults()

	ts := SelectorStrings(c)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", selectorPreamble(len(ts)))
	b.WriteString(renderConnection(c, ts))
	b.WriteString(renderPool(c, "phone-pool", c.Pool.String()))

	// Deliberately not generated here: a credential in a file this tool writes
	// alongside a configuration is a credential in the operator's editor and
	// their backups. `user add` writes one, into a 0600 file that is nothing
	// but the credential, and prints the secret once.
	fmt.Fprintf(&b, `# No credential here. Add people with:
#
#   gotun ikev2 user add <name>
#
# which writes a 0600 snippet beside this file and prints the password once.
# For a single user with no credential management, by hand:
#
# secrets {
#   eap-%s {
#     id = %s
#     secret = <the password you typed into the phone>
#   }
# }
`, c.ClientID, c.ClientID)

	return b.String(), nil
}

const timeLayout = "2006-01-02T15:04:05Z07:00"

func selectorPreamble(n int) string {
	return fmt.Sprintf(`# The traffic selectors below are the only thing deciding what the phone
# tunnels: Apple's IKEv2 payload carries no routes, and iOS ignores
# split-exclude attributes, so "everything except private space" has to be sent
# as the positive selectors that remain.
#
# They are prefixes rather than ranges deliberately. A selector is a range on
# the wire and the range form is four entries instead of %d, but a client that
# rounds each range up to its smallest covering prefix turns a range spanning
# 10/8 into a 0.0.0.0/1 route and swallows its own LAN. charon's client does
# exactly that.`, n)
}

// dpdDelay translates Apple's coarse rate into the gateway's interval, so the
// two ends agree about how fast a dead peer is noticed.
//
// They do not have to match -- each side runs its own DPD -- but a gateway
// holding a dead SA for half an hour while the phone gave up after a minute
// means the phone's reconnect races the gateway's stale state.
func dpdDelay(rate string) string {
	switch rate {
	case DPDLow:
		return "1800s"
	case DPDMedium:
		return "600s"
	case DPDNone:
		return "0s"
	default:
		return "60s"
	}
}

// SelectorStrings renders the selectors the way swanctl's local_ts expects, for
// callers that want the list without the surrounding configuration.
func SelectorStrings(c Config) []string {
	sel := c.Selectors()
	out := make([]string, 0, len(sel))
	for _, p := range sel {
		out = append(out, p.String())
	}
	return out
}

// SelectorPrefixes exposes the same decision in kernel form.
func SelectorPrefixes(c Config) []netip.Prefix { return c.Selectors() }
