package ikev2

import (
	"fmt"
	"net/netip"
	"strings"
)

// connParams is what differs between the two shapes of generated gateway
// configuration.
//
// The shared-connection shape accepts any identity that has a secret; the
// per-user shape pins one identity to one connection, which is what makes a
// fixed virtual IP possible at all -- strongSwan's pools are per-connection
// and not identity-aware, so one connection with several pools hands out
// whichever address is free rather than the user's own.
type connParams struct {
	Name     string // connection and child section name
	Pool     string // pool section name
	RemoteID string // identity to expect; "%any" accepts anyone with a secret
}

// renderConnection emits one connection block.
//
// Shared by both shapes on purpose: the traffic selectors are the single
// decision this package exists to make, and two renderers would eventually
// disagree about them while every test still passed.
//
// Every key sits on its own line, which is not style. A strongswan.conf value
// extends to the end of its line, so `local-1 { auth = pubkey  id = x }`
// parses auth as "pubkey  id = x }" and the connection is discarded with
// "invalid value for: auth" -- an error that reads like an unsupported auth
// method rather than a syntax mistake.
func renderConnection(c Config, p connParams, ts []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "connections {\n  %s {\n", p.Name)
	b.WriteString("    version = 2\n")
	fmt.Fprintf(&b, "    pools = %s\n", p.Pool)
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
	// shared secret to end up in a generated profile. eap_id defaults to id,
	// so naming the identity once pins both the IKE identity the phone sends
	// and the EAP identity it authenticates with.
	b.WriteString("    remote-1 {\n")
	b.WriteString("      auth = eap-mschapv2\n")
	fmt.Fprintf(&b, "      id = %s\n", p.RemoteID)
	b.WriteString("    }\n")
	b.WriteString("    children {\n")
	fmt.Fprintf(&b, "      %s {\n", p.Name)
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

// RenderSwanctl emits the single-user gateway half: one road-warrior connection
// accepting any identity that has a secret, the virtual-IP pool, and the
// narrowed traffic selectors.
//
// For more than one person prefer `gotun ikev2 user add`, which writes a
// connection per user and so can pin each one a fixed address and revoke them
// individually. The two shapes must not share a conf.d directory: they would
// both match, and which connection charon selected would be an accident.
func RenderSwanctl(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	c.withDefaults()

	ts := SelectorStrings(c)
	var b strings.Builder
	fmt.Fprintf(&b, `%s
# Single-user shape: one connection accepting any identity that has a secret.
# For several people use "gotun ikev2 user add", which gives each one its own
# connection, a fixed virtual IP and a credential you can revoke on its own.

`, selectorPreamble(len(ts)))
	b.WriteString(renderConnection(c, connParams{
		Name:     "phone",
		Pool:     "phone-pool",
		RemoteID: "%any",
	}, ts))
	b.WriteString(renderPool(c, "phone-pool", c.Pool.String()))

	// Deliberately not generated here: a credential in a file this tool writes
	// is a credential in the operator's shell history, their editor's swap file
	// and their backups. `user add` does write one, into a 0600 file that is
	// nothing but the credential, and prints the secret once.
	fmt.Fprintf(&b, `# Add the EAP credential by hand, in /etc/swanctl/swanctl.conf or a file
# beside it. It is not generated:
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

// RenderUser emits one user's whole gateway half: their connection, their
// single-address pool, and their secret.
//
// All three in one file so that revocation is a delete rather than an edit --
// nothing has to parse and rewrite a configuration that is currently
// authenticating other people.
func RenderUser(c Config, u User, secret string) (string, error) {
	if err := ValidateUserName(u.Name); err != nil {
		return "", err
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	c.withDefaults()
	if !u.VIP.IsValid() {
		return "", fmt.Errorf("ikev2: user %q has no virtual IP", u.Name)
	}
	if !c.Pool.Contains(u.VIP) {
		return "", fmt.Errorf("ikev2: user %q's address %v is outside the pool %v",
			u.Name, u.VIP, c.Pool)
	}
	if secret == "" {
		return "", fmt.Errorf("ikev2: user %q has no secret", u.Name)
	}

	ts := SelectorStrings(c)
	pool := "pool-" + u.Name

	var b strings.Builder
	// The header is what List reads back. Deriving the name and address from
	// the body instead would mean parsing swanctl.conf syntax to answer "who
	// exists", and getting that wrong hands a second user an address already
	// in use.
	fmt.Fprintf(&b, "%s%s\n%s%s\n%s%s\n",
		hdrName, u.Name, hdrVIP, u.VIP, hdrCreated, u.Created.UTC().Format(timeLayout))
	fmt.Fprintf(&b, `#
# Generated by gotun ikev2 user add. THIS FILE IS A CREDENTIAL: mode 0600, and
# it does not belong in a repository or a backup that others can read.
#
# Revoking %s means deleting this file AND reloading AND terminating the live
# session. The first two alone do not revoke anything: the connection does not
# reauthenticate, so an established session rekeys without consulting the
# secret and survives indefinitely. Measured; see docs/ikev2-phone.md.
#
#   gotun ikev2 user revoke %s
#
%s

`, u.Name, u.Name, selectorPreamble(len(ts)))

	b.WriteString(renderConnection(c, connParams{
		Name:     u.Name,
		Pool:     pool,
		RemoteID: u.Name,
	}, ts))
	// A single-address pool is what pins the address to this user, and the
	// connection being per-user is what makes the pool reachable only by them.
	b.WriteString(renderPool(c, pool, u.VIP.String()+"/32"))
	fmt.Fprintf(&b, "secrets {\n  eap-%s {\n    id = %s\n    secret = \"%s\"\n  }\n}\n",
		u.Name, u.Name, secret)
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
