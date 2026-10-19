package ikev2

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
)

// uuidNamespace is a fixed namespace for name-based UUIDs. Its value is
// arbitrary; what matters is that it never changes, because the UUIDs derived
// from it are the phone's identity for this profile.
var uuidNamespace = [16]byte{
	0x4f, 0x1a, 0x8e, 0x7c, 0x2b, 0x93, 0x4d, 0x56,
	0xa1, 0x08, 0xd3, 0x62, 0x5e, 0x9f, 0x11, 0x74,
}

// deterministicUUID derives an RFC 4122 version 5 UUID from a name.
//
// Deterministic on purpose. iOS keys an installed profile by its PayloadUUID,
// so a freshly random one on every run makes a second VPN entry appear beside
// the first instead of replacing it -- and the operator then has two profiles
// with the same display name and no way to tell which one On-Demand is using.
func deterministicUUID(name string) string {
	h := sha1.New()
	h.Write(uuidNamespace[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// EncodeProfile builds the .mobileconfig an iPhone installs.
//
// What is deliberately absent matters as much as what is present:
//
//   - **No VPNType AlwaysOn.** Supervised Always-On VPN blocks traffic when the
//     tunnel is down. That is the opposite of the requirement, and it is a
//     single key away.
//   - **No AuthPassword.** A profile carrying the EAP password is a credential
//     in a file that gets AirDropped or emailed to a phone and then sits in
//     Downloads. iOS stores the password in the keychain after the first manual
//     connect, so On-Demand works unattended from then on without it.
//   - **No routes.** There is no key for them. Routing comes entirely from the
//     traffic selectors the gateway narrows to, which is why Config.Selectors
//     is the single source of truth and why this function cannot contradict it.
//   - **No crypto parameters.** iOS proposes a sane default set; the gateway's
//     proposals are broad enough to meet it. Pinning both ends from here would
//     turn a mismatch into "no proposal chosen" on the phone, with nothing to
//     read.
func EncodeProfile(c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.withDefaults()

	// Avoid "com.example.gotun.gotun" when the profile is simply called after
	// the tool. The identifier is what iOS shows under the profile's details,
	// and a doubled component reads like a bug in the generator.
	profileID := c.Identifier
	if name := sanitizeID(c.ProfileName); !strings.HasSuffix(profileID, "."+name) {
		profileID += "." + name
	}
	vpnID := profileID + ".vpn"

	p := &plist{}
	p.header()
	p.openDict(0) // root

	p.key(1, "PayloadContent")
	p.raw(1, "<array>")
	p.openDict(2) // the VPN payload

	p.str(3, "PayloadType", "com.apple.vpn.managed")
	p.num(3, "PayloadVersion", 1)
	p.str(3, "PayloadIdentifier", vpnID)
	p.str(3, "PayloadUUID", deterministicUUID(vpnID))
	p.str(3, "PayloadDisplayName", c.ProfileName)
	p.str(3, "UserDefinedName", c.ProfileName)
	p.str(3, "VPNType", "IKEv2")

	p.key(3, "IKEv2")
	p.openDict(3)
	p.str(4, "RemoteAddress", c.Server)
	// RemoteIdentifier must equal a subjectAltName on the gateway certificate.
	// iOS authenticates the server and then checks this separately, so a
	// mismatch fails after a successful handshake -- which reads as a crypto
	// problem rather than a naming one.
	p.str(4, "RemoteIdentifier", c.GatewayID)
	p.str(4, "LocalIdentifier", c.ClientID)
	// AuthenticationMethod None plus ExtendedAuthEnabled is EAP: the gateway
	// proves itself with a certificate, the phone with a username and
	// password. Certificate client auth would need a second payload carrying a
	// PKCS#12, which this tool does not generate for the same reason it does
	// not generate the password.
	p.str(4, "AuthenticationMethod", "None")
	p.num(4, "ExtendedAuthEnabled", 1)
	p.str(4, "AuthName", c.ClientID)
	p.str(4, "DeadPeerDetectionRate", c.DPDRate)
	p.num(4, "DisableMOBIKE", 0)
	p.num(4, "DisableRedirect", 0)
	p.num(4, "EnablePFS", 1)
	p.num(4, "EnableCertificateRevocationCheck", 0)
	// The two keys that are the whole battery argument: the NAT keepalive is
	// handed to hardware, so the application processor does not wake to send
	// it while the phone sleeps. A WireGuard NetworkExtension cannot have
	// this; its keepalive is a userspace timer.
	p.num(4, "NATKeepAliveOffloadEnable", 1)
	p.num(4, "NATKeepAliveInterval", c.KeepAliveInterval)
	p.closeDict(3)

	// Connected by hand when on-demand is off, and the rules are omitted
	// entirely rather than left present-but-inert: a rule list that is not
	// being evaluated is the kind of thing somebody later reads as the
	// behaviour and is wrong about.
	if c.OnDemandDisabled {
		p.num(3, "OnDemandEnabled", 0)
	} else {
		p.num(3, "OnDemandEnabled", 1)
		p.key(3, "OnDemandRules")
		p.raw(3, "<array>")
		for _, r := range onDemandRules(c) {
			p.openDict(4)
			p.str(5, "Action", r.action)
			if r.interfaceType != "" {
				p.str(5, "InterfaceTypeMatch", r.interfaceType)
			}
			if len(r.ssids) > 0 {
				p.key(5, "SSIDMatch")
				p.raw(5, "<array>")
				for _, s := range r.ssids {
					p.raw(6, "<string>"+escape(s)+"</string>")
				}
				p.raw(5, "</array>")
			}
			if r.urlProbe != "" {
				p.str(5, "URLStringProbe", r.urlProbe)
			}
			p.closeDict(4)
		}
		p.raw(3, "</array>")
	}

	p.closeDict(2) // VPN payload

	// The root that signed the gateway's certificate, delivered in the same
	// profile so it is trusted for it. Without this a self-signed gateway is
	// rejected with a generic connect error that says nothing about trust.
	if len(c.CAPEM) > 0 {
		der, err := caDER(c.CAPEM)
		if err != nil {
			return nil, err
		}
		caID := profileID + ".ca"
		p.openDict(2)
		p.str(3, "PayloadType", "com.apple.security.root")
		p.num(3, "PayloadVersion", 1)
		p.str(3, "PayloadIdentifier", caID)
		p.str(3, "PayloadUUID", deterministicUUID(caID))
		p.str(3, "PayloadDisplayName", c.ProfileName+" CA")
		p.str(3, "PayloadCertificateFileName", "gotun-ca.crt")
		// Apple's certificate payloads carry DER, base64-encoded.
		p.data(3, "PayloadContent", der)
		p.closeDict(2)
	}

	p.raw(1, "</array>")

	p.str(1, "PayloadType", "Configuration")
	p.num(1, "PayloadVersion", 1)
	p.str(1, "PayloadIdentifier", profileID)
	p.str(1, "PayloadUUID", deterministicUUID(profileID))
	p.str(1, "PayloadDisplayName", c.ProfileName)
	p.str(1, "PayloadOrganization", "gotun")
	p.bool(1, "PayloadRemovalDisallowed", false)

	p.closeDict(0)
	p.footer()
	return p.bytes(), nil
}

type onDemandRule struct {
	action        string
	interfaceType string
	ssids         []string
	urlProbe      string
}

// onDemandRules builds the ordered rule list that makes a dead tunnel degrade
// to plain internet rather than to no internet.
//
// Order is the mechanism. iOS evaluates rules top to bottom and takes the first
// match, so the catch-all Disconnect has to be last: it is what turns an
// unreachable gateway into direct traffic rather than into a phone sitting in
// "connecting" with nothing flowing.
//
// The probe is why the Connect rule is conditional at all. A bare Connect holds
// matching connections while iOS retries, which is the "stuck on no internet"
// complaint; URLStringProbe matches only when the URL returns 200 without a
// redirect, so the tunnel is attempted only when the gateway has already
// answered from outside.
func onDemandRules(c Config) []onDemandRule {
	var rules []onDemandRule

	// At home the tunnel would hairpin out to the gateway's public address and
	// back in through the same uplink it exits from, across two layers of NAT
	// whose loopback handling is not something to rely on.
	if len(c.HomeSSIDs) > 0 {
		rules = append(rules, onDemandRule{
			action:        "Disconnect",
			interfaceType: "WiFi",
			ssids:         c.HomeSSIDs,
		})
	}

	rules = append(rules, onDemandRule{
		action:   "Connect",
		urlProbe: strings.TrimSpace(c.ProbeURL),
	})

	// Unreachable when there is no probe, since the Connect above then matches
	// everything. Emitted regardless, because a profile whose last rule is not
	// a catch-all Disconnect is one edit away from being a kill switch, and
	// the shape should be visible in every version of the file.
	rules = append(rules, onDemandRule{action: "Disconnect"})
	return rules
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "profile"
	}
	return out
}

func escape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// plist is a minimal indentation-aware writer.
//
// Hand-rolled rather than encoding/xml with structs because a plist dict is an
// ordered sequence of alternating key and value elements, which Go's XML
// encoder cannot express without a custom marshaller per dict -- more code, and
// harder to read against Apple's own documentation.
type plist struct{ b bytes.Buffer }

func (p *plist) header() {
	p.b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	p.b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	p.b.WriteString(`<plist version="1.0">` + "\n")
}

func (p *plist) footer() { p.b.WriteString("</plist>\n") }

func (p *plist) indent(n int) { p.b.WriteString(strings.Repeat("\t", n)) }

func (p *plist) raw(n int, s string) {
	p.indent(n)
	p.b.WriteString(s + "\n")
}

// openDict emits the dict element at indent n; its keys belong at n+1.
func (p *plist) openDict(n int)  { p.raw(n, "<dict>") }
func (p *plist) closeDict(n int) { p.raw(n, "</dict>") }

func (p *plist) key(n int, k string) { p.raw(n, "<key>"+escape(k)+"</key>") }

func (p *plist) str(n int, k, v string) {
	p.key(n, k)
	p.raw(n, "<string>"+escape(v)+"</string>")
}

func (p *plist) num(n int, k string, v int) {
	p.key(n, k)
	p.raw(n, fmt.Sprintf("<integer>%d</integer>", v))
}

// data emits a <data> element, wrapped the way Apple's own profiles are so a
// long certificate stays readable.
func (p *plist) data(n int, k string, v []byte) {
	p.key(n, k)
	p.raw(n, "<data>")
	enc := base64.StdEncoding.EncodeToString(v)
	for len(enc) > 0 {
		chunk := enc
		if len(chunk) > 64 {
			chunk = chunk[:64]
		}
		p.raw(n+1, chunk)
		enc = enc[len(chunk):]
	}
	p.raw(n, "</data>")
}

func (p *plist) bool(n int, k string, v bool) {
	p.key(n, k)
	if v {
		p.raw(n, "<true/>")
		return
	}
	p.raw(n, "<false/>")
}

func (p *plist) bytes() []byte { return p.b.Bytes() }
