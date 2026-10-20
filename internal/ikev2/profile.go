package ikev2

import (
	"crypto/sha1"
	"fmt"
	"strings"

	"howett.net/plist"
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

// The types below mirror Apple's published payload schema, which is vendored
// under testdata/schema and checked against in
// TestProfile_ConformsToApplesPublishedSchema.
//
// Typed rather than hand-written XML because the one class of bug this file
// has actually produced is a key in the wrong place: a dictionary nested one
// level too deep is an unknown key, which iOS ignores in silence, so the
// profile installs cleanly, looks right and changes nothing. A struct cannot
// put DNS inside IKEv2 without someone writing it there on purpose, and the
// schema test catches it even then.
//
// Field order is not meaningful: a plist dict is a dictionary, and the
// marshaller sorts keys. Nesting is what matters.

type profileRoot struct {
	PayloadContent           []any  `plist:"PayloadContent"`
	PayloadDisplayName       string `plist:"PayloadDisplayName"`
	PayloadIdentifier        string `plist:"PayloadIdentifier"`
	PayloadOrganization      string `plist:"PayloadOrganization"`
	PayloadRemovalDisallowed bool   `plist:"PayloadRemovalDisallowed"`
	PayloadType              string `plist:"PayloadType"`
	PayloadUUID              string `plist:"PayloadUUID"`
	PayloadVersion           int    `plist:"PayloadVersion"`
}

type vpnPayload struct {
	PayloadType        string        `plist:"PayloadType"`
	PayloadVersion     int           `plist:"PayloadVersion"`
	PayloadIdentifier  string        `plist:"PayloadIdentifier"`
	PayloadUUID        string        `plist:"PayloadUUID"`
	PayloadDisplayName string        `plist:"PayloadDisplayName"`
	UserDefinedName    string        `plist:"UserDefinedName"`
	VPNType            string        `plist:"VPNType"`
	IKEv2              ikev2Settings `plist:"IKEv2"`
	// A SIBLING of IKEv2, because Apple's schema puts it at the payload level:
	// it applies to every VPN type. Nested inside IKEv2 it is an unknown key
	// and iOS ignores it, which is how a profile once shipped with the
	// resolver configured and never used.
	DNS *dnsSettings `plist:"DNS,omitempty"`
}

type ikev2Settings struct {
	RemoteAddress    string `plist:"RemoteAddress"`
	RemoteIdentifier string `plist:"RemoteIdentifier"`
	LocalIdentifier  string `plist:"LocalIdentifier"`
	// AuthenticationMethod None plus ExtendedAuthEnabled is EAP: the gateway
	// proves itself with a certificate, the phone with a username and
	// password. No AuthPassword: a profile carrying it is a credential in a
	// file that gets AirDropped to a phone and then sits in Downloads, and iOS
	// keeps the password in the keychain after the first connect anyway.
	AuthenticationMethod string `plist:"AuthenticationMethod"`
	ExtendedAuthEnabled  int    `plist:"ExtendedAuthEnabled"`
	AuthName             string `plist:"AuthName"`
	// This is also the fail-open latency: nothing re-evaluates an On-Demand
	// rule while the SA is alive, so a tunnel that dies mid-session is noticed
	// by DPD and traffic is held until then.
	DeadPeerDetectionRate string `plist:"DeadPeerDetectionRate"`
	DisableMOBIKE         int    `plist:"DisableMOBIKE"`
	DisableRedirect       int    `plist:"DisableRedirect"`
	EnablePFS             int    `plist:"EnablePFS"`

	EnableCertificateRevocationCheck int `plist:"EnableCertificateRevocationCheck"`
	// The two keys that are the whole battery argument: the NAT keepalive is
	// handed to hardware, so the application processor does not wake to send
	// it while the phone sleeps. A WireGuard NetworkExtension cannot have
	// this; its keepalive is a userspace timer.
	NATKeepAliveOffloadEnable int `plist:"NATKeepAliveOffloadEnable"`
	NATKeepAliveInterval      int `plist:"NATKeepAliveInterval"`

	// On-Demand belongs to the VPN-type dictionary, not the payload root.
	// Both placements are accepted by current iOS, but only this one is in the
	// schema, and relying on tolerance is how a configuration stops working at
	// an OS upgrade with nothing to point at.
	OnDemandEnabled int            `plist:"OnDemandEnabled"`
	OnDemandRules   []onDemandRule `plist:"OnDemandRules,omitempty"`
}

// dnsSettings is what makes the pushed resolver one the phone actually uses.
//
// A split tunnel is not the network's default route, so iOS treats the
// tunnel's DNS servers as supplemental: consulted only for the domains listed
// here. With no list, nothing matches and not one query arrives.
type dnsSettings struct {
	ServerAddresses []string `plist:"ServerAddresses"`
	// The single empty string is the documented way to say "every domain": it
	// becomes the default domain, so all queries go to the tunnel's resolver
	// first.
	SupplementalMatchDomains []string `plist:"SupplementalMatchDomains"`
	// Not appended to the search list. An empty search domain is meaningless,
	// and a real one would start completing bare hostnames unasked.
	SupplementalMatchDomainsNoSearch int `plist:"SupplementalMatchDomainsNoSearch"`
}

type onDemandRule struct {
	Action             string   `plist:"Action"`
	InterfaceTypeMatch string   `plist:"InterfaceTypeMatch,omitempty"`
	SSIDMatch          []string `plist:"SSIDMatch,omitempty"`
	URLStringProbe     string   `plist:"URLStringProbe,omitempty"`
}

type certPayload struct {
	PayloadType                string `plist:"PayloadType"`
	PayloadVersion             int    `plist:"PayloadVersion"`
	PayloadIdentifier          string `plist:"PayloadIdentifier"`
	PayloadUUID                string `plist:"PayloadUUID"`
	PayloadDisplayName         string `plist:"PayloadDisplayName"`
	PayloadCertificateFileName string `plist:"PayloadCertificateFileName"`
	// DER, not PEM. Handing Apple a PEM block produces a profile that installs
	// and then validates nothing, which reads as a problem with the CA rather
	// than with the encoding.
	PayloadContent []byte `plist:"PayloadContent"`
}

// EncodeProfile builds the .mobileconfig an iPhone installs.
//
// What is deliberately absent matters as much as what is present:
//
//   - **No VPNType AlwaysOn.** Supervised Always-On VPN blocks traffic when the
//     tunnel is down. That is the opposite of the requirement, and it is a
//     single key away.
//   - **No AuthPassword.** See ikev2Settings.
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

	vpn := vpnPayload{
		PayloadType:        "com.apple.vpn.managed",
		PayloadVersion:     1,
		PayloadIdentifier:  vpnID,
		PayloadUUID:        deterministicUUID(vpnID),
		PayloadDisplayName: c.ProfileName,
		UserDefinedName:    c.ProfileName,
		VPNType:            "IKEv2",
		IKEv2: ikev2Settings{
			RemoteAddress: c.Server,
			// Must equal a subjectAltName on the gateway certificate. iOS
			// authenticates the server and then checks this separately, so a
			// mismatch fails after a successful handshake -- which reads as a
			// crypto problem rather than a naming one.
			RemoteIdentifier:                 c.GatewayID,
			LocalIdentifier:                  c.ClientID,
			AuthenticationMethod:             "None",
			ExtendedAuthEnabled:              1,
			AuthName:                         c.ClientID,
			DeadPeerDetectionRate:            c.DPDRate,
			DisableMOBIKE:                    0,
			DisableRedirect:                  0,
			EnablePFS:                        1,
			EnableCertificateRevocationCheck: 0,
			NATKeepAliveOffloadEnable:        1,
			NATKeepAliveInterval:             c.KeepAliveInterval,
		},
	}

	// Connected by hand when on-demand is off, and the rules are omitted
	// entirely rather than left present-but-inert: a rule list that is not
	// being evaluated is the kind of thing somebody later reads as the
	// behaviour and is wrong about.
	if !c.OnDemandDisabled {
		vpn.IKEv2.OnDemandEnabled = 1
		vpn.IKEv2.OnDemandRules = onDemandRules(c)
	}

	if len(c.DNSMatchDomains) > 0 {
		vpn.DNS = &dnsSettings{
			ServerAddresses:                  []string{c.VIPGateway.String()},
			SupplementalMatchDomains:         c.DNSMatchDomains,
			SupplementalMatchDomainsNoSearch: 1,
		}
	}

	content := []any{vpn}

	// The root that signed the gateway's certificate, delivered in the same
	// profile so it is trusted for it. Without this a self-signed gateway is
	// rejected with a generic connect error that says nothing about trust.
	if len(c.CAPEM) > 0 {
		der, err := caDER(c.CAPEM)
		if err != nil {
			return nil, err
		}
		caID := profileID + ".ca"
		content = append(content, certPayload{
			PayloadType:                "com.apple.security.root",
			PayloadVersion:             1,
			PayloadIdentifier:          caID,
			PayloadUUID:                deterministicUUID(caID),
			PayloadDisplayName:         c.ProfileName + " CA",
			PayloadCertificateFileName: "gotun-ca.crt",
			PayloadContent:             der,
		})
	}

	return plist.MarshalIndent(profileRoot{
		PayloadContent:           content,
		PayloadDisplayName:       c.ProfileName,
		PayloadIdentifier:        profileID,
		PayloadOrganization:      "gotun",
		PayloadRemovalDisallowed: false,
		PayloadType:              "Configuration",
		PayloadUUID:              deterministicUUID(profileID),
		PayloadVersion:           1,
	}, plist.XMLFormat, "\t")
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
	// back in through the same uplink it exits from, across NAT whose loopback
	// handling is not something to rely on -- measured absent on the deployed
	// upstream.
	if len(c.HomeSSIDs) > 0 {
		rules = append(rules, onDemandRule{
			Action:             "Disconnect",
			InterfaceTypeMatch: "WiFi",
			SSIDMatch:          c.HomeSSIDs,
		})
	}

	rules = append(rules, onDemandRule{
		Action:         "Connect",
		URLStringProbe: strings.TrimSpace(c.ProbeURL),
	})

	// Unreachable when there is no probe, since the Connect above then matches
	// everything. Emitted regardless, because a profile whose last rule is not
	// a catch-all Disconnect is one edit away from being a kill switch, and
	// the shape should be visible in every version of the file.
	rules = append(rules, onDemandRule{Action: "Disconnect"})
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
