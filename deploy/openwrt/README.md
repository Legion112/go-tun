# Running gotun on an OpenWrt router

gotun classifies and routes; **netifd owns the WireGuard interface**. That split is
deliberate: the tunnel is then visible in LuCI, survives sysupgrade, gets MSS
clamping for free from the firewall zone, and gotun never has to hold a private
key on the router. Run `gotun apply` without `-wg-config` and the WireGuard spec
is unmanaged, so gotun will not touch the device.

## What gotun installs

One nft table (`inet gotun`), one `ip rule` at priority 100, one route in table
100, and three `send_redirects=0` sysctls. Nothing else. `gotun clear` removes
the rule first, so traffic stops being steered before anything it points at is
torn down.

## Install

```sh
make build-arm64
scp bin/gotun-linux-arm64 root@router:/usr/bin/gotun
scp deploy/openwrt/gotun.init root@router:/etc/init.d/gotun
scp deploy/openwrt/hotplug-iface-gotun root@router:/etc/hotplug.d/iface/99-gotun
ssh root@router 'chmod +x /usr/bin/gotun /etc/init.d/gotun /etc/hotplug.d/iface/99-gotun'
```

Then create `/etc/gotun/gotun.conf` from `gotun.conf.example`, put the prefix list
at the path it names, and `/etc/init.d/gotun enable`.

The split resolver is a separate service, for the reasons in **DNS** below. It is
optional -- routing works without it -- but a foreign name resolved without the
tunnel gives a *different* answer, not merely a slower one:

```sh
scp deploy/openwrt/gotun-dns.init root@router:/etc/init.d/gotun-dns
ssh root@router 'chmod +x /etc/init.d/gotun-dns && /etc/init.d/gotun-dns enable'
```

Its own settings live in `/etc/gotun/gotun-dns.conf`; see
`gotun-dns.conf.example`. All of them have defaults, so the file is optional.

## Persistence across firmware upgrades

`/usr/bin` is wiped by sysupgrade; `/etc` is not, but only if listed. Add both the
binary and the config directory:

```sh
printf '/usr/bin/gotun\n/etc/gotun/\n/etc/init.d/gotun\n/etc/init.d/gotun-dns\n/etc/hotplug.d/iface/99-gotun\n' >> /etc/sysupgrade.conf
# With the IKEv2 transport, the xfrm interface script and everything swanctl
# holds -- the CA key above all, since losing it means reissuing every profile.
printf '/etc/init.d/gotun-ipsec\n/etc/swanctl/\n' >> /etc/sysupgrade.conf
# With the sing-box transport, its init script. sing-box's own binary lives in
# /usr/bin and has to be reinstalled either way.
printf '/etc/init.d/singbox\n' >> /etc/sysupgrade.conf
```

Without this, a firmware upgrade silently leaves the router with no classifier:
the ip rule and nft table are gone too (they are kernel state, not files), so
traffic quietly reverts to going out the ISP for everything. Nothing breaks, which
is exactly why it is easy to miss.

## Transport: XRay (VLESS/Reality) via sing-box

Plain WireGuard is unusable on this path (see the next section). XRay over **TCP
443** is not, and is already proven working from other devices on the same line.

XRay is a proxy, not a route-based tunnel, and gotun routes by interface. sing-box
bridges the two in a single static binary: a `tun` inbound plus a `vless`/reality
outbound. gotun then needs no changes at all -- `-tunnel-iface xray0` -- and the
transport can be swapped later without touching gotun.

```sh
# 27 MB static binary; OpenWrt feeds carry no sing-box/xray package.
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -tags "with_gvisor,with_utls" -trimpath -ldflags "-s -w" \
  -o sing-box github.com/sagernet/sing-box/cmd/sing-box

scp sing-box root@router:/usr/bin/sing-box
scp deploy/openwrt/singbox-xray.json.example root@router:/etc/gotun/singbox.json
scp deploy/openwrt/singbox.init root@router:/etc/init.d/singbox
```

Fill in the client UUID, then `sing-box check -c /etc/gotun/singbox.json`.

**The tun stack must be `gvisor`, not `system`.** This costs an afternoon to
discover: with `"stack": "system"` the tun comes up, packets reach it, and
sing-box logs *nothing at all* -- no inbound connection, no error. The system
stack relies on the redirect rules `auto_route` installs, which we deliberately
do not want, so without them it silently processes nothing. gvisor handles
packets in userspace and needs no routing help, which is why the binary is built
with `-tags with_gvisor`.

**`auto_route` must stay `false`.** gotun owns table 100, and letting sing-box
install routes of its own would hijack the main table — including sing-box's own
connection out to the server, which is a loop that is tedious to debug. With it
false the only route that appears is the kernel's on-link `/30` for the tun's own
address; verify with `ip route show default | grep xray0`, which must print
nothing.

Because sing-box terminates TCP and opens its own connection outbound, the LAN
client's source address never leaves the router, so the tun zone needs no
masquerade — only `mtu_fix`, since the tun runs at MTU 1400 and this is TCP
carried inside TCP.

Verified on the target: the binary runs, `sing-box check` passes, the tun comes up
and is removed cleanly on stop, and the main table is untouched.

## Known blocker: new WireGuard sessions do not survive on this path

Not a router problem, and **not fixable by changing firmware**. A brand-new plain
WireGuard session to the exit VPS completes its first handshake and then dies: rx
freezes at the handshake response, tx keeps climbing, no later handshake ever
completes, and the session expires after ~180 s. It reproduces identically from
two different boxes -- the OpenWrt router and the x86 Linux box behind it -- so it
does not depend on which host originates it.

Meanwhile a plain WireGuard tunnel established months earlier to the *same* VPS IP
and port carries hundreds of megabytes without trouble. New sessions die;
established ones live. On this path that points at DPI on WireGuard session
setup rather than at any host, which matches how Russian ISPs are known to behave.

Ruled out, each with a measurement rather than a guess: MTU, MASQUERADE, conntrack
capacity, NIC errors, TX checksum offload, the MediaTek PPE hook, the VPS firewall
and peer config, and the router's own UDP egress. nft counters in the `output` and
`postrouting` hooks confirm the packets leave the router; per-peer counters on both
ends show where they stop.

Two traps to avoid when re-testing this:

- `nslookup` is a poor UDP probe here. It uses port 53, and foreign resolvers are
  blocked separately by the same ISP, so a failure says nothing about UDP in
  general. A probe to a Russian resolver succeeds and proves the router's own UDP
  egress is fine.
- This busybox `nc` is the minimal build. It silently ignores `-u` and `-p`, so
  UDP probes built on it never send anything and read as total packet loss.

The practical route forward is an obfuscated transport rather than plain
WireGuard; the exit VPS already runs AmneziaWG alongside it. Note the operational
risk this implies for the existing tunnel: it works because it is established, so
if it ever drops it may not come back.

## DNS

Routing alone is not enough. Resolving a foreign name without the tunnel does not
just give a slower answer, it gives a *different* one: measured here,
`www.google.com` resolves to a different front-end via a local resolver than
through the tunnel, and a direct query to a foreign resolver comes back with an
address *and* NXDOMAIN in the same reply. So `gotun-dns` splits DNS the same way
`gotun` splits routing -- direct-class names to a local resolver, everything else
resolved through the tunnel with `SO_MARK`.

It listens on `127.0.0.2:53`, because dnsmasq owns `:53` here and also serves
DHCP. Point dnsmasq at it:

```sh
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server=127.0.0.2
uci add_list dhcp.@dnsmasq[0].server=77.88.8.8   # fallback
uci commit dhcp && /etc/init.d/dnsmasq reload
```

The fallback is deliberately a *local* resolver rather than a foreign one. If
gotun-dns is down, a geo-localised answer still connects; an interfered one does
not.

Marked DNS is UDP, and it does traverse VLESS -- sing-box logs
`outbound packet connection to 1.1.1.1:53` -- so the split survives the move to a
proxy transport.

## Exposing a host: a port forward is not enough

A forwarded port gets packets *in*. Getting them back out needs
`GOTUN_DIRECT_SRC`.

Classification reads the destination, and the destination of a reply is whoever
connected. For a player, a peer or a monitoring probe from outside Russia that
address is non-direct, so the reply is marked and leaves through the exit hop.
It arrives from the VPS, not from the address the peer dialled, and the
connection never establishes. Nothing in the setup looks wrong: the forward is
right, the server is listening, the inbound packet really does arrive, and
tcpdump on the server shows it answering.

Inbound is unaffected either way. The mark chain sits at mangle + 1, ahead of
nat prerouting, so it still sees the router's own WAN address as the destination
and the ingress guard returns before anything is marked. Only the reply needs
help, and it needs it by source:

```sh
GOTUN_DIRECT_SRC=192.168.8.162
```

That host then keeps the uplink for everything it originates as well, which for
a server is the point — it should be reachable, and listed in any public server
browser, at the address players actually dial.

`-mark-iface` cannot express this: such a host normally shares `br-lan` with
every ordinary client, so scoping by ingress interface would exempt the whole
LAN with it.

## A phone on IKEv2/IPsec

Deployed and measured on this router. The pieces, in the order they have to
exist:

```sh
opkg update
opkg install kmod-xfrm-interface ip-full strongswan-full strongswan-swanctl strongswan-pki
```

Two of those are go/no-go, and neither announces itself as the cause.

`kmod-xfrm-interface`: without it `ip link add type xfrm` answers `RTNETLINK
answers: Not supported`, route-based IPsec is impossible, and the fallback --
classifying by source address rather than by ingress interface -- is not built.
The package exists for this kernel; it is simply not installed by default.

`ip-full`: busybox's `ip` cannot create an xfrm interface even with the module
loaded. It does not say so either -- it answers `RTNETLINK answers: Invalid
argument`, because it never passes the `if_id`, which reads as a kernel problem
rather than a missing package. Verified against a stock 21.02.7 rootfs. This
router already has `ip-full` from its vendor firmware, which is why the list
went this long without it.

There is also an `xfrm` package, and it is *not* wanted here: it adds netifd's
`proto xfrm` to `/etc/config/network`, and `/etc/init.d/gotun-ipsec`
deliberately does not use netifd for this -- see the comment at the top of that
script for why owning the whole device beats owning half of it.

Then the interface, the PKI, and the configuration:

```sh
scp deploy/openwrt/gotun-ipsec.init root@router:/etc/init.d/gotun-ipsec
ssh root@router 'chmod +x /etc/init.d/gotun-ipsec && /etc/init.d/gotun-ipsec enable && /etc/init.d/gotun-ipsec start'

ssh root@router 'cd /etc/swanctl
  pki --gen --type ecdsa --size 256 --outform pem > private/gotun-ca.key
  pki --self --ca --in private/gotun-ca.key --type ecdsa --dn "CN=gotun home CA" \
      --lifetime 3650 --outform pem > x509ca/gotun-ca.pem
  pki --gen --type ecdsa --size 256 --outform pem > private/gotun-gw.key
  pki --pub --in private/gotun-gw.key --type ecdsa | pki --issue \
      --cacert x509ca/gotun-ca.pem --cakey private/gotun-ca.key \
      --dn "CN=vpn.home" --san vpn.home --san <public-ip> \
      --flag serverAuth --lifetime 3650 --outform pem > x509/gotun-gw.pem
  chmod 600 private/gotun-ca.key private/gotun-gw.key'

gotun ikev2 -server <public-ip> -gateway-id vpn.home \
  -ca /etc/swanctl/x509ca/gotun-ca.pem -server-cert gotun-gw.pem \
  -vip-subnet 10.231.17.0/24 -vip-gateway 10.231.17.1 -pool 10.231.17.16/28 \
  -if-id 0x61 -families v4 \
  -out-swanctl /etc/swanctl/conf.d/gotun-ikev2.conf
gotun ikev2 user add <name> ...   # the same flags, plus -probe-url and -home-ssid
```

Put the gateway certificate's **public** address in a SAN and pass it as
`-gateway-id`: iOS authenticates the server and then checks the identifier
separately, so a mismatch fails after a successful handshake and reads as a
crypto problem rather than a naming one.

### Firewall

A zone of its own, by device rather than by network, because the interface is
not netifd's:

```sh
uci set firewall.ipseczone=zone
uci set firewall.ipseczone.name=ipsec
uci set firewall.ipseczone.device=ipsec0
uci set firewall.ipseczone.input=REJECT
uci set firewall.ipseczone.forward=REJECT
uci set firewall.ipseczone.mtu_fix=1
# ipsec -> wan carries the direct class, ipsec -> the tun zone the tunnel class.
# NOT ipsec -> lan: gotun's home_nets rule is the second line of defence, and
# the traffic selectors are the first.
```

Plus an input rule for DNS from the zone, and `udp 500` and `udp 4500` from
`wan`. `uci batch` splits values on whitespace, so a multi-valued option has to
be written with `add_list` -- `dest_port='500 4500'` in a batch silently
becomes `500`.

### What the upstream NAT needs

Two layers here, so the forwards go on the **upstream** router, not this one:
`udp 500`, `udp 4500`, and the probe's TCP port, all to this router's WAN
address. Pin that address to the MAC on the upstream DHCP server, or the
forwards quietly start pointing at nothing.

**Hairpin does not work** on the measured upstream (an MTS GPON ONT): from
inside the house, the public address times out. So a phone at home cannot dial
the public address, and the profile needs `-home-ssid` listing every SSID that
lands on this router -- the tunnel is then simply off at home, where the split
already comes from the classifier anyway.

### Measured on the live router

- iOS accepted all **52 traffic selectors** in one `local_ts`. The limit is
  undocumented and this was the open question; it is answered.
- iOS accepted the self-signed gateway certificate from the CA payload the
  profile carries, with no separate install and no trust toggle.
- iOS negotiated `AES_CBC-256/HMAC_SHA2_256/MODP_2048`, not the GCM/ECP entries
  offered first. Works, but MODP-2048 is a slow DH on this CPU.
- Leaving home Wi-Fi, iOS sent **no DELETE** -- it simply stopped. The stale SA
  lingered until the next connect arrived with `INITIAL_CONTACT`. From the
  gateway, a departed client and a present one look identical, which is why
  `gotun ikev2 user revoke` terminates rather than trusting the session to be
  gone.
- `uhttpd` owns `127.0.0.1:8443` here, so the health endpoint binds the WAN
  address instead. It logs the bind failure and carries on rather than taking
  the watchdog down with it.
- **A pushed resolver is not a used resolver.** A split tunnel is not the
  default route, so iOS treats the tunnel's DNS servers as supplemental and
  consults them only for domains the profile names. `gotun ikev2 -dns-match
  all` emits the `DNS` dictionary that fixes it -- at the **payload** level,
  beside `IKEv2` rather than inside it, since a key nested in the wrong place
  is ignored in silence. Measured after: every query from the phone arrives,
  and every forwarded one reaches `gotun-dns` rather than dnsmasq's fallback.
- The existing dnsmasq `server=` list has `127.0.0.2` first and a plain RU
  resolver second, and dnsmasq is free to use either. It happened to use only
  the first throughout; `strict-order` would make that a guarantee rather than
  an observation.

## Rollback

One command, and it takes effect immediately:

```sh
ip rule del priority 100
```

That is enough on its own — the nft table keeps marking packets, but with no rule
consulting the mark, every packet follows `main`. `/etc/init.d/gotun stop` does the
full teardown.

## The fail-open trade

The default is fail-open: if the tunnel becomes unusable the route in table 100 is
withdrawn, the lookup misses, and marked traffic follows `main` out the ISP. That
is the right default for a household gateway — nobody loses internet because a VPS
rebooted — but it is silent. Geo-blocked services simply start behaving as if you
were back in the country you were routing around. Check egress identity
periodically; that is the only symptom.

Route-level fail-open covers the link going down. A tunnel that is *up but dead*
(no handshake) keeps its route and swallows traffic; detecting that needs a health
probe flipping `-tunnel-up`, which is not implemented.

## Interfaces

`GOTUN_MARK_IFACE` is the list of client-facing interfaces to classify. Leaving it
empty classifies traffic arriving on **any** interface, WAN-inbound included. The
day a guest or IoT bridge is enabled it has to be added here, or clients on it get
no split routing and nothing reports that.
