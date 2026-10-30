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

The binary comes from a [release](https://github.com/Legion112/go-tun/releases)
or from this tree; the scripts below come from the tree either way. Pick the
release binary matching `DISTRIB_ARCH` in the router's `/etc/openwrt_release`
(see **Download** in the top-level README) — `arm64` on a Flint 2:

```sh
curl -LO https://github.com/Legion112/go-tun/releases/latest/download/gotun-linux-arm64
scp gotun-linux-arm64 root@router:/usr/bin/gotun
```

or build it here with `make build-arm64` and copy `bin/gotun-linux-arm64`
instead. Then the scripts:

```sh
scp deploy/openwrt/gotun.init root@router:/etc/init.d/gotun
ssh root@router 'mkdir -p /etc/hotplug.d/net'
scp deploy/openwrt/hotplug-iface-gotun root@router:/etc/hotplug.d/iface/99-gotun
scp deploy/openwrt/hotplug-iface-gotun root@router:/etc/hotplug.d/net/99-gotun
ssh root@router 'chmod +x /usr/bin/gotun /etc/init.d/gotun /etc/hotplug.d/iface/99-gotun /etc/hotplug.d/net/99-gotun'
ssh root@router 'gotun version'   # names the architecture; "not found" means the wrong binary
```

Both directories, and that is not belt-and-braces. The two kinds of hotplug
event describe themselves differently and only one of them happens here:

| | `ACTION` | `INTERFACE` | `DEVICE` |
|---|---|---|---|
| `iface` | `ifup` | the UCI section name | the device |
| `net` | `add` | the device | empty |

A device netifd does not manage produces **only** the `net` event, so a tun with
no UCI section of its own is invisible to a hook in `iface/` alone. This router
happens to have one — `network.xray0`, named identically to the device — which
is why the `iface` event fires here; a box without it would see nothing.

The naming coincidence also matters for the comparison. `INTERFACE` is the
section name, so a hook matching on it works only where the section and the
device share a name, as they do here. `gotun hotplug` matches `DEVICE` when the
event carries one, which is correct either way. Both shapes are measured in the
deploy lab against real netifd.

Then create `/etc/gotun/gotun.conf` from `gotun.conf.example`, put the prefix list
at the path it names, and check it before starting anything:

```sh
ssh root@router 'gotun check -config /etc/gotun/gotun.conf'
```

`check` reads nothing but the file and the prefix list, writes nothing, and
prints the settings the service will actually run with — the file, the flags and
the defaults already reconciled. Then `/etc/init.d/gotun enable`.

**Run `check` rather than trusting `start`.** `/etc/init.d/gotun start` exits 0
even when it refuses: `rc.common` discards `start_service`'s return value, so a
missing config or an unreadable prefix list prints its reason and still reports
success. The service is not running, nothing says so, and the next incident gets
diagnosed from that. `gotun check` is the command with an honest exit status,
which is also why `gotun.init` runs it as a pre-flight on every start.

From the working tree there are two read-only targets, and neither changes
anything on the router.

`make check-router` stages the aarch64 binary in `/tmp`, runs `gotun check` with
it against the live config, and removes it. This is the gate: it closes the one
gap the container lab cannot, since everything there runs amd64 while the gateway
is aarch64, so "it compiles" was all that had ever been established about the
binary that actually ships.

`make verify-router` does the same check against the live
gateway and dumps the state that goes with it — the ip rule, table 100, the nft
table, which services are enabled and running, and the tunnel device. It is
read-only, and it is the gate worth running before and after any deploy: the
container tests run amd64 while the gateway is aarch64, so the two things most
likely to take the house offline — a binary for the wrong architecture and a
config that has drifted — are exactly the two no container can report on.

The lab does now run netifd and fw3, in a second fixture alongside the fast one.
That is what established which hotplug events actually occur here, and it is
where the firewall coexistence is checked: that `gotun apply` leaves fw3's rules
untouched, and that a firewall reload — which OpenWrt triggers by itself on
every interface event, through `/etc/hotplug.d/iface/20-firewall` — leaves the
nft table, the ip rule and table 100 intact.

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
printf '/usr/bin/gotun\n/etc/gotun/\n/etc/init.d/gotun\n/etc/init.d/gotun-dns\n/etc/hotplug.d/iface/99-gotun\n/etc/hotplug.d/net/99-gotun\n' >> /etc/sysupgrade.conf
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

### Ad blocking with AdGuard Home, without betting DNS on it

GL.iNet firmware ships AdGuard Home (`/usr/bin/AdGuardHome`, disabled by
default). It goes **in front of** gotun-dns, never behind it:

```
client -> dnsmasq :53 -> AdGuard Home 127.0.0.1:3053 -> gotun-dns 127.0.0.2:53 -> Direct / Exit
                      \-> gotun-dns -> 77.88.8.8   (what dnsmasq falls back to, in order)
```

Behind it, or left on its own upstreams, AdGuard Home resolves foreign names
itself, unmarked, over the ISP -- exactly the interfered answers gotun-dns exists
to avoid. Its only upstream is gotun-dns.

Blocking is the part allowed to fail. Two things stand in the way of that, and
both are why this is wired by hand rather than through the GL.iNet UI:

- The UI's AdGuard toggle replaces dnsmasq's `server` list with
  `127.0.0.1#3053`, dropping gotun-dns and the fallback.
- Its "AdGuard Home handle client requests" mode redirects clients' port 53
  straight to AdGuard Home in nft (`/etc/firewall.dns_order`), so dnsmasq is not
  in the path at all and a dead AdGuard Home is a dead LAN.

And dnsmasq's own failover is too slow to rely on. It moves down its list only
when a client retries: measured here with `strict-order`, every uncached lookup
stalled about 2 s for as long as AdGuard Home was hung or stopped (a glibc client
waits its full 5 s), and without `strict-order` a hung AdGuard Home failed
lookups outright after 6 s. The pre-existing gotun-dns → 77.88.8.8 fallback had
the same 2 s stall. So `gotun dnswatch` probes each hop every 2 s and rewrites
dnsmasq's list to the ones that answer:

| AdGuard Home | gotun-dns | dnsmasq tries |
|---|---|---|
| up | up | AdGuard Home, gotun-dns, 77.88.8.8 |
| down | up | gotun-dns, 77.88.8.8 -- unfiltered, still split |
| either | down | 77.88.8.8 -- AdGuard's only upstream is gotun-dns, so it goes too |

gotun-dns counts as up only if it answers both a `.ru` canary and a foreign one,
so a tunnel that stops carrying DNS falls back to the local resolver instead of
timing out every foreign lookup. 77.88.8.8 is never removed. On stop the watcher
writes the full list back -- slower to fail over, never missing a hop.

AdGuard Home, configured from the shell:

```sh
C=/etc/AdGuardHome/config.yaml
# Loopback only: the web UI has no password, and the DNS port is for dnsmasq alone.
sed -i -e 's/^bind_host: 0.0.0.0/bind_host: 127.0.0.1/' \
  -e '/^  bind_hosts:/{n;s/- 0.0.0.0/- 127.0.0.1/}' $C
# Everything arrives from dnsmasq, i.e. from one client: the default limit of 20 q/s
# per client would throttle the whole LAN.
sed -i -e 's/^  ratelimit: 20/  ratelimit: 0/' \
  -e 's/^  upstream_timeout: 10s/  upstream_timeout: 2s/' \
  -e 's/^  use_private_ptr_resolvers: true/  use_private_ptr_resolvers: false/' \
  -e 's/^  cache_optimistic: false/  cache_optimistic: true/' $C
sed -i -e '/^  upstream_dns:/,/^  upstream_dns_file/c\  upstream_dns:\n  - 127.0.0.2:53\n  upstream_dns_file: ""' $C
uci set adguardhome.config.enabled=1 && uci commit adguardhome   # not dns_enabled
/etc/init.d/adguardhome start
# It migrates the config on first start; then add the fallback for gotun-dns being down.
sed -i 's/^  fallback_dns: \[\]/  fallback_dns:\n    - 77.88.8.8:53/' $C
/etc/init.d/adguardhome restart
```

The ratelimit line is not optional. `use_private_ptr_resolvers` off stops
AdGuard Home sending LAN reverse lookups back to dnsmasq, which forwards them to
AdGuard Home. Its web UI is then reachable through
`ssh -L 3000:127.0.0.1:3000 root@router` at `http://localhost:3000`; leave the
upstream there as it is.

Then the watcher, and dnsmasq switched from its `server` list to the file the
watcher owns. Set `GOTUN_DNS_FILTER=127.0.0.1:3053` in
`/etc/gotun/gotun-dns.conf` first (see `gotun-dns.conf.example`); gotun-dns
must be a build that knows the key, or it refuses the file.

```sh
scp deploy/openwrt/gotun-dnswatch.init root@router:/etc/init.d/gotun-dnswatch
ssh root@router 'chmod +x /etc/init.d/gotun-dnswatch'
ssh root@router "printf '/etc/init.d/gotun-dnswatch\n/etc/AdGuardHome/config.yaml\n' >> /etc/sysupgrade.conf"
ssh root@router '
  printf "server=127.0.0.1#3053\nserver=127.0.0.2\nserver=77.88.8.8\n" > /etc/gotun/dnsmasq.servers
  uci -q delete dhcp.@dnsmasq[0].server
  uci set dhcp.@dnsmasq[0].serversfile=/etc/gotun/dnsmasq.servers
  uci set dhcp.@dnsmasq[0].strictorder=1
  uci commit dhcp && /etc/init.d/dnsmasq restart
  /etc/init.d/gotun-dnswatch enable && /etc/init.d/gotun-dnswatch start'
```

dnsmasq starts long before the watcher, so the file is created by hand once and
lives in `/etc/gotun/`; after that the watcher rewrites it in place, only on a
change, and SIGHUPs dnsmasq, which re-reads a servers file without restarting.

Measured on the live router, a fresh name looked up once a second through
`192.168.8.1`, each failure held for 25 s: no lookup failed. Stalls before the
watcher removed the hop: AdGuard Home hung (SIGSTOP), 2 lookups at about 2 s;
AdGuard Home stopped, 1 at 2 s; gotun-dns hung, 1 at 4 s. Each hop was back in
the list within about 6 s of recovering. `logread | grep dnswatch` shows every
transition.

To take it out: `/etc/init.d/gotun-dnswatch disable && /etc/init.d/gotun-dnswatch stop`,
then `uci delete dhcp.@dnsmasq[0].serversfile` and restore the `server` list
above. Turning AdGuard Home off alone is safe: the watcher drops it.

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

You should not have to remember either of those: `gotun ipsec up` attempts the
operation and names the package that is missing from how it failed. The two
answers above are the two it tells apart.

There is also an `xfrm` package, and it is *not* wanted here: it adds netifd's
`proto xfrm` to `/etc/config/network`, and `/etc/init.d/gotun-ipsec`
deliberately does not use netifd for this -- see the comment at the top of that
script for why owning the whole device beats owning half of it.

Then make charon load the configuration at boot, which it does not do by
itself:

```sh
scp deploy/openwrt/strongswan-gotun.conf root@router:/etc/strongswan.d/gotun-ikev2.conf
ssh root@router "printf '/etc/strongswan.conf\n/etc/strongswan.d/\n/etc/swanctl/swanctl.conf\n' >> /etc/sysupgrade.conf"
```

And make two includes in the packaged files tolerant, because both point into
`/var`, which is a symlink to `/tmp`:

```sh
ssh root@router '
  sed -i "s|^include /var/ipsec/strongswan.conf|include /var/ipsec/*.conf|" /etc/strongswan.conf
  sed -i "s|^include /var/swanctl/swanctl.conf|include /var/swanctl/*.conf|" /etc/swanctl/swanctl.conf'
```

**This is the step whose absence does not announce itself.** Without it the
IKEv2 transport does not survive a reboot: `/etc/init.d/swanctl` starts charon
but never calls `swanctl --load-all` — it only does that from `reload_service` —
and the start-script that would, OpenWrt writes into
`/var/ipsec/strongswan.conf`, generated from UCI `/etc/config/ipsec`. A
swanctl-only deployment has no such UCI config, so the file is never written,
and `/var` is tmpfs besides. charon then comes up listening on 500 and 4500 with
no connections loaded, every handshake is refused, and nothing anywhere says
why. With the literal include still in place, `swanctl` does not even run: it
exits with `no files found matching '/var/ipsec/strongswan.conf'`, which reads
as a broken installation rather than a missing file.

`make verify-router` reports charon's loaded connections for exactly this
reason.

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

gotun ikev2 -config /etc/gotun/gotun.conf \
  -out-swanctl /etc/swanctl/conf.d/gotun-ikev2.conf
```

The gateway itself is described once, in the `GOTUN_IKEV2_*` block of
`/etc/gotun/gotun.conf` — see `gotun.conf.example` for the block and what each
setting is for. That file lives on the router and nowhere else: it names this
deployment's public address, its Wi-Fi networks and its certificate paths, none
of which belong in a repository. The example is the template; the real one is
never committed.

Issuing a credential is then one line, and adding `-config` to any other
`gotun ikev2 user` subcommand works the same way:

```sh
gotun ikev2 user add <name> -config /etc/gotun/gotun.conf \
  -out-profile /tmp/<name>.mobileconfig
```

That writes the credential, prints the password once, reloads charon and writes
the profile. The profile carries **no password** — it is typed into the phone
once and kept in its keychain — so the file itself is not a credential and can
be sent over anything. `gotun ikev2 user profile <name> -config ...` reissues it
at any time without changing the password, and installs over the old one because
the UUID comes from the identifier rather than being random.

A flag passed explicitly still wins over the file, which is what makes a one-off
variation possible without editing the config. And there is deliberately no
`GOTUN_IKEV2_IFID`: the interface id is `GOTUN_IPSEC_IFID`, the same key
`gotun ipsec` reads, because it is one number — a connection and a device
carrying different `if_id`s negotiate perfectly and then deliver packets
nowhere.

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
(no handshake) keeps its route and swallows traffic until `gotun watch` notices:
it probes `GOTUN_PROBE_TARGET` bound to the tunnel device and withdraws the route
after `GOTUN_FAIL_AFTER` consecutive failures, so the swallowing lasts about
interval × fail-after.

`GOTUN_FAIL_MODE=closed` keeps a `blackhole default metric 100` under the tunnel
route instead, so marked traffic is dropped rather than leaked when the tunnel is
lost. The probe is bound to the device, not routed through table 100, so recovery
works the same in either mode.

## Interfaces

`GOTUN_MARK_IFACE` is the list of client-facing interfaces to classify. Leaving it
empty classifies traffic arriving on **any** interface, WAN-inbound included. The
day a guest or IoT bridge is enabled it has to be added here, or clients on it get
no split routing and nothing reports that.
