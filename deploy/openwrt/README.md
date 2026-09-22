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

## Persistence across firmware upgrades

`/usr/bin` is wiped by sysupgrade; `/etc` is not, but only if listed. Add both the
binary and the config directory:

```sh
printf '/usr/bin/gotun\n/etc/gotun/\n/etc/init.d/gotun\n/etc/hotplug.d/iface/99-gotun\n' >> /etc/sysupgrade.conf
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
