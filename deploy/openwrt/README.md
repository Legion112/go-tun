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

## Known blocker on GL.iNet Flint 2 (MT7986, OpenWrt 21.02)

**This router cannot terminate the tunnel itself.** Locally-originated UDP is
dropped on WAN egress, while locally-originated ICMP and TCP egress normally and
forwarded/NATed UDP egresses normally. Measured at both ends:

| from Flint's own stack, to the VPS | result |
|---|---|
| ICMP | arrives |
| TCP 22 | arrives, full handshake and SSH banner |
| UDP (any port) | never arrives |
| UDP, but *forwarded* from a LAN host through Flint's NAT | arrives |

The last two rows are indistinguishable on the wire — same source IP after
masquerade, same protocol, same destination, both new flows — so it is not the
ISP and not DPI. Flint's own UDP also works fine out `br-lan`, so it is specific
to the WAN path. nft counters in the `postrouting` hook confirm the packets get
that far, so the loss is below netfilter, in the driver or hardware path.

The consequence is not specific to WireGuard: any UDP-based tunnel originating on
this router will fail. gotun's classifier itself works perfectly here — marking,
the mark-to-table lookup, and RU-direct were all verified — so the workable shapes
are to keep tunnel termination on a separate box, or to fix/replace the firmware.

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
