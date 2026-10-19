# A phone on IKEv2/IPsec through the gateway

Target: an iPhone using Apple's **native** IKEv2 client, tunnelling to flint2,
where `gotun` makes the RU / non-RU decision and sends the two classes out the
uplink and the exit hop respectively.

```
iPhone (in-kernel IKEv2, no app)
  | ESP in UDP/4500
  v
MTS GPON router          forwards UDP 500, UDP 4500, TCP <probe> to flint2
  v
flint2: charon terminates IKE; decrypted packets surface on xfrm0
  |-- dst in ru_nets --> direct, out the MTS uplink   (RU egress identity)
  '-- else            --> mark 0x1 -> table 100 -> xray0 -> exit VPS
```

This is the same shape as `TestPhoneDeploy_SmartRoutingWithoutLANAccess`, with
WireGuard replaced by IPsec. Everything interesting is in what that replacement
changes, which is more than it looks.

## Why IKEv2, stated as a mechanism

The battery argument is real but it is not "IPsec is lighter than WireGuard".
It is that Apple's own client gets two things a NetworkExtension cannot:

- `NATKeepAliveOffloadEnable` hands NAT keepalives to hardware, so the
  application processor does not wake to send them while the phone sleeps. A
  WireGuard `PersistentKeepalive` is a userspace timer in an extension process.
- `DeadPeerDetectionRate` is coarse on purpose: `Low` = 30 min, `Medium` =
  10 min, `High` = 1 min, and DPD only runs when the SA is otherwise idle.

Both of those cut radio wakeups, which is where phone VPN battery actually
goes. Note the direct consequence for requirement two below: **DPD rate is also
the fail-open latency.** The battery knob and the availability knob are the same
knob, turned in opposite directions.

## Decision 1: route-based IPsec, not policy-based

Classic strongSwan installs XFRM *policies* and no interface. Decrypted client
packets then surface on the **physical WAN device**, and gotun's whole inbound
model is interface-named: `-mark-iface` scopes the classifier by ingress device
and `home_nets` isolation is `iifname <dev> ip daddr @home_nets drop` in the
forward hook. Neither has anything to attach to.

So: **route-based**, with an XFRM interface.

```sh
ip link add ipsec0 type xfrm dev <wan> if_id 0x61
# swanctl: children { phone { if_id_in = 0x61  if_id_out = 0x61 } }
```

Decrypted packets then arrive on `ipsec0` and gotun needs no new classification
axis at all — `-clients-iface ipsec0 -mark-iface br-lan,ipsec0` and the existing
rules apply unchanged. That is the entire reason to prefer it.

The fallback, if the router's kernel has no `CONFIG_XFRM_INTERFACE`, is
policy-based plus a new **source** axis: mark by VIP pool rather than by ingress
device. That is a larger change than it sounds, because the ingress guard would
have to become "iif in MarkIIfNames **or** saddr in MarkSources", and the
forward-hook isolation would have to grow a source form too. Check the kernel
before writing any of it:

```sh
opkg list | grep -E 'xfrm|strongswan'
ip link add t0 type xfrm dev eth0 if_id 1 && ip link del t0   # the real test
```

## Decision 2: the phone's routing table is the gateway's decision

The requirement is "everything except private networks goes through the
tunnel". There is no client-side way to say that:

- Apple's IKEv2 payload has **no** `ExcludedRoutes` / `IncludedRoutes`. Routing
  comes from the narrowed traffic selectors the gateway returns (`TSr`).
- iOS does not honour split-exclude attributes. The only way to express "all
  but these" is to send the **inverse** as positive selectors.

So the gateway offers `local_ts = <complement of private space>` and iOS installs
exactly those routes. Private destinations are left on the physical interface,
which is the requirement, and the hotel LAN and AirPrint keep working.

**Emit prefixes, not ranges -- measured, against the obvious choice.** A
traffic selector is a start-end range on the wire, swanctl accepts
`a.b.c.d-w.x.y.z`, and the same set is 4 ranges against 31 prefixes in the lab
(7 against 52 in production, provided reserved space is cut alongside the
non-routable list). Ranges look strictly better.

They are not. charon's own client rounds each received range up to its smallest
covering prefix when it installs routes, so `11.0.0.0-100.63.255.255` becomes a
`0.0.0.0/1` route that swallows 10/8. Measured in the lab: with range selectors
a host on the client's own access network goes unreachable the moment the tunnel
comes up, while `swanctl --list-sas` shows the exact ranges negotiated. That is
requirement one failing silently with the gateway reporting success. With
prefix selectors the same client installs 31 exact routes, the neighbour stays
on-link, and the destination sees the client's real address.

iOS may well decompose ranges exactly. The point is that the only client whose
behaviour can be observed does not, and the failure is silent, so the shorter
list is not worth the bet. `Range` stays the internal primitive -- it is how the
complement is computed -- but `Range.Prefixes()` is what ships.

For reference, the production complement as ranges, which is what would have
been shipped:

```
1.0.0.0-9.255.255.255          11.0.0.0-100.63.255.255
100.128.0.0-126.255.255.255    128.0.0.0-169.253.255.255
169.255.0.0-172.15.255.255     172.32.0.0-192.167.255.255
192.169.0.0-223.255.255.255
```

`0.0.0.0/8` and `240.0.0.0/4` are deliberately **not** in
`policy.DefaultNonRoutable` -- nothing on a LAN is addressed there, so the
classifier never needed them -- but leaving them in the IKEv2 cut makes the
complement advertise `240.0.0.0-255.255.255.255`, a selector no packet will ever
use. Both facts are pinned in `TestComplement_PrivateAndReservedIsSevenV4Ranges`
and `TestComplement_LeavingReservedInAddsOneDeadRange`.

### The trap: the gateway's own inner address is private

`gotun-dns` has to be reachable from the phone, and it listens on the
tunnel-side gateway address. That address is inside RFC1918, so the complement
above **excludes it** — the phone would send DNS to the café's resolver instead,
get a non-RU answer for a `.ru` name, and every GeoDNS service would misfire
while the tunnel looked perfectly healthy. Exactly the silent class of failure
this project keeps finding.

The VIP subnet must be punched back in as an eighth selector, and it should be a
deliberately unusual /24 so it cannot collide with the network the phone is
sitting on.

### The real risk: IPv6 on cellular

iOS proposes both families. If the gateway returns no IPv6 selectors, the phone
keeps its IPv6 default on the carrier and every IPv6-capable destination sees its
real address. On an IPv6-only or IPv6-preferred mobile network that is not an
edge case, it is **most of the traffic** — the same leak already documented for
the LAN side, where clients prefer IPv6 whenever both families resolve.

This has to be decided before deploying, not after:

- **Carry it.** `gotun ikev2 -families v4,v6` offers IPv6 as **`2000::/3`**
  rather than as the complement of the non-routable list. That is a base, not a
  complement, and it is both exactly right and one selector instead of about
  twenty: 2000::/3 is the only globally routable IPv6 range, so everything the
  complement would add describes space no packet is addressed to. It still needs
  a v6-capable `xray0` and a non-empty `ru_nets6` -- note the existing
  `-ipv6 auto` guard, since an empty `ru_nets6` makes `ip6 daddr != @ru_nets6`
  match everything and a half-done v6 rollout pushes all IPv6 into the tunnel.
- **Refuse it.** Offer no v6 selectors and accept a documented leak, which is
  what `-ipv6-fallback direct` already does on the LAN.

There is no third option where it quietly works.

## Decision 3: fail-open, in three layers

Requirement two is that a broken tunnel degrades to plain internet rather than
to no internet. Three separate things have to be true, and only the third is
gotun's.

**Layer 1 — never arm the kill switch.** Supervised *Always-On* VPN
(`VPNType: AlwaysOn`) blocks traffic when the tunnel is down. Ordinary On-Demand
does not: `Action: Disconnect` is documented as "tear down the VPN connection,
prevent reconnect while matching". So this must be a plain IKEv2 payload with
On-Demand rules, never an Always-On payload.

**Layer 2 — gate connecting on a probe, so the phone never sits in limbo.** A
bare `Action: Connect` holds matching connections while iOS retries; that is the
"stuck on NO INTERNET" complaint. Rule-level `URLStringProbe` matches only when
the URL returns 200 without redirection, so:

| # | Rule | Effect |
|---|------|--------|
| 1 | `Action: Disconnect`, `SSIDMatch: [<home SSID>]` | at home, no tunnel — avoids hairpinning the tunnel back through the double NAT |
| 2 | `Action: Connect`, `URLStringProbe: http://<ddns>:<port>/alive` | connect only when flint2 answers from outside |
| 3 | `Action: Disconnect` | catch-all: unreachable gateway means go direct |

The probe is fetched over the physical interface, so it must be flint2's
**public** address — pointing it at the inner address would make it fail
whenever the tunnel is down, rule 2 would never match, and the phone would never
connect at all.

**Make the probe tell the truth.** If `/alive` answers whenever the web server is
up, the phone connects into a tunnel whose exit hop is dead, and gotun's
route-level fail-open then sends it out the RU uplink — silently, which the
OpenWrt notes already name as the one symptom you have to go looking for. Tie
the endpoint to the exit-hop health `gotun watch` already computes, and the
silent leak becomes a VPN icon that is visibly off.

**Layer 3 — gotun's own `-fail-mode open`**, which is already the default and
already tested: the table-100 route is withdrawn, the lookup misses, marked
traffic follows `main`.

**The cost, stated plainly.** Nothing re-probes while the SA is alive. A tunnel
that dies mid-session is noticed by DPD, so traffic is held for up to one DPD
interval before the phone falls back. `High` = 1 min of held traffic and the most
radio wakeups; `Medium` = up to 10 min. Availability and battery are the same
dial. `High` is the right default for this requirement, and the reason should be
written down so it does not get "optimised" later.

## Decision 4: two tunnels stack, and nothing reconciles their MTUs

The inner packet crosses ESP-in-UDP (~73-100 bytes of overhead) and then
`xray0`, which runs at MTU 1400 carrying TCP inside TCP. A 1400-byte packet from
the phone arriving at a 1400-MTU tun has nowhere to go. ICMP is unaffected, so
latency checks look perfect while large TCP responses stall — the same shape as
the MediaTek offload measurement.

The CHILD SA / `ipsec0` MTU has to sit below `xray0`'s, and the zone needs MSS
clamping. On OpenWrt that is `mtu_fix` on the zone, which is where it belongs:
gotun classifies, it does not firewall the box it runs on. The lab has no
firewall, so the lab has to install the clamp explicitly and the deploy notes
have to say so.

## What gotun has to grow

| # | Change | Why | Status |
|---|--------|-----|--------|
| 1 | `prefixes.Subtract` / `Complement`, returning `Range` with a `Prefixes()` decomposition | the inverse list is the only way to express the requirement; `Subtract` rather than `Complement` is the primitive because punching the VIP subnet back into the cut is the common case, not a special one | **done** |
| 2 | `gotun ikev2` -- emits the swanctl configuration and the `.mobileconfig` from one source | not because the two share a selector list (the profile carries no routes at all) but because the invariants tying them together have no other home: the identity the phone expects must be the one the gateway presents, and the resolver the gateway pushes must be inside the selectors it offers | **done** |
| 3 | `-clients-iface` for a non-WireGuard device | the inbound device may not be WireGuard at all, and on OpenWrt netifd owns it so there is no config to infer a name from | **done** |
| 4 | `Compile` emitting `home_nets` isolation from the clients interface rather than from a held private key | gating it on `PrivateKey` meant the isolation silently did not exist on the deployment that needs it most. "Does gotun own the device" and "is there a device" are now separate questions | **done** |
| 5 | `Compile` rejecting a clients interface absent from `-mark-iface` | such a client gets no split routing at all and nothing reports it; refusing is the only way it becomes visible | **done** |
| 6 | A test that nothing on the WAN device is marked | the WireGuard analogue is `-endpoint` exclusion. The phone's public address is dynamic so there is nothing to exclude; the claim is that ESP never reaches the classifier. That is an argument, and arguments belong in a test | **done** -- an nft counter, measured non-zero on the xfrm interface and on UDP/4500 at the WAN |
| 7 | `gotun watch -health-listen` -- the exit hop's health as an HTTP status | turns layer 2 of fail-open into something that reflects reality: a probe answering 200 because a web server is up invites the phone into a tunnel whose exit is dead | **done** |

Deliberately **not** in gotun: MSS clamping, and the host firewall stanza that
keeps the peer off the router's own services. Both are the firewall's job and
both already have a precedent in the WireGuard test.

## The lab

`test/integration/ikev2_phone_test.go`, alongside the WireGuard version rather
than replacing it -- both transports are real and both will be deployed.

Image: `strongswan-charon`, `strongswan-swanctl`, `strongswan-pki`,
`libcharon-extauth-plugins` and **`libstrongswan-standard-plugins`**. The last
one is the trap: without it charon starts and loads cleanly and then has no
cipher for any modern proposal, so the failure surfaces as "no proposal chosen"
rather than as a missing package. `encap = yes` is set so the lab runs over
UDP/4500 exactly as the double NAT will, instead of raw ESP on a Docker bridge.

Host constraint: `ip link add type xfrm` needs `xfrm_interface`, which on a
stock kernel is a module. Loading it is host kernel state, not host *network
namespace* state, so it does not break the isolation invariant -- but the test
skips with the `modprobe` line in the message rather than loading it silently.

Topology: `flint` (home/inet/wgnet/ru), `phone` and `cafe-printer` on `inet`,
`home-pc` and `home-nas` on `home`, `exit` on `wgnet`+`foreign`, `ru-dest`,
`foreign-dest`. `cafe-printer` is new relative to the WireGuard test and exists
only for requirement one: it is the device on whatever network the phone is
sitting on that has to keep working.

### Two things the lab cost an hour to learn

**The gateway's xfrm address must be a `/24`, not a `/32`.** charon installs no
route for an xfrm interface, so with a `/32` the VIP pool is not on-link and
every reply to the client fails source lookup with "network is unreachable" --
while the SA stays `ESTABLISHED`, `swanctl --list-sas` looks perfect, and the
interface quietly counts TX errors.

**One key per line in `swanctl.conf`.** A value extends to the end of the line,
so `local { auth = psk  id = flint }` parses `auth` as `psk  id = flint }` and
the connection is discarded with `invalid value for: auth` -- which reads like
an unsupported auth method rather than a syntax error.

### Assertions, each named for the failure it catches

1. **The SA establishes from the WAN with no ICMP help, UDP-encapsulated.** The
   host firewall stanza drops ICMP to the router, so the negotiation carries
   itself.
2. **The client negotiated exactly the offered selectors, and installed exactly
   those routes.** Both halves: a client can accept the selectors and still
   install a rounded-up route, which is the range-form failure above. The
   client's view is read, not the gateway's -- the gateway echoing its own
   configuration proves nothing about what the peer accepted.
3. **A host on the phone's own access network stays on-link and sees the
   phone's real address.** Reachability alone would also be satisfied by
   hairpinning out through the tunnel and back.
4. **The classifier is scoped to the xfrm interface and not to the WAN device.**
5. **Split routing by source identity**: the RU destination sees the client's
   VIP, the foreign destination sees the exit.
6. **Counters**, confirming decrypted packets arrived on the xfrm interface and
   ESP arrived on the WAN device. Deliberately after assertion 5: until
   something has crossed the tunnel both read zero for an honest reason.
7. **DNS to the gateway's VIP address works and splits.** This is what the
   punched-back selector buys.
8. **No home LAN, no router services** -- the forward-hook isolation and the
   host input stanza, neither sufficient alone.
9. **1 MiB over both classes.** ESP-in-UDP inside wg-exit is two stacked
   encapsulations and the symptom of getting it wrong is invisible to every
   other assertion here.
10. **The home LAN is unaffected**: isolation is one-way, not a partition.
11. **Fail-open at the client.** Terminating the SA is what an iPhone does when
    DPD gives up. Table 220 must empty, the RU destination must stay reachable,
    and it must see the client's real address rather than its VIP -- the first
    proves traffic is not held, the second proves it went direct.

Gateway-side fail-open is **not** re-proved here; `topology_test.go` already
covers it and it is transport-independent.

### An advantage over WireGuard worth writing down

The home LAN is inside the negotiated selectors in this lab on purpose, so the
packet really arrives on the xfrm interface and gotun's isolation is what drops
it. In production the RFC1918 cut means the home LAN is not in the selectors at
all, and the gateway's **inbound XFRM policy** drops anything outside them.

That is strictly stronger than the WireGuard arrangement. There, `AllowedIPs`
on the server constrains the peer's source addresses, but the peer chooses its
own destinations freely and only the nft rule stands between a client and the
home LAN. With IPsec the kernel enforces the destination set the gateway
negotiated, and gotun's isolation becomes defence in depth rather than the only
defence.

### Status

All eleven assertions pass, as do the two IKEv2 tests added since, the
WireGuard phone test, the rest of the integration suite and the real-nft round
trips.

### A bug this turned up, which had nothing to do with IPsec

Adding a second interface to `-mark-iface` -- a LAN bridge plus the phone's
tunnel device, which is the whole point of `-clients-iface` -- broke nft JSON
readback of the ingress guard.

The renderer always emits an anonymous set (`iifname != { "br-lan" }`), but nft
normalizes a one-element set back to a bare string on readback and keeps the set
form from two elements up. The JSON parser only read the bare string, so with
two interfaces it found no names at all: the guard never matched the spec, and
reconciliation being delete-and-rewrite, **every apply deleted and rebuilt the
whole table** -- all ~17k set elements -- and reset the counters live
verification reads.

The text parser already handled the braced list, so this was the JSON path
alone. That is the third instance of the same shape in this package: two
readback paths with opposite blind spots, where a table reads as converged on
one kind of box and as permanent drift on another. OpenWrt ships nftables
without JSON, so the live router was on the path that worked -- which is why
nothing had noticed.

Pinned at one, two and three interfaces in
`TestIngressGuard_BothParsersFindEveryInterface`, because the one-interface case
round-trips cleanly either way and every test in the package classified exactly
one interface until now.

### Three transports at once

`TestMultiTransport_EveryPathGetsSmartRoutingAtOnce` is the shape the gateway
actually runs in: a phone on IKEv2, a laptop on WireGuard and a desktop on the
home LAN, simultaneously, all getting the same decision. Each reaches the
classifier through a different kind of device -- an xfrm interface, a WireGuard
interface, a bridge -- so gotun has to treat them as three inbound devices
rather than one.

`-clients-iface` therefore takes a list. Before it did, the isolation rule
existed for whichever device happened to be named, and clients on the others got
the geo split **and** unrestricted access to the home LAN -- a combination that
works, so nothing reported it. Verified by naming one device in the lab: the
laptop then reaches the NAS and the live table has no rule for its interface.

Running the transports in sequence would not have asked the question. They share
one classifier, one routing table and one exit hop, which is why every path is
exercised again at the end, after the others have been used.

Two refusals landed alongside the list. A clients interface whose name carries a
comma, whitespace or a slash is rejected whatever `-mark-iface` says, because an
unsplit list renders as `iifname "ipsec0,wgphone"` and matches a device that
cannot exist -- isolation applies to nothing while apply reports success, and
the ingress-guard check cannot catch it when `-mark-iface` is empty. And
`-wg-clients-config` with more than one clients interface is refused outright:
gotun can own exactly one inbound WireGuard device, and picking one of several
implicitly is the kind of guess this codebase does not make.

### Three more tests, since

**MOBIKE**, in `TestIKEv2Phone_MOBIKESurvivesAccessNetworkChange`. Two access
networks; the phone roams from one to the other while dialling the same gateway
address throughout, which is the Wi-Fi-to-LTE case.

The discriminator is the SA's own serial. A session that survived the move stays
`#1`; one that silently tore down and reconnected comes back as `#2`, and every
other symptom -- traffic flowing, the interface up, the gateway content -- looks
identical either way. Verified by turning MOBIKE off: the test then fails with
`#1 -> #2` while the tunnel still works, which is exactly the twenty-second drop
on a train platform that reachability-only assertions miss.

**The generated configuration**, in
`TestIKEv2Generated_ConfigIsAcceptedByCharon`. `gotun ikev2` runs with
production-shaped inputs, a throwaway PKI is minted, and charon loads the
result. The unit tests pin what the generator writes; only a daemon can say
whether that is a configuration -- and the production selector list is 53
entries on one `local_ts` line, with no documented limit on the file format, on
charon, or on iOS. Two of those three are now answered. The test reads the
selectors back out of the loaded connection rather than trusting
`--load-all`, because accepted is not the same as kept: a truncated list would
narrow the tunnel silently.

**The profile**, in `internal/ikev2`. The on-demand polarity cannot be proven by
packets in a lab, so it is pinned as configuration: no `AlwaysOn`, the catch-all
`Disconnect` present and last, the `Connect` rule gated on a probe, and -- in
`TestGeneratedFilesCarryNoCredential` -- neither generated file carrying a
secret.

## What the lab still cannot prove

A strongSwan client is not an iOS client. Out of reach here, and therefore
deploy-time checks against the real phone:

- that iOS accepts this selector list and installs these routes;
- the On-Demand rule evaluation order and the probe's effect;
- whether `AuthenticationMethod: SharedSecret` is usable on iOS at all. The lab
  uses PSK because the datapath it measures is identical either way and the auth
  path cannot be proven here regardless; certificates plus EAP-MSCHAPv2 are the
  well-trodden path and the better fit for On-Demand, since there is no prompt
  to miss;
- the battery claim, which needs days of Screen Time on the phone, not a test.

## The generator

```bash
gotun ikev2 -server vpn.example.net \
  -vip-subnet 10.231.17.0/24 -vip-gateway 10.231.17.1 -pool 10.231.17.16/28 \
  -probe-url http://vpn.example.net:8443/alive \
  -home-ssid HomeWiFi -client-id iphone
```

It writes the swanctl configuration and the `.mobileconfig`, and refuses the
configurations whose failure mode is silence:

| Refusal | What it would otherwise look like |
|---|---|
| a selector covering private space | local things stop working while the internet is fine, and nothing says why. Checked against `ikev2.MustStayLocal`, restated in the package rather than taken from the caller's list -- a floor that came from the value being checked would check nothing |
| no selector covering the VIP subnet | a healthy tunnel with every GeoDNS answer quietly wrong, because the phone resolves through whatever network it is attached to |
| a probe URL on a private address | the probe fails precisely when the tunnel is down, so the Connect rule never matches and the phone never connects -- which reads as fail-open working perfectly, because traffic does flow |
| a resolver or pool outside the VIP subnet | replies with nowhere to go, on an SA that reads `ESTABLISHED` |
| a keepalive under 20 seconds | Apple ignores the key rather than clamping it, so the interval silently reverts to the system default and the battery argument stops applying |

Three things it deliberately does not do, and says so on stderr: the EAP secret
(a credential in a generated file is a credential in shell history, editor swap
files and backups), the xfrm interface, and `gotun apply -clients-iface`.

The UUIDs are derived from the profile identifier rather than random, because
iOS keys an installed profile by its `PayloadUUID`: a fresh one on every run
adds a second VPN entry beside the first instead of replacing it, leaving two
profiles with the same display name and no way to tell which one On-Demand is
using.

## Credentials: one per person, revocable

The shared-secret shape answers "can this phone connect". It cannot answer "can
*this person* stop connecting", which is the question that matters the moment
there is more than one phone.

`gotun ikev2 user add <name>` writes one file per person into
`/etc/swanctl/conf.d/`: a connection, a single-address pool, and a generated
secret, mode 0600. The password is printed once and stored nowhere else -- not
in the `.mobileconfig`, which is a file that gets AirDropped to a phone and
then sits in Downloads. iOS keeps it in the keychain after the first connect,
so On-Demand stays unattended.

### Why a whole connection per user, not just a secret

Because of the fixed address, which is what makes a name useful after the fact.
strongSwan's pools are **per connection and not identity-aware**: one shared
connection listing several pools hands out whichever address happens to be
free, so a log entry from last week cannot be attributed to anybody. A
connection per user with a one-address pool pins it -- measured: alice stays
`10.231.17.17` across reconnects, bob `.18`.

Two things fall out of that for free. `swanctl --list-sas` names each SA after
its connection, so the gateway can say who is who without any extra machinery.
And `swanctl --terminate --ike <name>` addresses exactly one person.

One file per user rather than one file with N stanzas, because revocation is
then a delete: nothing has to parse and rewrite a configuration that is
currently authenticating other people.

### Revoking takes two steps, and the first one looks like enough

Measured in the lab, and this is the finding the whole procedure is shaped
around:

| action | effect |
|---|---|
| delete the credential, `swanctl --load-all` | new sessions are refused -- `no EAP key found for hosts ... 'alice'` |
| the session alice **already had** | **still works**, indefinitely |
| `swanctl --terminate --ike alice` | the session ends; she cannot come back |

The reason is in the connection's own summary: `no reauthentication, rekeying
every 14400s`. The IKE_SA rekeys without re-running EAP, so the secret is never
consulted again after the initial authentication. Removing it is invisible to an
established tunnel.

So `user revoke` reloads **and** terminates, and fails with a non-zero exit if
it cannot do the second part -- a revocation that reported success while the
tunnel stayed up is the worst outcome available here. `-apply false` does
neither and says `NOT APPLIED` on stderr, with both commands to run by hand.

`TestIKEv2Users_NamedCredentialsAreFixedAndRevocable` asserts the surviving
session deliberately, with a note in the test: if that assertion ever starts
failing, reauthentication has been turned on somewhere and both this document
and the revoke path should be revisited.

### A revoked address is held back

Handing a revoked user's address to the next person would make every log entry
from before the revocation attribute the old user's traffic to the new one --
the one thing a fixed address was for. So `revoke` leaves a tombstone holding
the name and the address.

The tombstone carries no credential and its suffix deliberately does not match
swanctl's `include conf.d/*.conf`, so charon cannot act on it. It is written
before the credential is deleted, so a crash in between leaves the address held
rather than silently free. `user purge` releases it, and says what that costs.

### Still a password, and that is a staging post

EAP-MSCHAPv2 was chosen because it needs no PKI lifecycle and lands on the
already-generated connection shape unchanged. The trade is real: it is a shared
secret the person knows, so it can be reused elsewhere or written down, and
MSCHAPv2 is dated -- protected here only by the enclosing IKE_SA.

Per-user certificates are the better end state: no password at all, and the
best possible On-Demand behaviour. The cost is a CA to own and a PKCS#12 in the
profile, which turns the profile itself into a credential. The revocation
mechanism has to be explicit there too -- with a shared CA and `id = %any`,
deleting nothing revokes anything.

## The probe endpoint

```bash
gotun watch ... -health-listen 0.0.0.0:8443
```

`GET /alive` answers 200 while the tunnel carries traffic and 503 once the
watchdog has withdrawn the route. Three decisions worth keeping:

- **The status keys on the acted-upon belief, not the latest verdict.** A single
  failed probe does not withdraw the route, and the phone must follow the route
  -- flapping it direct on one bad check would leak on every transient. `Unknown`
  is likewise inert: a 503 there would send the phone direct out of uncertainty
  rather than out of failure.
- **The body says only `up` or `down`.** It is published through every NAT in
  front of the gateway, so a stranger can read it. The reason is already in the
  log.
- **A bind failure does not stop the watchdog.** Losing the thing that reports
  on the tunnel is better than losing the tunnel, and the phone reads an
  unreachable probe as "stay direct", which is the safe side.

Proven end to end in `TestWatch_DeadTunnelFallsBackAndRecovers`: 200, then 503
when the underlay is black-holed, then 200 again on recovery.

## Deploy checklist for flint2

0. `kmod-xfrm-interface` and strongswan present; the `ip link add type xfrm`
   probe above succeeds. Without the kernel option, the fallback is the
   source-based classification axis described under Decision 1, which is a
   larger change than it sounds.
1. MTS GPON router: forward UDP 500, UDP 4500 and the probe's TCP port to
   flint2. Two layers of forward, not one — the second NAT needs its own.
   `gotun ikev2` prints the exact host and port on stderr.
2. Mint the gateway certificate with `pki`, with the DDNS name in its
   subjectAltName. `-gateway-id` must equal that SAN: iOS authenticates the
   server and then checks the identifier separately, so a mismatch fails after
   a successful handshake and reads as a crypto problem.
3. `gotun ikev2 -server <ddns> -vip-subnet … -probe-url …`, then add the EAP
   secret by hand from the commented stanza it leaves behind.
4. `ipsec0` as a netifd `proto xfrm` interface in its own zone: input REJECT
   plus Allow-DNS, forward to WAN and to the xray zone, `mtu_fix` on. Address it
   with a `/24` inside the VIP subnet — a `/32` leaves the pool off-link and
   every reply to the phone fails source lookup while the SA still reads
   `ESTABLISHED`.
5. `gotun apply ... -clients-iface ipsec0 -mark-iface br-lan,ipsec0 -lan
   192.168.8.0/24`. `Compile` now refuses a clients interface missing from
   `-mark-iface`, so this one can no longer be got wrong silently.
6. `gotun-dns` listening on the VIP-side gateway address as well as `127.0.0.2`.
   The pool pushes it as `INTERNAL_IP4_DNS`, so the profile needs no DNS stanza.
7. `gotun watch ... -health-listen 0.0.0.0:<probe port>`, so the phone's
   On-Demand probe reflects the exit hop rather than the web server.
8. Verify egress identity from the phone both ways before trusting it: a RU
   address and a foreign address, from the phone, compared against the router's
   WAN and the exit's public address. Reachability is not evidence of path.

## Still open

- **The selector count.** 52 IPv4 prefixes, and no documented iOS limit. If a
  real phone rejects the list, the fix is not to switch to ranges -- charon's
  client proves those round up and swallow the phone's own LAN -- it is to
  coarsen the exclusion, which trades correctness for length. The number is
  pinned in `TestSelectors_IPv4CountIsPinned` so that trade has to be argued
  for.
- **Client certificates.** See "Still a password" above: per-user certificates
  are the better end state, and the cost is a CA to own plus a PKCS#12 in the
  profile, which turns the profile into a credential.
- **The battery claim**, which needs days of Screen Time, not a test.
