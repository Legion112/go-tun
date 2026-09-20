# go-tun

Gateway split-tunnel for client traffic: clients keep local LAN on-link and send non-local traffic to **gotun**; gotun sends Russian destinations **direct** and everything else via a **WireGuard** hop outside Russia.

## Purpose

- Clients are intentionally dumb: no geo logic.
- `gotun` owns the RU / non-RU decision and configures the **Linux kernel** datapath (nftables + policy routing + WireGuard).
- Userspace only reconciles desired state; packets are not proxied in userspace.

## Architecture

```
Client --LAN on-link--> local peers
Client --default------> gotun
                          |-- dst in ru_nets --> direct
                          |-- else          --> wg-exit --> exit (outside RU)
```

Control flow:

1. Build a `Policy` (direct prefixes, tunnel endpoint, LANs, mark/table, fail mode).
2. Compile to declarative `DesiredKernelState` (no shell-op ordering in the model).
3. Reconcile owned Linux objects: sysctl → nftables → WireGuard → ip rules/routes.

Gotun does **not** masquerade by default; the exit peer should accept the client LAN via WireGuard AllowedIPs (and may SNAT toward foreign destinations).

## Why MaxMind Country prefixes

Routing uses MaxMind-style country classification (`country_iso_code`). For the kernel we materialize **CIDRs** into an nftables set instead of per-packet MMDB lookups.

Optional local GeoIP2/GeoLite2 City or Country MMDB at `data/geo/GeoIP2-City.mmdb` (gitignored — licensed MaxMind data must not be committed):

```bash
make fetch-prefixes     # uses local MMDB if present → prefixes.txt
gotun fetch -mmdb data/geo/GeoIP2-City.mmdb -country RU -out prefixes.txt
```

Without a local MMDB: GeoLite2-Country CSV download (`MAXMIND_LICENSE_KEY` required).

Unit tests use small CSV fixtures under `testdata/prefixes/`; large-set extract/compile/render runs when `data/geo/GeoIP2-City.mmdb` is present (skip otherwise). Real nftables load of the full RU set:

```bash
make test-large-set     # GOTUN_LARGE_SET=1; Docker --network none; needs local MMDB + gotun:lab
```


## Fail-closed + endpoint exclusion

Table **100 always** ends with a terminal **blackhole** default (high metric). When the tunnel is up, a lower-metric `default dev wg-exit` is preferred. If `wg-exit` disappears **without** a control-plane reapply, marked (non-RU) traffic still hits the blackhole and does **not** fall through RPDB into the ISP/`main` table. `-tunnel-up=false` installs only the blackhole. RU (unmarked) traffic continues on the main table.

The WireGuard **underlay endpoint IP** is excluded from marking so handshake/path cannot recurse into `wg-exit`.

## Why nftables

Greenfield choice: one rule system, native interval sets, and **single-transaction** table replacement via one `nft -f` batch (delete+recreate owned table atomically). Not an iptables+ipset stack.

## Ownership

Reconciler only touches objects it owns:

- nftables table **`inet gotun`**
- routing table **`100`** and ip rule priority **`100`**
- WireGuard interface from policy (default `wg-exit`) when managed

`gotun clear` deletes those owned objects only.

## ICMP redirects

`gotun apply` sets `net.ipv4.conf.all.send_redirects=0`, the `default` equivalent, and the same per **LAN-facing interface** (discovered from the `-lan` prefixes). The kernel ORs the `all` and per-device values, so clearing `all` alone leaves redirects enabled on any interface whose own value is `1`.

A policy-routing gateway must not emit redirects: for direct-class traffic the next hop is on the same interface the packet arrived on, so the kernel would tell the client "reach that yourself", and the client then caches a route that bypasses the gateway. Today the egress is identical either way, but the client's route table stops reflecting the policy — `ip route get <direct-ip>` on a client shows the ISP router, which looks exactly like a failed cutover.

## Idempotency

Re-applying the **same** `Policy` must be a **semantic no-op** (no meaningful kernel changes). Equality is by table/set/rule/route/sysctl content — not nft handle numbers.

## Partial failure

v1 has **no** cross-subsystem transaction (nft + netlink + WireGuard). On mid-apply failure the command exits non-zero; some owned objects may already be updated. Recovery is a successful full `gotun apply`.

## DNS (v1)

Packet classification remains **IP-destination based**. Companion **`gotun-dns`** provides domain-suffix split resolver egress (Direct vs Exit); see [Split DNS](#split-dns-gotun-dns). nft DNS redirect is still out of scope — clients must point DNS at the gateway explicitly.

## IPv6 (v1)

No IPv6 split routing. Lab and apply disable/drop IPv6 so it cannot bypass policy. Full IPv6 support is TODO.

## Host isolation

**Host network namespace is never modified** by labs or tests. Integration tests use disposable Docker **bridge** networks (`--internal`), never `--network=host`. Only the Docker API control plane runs on the host.

## Lab topology

Outbound split lab containers: `client`, `gotun`, `exit`, `ru-dest`, `foreign-dest`.

| Path | Expected |
|------|----------|
| client → RU IP | via gotun direct (not wg-exit/exit) |
| client → foreign IP | via gotun wg-exit → exit |
| WG down (no reapply) | foreign fails; RU works |
| endpoint IP | not via wg-exit |

## LAN / Pi deployment

Typical home install: Pi on the LAN; router port-forwards **only** the inbound clients WireGuard UDP port to the Pi; your PC uses the Pi’s **LAN IP** as gateway (not the public IP).

Invariants (proven by `TestLANDeploy_PortForwardHomeIsolation`):

1. WAN peers reach gotun only via the forwarded WG port.
2. Home devices use gotun’s LAN address directly.
3. Tunneled WAN peers cannot reach home-LAN destinations (`iifname "wg-clients" ip daddr @home_nets drop` in `inet gotun`).

Apply with a second config for the clients listen interface:

```bash
gotun apply -prefixes prefixes.txt -endpoint <exit-underlay> \
  -lan 192.168.1.0/24 \
  -wg-config wg-exit.conf \
  -wg-clients-config wg-clients.conf \
  -tunnel-up true
```

`-lan` feeds both mark exclusions and the `home_nets` isolation set.

## Deployment topology (high fidelity)

Integration hierarchy:

```text
topology_test.go       → kernel/policy correctness (fast)
lan_deploy_test.go     → home-router port-forward + LAN isolation
deploy_topo_test.go    → RU vs external Internet, egress identity
```

`TestDeployTopo_EgressIdentity` places the Pi **only** on home LAN. A remote client on RU Internet reaches the Pi via home-router DNAT. The physical RU↔external uplink remains; the test proves path choice by **source identity** at destinations (`labhttp` `GET /peer` from `RemoteAddr`):

- RU destination sees **home-router WAN**
- non-RU destination sees **remote-hop**

## Build & test

Requires Go **1.26+**. Integration and large-set tests talk to the Docker **daemon** via the Engine API (socket / `DOCKER_HOST`); the `docker` CLI is only needed for `make docker-build`.

```bash
make build               # bin/gotun
make test                # unit tests only (large MMDB compile/render if MMDB present)
make docker-build        # gotun:lab image (docker CLI)
make test-integration    # GOTUN_INTEGRATION=1; isolated Docker nets
make test-large-set      # GOTUN_LARGE_SET=1; full RU set → nft in Docker (--network none)
make fetch-prefixes      # prefer local data/geo/*.mmdb; else CSV + MAXMIND_LICENSE_KEY
make clean
```

CLI:

```bash
gotun fetch -mmdb data/geo/GeoIP2-City.mmdb -out prefixes.txt -country RU
gotun fetch -out prefixes.txt -country RU   # CSV download; needs MAXMIND_LICENSE_KEY
gotun amnezia -mmdb data/geo/GeoIP2-City.mmdb -out amnezia-sites.json -format official
gotun amnezia -out amnezia-sites.json -format ios   # CSV download; CIDR in ip (iOS import workaround)
gotun apply -prefixes prefixes.txt -endpoint 10.20.0.2 -lan 10.10.0.0/24 -wg-config wg-exit.conf -tunnel-up true
gotun apply ... -wg-clients-config wg-clients.conf   # optional inbound clients iface + home isolation
gotun clear
```

### Prefix collapse (default)

By default, `gotun fetch`, `gotun apply`, and `gotun amnezia` run **`CollapseIPv4`** at the configuration boundary: canonicalize, dedupe, drop covered prefixes, and merge sibling CIDRs. Coverage is unchanged (same IPv4 address union); only the representation shrinks (often ~70k → ~12k for a full RU extract). Low-level parsers stay uncollapsed so parse/extract tests remain exact. `gotun apply` also collapses whatever file you pass, so older unaggregated `prefixes.txt` files still benefit.

### Amnezia client export

`gotun amnezia` fetches the same country CIDRs as `gotun fetch` (after collapse), then writes Amnezia **site-based split tunneling** JSON for import.

- `-format official` (default): `{"hostname":"<cidr>","ip":""}` — documented Amnezia / iplist shape
- `-format ios`: `{"hostname":"site-N","ip":"<cidr>"}` — workaround when iOS import strips `/prefix` from `hostname`

The JSON does not encode route mode. In the Amnezia app, enable site-based split tunneling and choose the mode where **listed sites bypass the VPN** (country CIDRs go direct; everything else uses the tunnel — same intent as gotun).

### Split DNS (`gotun-dns`)

Companion binary on the **gateway** (not inside `gotun apply`). Clients / Amnezia should use the gateway IP as DNS instead of the remote hop’s resolver so GeoDNS (e.g. Yandex Lavka) sees a RU egress for `.ru` names.

```bash
gotun-dns -listen :53 \
  -direct-upstream 77.88.8.8:53 \
  -exit-upstream 1.1.1.1:53 \
  -mark 0x1
```

| Name class | Path | Dial |
|------------|------|------|
| ends with `.ru` | **Direct** | unmarked → main / ISP |
| everything else | **Exit** | `SO_MARK` (default `0x1`, same as `gotun apply`) → table 100 → `wg-exit` |

**Capabilities:** `CAP_NET_BIND_SERVICE` to bind `:53` as non-root; `CAP_NET_ADMIN` (or `CAP_NET_RAW` where supported) for Exit-path `SO_MARK`. Without the mark capability, Direct queries may work while Exit lookups fail with `EPERM`.

UDP responses with **TC** are retried over TCP on the **same** Direct/Exit dialer. Truncation fallback is implemented in gotun-dns (miekg does not auto-retry).

**DNS vs packet policy:** DNS policy only chooses **resolver egress**. nftables still classifies the returned A/AAAA via `ru_nets` independently. A Direct resolve that yields a non-RU CDN edge can still be sent via `wg-exit`. Future work: TTL-bound `dns_direct_nets` learned from Direct answers (not in this milestone).

Interfaces: exit hop default **`wg-exit`**; inbound clients **`wg-clients`**.

GeoDNS lab: `TestDNSSplit_GeoEgressIdentity` under `make test-integration` (`labdns` answers by query source IP).

### Client cutover (`gotun-client`)

Points a **client** host's default route at the gotun gateway and its DNS at the gateway-side resolver, keeping every on-link LAN reachable, and restores the previous settings on `disable`. NetworkManager only.

```bash
gotun-client status                      # read-only; safe unprivileged
gotun-client enable  -dry-run            # print the exact nmcli commands, change nothing
gotun-client enable                      # snapshot -> arm rollback -> apply -> verify
gotun-client confirm                     # cancel the armed rollback
gotun-client verify  -foreign-ip <ip> -ru-ip <ip> \
  -expect-foreign-egress <exit-public-ip> -expect-ru-egress <isp-wan-ip>
gotun-client disable                     # restore the snapshot
```

**Why not `ipv4.gateway`.** NetworkManager only materialises `ipv4.gateway` alongside a static `ipv4.addresses`, so on a DHCP profile (`ipv4.method=auto`) it is silently inert. `enable` instead sets `ipv4.never-default yes` and appends an explicit default to `ipv4.routes`:

```
nmcli connection modify <con> ipv4.never-default yes \
  +ipv4.routes "0.0.0.0/0 <gateway>" \
  ipv4.ignore-auto-dns yes ipv4.dns <dns> ipv6.ignore-auto-dns yes
```

`+ipv4.routes` appends, so a pre-existing static route survives; `enable` refuses outright when `ipv4.routes` is already set unless `-force`.

**`-apply-mode`** is an escalation ladder, so the risky form is never the first one tried:

| Mode | Command | Link bounce | Survives reboot | Revert |
|------|---------|-------------|-----------------|--------|
| `device` (default) | `nmcli device modify` (D-Bus reapply) | no — an SSH session over the interface survives | no | `nmcli device reapply` |
| `temporary` | `nmcli connection modify --temporary` + `up` | yes | no | restart NetworkManager |
| `persistent` | `nmcli connection modify` + `up` | yes | **yes** | `disable`, or a console |

**Safety contract.** The snapshot is written before anything is mutated, and the automatic rollback is armed *before* the apply, as a transient systemd timer — the countdown is held by PID 1, so it survives the process exiting, the SSH session dropping, and `kill -9`. `enable` then asserts that the default route moved, that exactly one default route exists, and that no protected LAN hairpins through the gateway; any failure rolls back. A rollback failure reports both errors and deliberately leaves the timer armed. `-detach` (default on for link-bouncing modes) re-runs the apply under a transient unit so the SSH drop it causes cannot kill it mid-change.

**Protected LAN set** = every IPv4 prefix on an UP non-loopback interface, plus each repeatable `-lan CIDR`. A multi-homed host keeps *all* of its prefixes on-link; two hosts per prefix are probed, because a stale per-destination route exception can make a single probe read on-link when the prefix is not.

**Gateway-side requirement.** The exit peer's `AllowedIPs` must include every client LAN that will source traffic through the tunnel, **and** that LAN must be source-NATed on the way out. `AllowedIPs` alone only gets the packet accepted and routed: without SNAT it leaves the exit host with an RFC1918 source, is dropped upstream, and no reply is ever generated — while `wg show` counters still climb and the tunnel looks healthy. Symptom: connections hang rather than fail.

## Out of scope (v1)

- Userspace SOCKS/proxy
- IPv6 split routing
- nft/iptables forced DNS redirect
- iptables+ipset backend
- Fail-open on tunnel loss
- Cross-subsystem rollback
- Applying rules on the host netns

## TODO / future improvements

Do **not** implement these until the v1 core (build, unit tests, integration invariants) is green:

- [ ] **IPv6 support** — `ru_nets6`, mark + policy routing; stop blanket disable/drop
- [ ] **DNS → packet coupling** — learn Direct-path A/AAAA into TTL-bound `dns_direct_nets`
- [ ] **Fail-open mode** — optional ISP fallback when WG is down
- [ ] **Prefix source refresh** — scheduled/atomic MaxMind updates in production
- [ ] **Observability** — counters for marked vs direct, set size, reconcile errors
- [ ] **Multi-exit / multi-peer WireGuard**
- [ ] **Stronger apply transactions** — cross-subsystem rollback if needed
