# Learned direct exceptions

Status: **proposed, not implemented.** This describes a class of bug we hit in
production on 2026-10-18 and a runtime mechanism to heal it. Nothing here is in
the tree yet.

**Read Track 1 first.** The motivating bug turned out to be a three-year-old
geolocation snapshot, not an unfixable gap in geolocation. Refresh the data and
measure before building anything that learns at runtime.

## The bug we hit

The World Class iPhone app (`com.worldclass.lifestyle`) refused to work,
reporting that the connection looked like it came from abroad. The app was right.

`worldclass.ru` runs a DNS wildcard, so almost every name under it answers with
one RU address. Two names do not:

| Name | Address | MaxMind verdict | Egress |
|---|---|---|---|
| `worldclass.ru` (apex) | 168.113.248.31 | `168.112.0.0/15` = **US** | marked → `xray0` → 185.80.130.211 |
| `my.worldclass.ru` | 168.113.248.32 | `168.112.0.0/15` = **US** | marked → `xray0` → 185.80.130.211 |
| `app.worldclass.ru` | 168.113.248.33 | `168.112.0.0/15` = **US** | marked → `xray0` → 185.80.130.211 |
| `*.worldclass.ru` (`api.`, `lk.`, `www.`, …) | 95.213.154.241 | `95.213.154.0/23` = RU | direct, home address |

The classifier did exactly what it was told. The data under it was wrong, and
the reason turned out to be duller and more fixable than first assumed — see
**Validation** below. `data/geo/GeoIP2-City.mmdb` has a file mtime of 2026-08-13,
which is when it was copied onto this machine. Its actual `build_epoch` is
**1694704459 = 2023-09-14**. We have been routing a household on a three-year-old
geolocation snapshot.

That snapshot has no real data for this block at all. The entire
`168.113.0.0/16` is covered by one `168.112.0.0/15` record whose coordinates are
37.751,-97.822 with `accuracy_radius: 1000` — the geographic centre of the
continental US, which is what MaxMind emits when it knows only the continent.

The result is worse than "one site is slow". The app authenticates against one
backend and calls another, so a single session arrives from two countries. Every
anti-fraud layer in existence flags that, and in this case it is not even a false
positive — those requests genuinely are leaving through a tunnel.

## Why this is a class, not a row

Three properties make this recur rather than resolve:

1. **The snapshot is always behind, and nothing tells you how far.** A stale MMDB
   is indistinguishable from a current one at the call site: it answers every
   query confidently. Ours was three years old and the only visible symptom was a
   gym app complaining about a foreign connection.
2. **The failure is silent and misattributed.** Nothing errors. The site loads,
   the app starts, and then some server-side check rejects you. The user blames
   the app, the app blames the IP, and nobody blames the routing table. We lost
   an evening to this one and only found it by reading conntrack on the gateway.
3. **Split-brain domains amplify it.** A wildcard zone with a couple of
   off-wildcard hosts is common, and it is the worst case: the two egress
   identities are in the same session, so the service sees something that looks
   actively evasive rather than merely foreign.

Assume every refresh of `prefixes.txt` leaves some number of RU services
misclassified. The question is not whether to carry exceptions but where they
come from.

## Validation

Checked on 2026-10-18 after the MaxMind verdict was questioned. Every independent
source says RU; only our snapshot says otherwise.

| Source | Verdict for 168.113.248.33 |
|---|---|
| RIPE RDAP | `168.113.248.0/23`, name **RU-SERVICEPIPE**, `country: RU`, type ASSIGNED PI, registrant SERVICEPIPE LLC |
| BGP (RIPEstat) | `168.113.248.0/24` originated by **AS201706**, AS-SERVICEPIPE, SERVICEPIPE LLC |
| RIPE `delegated-ripencc-extended-latest` | `168.113.248.0/23` — `ripencc\|RU\|ipv4\|168.113.248.0\|512\|…\|assigned` |
| IP2Location (via whatismyipaddress) | Russian Federation, Tomskaya oblast, ServicePipe LLC, Data Center/Transit |
| **our MaxMind snapshot (2023-09-14)** | **US**, continent-level default |

So this is not a case of geolocation being inherently unable to see RU hosting in
legacy space. The registry has said RU all along, in a free file, at a /23 that
covers all three addresses.

### Blast radius

Measured by merging every `ripencc|RU|ipv4` allocated/assigned record and
subtracting the deployed `/etc/gotun/prefixes.txt`:

```
RIPE RU ipv4 (merged)      :   7408 ranges    45,239,616 addresses
deployed prefixes.txt v4   :   9171 ranges    45,179,424 addresses
RU per RIPE but NOT direct :   1464 ranges     1,802,880 addresses  (4.0%)
```

The totals are close, so the direct set is broadly right — but **1.8 million RU
addresses in 1464 separate ranges are being tunnelled right now**. The largest
are `109.254.0.0/16`, `136.234.0.0/18`, `135.106.136.0/21`, `138.16.140.0/22`,
`153.51.32.0/19`, and — sixth on the list — `168.113.128.0/18`, the World Class
neighbourhood.

World Class was not bad luck. It is one of 1464, and it only surfaced because the
service happened to split a login flow across a correctly-classified wildcard and
a misclassified apex.

## Track 1: fix the data (do this first; it is free and it is most of the fix)

Two steps, in order:

1. **Refresh the MMDB.** We are three years stale. This alone may resolve a large
   share of the 1464 ranges, and costs nothing but a download. Nothing below is
   worth building before this is done and re-measured.
2. **Union in the RIR delegation file.** `delegated-ripencc-extended-latest` lists
   allocations by country from the registry itself rather than from geolocation
   inference. It is authoritative, free, updated daily, cannot be influenced by an
   attacker, and needs no new runtime state. `gotun fetch` should emit
   {MaxMind RU} ∪ {RIPE RU-delegated} and `Collapse` the union.

The open question from the first draft — whether RIPE actually attributes
`168.113.248.0/24` to RU — is **answered: yes**, as a /23. Track 1 would have
prevented the motivating bug outright.

Residual after Track 1: a RU service on space delegated to a foreign LIR, or on
space whose registry country is stale. Smaller than assumed, and that residual is
all Track 2 needs to handle.

## Track 2: learn from our own DNS answers

`gotun-dns` already sees every query and already decides Direct vs Exit by name
suffix. It therefore holds both halves of a contradiction we currently throw away:

> We classified this name as **Direct** because it is `.ru`, and the answer we got
> back is an address our prefix set calls **not RU**.

That contradiction is the signal. When it fires, record the answer address as a
learned direct exception, and the next connection to that address goes direct.

### Eventual consistency is the right trade

The first connection to a newly-seen address still goes through the tunnel,
because the exception is installed after the answer is returned, not before. The
alternative — hold the DNS reply until the kernel is updated — adds latency to
every query to remove one wrong-path connection, and would make the resolver's
availability depend on the kernel write succeeding. Not worth it.

So: **first request tunnelled, subsequent requests direct.** For a login flow
this means the very first call of a fresh install may still be seen from the
exit. Acceptable; a retry fixes it, and in practice the app resolves several
names before it calls anything interesting.

### Where exceptions live in the kernel

Not in `ru_nets`. The reconciler replaces the owned table wholesale —
`delete table inet gotun` and `add table inet gotun` in one `nft -f`
transaction — so anything added out of band is destroyed on the next apply. Worse,
the drift-reconciling watchdog (5dbc19b) would see an out-of-band element
as drift and remove it, so the mechanism would fight the watchdog and lose
intermittently, which is the least debuggable outcome available.

Instead: a second set that gotun owns the *existence* of but not the *contents* of.

```
set direct_learned  { type ipv4_addr; flags interval; }
set direct_learned6 { type ipv6_addr; flags interval; }

ip  daddr != @ru_nets  ip  daddr != @direct_learned  meta mark set 0x1
ip6 daddr != @ru_nets6 ip6 daddr != @direct_learned6 meta mark set 0x1
```

Verified to load as valid nft (checked in a throwaway netns, not on a live host).
An empty `direct_learned` is safe here: no element matches, so `!=` is true for
everything and the conjunction degrades exactly to today's rule. This is worth
stating because it is the inverse of the trap we already fell into once — an
empty `ru_nets6` under `ip6 daddr != @ru_nets6` matches *everything* and tunnels
all IPv6. Under `!=` in a conjunction, empty is a no-op; as the sole condition,
empty is a catastrophe. Keep a test on both.

The cost is a second set lookup per packet in the prerouting hot path. At
household scale that is noise, and the alternative (merging into `ru_nets`) is
what creates the watchdog fight above.

**The reconciler must be taught that `direct_learned` is declared but not
content-reconciled.** That is a real hole in the ownership model — "gotun only
touches objects it owns" becomes "…and owns one set whose elements it does not
manage". It needs to be explicit in the model, not an accident of omission, or
the next person to tighten drift detection will silently break this.

### Who writes the kernel

`gotun-dns` learns and persists. `gotun watch` applies. The resolver stays a
resolver and never touches netlink or shells out to `nft`; the one process that
already owns kernel state keeps owning it.

Latency matters here — a 60s watch interval would make "the second request goes
direct" false for a minute. So `watch` takes an inotify watch on the store file
and reconciles `direct_learned` on write, which puts the delay in the
milliseconds.

The simpler fallback, if inotify turns out to be a nuisance on OpenWrt, is for
`gotun-dns` to issue `nft add element` itself. It is less clean and splits kernel
ownership across two binaries; prefer the file-watch.

### Durable store

Flash on these routers does not enjoy being written to. A write per learned answer
would be actively destructive, so the in-memory set is authoritative for the hot
path and the file is a checkpoint.

- Path: `/etc/gotun/learned-direct.jsonl`, already covered by the
  `/etc/gotun/` entry in `sysupgrade.conf`.
- Append-only, one JSON record per line:
  `{"prefix":"168.113.248.31/32","name":"app.worldclass.ru","first":"…","last":"…","hits":7}`
- Flushed on a dirty-flag ticker (default 60s) and on shutdown, never per query.
- Compacted on startup: merge duplicate prefixes, drop expired entries, drop
  anything now covered by `prefixes.txt`, rewrite the file once.

Append-only rather than a rewritten blob because appends are cheap and a truncated
tail after power loss costs one entry rather than the whole store.

### Compression and widening

Learned entries arrive as single addresses. The obvious worry is set growth, and
it is the wrong worry: nftables interval sets carry our 12106-line RU list without
complaint, and a household will learn entries in the hundreds, not the millions.

The real argument for widening is **latency**, not size. Every distinct address in
a misclassified block costs one more tunnelled first request. `worldclass.ru`
burned three. Widening to the enclosing /24 preempts the rest.

Proposed rule, run at compaction rather than inline:

- When ≥ N (default 2) distinct learned addresses fall inside the same /24, and
  that /24 is not already covered by `ru_nets`, promote them to the /24.
- Cap widening at /24 for IPv4 and /48 for IPv6. The cap is a safety limit, not a
  tuning knob: a wider prefix sends genuinely foreign neighbours direct, which is
  the exact leak the tunnel exists to prevent.
- Then run the result through `prefixes.Collapse`, which already does lossless
  merging and is fuzz-tested.

Widening trades precision for latency, and the trade is only sound because the
cap is tight. Do not raise it to /16 because the set looks untidy.

### Expiry, and closing the loop

Every entry carries `last` (last confirming observation). An entry not confirmed
for 30 days is dropped at compaction. Without this, a one-off CDN answer pins a
foreign address as direct forever, and when the service moves on, that exception
becomes a small permanent leak in the opposite direction — traffic that should be
tunnelled going direct, silently, which is the failure mode this project cares
most about.

The self-healing closes properly at load time: any learned prefix now covered by
`prefixes.txt` is discarded. When MaxMind or RIPE eventually carves out
`168.113.248.0/24`, our exception evaporates on the next refresh with no
intervention.

## Poisoning: the part that decides whether this ships

This mechanism converts a DNS answer into a routing exception. Anyone who can
register a `.ru` name controls DNS answers. So, stated plainly: **an attacker can
make gotun route a chosen address direct** by pointing a `.ru` name at it and
getting the client to resolve it once (an image tag on any page suffices).

What that buys them: de-tunnelling a specific destination, so a host they control
sees the real home address instead of the exit. For a tool whose purpose is
controlling which addresses see you, that is the whole ballgame. It deserves more
caution than the convenience warrants on its own.

Required mitigations, all of them, not a selection:

- **Opt-in, default off** (`-learn-direct=false`). A behaviour that de-tunnels
  destinations must never arrive in an upgrade unannounced.
- **Learn only from the Direct upstream.** We already send `.ru` to the RU
  resolver; answers that arrived via the exit are never a learning input.
- **Require repetition.** Do not learn on first sight — require K (default 3)
  observations of the same (name, address) pair, spread over at least T (default
  60s). A drive-by single resolution then teaches nothing.
- **Rate-limit and cap.** At most 20 new entries per minute, at most 2048 total.
  On hitting the cap, stop learning and log loudly rather than evicting silently.
- **Refuse to learn** anything in `TunnelEndpoints`, `LANs`, `NonRoutable`, or
  already in `ru_nets`. An exception overlapping the endpoint list is a tunnel
  that eats itself.
- **Log every learn at info.** The store must be auditable after the fact; "it
  started going direct and nobody knows why" is not an acceptable state for this
  project.

Even with all of that, the honest summary is that the suffix list is a trust
boundary. `.ru` currently means "we trust the whole RU namespace to tell us the
truth about addresses". Narrowing the learn trigger to an operator-supplied
allowlist of names (`-learn-direct-names=worldclass.ru,…`) removes the attack
almost entirely at the cost of the automation being automatic. **That may well be
the version worth shipping**, and the fully automatic one may belong behind a flag
nobody turns on.

## Config surface

```
gotun-dns -learn-direct=false \
          -learn-store=/etc/gotun/learned-direct.jsonl \
          -learn-min-hits=3 -learn-min-age=60s \
          -learn-ttl=720h -learn-max=2048 -learn-rate=20/min \
          -learn-names=""        # empty = any Direct-classified name

gotun apply -learn-store=/etc/gotun/learned-direct.jsonl
gotun watch -learn-store=…      # inotify + reconcile direct_learned
```

## Testing

- Unit: contradiction detection; store round-trip; compaction; widening at the
  /24 threshold and refusal above the cap; expiry; the refuse-to-learn lists.
- Property/fuzz: widening + `Collapse` must never produce a set covering an
  address that no input justified. Model on `collapse_fuzz_test.go`.
- nft: `direct_learned` empty must compile and must be a no-op; `ru_nets6` empty
  under a sole `!=` must still refuse to classify. Both in one test so the
  asymmetry is documented where someone will read it.
- Integration (lab): add a `ru-dest-misgeo` container whose address is outside
  `ru_nets`, with a `.ru` name. Assert first connection egresses via exit,
  and after K resolutions subsequent connections egress direct.

## Implementation slices

0. **Refresh the MMDB.** Free, no code. Re-measure the blast radius afterwards.
1. **Track 1.** Add the RIPE delegated-file union to `gotun fetch`, `Collapse`
   the result, redeploy `prefixes.txt`, and re-measure again. Also emit a warning
   when the MMDB `build_epoch` is older than some threshold, so the next
   three-year snapshot announces itself.

   **Stop here and look at the number before continuing.** If the residual after
   slices 0 and 1 is small, Track 2 is not worth its attack surface and the rest
   of this list should not be built.
2. Store package: load/append/compact/expire/widen, no network, fully unit-tested.
3. `direct_learned` sets + conjunction rule in `compile`, with the reconciler
   taught the content carve-out. Still fed by nothing — operator-populated file
   only. This alone is already a usable manual override, and `gotun fetch` does
   not clobber it.
4. Learning in `gotun-dns`, behind `-learn-direct`, with `-learn-names` as the
   recommended mode.
5. `watch` inotify reconcile.
6. Lab integration test.

Slice 3 is worth landing on its own merit: today a manual override appended to
`prefixes.txt` is silently wiped by the next `gotun fetch`, which is its own small
trap.

## Open questions

- After an MMDB refresh plus the RIPE union, how large is the residual? Re-run the
  blast-radius measurement above. If it collapses to a handful of ranges, Track 2
  is not worth its security surface and this doc should end at Track 1.
- Should the RIR union cover other registries? A RU service on ARIN- or
  APNIC-delegated space is the same bug with a different file.
- Should a learned exception apply to the whole answer set of a name, or only to
  addresses actually connected to? Learning the whole RRset is simpler; learning
  on connection needs conntrack correlation we do not have.
- CNAME chains across TLDs: `static.avito.ru` → `cdnvideo.ru` resolves fine today,
  but a `.ru` name CNAMEd to a genuinely foreign CDN would teach us to send that
  CDN direct. Probably want to classify on the final owner name, not the queried
  one.
