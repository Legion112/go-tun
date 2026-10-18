# gotun TODO

Ordered roughly by value. Items with a design doc link are specified; the rest
are one-liners that still need thinking through.

## Routing correctness

- [ ] **The geo snapshot is three years old.** `data/geo/GeoIP2-City.mmdb` has
      `build_epoch` 1694704459 = **2023-09-14**. The file mtime (2026-08-13) is
      only when it was copied here and hides this completely. Refresh it, then
      regenerate and redeploy `prefixes.txt`. Everything below is cheaper to judge
      once this is done.

- [ ] **Union the RIR delegation file into `gotun fetch`.**
      `delegated-ripencc-extended-latest` is authoritative, free, daily, and
      immune to the staleness above. Measured against the deployed list today:
      **1,802,880 RU addresses across 1464 ranges are currently being tunnelled**
      — 4.0% of RU space. Largest: `109.254.0.0/16`, `136.234.0.0/18`,
      `135.106.136.0/21`, `138.16.140.0/22`, `153.51.32.0/19`,
      `168.113.128.0/18`. Emit {MaxMind RU} ∪ {RIPE RU} and `Collapse` the union.

- [ ] **Re-measure the residual** after the two items above, using the method in
      [docs/direct-learning.md](docs/direct-learning.md#blast-radius). The result
      decides whether the next item is worth building at all.

- [ ] **Self-healing direct exceptions** —
      [docs/direct-learning.md](docs/direct-learning.md). A `.ru` name resolving
      to an address our prefix set calls non-RU is a contradiction we currently
      discard; it could become a durable direct exception. **Deprioritised**: the
      motivating case (`worldclass.ru` on `168.113.248.0/23`, RU per RIPE, BGP and
      IP2Location, US per our 2023 snapshot) is fixed by the two items above, and
      this mechanism converts DNS answers into routing exceptions, which is a real
      attack surface. Read the poisoning section before writing any of it; the
      operator-allowlist variant is probably the only version worth shipping.

- [ ] **`gotun fetch` clobbers manual overrides.** It rewrites `prefixes.txt`
      wholesale, so a hand-added CIDR survives until the next refresh and then
      vanishes months later, which reads as the original bug coming back. Needs a
      separate overrides file the generation step concatenates.

- [ ] **Stale `direct-src` on flint2.** The prerouting chain still carries
      `ip saddr 192.168.8.162 return comment "direct-src"`, which was N150's
      address. That box is now the Project Zomboid server, so the rule currently
      exempts a game server from the tunnel — possibly what we want, but by
      accident rather than decision. Confirm intent, then document or drop it.

## Operability

- [ ] **Warn on a stale geo snapshot.** `gotun fetch` and `gotun apply` both know
      the MMDB's `build_epoch` and neither says anything about it. A line at apply
      time — "geo data is 1130 days old" — would have turned this whole
      investigation into a glance. The failure mode being silent is the recurring
      theme in this project; this one was silent for three years.

- [ ] **No `gotun status`.** Subcommands are `fetch`, `amnezia`, `apply`,
      `watch`, `clear`. Diagnosing the gateway means reading `nft list table`,
      `ip rule`, and `ip route show table 100` by hand. A read-only `status` that
      answers "would this address go direct or via the tunnel, and why" would have
      cut the World Class investigation to one command.

## Docs

- [ ] **`docs/monitoring.md` targets a decommissioned host.** Written throughout
      against N150 as the producer; gotun moved to flint2 on 2026-10-08. The
      deferred-until-NAS decision still stands, but the box names and the
      `wg-exit` assumptions (the transport is `xray0` now) are wrong.
