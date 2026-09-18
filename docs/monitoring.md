# gotun tunnel monitoring (deferred)

Status: **postponed** until home-lab storage exists. Do not implement scrapers, exporters, or long-retention metrics on N150 alone.

## Why wait

There is no dedicated metrics store yet. Planned home lab:

- NAS with ~40 TB usable (RAID5, 3×20 TB)
- On that (or a VM backed by it): Prometheus / VictoriaMetrics (+ Grafana, optionally Loki)
- N150 stays a thin producer; history lives on the NAS

Until that side project is up, keep operating gotun without a metrics pipeline. Revisit this doc when the NAS can hold 30–90 days of scrapes.

## Goal

Treat the exit hop as a first-class signal, not just “`gotun.service` / `wg-exit` is up.” Capture enough time series to see diurnal ISP/DPI patterns and correlate flaps with apply/clear/port rotates.

## What to measure (N150)

| Signal | Why |
|---|---|
| Handshake age (`wg show` latest-handshake) | Stale (>2–3× keepalive) ⇒ tunnel dead even if `wg-exit` is up |
| RX/TX byte deltas | TX grows, RX flat ⇒ initiation/handshake path OK, data plane dead |
| Peer RTT (`ping 10.67.0.1`) | Underlay + crypto latency to exit VPS |
| Marked foreign RTT (`ping -m 1` to a stable IP) | End-to-end policy path via exit |
| Unmarked RU RTT | Control: Flint / house uplink still healthy |
| Egress identity (occasional marked vs unmarked public IP) | Proves MASQUERADE / path split, not just ICMP |
| `gotun` apply / clear / restart events | Correlate flaps with config changes |

Optional later:

- nft counters on `exclude-endpoint` / mark rules
- client ListenPort rotation events
- VPS `wireguard-go` CPU / peer transfer (optional scrape on `vpn`)

## Alert ideas (once scraped)

- `handshake_age_seconds > 180`
- `rate(rx_bytes) == 0` AND `rate(tx_bytes) > 0` for ~2m
- peer or marked RTT missing / `> 200ms`
- unmarked RU path failing (uplink, not tunnel)

## Target shape (after NAS)

```text
N150 ──(textfile / small exporter)──► Prometheus or VictoriaMetrics (on NAS) ──► Grafana
  │                                         ▲
  └── journal / watchdog ──────────────────► Loki (optional) ─┘
vpn (optional): handshake / peer bytes only
```

Guidelines:

- Keep scrapers small on N150; store history on the NAS.
- ~15s scrape for WG/handshake/RTT; identity checks every 1–5m (avoid probe flood).
- Retention 30–90d is enough to see diurnal filtering patterns.
- Metrics say *what* broke; logs say *when* ListenPort was rotated or `gotun apply` ran.

## First implementation slice (when unblocked)

1. Stand up Prometheus or VictoriaMetrics + Grafana on NAS-backed host.
2. On N150: systemd timer + script → Prometheus textfile (parse `wg show`, peer ping, marked/unmarked RTT).
3. Three alerts: handshake age, RX stall, marked RTT.
4. Optional: journal → Loki for `gotun.service` / `wg-quick@wg-gotun`.

Pretty dashboards and VPS exporters can follow after a week of data.

## Related ops (live today, not metrics)

N150 rollback / clear notes live on the box at `/etc/gotun/ROLLBACK.txt` (not in this repo; secrets stay on the host).
