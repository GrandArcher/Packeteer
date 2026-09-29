# Changelog

All notable changes to Packeteer are documented here. Versions are Git tags on `main`. The image tags `ghcr.io/grandarcher/packeteer:0.1.0` and `:latest` are published from the `v0.1.0` tag. `:edge` tracks `main`.

## [Unreleased]

### Added

- Inbound commit control (#25, first half; lab-proven only). New optional `inbound` block with its own `mode` (default `observe`) and a new in-process inbound announcer (`inbound.announcer`, type `gobgp`) with a marker community and a per-provider catalog of prepend signals and provider TE communities. When a provider's inbound 95th percentile is over commit, the operator's own prefixes are re-announced to the edge with that provider's catalog communities, `packeteer_community`, and `no-export`; the edge's policy applies the prepend on that session only ([docs/inbound.md](docs/inbound.md)). `suggest` is the moderated path (`GET /api/inbound`, `inbound.steered` / `inbound.released` events), and nothing is announced outside `inject`. Hold time, `release_pct`, a cooldown, `improvement_ttl`, a shared `max_improvements`, the allowlist, and the learned RIB all apply; stale telemetry releases at once, RIB loss and shutdown withdraw, and it never steers away from every provider. Outbound improvements refuse inbound prefixes. The `fixed` telemetry plugin gains `in_mbps`. New FRR lab job with two simulated transits proves the prepend and TE community on the right session and a plain path after release, SIGTERM, and SIGKILL. Rollback: `inbound.mode: observe` and restart.

## [0.2.0] - 2026-09-28

Second release: the v0.2 IRP-parity milestone (#15–#24). More probing (UDP, traceroute discovery, retry, outage detection), SNMP telemetry and 95th-percentile commit control, cost-aware routing, routing policies and maintenance windows, passive problem detection, alerts, reports and history, and read-only troubleshooting tools. The default stays `mode: observe`; every new capability is off unless configured, and injection still requires the learned RIB, the allowlist, the community, the cap, and hold time. CI still proves announce, withdraw, and crash-withdraw against FRR with documentation prefixes.

### Added

- Troubleshooting tools (#24). `/api/troubleshoot/lookingglass` shows the learned route for a prefix, the longest covering route, and learned more-specifics. With `troubleshoot.enabled: true`, `POST /api/troubleshoot/probe` probes one address from every provider with the prober chain, `POST /api/troubleshoot/traceroute` runs a UDP traceroute from each provider's source, and `POST /api/troubleshoot/whois` looks up an address, prefix, or ASN through the new `whois` plugin kind (built-in `rdap`). The dashboard has a Troubleshooting section. Requests are rate limited (`requests_per_minute`, default 6), need basic auth when it is on, and refuse loopback, link-local, multicast, and unspecified targets. The tools are read-only: on-demand results never reach the decision loop and nothing announces. The looking glass is always on; the rest are off by default.
- Reports and history (#23). New `storage` plugin kind with the `sqlite` built-in (embedded, pure Go, file on the `/var/lib/packeteer` volume, `retention` default 400 days). The controller records daily probe rollups per prefix and provider, one row per improvement with before (native) and after (chosen provider) loss and latency, and per-prefix origin ASN, country, and volume. `/api/reports/<name>` serves `summary`, `improvements`, `causes`, `performance`, `providers`, `prefixes`, `asns`, `countries`, `probes`, and `savings` as JSON or CSV (`?format=csv`), and the dashboard has a Reports section. History is written once a minute and on shutdown after the withdraw; a storage failure never delays or withdraws an improvement. Storage does not announce. Off unless `storage` is set; the example config sets it.
- Alerts and notifications (#22). A documented event catalog ([docs/EVENTS.md](docs/EVENTS.md)) with severities, SNMP trap IDs, and dedup keys: improvement added, switched, and removed; provider (probe source) down and up; iBGP session down and up; commit exceeded and cleared; announcer sync failed and recovered; outage incidents; controller started and stopping. New `smtp` notifier (STARTTLS required by default, credentials from the environment) and `snmptrap` notifier (SNMPv2c or v3, secrets from the environment). The `webhook` notifier gains `slack`, `teams`, and `pagerduty` presets (problems trigger, recoveries resolve the same dedup key) and a `template` body for SMS and other gateways. Every notifier, `exec` included, takes `events`, `min_severity`, and `rate_limit`. Each notifier has its own bounded queue, so a slow or failing notifier never delays probing, decisions, or withdrawals. Notifiers never announce. Off unless `notifiers` is configured.
- Passive problem detection (#21). The `span` target source reads a SPAN/mirror port with AF_PACKET (`NET_RAW`, host networking) or replays a classic pcap, follows TCP connections between your `local` networks and remote addresses, and scores remote prefixes by retransmissions, handshake timeouts, remote resets, and optionally handshake RTT. Problem prefixes are probed first. The `flow` source gains an optional `problems` block that scores the same failures from TCP flags on unsampled NetFlow v5/v9 and IPFIX. Neither announces. Off unless configured.
- Routing policies (`policies`). The `rules` policy matches by prefix, origin ASN, or country (a MaxMind-format database you mount) and applies `ignore`, `allow`, `deny`, `static`, or `vip`. A prefix match beats an ASN match, which beats a country match; the longest prefix wins, then list order. The `maintenance` policy excludes providers during cron-scheduled, one-off, or on-demand windows (`POST /api/maintenance`, basic auth required). Decisions show the matched policy. Every verdict still goes through the RIB, allowlist, cap, and withdraw rules. A `static` rule requires `max_loss_pct` (optional `max_rtt`): the pin is announced and held only while its path stays inside that ceiling, and switching an existing improvement onto it waits out `hold_time`. Pins expire on `improvement_ttl` like other improvements and return next round if the prefix is still in the RIB. On-demand maintenance windows are in memory only and end on restart; configure planned windows in `windows`. Off unless listed.
- `snmp` telemetry plugin. Polls interface octet counters over SNMP v2c or v3 and tracks 95th-percentile usage for the open UTC billing period (`separate`, `greater`, and `greater_separate`). Credentials are environment variables. The collector does not announce. Samples are in memory and are cleared on restart. `/api/telemetry` and `packeteer_telemetry_*` expose them.
- `commit` scorer. Keeps each provider's billable 95th under its commit by moving prefixes that have flow volume onto a provider with room, and can balance a provider group (`equal` or `proportional`). `precedence` orders destinations and is the last resort; sharing a group does not outrank it. A move that increases loss is refused unless `loss_override` is set, and Decide enforces that for every planner. A commit steer whose loss clears `min_loss_delta_pct` is withdrawn and waits out `hold_time`. A smaller gap stays. Improvements are tagged `performance` or `commit`, share `max_improvements` (a new performance move can displace the smallest commit steer), and still require the learned RIB. The default scorer remains `weighted`. Switching back and restarting withdraws commit improvements.
- `cost` scorer and `providers[].cost`. Moves a prefix to the cheapest priced provider whose path is inside a performance floor (`floor.max_loss_pct`, `floor.max_rtt`, measured from the best path) and cheaper than native. `precedence: performance` (default) lets performance moves win; `precedence: cost` keeps a native path inside the floor and prefers the cheapest in-floor path over the fastest. Decide re-checks the floor and the price and withdraws a cost steer at once when it leaves the floor. Improvements are tagged `cost`, share `max_improvements`, and still require the learned RIB and the allowlist. `/api/improvements` reports `cost_delta` and `est_savings`, and `packeteer_estimated_savings` sums them. The default scorer remains `weighted`; switching back and restarting withdraws cost improvements. The FRR lab has a cost-cause announce, withdraw, and SIGKILL job.
- `fixed` telemetry plugin, for labs and tests. It reports a configured billable figure and can re-read a file. It does not poll and it does not announce.
- Static targets accept an optional `mbps` rate so commit control can run without a flow export. The FRR lab has a commit-cause announce, withdraw, and SIGKILL job.
- `outage` target source. Probe results inside a window are correlated by learned AS path and by provider. Enough prefixes failing together re-queues the affected prefixes (capped) and emits `outage.as` or `outage.circuit`. One prefix does not. The source does not announce.
- `udp` prober. A datagram reply counts. An ICMP destination-unreachable counts only when the sender is the target, so a firewall `REJECT` is loss. It is not in the default chain. A TCP RST from a middlebox is still indistinguishable from the target.
- `traceroute` target source. When the configured host does not answer, probes move to the last stable hop. The prefix is unchanged and the hop is not announced. Discovery runs in the background, returns the last cache immediately, and is capped by `budget` (default 10s).
- `vip` target source. Prefixes, and prefixes whose learned AS path contains a listed ASN, are probed on their own interval. `max_targets` (default 100) caps the list. The expansion is rebuilt only when the RIB changes. The interval must be shorter than the staleness window, and it cannot slow a prefix another source already listed. The global packet rate limit still applies. ASN matches wait until the RIB is ready.
- Retry probing. `probe.retry_loss_pct` (default off) re-measures a lossy sample with `probe.retry_packets` before it is stored.

## [0.1.0] - 2026-09-25

First release. An observe-first BGP path performance controller in one container. Injection is opt-in and is tested in CI against FRR with documentation prefixes (RFC 5737) and the private ASN 64512.

### Added

- Probe engine. ICMP echo and TCP connect (port 443), sourced from each provider, with a worker pool and a global packet-rate cap. Loss, RTT min/avg/max, and jitter.
- Target sources: a static prefix list, and a flow collector for NetFlow v5/v9, IPFIX, and sFlow v5 (top prefixes by bytes).
- Learn-only iBGP RIB view on an embedded GoBGP speaker. Graceful restart is not enabled. The speaker proposes a 90s hold time.
- Decision engine with a weighted scorer, loss and latency thresholds, hold time, a cooldown after flip-back, an improvement cap (default 50), and an improvement TTL.
- Inject mode. The `gobgp` announcer publishes the exact learned prefix on that same iBGP session, with the provider next hop, `local_pref`, the configured community, and `no-export`.
- Withdraw on shutdown, on a dead probe source, on stale measurements (including a probe round that never finishes), when every BGP session is down, and when a prefix the router was still advertising leaves the RIB. A best-path hide is kept so the route does not flap.
- Read-only HTTP surface on `127.0.0.1:8080`: dashboard, `/healthz`, `/readyz`, Prometheus `/metrics`, and a JSON API. Optional basic auth from the environment.
- Plugin host: prober, source, scorer, announcer, and notifier. Built-ins plus `exec` and `webhook`. Announcers stay in-process.
- Container image (linux/amd64, linux/arm64) and a Compose file. Config is a mounted file.
- FRR lab. The e2e job checks announce, flip-back, withdraw while the controller is alive, clean shutdown, and SIGKILL (the route is gone within the BGP hold timer).
- Operator quick start, config reference, router filters (MikroTik, FRR, Junos, IOS), and policy routing.

### Safety

- The shipped example and Compose instructions stay `mode: observe`.
- Inject requires `mode: inject`, a non-empty allowlist, a community, `local_pref`, a positive hold time, positive loss and latency thresholds, an announcer, and an iBGP neighbor.
- Packeteer does not announce a prefix that is absent from the learned RIB. `more_specific_bits` is rejected.
- Learned routes are not reflected. The export policy accepts only Packeteer's own routes that carry the community.
- No graceful restart.

### Known limitations

- On a best-path-only iBGP session the router stops advertising a prefix once Packeteer's route wins. A provider withdraw after that point is caught at `improvement_ttl`, unless the router keeps sending the native path (`advertise-best-external` on FRR and IOS). Additional paths and BMP are later.
- `observe` and `suggest` share one code path. Neither announces. Recommendations are the log, the dashboard, and `/api/decisions`.
- No inbound optimization, FlowSpec, RTBH, SNMP, commit or cost control, alerts beyond the webhook notifier, reports, or high availability.
- The flow collector is unauthenticated UDP. Firewall it to the exporter.
- The HTTP server is read-only and has no accounts or audit log. It defaults to loopback.
- Communities are RFC 1997 (two 16-bit integers). `router_id` is IPv4.
- RouterOS, Junos, and IOS snippets are documentation. The automated BGP test is the FRR lab.

[0.2.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.2.0
[0.1.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.1.0
