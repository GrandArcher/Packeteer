# Changelog

All notable changes to Packeteer are documented here. Versions are Git tags on `main`. The image tags `ghcr.io/grandarcher/packeteer:0.1.0` and `:latest` are published from the `v0.1.0` tag. `:edge` tracks `main`.

## [Unreleased]

### Added

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

[0.1.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.1.0
