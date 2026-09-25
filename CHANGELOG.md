# Changelog

All notable changes to Packeteer are documented here. Versions are Git tags on `main`. The image tags `ghcr.io/grandarcher/packeteer:0.1.0` and `:latest` are published from the `v0.1.0` tag. `:edge` tracks `main`.

## [Unreleased]

### Added

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
