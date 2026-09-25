# Threat model

Packeteer can change how a network forwards packets. Failure modes matter more than features.

## Routing failures

- **Flap** — oscillating improvements. Mitigate with hold time, hysteresis, and by keeping an improvement when the router hides the native path because Packeteer's route won. Withdrawing on that hide brings the native path back and the next round injects again.
- **Leak** — more-specifics learned from Packeteer advertised to transit. Mitigate with a well-known community and outbound filters on every eBGP session.
- **Blackhole** — inject toward a next-hop that is down. Mitigate by requiring a live RIB path and withdrawing on probe-source or session failure.
- **Over-injection** — thousands of more-specifics exhaust TCAM. Mitigate with max-improvements and prefix aggregation policy.
- **Stale intent** — controller dies, or keeps announcing a prefix the edge no longer has. Packeteer withdraws on shutdown, when a prefix the router was still advertising disappears, and at `improvement_ttl` when the native path is hidden by Packeteer's own route. It never enables graceful restart. The BGP hold timer is the backstop if the process is killed before the withdraw is sent.

## Flow input

The flow source accepts unauthenticated UDP. Anyone who can reach a listen port can add probe targets and spend probe budget. That does not inject routes: inject mode still requires the prefix in the learned RIB, the allowlist, thresholds, hold time, and the improvement cap. Run with host networking and firewall the port to the exporter. Counters live in memory for one window. Raw flow records are not written to disk.

## Measurement failures

- Asymmetric return path on probes
- Provider rate-limiting ICMP
- Probing the wrong source address (not actually leaving via that transit)

## Operational / public-repo failures

- Secrets or customer prefixes committed here
- CI publishing production telemetry
- An agent enabling `inject` in example config

Example config must remain `mode: observe`.
