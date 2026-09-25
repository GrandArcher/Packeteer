# Threat model

Packeteer can change how a network forwards packets. Failure modes matter more than features.

## Routing failures

- **Flap** — oscillating improvements. Mitigate with hold time, hysteresis, and a max flip rate.
- **Leak** — more-specifics learned from Packeteer advertised to transit. Mitigate with a well-known community and outbound filters on every eBGP session.
- **Blackhole** — inject toward a next-hop that is down. Mitigate by requiring a live RIB path and withdrawing on probe-source or session failure.
- **Over-injection** — thousands of more-specifics exhaust TCAM. Mitigate with max-improvements and prefix aggregation policy.
- **Stale intent** — controller dies, or keeps announcing a prefix the edge no longer has. Packeteer withdraws on shutdown and as soon as the prefix leaves the learned RIB, and never enables graceful restart; the BGP hold timer is the backstop if the process is killed before the withdraw is sent.

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
