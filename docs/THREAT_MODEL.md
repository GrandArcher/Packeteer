# Threat model

Packeteer can change how a network forwards packets. Failure modes matter more than features.

## Routing failures

- **Flap** — oscillating improvements. Mitigate with hold time, hysteresis, and by keeping an improvement when the router hides the native path because Packeteer's route won. Withdrawing on that hide brings the native path back and the next round injects again.
- **Leak** — more-specifics learned from Packeteer advertised to transit. Mitigate with a well-known community and outbound filters on every eBGP session.
- **Blackhole** — inject toward a next-hop that is down. Mitigate by requiring a live RIB path and withdrawing on probe-source or session failure.
- **Over-injection** — synthesizing more-specifics can exhaust TCAM. Packeteer announces only the exact prefix a neighbor advertised, so `max_improvements` bounds the number of routes. A config that sets `more_specific_bits` is rejected.
- **Stale intent** — controller dies, or keeps announcing a prefix the edge no longer has, or keeps announcing after probes stop refreshing. Packeteer withdraws on shutdown, when a prefix the router was still advertising disappears, when measurements are older than the max result age (checked on a timer, not only when a round completes), and at `improvement_ttl` when the native path is hidden by Packeteer's own route. A probe round that does not finish is abandoned at that same age and does not refresh results. It never enables graceful restart. The BGP hold timer is the backstop if the process is killed before the withdraw is sent. Packeteer proposes a 90s hold time so the timer cannot negotiate off; the router's shorter timer wins. The lab SIGKILLs Packeteer and checks that FRR drops the injected route once the session is down, and no later than that hold timer.

## Outage re-queue

The `outage` source can add up to `max_targets` probe targets from the learned RIB when a pattern matches. That spends probe budget. It does not announce: inject mode still requires the prefix in the learned RIB, the allowlist, thresholds, hold time, and the improvement cap. `min_prefixes` cannot be set below 2. Remove the source to turn it off. Events go to the configured notifiers and are not routes.

## SNMP telemetry

The `snmp` plugin reads interface counters from an agent you configure. The community and v3 passphrases come from the container environment, not from the config file, and they are not written to the log or the API. A failed poll does not withdraw routes and does not change a decision. The 95th-percentile window is in memory for the open billing period. `/api/telemetry` exposes rates and the commit figure to anyone who can open the HTTP port; the same loopback and basic-auth notes as the rest of the API apply. Removing the `telemetry` entry turns collection off.

## Flow input

The flow source accepts unauthenticated UDP. Anyone who can reach a listen port can add probe targets and spend probe budget. That does not inject routes: inject mode still requires the prefix in the learned RIB, the allowlist, thresholds, hold time, and the improvement cap. Run with host networking and firewall the port to the exporter. Counters live in memory for one window. Raw flow records are not written to disk.

## Ops surface

The HTTP server accepts GET and HEAD only. It defaults to `127.0.0.1:8080`. Set `http.listen` to `""` (or `PACKETEER_HTTP_LISTEN=off`) to disable it. A non-loopback listen address exposes probe results, decisions, active improvements, and learned exits for probed prefixes to anyone who can open the port. Set `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD` together before doing that; setting only one refuses to start. The dashboard loads no remote assets. The API does not announce routes. It does not list RIB prefixes that Packeteer is not probing.

## Measurement failures

- Asymmetric return path on probes
- Provider rate-limiting ICMP
- Probing the wrong source address (not actually leaving via that transit)

## Operational / public-repo failures

- Secrets or customer prefixes committed here
- CI publishing production telemetry
- An agent enabling `inject` in example config

Example config must remain `mode: observe`.
