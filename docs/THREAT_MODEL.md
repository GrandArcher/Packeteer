# Threat model

Packeteer can change how a network forwards packets. Failure modes matter more than features.

## Routing failures

- **Flap** — oscillating improvements. Mitigate with hold time, hysteresis, and by keeping an improvement when the router hides the native path because Packeteer's route won. Withdrawing on that hide brings the native path back and the next round injects again.
- **Leak** — more-specifics learned from Packeteer advertised to transit. Mitigate with a well-known community and outbound filters on every eBGP session.
- **Blackhole** — inject toward a next-hop that is down. Mitigate by requiring a live RIB path and withdrawing on probe-source or session failure.
- **Over-injection** — synthesizing more-specifics can exhaust TCAM. Packeteer announces only the exact prefix a neighbor advertised, so `max_improvements` bounds the number of routes. A config that sets `more_specific_bits` is rejected. With `more_specific` on, an improvement also announces learned more-specifics (still exact RIB prefixes), and `more_specific.max_routes` (default 100, at most 1000) bounds the routes on the router.
- **Stale intent** — controller dies, or keeps announcing a prefix the edge no longer has, or keeps announcing after probes stop refreshing. Packeteer withdraws on shutdown, when a prefix the router was still advertising disappears, when measurements are older than the max result age (checked on a timer, not only when a round completes), and at `improvement_ttl` when the native path is hidden by Packeteer's own route. A probe round that does not finish is abandoned at that same age and does not refresh results. It never enables graceful restart. The BGP hold timer is the backstop if the process is killed before the withdraw is sent. Packeteer proposes a 90s hold time so the timer cannot negotiate off; the router's shorter timer wins. The lab SIGKILLs Packeteer and checks that FRR drops the injected route once the session is down, and no later than that hold timer.

## Threat mitigation (RTBH and redirect)

A mitigation rule deliberately drops or diverts traffic toward a prefix, so a wrong or malicious rule is an outage the operator caused. Rules can only be added through the ops API with basic auth, only for a prefix inside `mitigation.allowlist` (a default route is refused), only up to `max_rules`, and only for the exact prefix in the learned RIB; the announcer re-checks the allowlist and the cap itself. Every rule expires (`max_ttl`, at most 168h), rules are in memory only so a restart clears them, and `mitigation.mode` defaults to `observe`. Routes carry NO_EXPORT and a marker the edge must opt in to, and the catalog may not reuse a provider's next hop. Probe-source loss does not withdraw mitigation routes, because probes do not create them; the TTL, removal, RIB loss, shutdown, and session loss do. Keep the HTTP port on loopback or behind your own access control.

## Outage re-queue

The `outage` source can add up to `max_targets` probe targets from the learned RIB when a pattern matches. That spends probe budget. It does not announce: inject mode still requires the prefix in the learned RIB, the allowlist, thresholds, hold time, and the improvement cap. `min_prefixes` cannot be set below 2. Remove the source to turn it off. Events go to the configured notifiers and are not routes.

## SNMP telemetry

The `snmp` plugin reads interface counters from an agent you configure. The community and v3 passphrases come from the container environment, not from the config file, and they are not written to the log or the API. A failed poll keeps the samples already stored. It does not withdraw a performance improvement. When the `commit` scorer is selected, a fresh billable 95th can steer an allowlisted prefix that is already in the learned RIB; a missing or stale reading creates no new commit move, and an existing commit move is released after `hold_time` once the planner stops asking for it. The 95th-percentile window is in memory for the open billing period. `/api/telemetry` exposes rates and the commit figure to anyone who can open the HTTP port; the same loopback and basic-auth notes as the rest of the API apply. Removing the `telemetry` entry turns collection off. Switching the scorer back to `weighted` withdraws commit improvements. `loss_override` defaults off, so commit control will not move traffic onto a higher-loss path unless the operator sets it. Decide enforces that check, not only the commit scorer. A commit steer whose loss clears `min_loss_delta_pct` is withdrawn and cannot return until `hold_time` has passed, so one lost probe cannot announce and withdraw the route on alternate rounds.

## Flow input

The flow source accepts unauthenticated UDP. Anyone who can reach a listen port can add probe targets and spend probe budget, and can report prefix volume that the `commit` scorer may use. That does not inject routes by itself: inject mode still requires the prefix in the learned RIB, the allowlist, thresholds, hold time, and the improvement cap, and a commit move also needs a fresh telemetry reading and a destination that is not a loss regression unless `loss_override` is set. Run with host networking and firewall the port to the exporter. Counters live in memory for one window. Raw flow records are not written to disk.

With `problems` set, the same unauthenticated records can also mark prefixes as problems (forged SYN-only or RST records). The effect is the same: extra probe targets, capped by `problems.max_targets`, and no route without the normal inject checks.

## Mirror (span) input

The `span` source reads a mirror port with an AF_PACKET socket and needs `NET_RAW`. That port carries copies of customer traffic. Packeteer parses TCP/IP headers and discards each packet; payloads, packets, and pcaps are not written anywhere. It keeps per-connection sequence state (capped by `max_flows`, forgotten after `flow_idle`) and per-prefix counters for one window, in memory. Promiscuous mode is a socket membership that the kernel drops when the process exits. Anyone who can put traffic on the mirror, or who controls a remote host, can make a prefix look broken (resets, withheld ACKs). That adds probe targets, capped by `max_targets`; it does not inject routes without a measured improvement, the learned RIB, the allowlist, the thresholds, hold time, and the cap. A mounted `pcap_file` is replayed once and is not modified.

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
