# Operating Packeteer: probing options, suggest and inject, rollback

The [README](../README.md) covers install and observe. This page is the rest of the run: the optional probing knobs, the move from observe to suggest to inject, and how to roll back.

## Probing options

A `udp` prober is an optional fallback after ICMP and TCP. It counts a reply from the target, not an ICMP unreachable from a firewall on the path. A `traceroute` source discovers the probe host in the background and moves the probe onto the last stable hop when the configured host does not answer. A `vip` source probes a capped prefix list, and a capped set of prefixes whose learned AS path contains a listed ASN, on an interval that must stay inside the staleness window.

Set `probe.retry_loss_pct` to re-measure a lossy sample, or `probe.dispersion_ms` to leave out a host whose RTT spread (slowest reply minus fastest) is wider than that limit and re-measure it, before the sample is stored. `probe.min_replies` (default 1) is how many replies a host needs before it defines the score. Both checks default off. A flow prefix offers up to three of its busiest destinations as candidates. The engine remembers which prober got a reply from a host and starts the next round there. Every `probe.prober_recheck_rounds` (default 10) it starts at the first prober again, so a host that begins answering ICMP is noticed.

The memory is capped, and a host that leaves the probe set is forgotten. Nothing is announced. An `outage` source watches completed rounds. When several prefixes that share an ASN (native path, another provider's learned path, or a traceroute hop's origin in the learned RIB), or that fail on one provider only, degrade together, it re-queues them and emits `outage.as` or `outage.circuit` to the configured notifiers. One noisy prefix does not. The re-queue is capped and is not an announcement. None of these announce a route. The global packet rate limit still applies. Details are in [docs/PLUGINS.md](PLUGINS.md).

## Suggest, then inject

The whole sequence on a simulated FRR edge, with the output to expect at each step, is [docs/walkthrough.md](walkthrough.md).

`mode: suggest` is the same process as observe. It writes recommendations to the log, the dashboard, and `/api/decisions`, and it still announces nothing. Set the thresholds from the example config first. With both deltas at `0`, no improvement is recorded.

Read `/api/improvements` and the dashboard's current exit against the recommended exit. An improvement appears only when the prefix is in the learned RIB, both the native provider and the candidate have fresh measurements, the gain clears the thresholds, the candidate's score is lower, the provider is not excluded, and the cap has room. When `thresholds.min_rtt_delta_pct` is set, an RTT win also has to be that percent of the current path's RTT. `thresholds.confirm_rounds` (default 1) is how many consecutive fresh rounds a new performance move or switch must win; while that streak is short, `/api/decisions` says `confirming` and nothing is announced. Early probes wait a quarter of the probe interval, and a round that cannot compare does not keep asking. Flip-back does not wait.

Inject only after the router filters in the guides are in place, and only for prefixes you mean to steer. Change the mounted config (do not change the example in this repository):

- `mode: inject`
- `allowlist.prefixes`: prefixes you operate. A learned prefix is eligible when it is equal to an entry or more specific and inside it. Packeteer announces that learned prefix. An entry that overlaps an exchange peering LAN is a load error.
- `packeteer_community`: `"<asn>:<value>"`, each half 0–65535, or a large community `"<global>:<data1>:<data2>"` (RFC 8092). Quote it. The export policy matches only this community.
- `local_pref`: higher than the native local preference on the edge. Optional `local_pref_cause` and `providers[].local_pref` override it (provider, then cause, then this value). A set `0` is rejected.
- Optional extra communities: `communities_cause` and `providers[].communities`, added after `packeteer_community`. The export policy does not match them. At most 16. No `0:x` or `65535:x`.
- `hold_time`: a positive duration (`15m` in the example).
- `thresholds.min_loss_delta_pct` and `thresholds.min_rtt_delta_ms`: both greater than 0.
- `bgp.neighbors`: at least one iBGP neighbor.
- `announcer` with `type: gobgp`. The announcer has no config block.

Packeteer reads the file at startup. Restart after you edit it:

```sh
docker restart -t 30 packeteer
# or, from the Compose directory:
docker compose restart -t 30
```

Then confirm one route on the router before you widen the allowlist.

On the router, an injected route shows your community and `no-export`:

- MikroTik: `/routing route print where bgp.communities~"64512:666"`
- FRR: `vtysh -c 'show bgp ipv4 unicast <prefix> json'` (communities `64512:666` and `no-export`, next hop of the chosen provider)
- Junos: `show route community 64512:666`
- IOS: `show ip bgp community 64512:666`

Replace `64512:666` with your community. The full filter snippets are in the router guides, not here, so this page cannot be copied onto an edge as an inject config.

## Rollback

Stopping the container withdraws every Packeteer route.

```sh
docker stop -t 30 packeteer
# or, from the Compose directory:
docker compose stop -t 30
```

`docker stop` sends SIGTERM. Packeteer withdraws, then closes the iBGP session. The Compose `restart: unless-stopped` policy does not start it again after `docker stop` or `docker compose stop`. Give the process 30 seconds so Docker does not SIGKILL it while the withdraw is in flight. The default Docker stop timeout is 10 seconds, which races the withdraw.

Confirm the routes are gone with the same show commands as above. The community lookup should be empty, and the prefix should be back on the provider exit. `docker compose down -t 30` stops and removes the container; the effect on BGP is the same.

`docker kill` does not withdraw. The routes remain until the router's BGP hold timer expires. The Compose restart policy also starts the container again after a kill. Use `docker stop` when you want the routes gone and the process left stopped.

With an active/standby pair (`ha`, [docs/ha.md](ha.md)), stopping the active instance withdraws its routes and hands over to the standby, which then announces. Stop both, or remove `ha` and run one instance, to roll back. `packeteer -backup` and `-restore` copy the config and report history.

Switching the file back to `mode: observe` and restarting withdraws as well: the old process withdraws on the way down, and the new process does not announce.

Other withdraws, while the container is still running:

- measurements older than about three probe intervals (a round that never finishes counts)
- a provider probe source that fails
- every iBGP session down
- the router withdraws a prefix it was still advertising after the improvement had been up for a few seconds

When Packeteer's route is best, a normal iBGP session stops sending the native path back. That hide is not a withdraw. The improvement stays until flip-back or `improvement_ttl`. See [docs/routers.md](routers.md).
