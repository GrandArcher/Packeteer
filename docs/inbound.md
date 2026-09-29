# Inbound optimization

Status: **lab-proven only** (#25): inbound commit control, inbound performance optimization, AS-path prepends, provider TE communities, selective announcements, inertia damping, and automated vs moderated steers. Do not run it with `inbound.mode: inject` on a public edge; the CI lab is the only place it has been proven.

## What it does

Outbound control changes where your edge sends traffic. Inbound control changes how your own prefixes look to each provider, so the rest of the internet sends less traffic in through one of them.

Two triggers steer inbound traffic away from a provider:

- **commit**: the provider's **inbound** 95th percentile (from a `telemetry` plugin) is above its `commit_mbps`.
- **performance** (`inbound.performance`): the probes rank the provider the worst performer. Over the prefixes every provider measured with a fresh result, its mean loss is `loss_pct` points, or its mean RTT `latency_ms`, above the best other provider. Only the single worst provider is steered for performance at a time. Outbound probes are the signal: a provider that loses or delays your outbound packets is usually a poor path in as well, and steering inbound traffic does not change the measurement, so the steer does not feed back into its own trigger.

To steer, Packeteer:

1. It re-announces each of your `inbound.prefixes` to the edge over the same iBGP session, with the exact learned prefix and next hop, `inbound.local_pref`, `packeteer_community`, the inbound announcer's `marker`, the catalog communities of every provider it is steering away from, and `no-export`.
2. The edge's import policy recognises the marker and prefers that route. Its export policy toward each provider turns a signal community into a prepend on that session only (or, for a `withhold` action, does not send the prefix to that provider at all: a selective announcement), passes the provider's own TE communities to that provider only, and strips Packeteer's communities.

A commit steer is released once the provider's inbound 95th is at or below `release_pct` (default 90) of the commit; a performance steer once both gaps are at or below `performance.release_pct` (default 50) of their thresholds. Either way the steer must first have been held for its hold time (`hold_time`, grown by damping). A released provider waits that hold time before it can be steered again. Packeteer never steers away from every non-excluded provider, so a withheld prefix is always still announced through another.

## Damping

Steering changes the traffic the commit trigger measures: moving inbound traffic off a provider brings its 95th under commit, releasing it brings the traffic back, and an undamped controller flips the edge every hold time. `inbound.damping` (on by default) stops that:

- **confirm** (default `1m`): a trigger must hold this long before a provider is steered, so a single noisy round never changes the edge.
- **backoff** (default `2`) and **max_hold** (default 8 × `hold_time`): a provider steered again within `max_hold` of its release is flapping. Each flap multiplies its hold time, and the cooldown after it, by `backoff`, up to `max_hold`. A provider left alone for `max_hold` starts over.
- **inertia**: when a commit steer flaps, Packeteer learns how much inbound traffic came back on the release (the 95th at the new steer minus the 95th at the release; `inertia_mbps` on `/api/inbound`). The steer is then released only when the 95th plus that amount is at or below `release_pct`, that is, when demand itself has dropped. `/api/inbound` lists the steer under `blocked` with an `inertia` reason while it would otherwise have been released.

The unit simulation (`internal/inbound/damping_test.go`) runs a day of one-minute rounds on a simulated network where steering moves 200 Mbps between providers: undamped it makes about 140 steer/release changes, damped it makes four (steer, release, damped steer, release when demand falls). One-minute performance noise makes about 290 undamped and none damped. The FRR lab checks the damped re-steer on the transits.

## Automated and moderated

| Mode | Behaviour |
|---|---|
| automated | `inbound.mode: inject`: steers are announced as they are decided. |
| moderated | `inbound.mode: suggest`, or a trigger listed in `inbound.moderated` while in `inject`: the steer is published on `GET /api/inbound` (with `moderated: true` for a listed trigger) and as an `inbound.steered` event, and nothing is announced. The operator applies the prepend by hand or approves automation by changing the config. |

`moderated: [performance]` is the usual mix: commit steers are automated, performance steers wait for a person. The HTTP API stays read-only; it never announces.

## Modes

`inbound.mode` is separate from the top-level `mode` and defaults to `observe`.

| Mode | Behaviour |
|---|---|
| `observe` | Logs `inbound steer` / `inbound release`. Nothing is announced. |
| `suggest` | The moderated path. Also publishes the suggestion on `GET /api/inbound` and as `inbound.steered` / `inbound.released` events ([EVENTS.md](EVENTS.md)), so an operator can apply the prepend by hand or approve switching to `inject`. Nothing is announced. |
| `inject` | Announces steer routes for every trigger not listed in `inbound.moderated`. Requires top-level `mode: inject`, `inbound.announcer`, and every inbound prefix inside `allowlist.prefixes`. |

## Safety

- Only prefixes in `inbound.prefixes`, inside the allowlist, and present in the learned RIB are ever announced. Outbound improvements refuse those prefixes, so outbound and inbound never publish the same prefix.
- Every steer route carries `packeteer_community` and `no-export`. Catalog communities cannot be well-known values (`0:x`, `65535:x`).
- Steer routes and outbound improvements share `max_improvements`; `inbound.max_improvements` can cap steer routes lower.
- Stale telemetry (older than 15 minutes), a telemetry error, or a missing row releases a commit steer at once. No fresh probe result for the provider (probe-source loss, or results older than about three probe rounds) releases a performance steer at once. All iBGP sessions down withdraws every steer route. SIGTERM withdraws them before the session closes. Graceful restart is never enabled, so a crash drops them with the session within the BGP hold time.
- Once the edge prefers the steer route it stops advertising the prefix to Packeteer. Packeteer keeps a steer route it already announced while the steer is wanted (withdrawing would flap it), and `improvement_ttl` retires it so the prefix has to reappear in the RIB before it is announced again.
- On Packeteer's own speaker the edge's copy of an inbound prefix is kept out of best-path selection by an import policy so the low local-pref steer route is exported. The RIB view reads routes before that policy, so learning is unchanged.

## Router contract

The edge has to opt in. Without the import rule below a steer route has `local_pref` 1 and loses to the edge's own route, so nothing changes.

**Do not** accept marker routes with a policy that keeps `no-export`: the edge would then prefer a route it cannot export, and withdraw your prefix from every provider.

FRR, as used in the lab ([lab/frr-inbound/frr.conf](../lab/frr-inbound/frr.conf)), with marker `64512:667`, a prepend signal `64512:1102` for transit-a, transit-a's TE community `64496:3`, and a withhold signal `64512:1209` for transit-b:

```
bgp community-list standard packeteer-inbound permit 64512:667
bgp community-list standard no-export permit no-export
bgp community-list standard steer-a-prepend2 permit 64512:1102
bgp community-list standard steer-b-withhold permit 64512:1209
bgp community-list standard strip-to-transit-a permit 64512:666
bgp community-list standard strip-to-transit-a permit 64512:667
bgp community-list standard strip-to-transit-a permit 64512:1102
bgp community-list standard strip-to-transit-a permit 64512:1209
!
route-map from-packeteer permit 5
 match community packeteer-inbound
 set comm-list no-export delete
 set weight 65535
route-map from-packeteer permit 10
 match community packeteer
route-map from-packeteer deny 100
!
route-map to-transit-a permit 10
 match community steer-a-prepend2
 set as-path prepend 64512 64512
 set comm-list strip-to-transit-a delete
route-map to-transit-a permit 20
 set comm-list strip-to-transit-a delete
!
! selective announcement: nothing to transit-b while 64512:1209 is set
route-map to-transit-b deny 10
 match community steer-b-withhold
route-map to-transit-b permit 20
 set comm-list strip-to-transit-b delete
```

Strip communities with **one standard list per transit** that names every value Packeteer and the other transits' catalogs can send. FRR keeps only the last `set comm-list … delete` in a route-map entry, so two separate delete lines strip only the second list and Packeteer's communities leak to the transit.

The edge must also advertise the prefix to Packeteer with a next hop that is not one of its own addresses (the lab rewrites it), or rewrite the next hop on import, because Packeteer re-announces the learned next hop.

## Config

```yaml
telemetry:
  - type: snmp          # inbound reads the inbound 95th percentile
    config: { ... }
inbound:
  mode: suggest         # observe (default) | suggest | inject
  prefixes: [203.0.113.0/24]
  release_pct: 90
  performance: {latency_ms: 50}   # also steer away from the worst performer
  moderated: [performance]        # ...but only as a suggestion
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - provider: transit-a
          name: prepend-2
          prepend: 2                              # what the edge does for 64512:1102
          communities: ["64512:1102", "64496:3"]  # signal + transit-a's own TE community
        - provider: transit-b
          name: withhold
          withhold: true                          # edge does not export to transit-b
          communities: ["64512:1209"]
```

Keys are in [CONFIG.md](CONFIG.md#inbound).

## Lab

`lab/e2e-inbound.sh` (CI `e2e` job) runs the FRR edge with two simulated eBGP transits (AS 64496 and 64497) and checks on the transits themselves:

1. Commit steer: transit-a gets `64512 64512 64512` and `64496:3`, transit-b the plain path. Release leaves both plain.
2. Damping: over commit again inside the flap window gives a steer with a doubled hold and learned inertia; flipping usage under again must not release it for 25s.
3. SIGTERM withdraws the steer: both plain.
4. After a restart, transit-a's probes are 240 ms slower: a performance steer on transit-a; equal probes release it.
5. transit-b slowest: the selective announcement removes the prefix from transit-b while transit-a keeps the plain path; equal probes give it back.
6. transit-a slow again, then SIGKILL: both plain after the 9s hold timer.

## Rollback

Set `inbound.mode: observe` (or remove the `inbound` block) and restart. Every steer route is withdrawn on shutdown, and the edge falls back to its own route. To keep commit steers but stop automated performance steers, add `moderated: [performance]` (or remove `performance`) and restart.
