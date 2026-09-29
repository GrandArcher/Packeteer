# Inbound commit control

Status: **lab-proven only.** This is the first half of #25: inbound bandwidth (commit) control with AS-path prepends and provider TE communities. Inbound performance optimization, selective announcements, and inertia damping are still planned (see [IRP_PARITY.md](IRP_PARITY.md#inbound)). Do not run it with `inbound.mode: inject` on a public edge; the CI lab is the only place it has been proven.

## What it does

Outbound control changes where your edge sends traffic. Inbound control changes how your own prefixes look to each provider, so the rest of the internet sends less traffic in through one of them.

When a provider's **inbound** 95th percentile (from a `telemetry` plugin) is above its `commit_mbps`, Packeteer steers inbound traffic away from it:

1. It re-announces each of your `inbound.prefixes` to the edge over the same iBGP session, with the exact learned prefix and next hop, `inbound.local_pref`, `packeteer_community`, the inbound announcer's `marker`, the catalog communities of every provider it is steering away from, and `no-export`.
2. The edge's import policy recognises the marker and prefers that route. Its export policy toward each provider turns a signal community into a prepend on that session only, passes the provider's own TE communities to that provider only, and strips Packeteer's communities.

A steer is released once the provider's inbound 95th is at or below `release_pct` (default 90) of the commit and the steer has been held for `hold_time`. A released provider waits `hold_time` before it can be steered again. Packeteer never steers away from every non-excluded provider.

## Modes

`inbound.mode` is separate from the top-level `mode` and defaults to `observe`.

| Mode | Behaviour |
|---|---|
| `observe` | Logs `inbound steer` / `inbound release`. Nothing is announced. |
| `suggest` | The moderated path. Also publishes the suggestion on `GET /api/inbound` and as `inbound.steered` / `inbound.released` events ([EVENTS.md](EVENTS.md)), so an operator can apply the prepend by hand or approve switching to `inject`. Nothing is announced. |
| `inject` | Announces steer routes. Requires top-level `mode: inject`, `inbound.announcer`, and every inbound prefix inside `allowlist.prefixes`. |

## Safety

- Only prefixes in `inbound.prefixes`, inside the allowlist, and present in the learned RIB are ever announced. Outbound improvements refuse those prefixes, so outbound and inbound never publish the same prefix.
- Every steer route carries `packeteer_community` and `no-export`. Catalog communities cannot be well-known values (`0:x`, `65535:x`).
- Steer routes and outbound improvements share `max_improvements`; `inbound.max_improvements` can cap steer routes lower.
- Stale telemetry (older than 15 minutes), a telemetry error, or a missing row releases at once. All iBGP sessions down withdraws every steer route. SIGTERM withdraws them before the session closes. Graceful restart is never enabled, so a crash drops them with the session within the BGP hold time.
- Once the edge prefers the steer route it stops advertising the prefix to Packeteer. Packeteer keeps a steer route it already announced while the steer is wanted (withdrawing would flap it), and `improvement_ttl` retires it so the prefix has to reappear in the RIB before it is announced again.
- On Packeteer's own speaker the edge's copy of an inbound prefix is kept out of best-path selection by an import policy so the low local-pref steer route is exported. The RIB view reads routes before that policy, so learning is unchanged.

## Router contract

The edge has to opt in. Without the import rule below a steer route has `local_pref` 1 and loses to the edge's own route, so nothing changes.

**Do not** accept marker routes with a policy that keeps `no-export`: the edge would then prefer a route it cannot export, and withdraw your prefix from every provider.

FRR, as used in the lab ([lab/frr-inbound/frr.conf](../lab/frr-inbound/frr.conf)), with marker `64512:667`, a prepend signal `64512:1102` for transit-a, and transit-a's TE communities `64496:*`:

```
bgp community-list standard packeteer-inbound permit 64512:667
bgp community-list standard no-export permit no-export
bgp community-list standard steer-a-prepend2 permit 64512:1102
bgp community-list expanded packeteer-signals permit ^64512:
bgp community-list expanded transit-b-te permit ^64497:
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
 set comm-list packeteer-signals delete
 set comm-list transit-b-te delete
route-map to-transit-a permit 20
 set comm-list packeteer-signals delete
 set comm-list transit-b-te delete
```

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
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - provider: transit-a
          name: prepend-2
          prepend: 2                              # what the edge does for 64512:1102
          communities: ["64512:1102", "64496:3"]  # signal + transit-a's own TE community
```

Keys are in [CONFIG.md](CONFIG.md#inbound).

## Lab

`lab/e2e-inbound.sh` (CI `e2e` job) runs the FRR edge with two simulated eBGP transits (AS 64496 and 64497) and checks on the transits themselves: transit-a gets `64512 64512 64512` and `64496:3` while transit-b gets the plain path; release, SIGTERM, and SIGKILL (after the 9s hold timer) each leave both transits with the plain path.

## Rollback

Set `inbound.mode: observe` (or remove the `inbound` block) and restart. Every steer route is withdrawn on shutdown, and the edge falls back to its own route.
