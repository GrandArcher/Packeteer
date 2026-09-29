# Multiple edge routers and route reflectors

Packeteer can inject to several edge routers, or to one or more route reflectors that carry its routes to the edges (#27). Both are lab-proven only (`lab/e2e-multirouter.sh`), not on a public edge. Start in `mode: observe`, then `suggest`, before you set `mode: inject`.

Everything in [routers.md](routers.md) still applies to every router Packeteer peers with: iBGP in your own ASN, accept from Packeteer only routes that carry `packeteer_community`, never export that community to eBGP, graceful restart off. The examples use documentation addresses (RFC 5737) and the private ASN 64512. Replace them.

## Pick a model

| | Direct sessions to each edge | Through a route reflector |
|---|---|---|
| Sessions | One iBGP session per edge (`bgp.neighbors`, one entry each) | One (or two, for redundancy) iBGP session to the reflector |
| Next hop | Per router: the provider's `next_hop` where the edge owns that transit, a rewritten next hop (`next_hops`) where it reaches the transit through another router | The provider's `next_hop` everywhere. Every edge must resolve it (IGP, or the transit link in your IGP) |
| Routers that cannot reach a provider | Never get routes toward it | Get every route the reflector reflects; the edge's policy must drop what it cannot use |
| Losing the provider's router | Improvements onto that provider are retired at once (`egress router down`) | The reflector's paths from that edge disappear; the reflector keeps reflecting Packeteer's route until the decision engine retires it or Packeteer withdraws |
| What Packeteer learns | Each edge's best paths (add-path for more) | The reflector's best path per prefix (add-path on the reflector session for more) |

Direct sessions give Packeteer per-router control. A route reflector is simpler to operate when you already run one.

## Direct sessions: per-router provider reachability

List, on each neighbor, the providers that router forwards to itself (`providers`) and the providers it reaches through another router, with the next hop it uses for them (`next_hops`). Routes are matched to a provider by its `next_hop`, so every provider needs a distinct `next_hop` once any neighbor sets either list.

```yaml
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21     # transit-a's address on edge-a
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.22     # transit-b's address on edge-b
bgp:
  neighbors:
    - address: 192.0.2.251
      description: edge-a
      providers: [transit-a]
      next_hops:
        transit-b: 192.0.2.252   # edge-a reaches transit-b through edge-b
    - address: 192.0.2.252
      description: edge-b
      providers: [transit-b]     # edge-b has no path to transit-a
```

With this config an improvement onto transit-b is sent to edge-b with next hop `192.0.2.22` and to edge-a with next hop `192.0.2.252`. An improvement onto transit-a is sent to edge-a only. A provider in neither list of a neighbor is never announced to it.

- **Egress routers.** The neighbors that list a provider in `providers` are its egress routers. While none of them has an established session, the provider is unusable (`egress router down`): no new improvement goes there, and an active one is retired at once, ignoring `hold_time`. It is withdrawn from every router. The native provider is never marked.
- **One session drops.** Routes on that session disappear with it (no graceful restart); the other routers keep theirs. When the session returns, the speaker sends that router the routes it should have again.
- **All sessions drop.** The RIB view is not ready and every injected route is withdrawn, as with one router.
- **A neighbor with neither list** reaches every provider with its `next_hop`. That is the default and keeps a single-router config unchanged. It is also how a route reflector session is written.
- **Validation.** Unknown provider names, a provider in both lists of one neighbor, a `next_hops` address that is not an IP of the provider's family, shared provider next hops, and a non-excluded provider that no neighbor reaches are config errors.
- **Every prefix still has to be in the learned RIB view** (from any router), allowlisted, and under `max_improvements`. Every route carries `packeteer_community` and NO_EXPORT.

On each edge, Packeteer's route with a rewritten next hop must resolve: the next hop (edge-b's loopback or link address above) has to be in the IGP. The edge that owns the transit forwards with its own copy of Packeteer's route.

Inbound steer routes (`inbound`, #25) keep the learned next hop of your own prefix and go to every router; the per-router rules do not apply to them.

## Through a route reflector

Make Packeteer a route-reflector client, accept only its community, and let the reflector carry its routes to the edges. The reflector leaves the next hop unchanged, so every edge needs a route to every provider's `next_hop`.

```yaml
bgp:
  neighbors:
    - address: 192.0.2.250
      description: rr
```

FRR on the reflector:

```
bgp community-list standard packeteer permit 64512:666
!
route-map packeteer-in permit 10
 match community packeteer
route-map packeteer-in deny 100
!
router bgp 64512
 bgp router-id 192.0.2.250
 bgp cluster-id 192.0.2.250
 no bgp graceful-restart
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 timers 3 9
 neighbor 192.0.2.251 remote-as 64512
 neighbor 192.0.2.252 remote-as 64512
 !
 address-family ipv4 unicast
  neighbor 192.0.2.10 activate
  neighbor 192.0.2.10 route-reflector-client
  neighbor 192.0.2.10 route-map packeteer-in in
  neighbor 192.0.2.251 activate
  neighbor 192.0.2.251 route-reflector-client
  neighbor 192.0.2.252 activate
  neighbor 192.0.2.252 route-reflector-client
 exit-address-family
```

On every edge, keep the eBGP filter that rejects `packeteer_community` toward transits and peers. The edges do not need a session to Packeteer.

- **What Packeteer learns.** The reflector sends its best path per prefix. Once Packeteer's route is the reflector's best, the reflector stops sending the native path (the same hide as on a single edge, see [routers.md](routers.md#when-the-native-path-disappears)). Add-path on the reflector session (`bgp.neighbors[].add_path` and `neighbor 192.0.2.10 addpath-tx-all-paths` on the reflector) or BMP from the edges keeps the other paths visible.
- **Its own route reflected back.** A path carrying `packeteer_community` is ignored, so a reflector that sends Packeteer's route back never keeps its prefix learned.
- **Redundant reflectors.** List both. Packeteer announces on both sessions; one dropping leaves the other. Both dropping withdraws everything.
- **Losing an edge.** Its paths leave the reflector, and the reflector's best changes. Packeteer does not know which edge owns which provider in this model; set `providers` on a reflector session only if that reflector serves one edge.

## Rollback

Remove `providers` and `next_hops` from every neighbor and restart: every route goes to every neighbor with the provider's `next_hop`, as before #27. To leave a route reflector, point `bgp.neighbors` back at a single edge and restart. Stopping Packeteer (SIGTERM) withdraws every route on every session; a crash drops them with the sessions.

## Lab

`lab/e2e-multirouter.sh` runs two FRR edges (edge-a with transit-a, edge-b with transit-b), a route reflector with both edges as clients, and the two simulated transits (`lab/docker-compose-multirouter.yml`). Part one peers Packeteer with both edges (`lab/packeteer-multirouter.yaml`); part two with the reflector only (`lab/packeteer-rr.yaml`). See [lab/README.md](../lab/README.md).
