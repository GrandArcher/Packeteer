# FRR

This guide sets up an FRR edge router for Packeteer: the iBGP session, the two filters inject needs, and the checks for each step. The [walkthrough](walkthrough.md) runs the configuration below unchanged in its lab, and CI runs that walkthrough on every change: the session comes up, an injected route is accepted with the community and `no-export`, it is never advertised to either transit, and a stop withdraws it.

Shared rules for every router (what Packeteer sends, why best-path-only sessions hide the native path, exchange peers) are in [routers.md](routers.md). The addresses are documentation ranges (RFC 5737) and the ASNs documentation or private-use values. Replace them.

This guide covers IPv4 unicast on FRR 10. The lab uses FRR 10.2.

## Full configuration

The edge is AS 64512 at `192.0.2.254`. Packeteer is `192.0.2.10`. transit-a (AS 64496) is `192.0.2.21` and transit-b (AS 64497) is `192.0.2.22`. Your own prefix is `203.0.113.0/24`. `64512:666` is `packeteer_community` in Packeteer's config.

<!-- lab-file: lab/frr-walkthrough/frr.conf -->
```
! Packeteer edge on FRR (docs/frr.md). The walkthrough lab runs this file
! unchanged (lab/docker-compose-walkthrough.yml, docs/walkthrough.md).
! Documentation addresses (RFC 5737) and documentation/private ASNs only.
!
! This router: AS 64512, 192.0.2.254. Packeteer: 192.0.2.10.
! transit-a: AS 64496 at 192.0.2.21. transit-b: AS 64497 at 192.0.2.22.
! Your own prefix: 203.0.113.0/24.
frr defaults traditional
hostname edge
log stdout informational
!
ip route 203.0.113.0/24 blackhole
!
ip prefix-list own-prefixes seq 5 permit 203.0.113.0/24
!
bgp community-list standard packeteer permit 64512:666
!
! From Packeteer: only routes that carry the Packeteer community.
route-map packeteer-in permit 10
 match community packeteer
route-map packeteer-in deny 100
!
! From every eBGP neighbor: your usual import policy, and strip the
! Packeteer community so nobody outside can set it.
route-map transit-in permit 10
 set comm-list packeteer delete
!
! Toward every eBGP neighbor: never a route with the Packeteer community,
! then your usual export policy (here: only your own prefix).
route-map ebgp-out deny 10
 match community packeteer
route-map ebgp-out permit 20
 match ip address prefix-list own-prefixes
route-map ebgp-out deny 100
!
router bgp 64512
 bgp router-id 192.0.2.254
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 graceful-restart-disable
 neighbor 192.0.2.10 timers 10 30
 neighbor 192.0.2.21 remote-as 64496
 neighbor 192.0.2.21 description transit-a
 neighbor 192.0.2.22 remote-as 64497
 neighbor 192.0.2.22 description transit-b
 !
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 192.0.2.10 activate
  neighbor 192.0.2.10 route-map packeteer-in in
  neighbor 192.0.2.21 activate
  neighbor 192.0.2.21 route-map transit-in in
  neighbor 192.0.2.21 route-map ebgp-out out
  neighbor 192.0.2.22 activate
  neighbor 192.0.2.22 route-map transit-in in
  neighbor 192.0.2.22 route-map ebgp-out out
 exit-address-family
!
```

What each part does:

- **`packeteer-in`** on the Packeteer session accepts only routes that carry `64512:666`. In observe and suggest Packeteer sends nothing, so the filter changes nothing until inject. It is still the first thing to install.
- **`ebgp-out`** on every eBGP session rejects a route with `64512:666` first, then applies your normal export policy. Packeteer also tags every route `no-export`; this filter is the layer you control. Put the deny at the top of the export route-map you already have.
- **`transit-in`** strips `64512:666` from routes learned from outside, so nobody outside your AS can make a route look like Packeteer's.
- **`graceful-restart-disable`** on the Packeteer neighbor. Packeteer never offers graceful restart, so its routes go with the session either way. This makes it explicit even when the router has graceful restart on for other peers.
- **`timers 10 30`** bounds how long a route stays after Packeteer dies without withdrawing (a `docker kill`, a host crash): the hold time, 30 seconds. A clean stop withdraws first and does not wait for it. Packeteer proposes 90 seconds; the lower value wins.
- **No next-hop change toward Packeteer.** FRR leaves the eBGP next hop on routes it sends over iBGP. Packeteer names today's exit by that next hop, so each provider's `next_hop` in Packeteer's config must be the transit's address as the edge sees it (`192.0.2.21`, `192.0.2.22`). Do not set `next-hop-self` on the Packeteer session.

Packeteer connects to the router. The router may also try to connect to Packeteer on port 179; that fails harmlessly unless Packeteer listens (`bgp.listen_port`). To make the router wait instead, add `neighbor 192.0.2.10 passive`.

## Adding it to a running router

On an edge that already has its transit sessions and export policy, add only the Packeteer pieces. In `vtysh`:

```
configure terminal
bgp community-list standard packeteer permit 64512:666
route-map packeteer-in permit 10
 match community packeteer
route-map packeteer-in deny 100
exit
router bgp 64512
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 graceful-restart-disable
 neighbor 192.0.2.10 timers 10 30
 address-family ipv4 unicast
  neighbor 192.0.2.10 activate
  neighbor 192.0.2.10 route-map packeteer-in in
 exit-address-family
end
write memory
```

Then, before inject, put the deny first in each eBGP export route-map. If your transit export route-map is called `transit-out` and its first entry is sequence 10 or higher:

```
configure terminal
route-map transit-out deny 5
 match community packeteer
end
write memory
```

## Packeteer side

```yaml
mode: observe                 # inject only after both filters are in place
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - name: transit-a
    source_ip: 192.0.2.11     # probe source, routed out of transit-a
    next_hop: 192.0.2.21      # transit-a's address as the edge sees it
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.22
bgp:
  neighbors:
    - address: 192.0.2.254
      description: edge
```

Probe sources: [policy-routing.md](policy-routing.md). Inject keys: [walkthrough.md](walkthrough.md#4-inject).

## Checks

The session (Packeteer logs `bgp session ... state=ESTABLISHED`, and `/readyz` turns 200):

```
vtysh -c 'show bgp neighbors 192.0.2.10'
```

`BGP state = Established`.

What Packeteer learned: `curl -fsS http://127.0.0.1:8080/api/prefixes` on the Packeteer host. Each probed prefix has `in_rib: true` and `rib_provider` set to the provider whose `next_hop` matches. An empty `rib_provider` means the next hop matches no provider.

In inject, the route Packeteer sent:

```
vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 routes'
```

The best path is `192.0.2.22 from 192.0.2.10` with `localpref 250` and `Community: 64512:666 no-export`.

Nothing leaks: the prefix must not be in the advertised routes toward any eBGP neighbor.

```
vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.21 advertised-routes'
vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.22 advertised-routes'
```

## Seeing the native path while steered

Once Packeteer's route is best, FRR stops sending the transit path to Packeteer. Packeteer keeps the improvement, but it learns about a transit withdraw only at `improvement_ttl`. To see it at once, pick one ([routers.md](routers.md#when-the-native-path-disappears)):

- `neighbor 192.0.2.10 advertise-best-external` in the address family: FRR keeps sending its best eBGP path.
- Add-path: `neighbor 192.0.2.10 addpath-tx-all-paths` in the address family, and `add_path: true` on the neighbor in Packeteer's config. Lab-proven in `lab/e2e-addpath.sh`.
- BMP: bgpd with `-M bmp` and a BMP target pointing at Packeteer's station (`rib_sources`). Lab-proven in `lab/e2e-bmp.sh`.

## Rollback

On the Packeteer host, `docker stop -t 30 packeteer` withdraws every Packeteer route, then closes the session. `mode: observe` and a restart does the same. On the router, `neighbor 192.0.2.10 shutdown` drops the session and every route learned on it.

## Flow export

FRR does not export flows. Run an exporter beside it: [routers.md](routers.md#flow-export).
