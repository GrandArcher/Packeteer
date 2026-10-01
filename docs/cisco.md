# Cisco IOS and IOS-XE

This guide sets up a Cisco IOS or IOS-XE edge router for Packeteer: the iBGP session, the two filters inject needs, and the checks for each step. Shared rules for every router are in [routers.md](routers.md). IOS-XR uses route-policy language and is not covered here.

**Not lab-tested.** CI has no IOS image. The configuration follows the same design as the [FRR guide](frr.md), which the [walkthrough](walkthrough.md) runs in CI, and uses standard IOS statements. Check it against your release in a maintenance window. The router interop matrix is tracked in #53.

The addresses are documentation ranges (RFC 5737) and the ASNs documentation or private-use values. Replace them. The edge is AS 64512 at `192.0.2.254`. Packeteer is `192.0.2.10`. transit-a (AS 64496) is `192.0.2.21` and transit-b (AS 64497) is `192.0.2.22`. Your own prefix is `203.0.113.0/24`. `64512:666` is `packeteer_community` in Packeteer's config. IPv4 unicast only.

## Configuration

```
! Show and match communities as ASN:value.
ip bgp-community new-format
!
ip prefix-list OWN-PREFIXES seq 5 permit 203.0.113.0/24
ip community-list standard PACKETEER permit 64512:666
!
! From Packeteer: only routes that carry the Packeteer community.
route-map PACKETEER-IN permit 10
 match community PACKETEER
route-map PACKETEER-IN deny 100
!
! From every eBGP neighbor: strip the Packeteer community, then your
! usual import policy.
route-map TRANSIT-IN permit 10
 set comm-list PACKETEER delete
!
! Toward every eBGP neighbor: never the Packeteer community first, then
! your usual export policy (here: only your own prefix).
route-map EBGP-OUT deny 10
 match community PACKETEER
route-map EBGP-OUT permit 20
 match ip address prefix-list OWN-PREFIXES
route-map EBGP-OUT deny 100
!
router bgp 64512
 bgp router-id 192.0.2.254
 bgp log-neighbor-changes
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 timers 10 30
 neighbor 192.0.2.10 ha-mode graceful-restart disable
 neighbor 192.0.2.21 remote-as 64496
 neighbor 192.0.2.21 description transit-a
 neighbor 192.0.2.22 remote-as 64497
 neighbor 192.0.2.22 description transit-b
 !
 address-family ipv4
  network 203.0.113.0 mask 255.255.255.0
  neighbor 192.0.2.10 activate
  neighbor 192.0.2.10 route-map PACKETEER-IN in
  neighbor 192.0.2.21 activate
  neighbor 192.0.2.21 route-map TRANSIT-IN in
  neighbor 192.0.2.21 route-map EBGP-OUT out
  neighbor 192.0.2.22 activate
  neighbor 192.0.2.22 route-map TRANSIT-IN in
  neighbor 192.0.2.22 route-map EBGP-OUT out
 exit-address-family
!
ip route 203.0.113.0 255.255.255.0 Null0
```

What each part does:

- **`ip bgp-community new-format`** makes IOS print and parse `64512:666` instead of one 32-bit number. The checks below assume it.
- **`PACKETEER-IN`** accepts only routes that carry `64512:666`. In observe and suggest Packeteer sends nothing, so it changes nothing until inject.
- **`EBGP-OUT`** denies any route with `64512:666` before your normal export entries. Packeteer also tags every route `no-export`, which IOS honors; the route-map is the layer you control. On an existing router, add the deny as the lowest sequence of the outbound route-map each eBGP neighbor already uses.
- **`TRANSIT-IN`** removes `64512:666` from routes learned from outside, so nobody outside your AS can make a route look like Packeteer's.
- **`ha-mode graceful-restart disable`** on the Packeteer neighbor. Packeteer never offers graceful restart; this keeps it off even when `bgp graceful-restart` is on for the rest of the router. Older IOS releases without per-neighbor `ha-mode` leave graceful restart off unless `bgp graceful-restart` is configured globally; leave it off.
- **`timers 10 30`** bounds how long a route stays when Packeteer dies without withdrawing. A clean stop withdraws first.
- **No `next-hop-self`** on the Packeteer neighbor. IOS leaves the eBGP next hop on routes it sends over iBGP. Packeteer names today's exit by that next hop, so each provider's `next_hop` in Packeteer's config must be the transit's address as the edge sees it.

IOS does not send communities to a neighbor without `send-community`. Packeteer does not need communities on the routes it learns, so the Packeteer neighbor needs none. Do not add `send-community` toward transits for Packeteer's sake.

## Packeteer side

The same as in the [FRR guide](frr.md#packeteer-side): `asn: 64512`, the providers with the transits' addresses as `next_hop`, and `bgp.neighbors` with `192.0.2.254`. Keep `mode: observe` until both filters are in place.

## Checks

```
show ip bgp summary
show ip bgp neighbors 192.0.2.10
show ip bgp neighbors 192.0.2.10 routes
show ip bgp 198.51.100.0/24
show ip bgp community 64512:666
show ip bgp neighbors 192.0.2.21 advertised-routes
show ip bgp neighbors 192.0.2.22 advertised-routes
```

- The session is `Established`.
- In observe and suggest, `neighbors 192.0.2.10 routes` is empty.
- In inject, the best path for the prefix is from `192.0.2.10`, with `localpref 250`, next hop `192.0.2.22`, and `Community: 64512:666 no-export`.
- `advertised-routes` toward each transit never lists the steered prefix.

## Seeing the native path while steered

Once Packeteer's route is best, IOS stops sending the transit path to Packeteer, and Packeteer learns about a transit withdraw only at `improvement_ttl` ([routers.md](routers.md#when-the-native-path-disappears)). `bgp advertise-best-external` in the address family keeps the best external path advertised to iBGP neighbors. Add-path (`bgp additional-paths send` with `neighbor 192.0.2.10 additional-paths send` and an `advertise` selection, plus `add_path: true` on Packeteer's neighbor) sends every path. Packeteer's add-path support is lab-proven against FRR only.

## Rollback

On the Packeteer host, `docker stop -t 30 packeteer` withdraws every Packeteer route, then closes the session. On the router, `neighbor 192.0.2.10 shutdown` drops the session and every route learned on it.
