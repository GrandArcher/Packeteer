# Internet VRF and partial-table providers

This guide covers two edge layouts (#206): the transit sessions live in a VRF (an "internet VRF" on an MPLS or multi-tenant edge), and no provider sends a full table. CI runs both in one FRR lab (`lab/e2e-vrf.sh`); the configuration below is that lab's edge file, unchanged. Lab-proven only, not on a public edge. The addresses are documentation ranges (RFC 5737) and the ASNs documentation or private-use values.

## Peering inside the VRF

Packeteer speaks IPv4 and IPv6 unicast iBGP. It does not speak the VPNv4 or VPNv6 families (RFC 4364), so it never sees route distinguishers or route targets. Put its session inside the internet VRF on the router, next to the transit sessions. From Packeteer's side it is an ordinary iBGP session, and nothing in its config names the VRF:

- It learns the VRF's best paths, and each provider's `next_hop` is the transit's address as the VRF sees it.
- An injected route lands in the VRF's table. It stays on this router only while the VRF neither exports it (a route target toward other PEs) nor leaks it into another VRF: NO_EXPORT does not stop it inside your AS, and over VPNv4 another PE would see it with Packeteer's local preference. Deny `packeteer_community` in the VRF's export and leak policies, as `ebgp-out` does toward the transits.
- The rules do not change: allowlist, learned prefixes only, `max_improvements`, `packeteer_community` plus `no-export`, hold time, no graceful restart, and withdraw on SIGTERM, on stale data, and with the session on SIGKILL.

Peer every session of one Packeteer instance into the same VRF. The learned view and the announcer do not tell VRFs apart: a second VRF's routes would mix with the first, and a steer would be sent into both.

### FRR

The edge is AS 64512. Its interface toward Packeteer (`192.0.2.10`) and both transits is in the Linux VRF `internet`. transit-a (AS 64496, `192.0.2.21`) sends a partial table and a default route; transit-b (AS 64497, `192.0.2.22`) sends a default route only. The lab creates the VRF before FRR starts (`ip link add internet type vrf table 10`, `ip link set internet up`, then `ip link set <interface> master internet`; see `lab/frr-vrf-start.sh`).

<!-- lab-file: lab/frr-vrf/frr.conf -->
```
! Packeteer edge with an internet VRF on FRR (docs/vrf.md). The VRF lab
! runs this file unchanged (lab/docker-compose-vrf.yml, lab/e2e-vrf.sh).
! Documentation addresses (RFC 5737) and documentation/private ASNs only.
!
! This router: AS 64512, 192.0.2.254 on an interface in VRF internet.
! Packeteer: 192.0.2.10, peered inside the VRF.
! transit-a: AS 64496 at 192.0.2.21, a partial table and a default route.
! transit-b: AS 64497 at 192.0.2.22, a default route only.
frr defaults traditional
hostname edge
log stdout informational
!
! Lab only: a default-VRF route for the same prefix. Packeteer's route must
! never replace it; lab/e2e-vrf.sh reads the kernel's main table.
ip route 198.51.100.0/24 blackhole
!
bgp community-list standard packeteer permit 64512:666
!
! From Packeteer: only routes that carry the Packeteer community.
route-map packeteer-in permit 10
 match community packeteer
route-map packeteer-in deny 100
!
! From every transit: strip the Packeteer community.
route-map transit-in permit 10
 set comm-list packeteer delete
!
! Toward every transit: never a route with the Packeteer community, then
! your usual export policy (the lab exports nothing else).
route-map ebgp-out deny 10
 match community packeteer
route-map ebgp-out deny 100
!
router bgp 64512 vrf internet
 bgp router-id 192.0.2.254
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 graceful-restart-disable
 neighbor 192.0.2.10 passive
 ! Hold time 9s: lab/e2e-vrf.sh bounds the SIGKILL withdraw on it.
 neighbor 192.0.2.10 timers 3 9
 neighbor 192.0.2.21 remote-as 64496
 neighbor 192.0.2.21 description transit-a
 neighbor 192.0.2.22 remote-as 64497
 neighbor 192.0.2.22 description transit-b
 !
 address-family ipv4 unicast
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

The filters are the standard-community part of the ones in [frr.md](frr.md), applied to the neighbors under `router bgp 64512 vrf internet`. Check with `show bgp vrf internet summary` and `show bgp vrf internet ipv4 unicast 198.51.100.0/24`; the kernel route is in `ip route show vrf internet`.

### Other routers

Not lab-tested here; the session and filters are the ones in each router guide, placed in the VRF.

- **Junos:** the Packeteer group goes under `routing-instances internet protocols bgp` with the transit groups ([junos.md](junos.md)).
- **Cisco IOS XE:** the Packeteer neighbor goes under `router bgp 64512` / `address-family ipv4 vrf internet` with the transit neighbors ([cisco.md](cisco.md)).
- **MikroTik RouterOS 7:** the Packeteer connection gets the VRF of the transit connections (`vrf=internet` on `/routing bgp connection`) ([mikrotik.md](mikrotik.md)).

## Probe source routing per VRF

Each provider is still measured from its `source_ip` ([policy-routing.md](policy-routing.md)). Packeteer does not bind probe sockets to a VRF, so keep the probe host's source addresses outside a VRF and do the per-provider routing on the router, inside the internet VRF:

- The router interface that faces the probe host is in the internet VRF, or the policy sends the probes into it.
- Each rule matches the provider's `source_ip` (and `dscp`, when set) and sets the provider's `next_hop` as a next hop in the internet VRF. `packeteer -pbr FORMAT` prints the rules for the default table; add the VRF where your router needs it. On FRR, add `nexthop-vrf internet` to each `set nexthop` line of the `pbr-map`. On IOS XE, use `set ip vrf internet next-hop <next_hop>` in the route-map. On RouterOS 7, give each per-provider table's default route the gateway `<next_hop>@internet`.
- `probe.path_check` still checks that the first hop of each source is its `next_hop`. A source the router sends out the wrong VRF or provider fails that check, and the provider is marked down and its improvements withdrawn.

## Partial-table and default-only providers

Packeteer does not need a full-table provider. It ranks and steers only prefixes it learned; everything else stays observe.

- **Learned prefixes are ranked.** A prefix a neighbor advertises exactly is compared across every provider, including one that sends only a default route: that provider reaches the prefix through its default, and the probes from its `source_ip` measure that path.
- **The default route is never steered.** A partial-table or default-only provider sends `0.0.0.0/0` or `::/0`. It is learned and can be a target, but Decide never moves it, even when it is allowlisted or a static policy pins it, and the announcer refuses it. The decision reason is `default route is never steered`; the Why? panel shows the RIB check failed with `default route`.
- **Destinations only the default route covers stay observe.** A flow toward them is aggregated to a probe prefix that is not learned, and a static target that is not learned gets `prefix not in RIB`. Neither is announced.
- **A provider that reaches only what it advertises needs the route check.** A partial table without a default (a paid peer, a regional transit) must not take a prefix it does not advertise. Give it `add_path: true` (with add-path on the session) or a `bmp` usage, so it is a candidate only for prefixes it has a path for ([CONFIG.md](CONFIG.md#add-path)). Leave the check off for a provider whose default route reaches everything, or it is never a candidate.
- The preflight warns when fewer than 10 prefixes are learned. That is expected with small partial tables.
