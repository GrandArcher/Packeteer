# Juniper Junos

This guide sets up a Junos edge router (MX, SRX, vMX) for Packeteer: the iBGP session, the two filters inject needs, and the checks for each step. Shared rules for every router are in [routers.md](routers.md).

**Not lab-tested.** CI has no Junos image. The configuration follows the same design as the [FRR guide](frr.md), which the [walkthrough](walkthrough.md) runs in CI, and uses standard Junos statements. Check it against your release and commit it with `commit check` and `commit confirmed` first. The router interop matrix is tracked in #53.

The addresses are documentation ranges (RFC 5737) and the ASNs documentation or private-use values. Replace them. The edge is AS 64512 at `192.0.2.254`. Packeteer is `192.0.2.10`. transit-a (AS 64496) is `192.0.2.21` and transit-b (AS 64497) is `192.0.2.22`. Your own prefix is `203.0.113.0/24`. `64512:666` is `packeteer_community` in Packeteer's config. IPv4 unicast only.

## Configuration

```
policy-options {
    prefix-list own-prefixes {
        203.0.113.0/24;
    }
    community packeteer members 64512:666;
    /* From Packeteer: only routes that carry the Packeteer community. */
    policy-statement packeteer-in {
        term tagged {
            from community packeteer;
            then accept;
        }
        term rest {
            then reject;
        }
    }
    /* From every eBGP neighbor: strip the Packeteer community, then your
       usual import policy. */
    policy-statement transit-in {
        term strip {
            then {
                community delete packeteer;
                next policy;
            }
        }
    }
    /* Toward every eBGP neighbor: never the Packeteer community first,
       then your usual export policy (here: only your own prefix). */
    policy-statement ebgp-out {
        term no-packeteer {
            from community packeteer;
            then reject;
        }
        term own {
            from {
                prefix-list own-prefixes;
            }
            then accept;
        }
        term rest {
            then reject;
        }
    }
}
protocols {
    bgp {
        group packeteer {
            type internal;
            local-address 192.0.2.254;
            hold-time 30;
            import packeteer-in;
            graceful-restart {
                disable;
            }
            neighbor 192.0.2.10 {
                description packeteer;
            }
        }
        group transit {
            type external;
            import transit-in;
            export ebgp-out;
            neighbor 192.0.2.21 {
                description transit-a;
                peer-as 64496;
            }
            neighbor 192.0.2.22 {
                description transit-b;
                peer-as 64497;
            }
        }
    }
}
routing-options {
    autonomous-system 64512;
    router-id 192.0.2.254;
}
```

What each part does:

- **`packeteer-in`** accepts only routes that carry `64512:666`. In observe and suggest Packeteer sends nothing, so it changes nothing until inject.
- **`ebgp-out`** rejects any route with `64512:666` before your normal export terms. Packeteer also tags every route `no-export`, which Junos honors; the filter is the layer you control. On an existing router, add the `no-packeteer` term as the first term of the export policy each eBGP group already uses (`insert ... before`).
- **`transit-in`** removes `64512:666` from routes learned from outside, so nobody outside your AS can make a route look like Packeteer's.
- **`graceful-restart disable`** on the group. Packeteer never offers graceful restart; this keeps it off even when `routing-options graceful-restart` is on for the rest of the router.
- **`hold-time 30`** bounds how long a route stays when Packeteer dies without withdrawing. A clean stop withdraws first.
- **No `next-hop self`** on the Packeteer group. Junos leaves the eBGP next hop on routes it sends over iBGP by default. Packeteer names today's exit by that next hop, so each provider's `next_hop` in Packeteer's config must be the transit's address as the edge sees it. The next hop of an injected route is that same transit address, which the edge resolves on its connected interface.

The default iBGP export sends the active BGP routes to Packeteer, which is what it needs. If the group has an export policy, make sure it still sends the transit-learned routes.

## Packeteer side

The same as in the [FRR guide](frr.md#packeteer-side): `asn: 64512`, the providers with the transits' addresses as `next_hop`, and `bgp.neighbors` with `192.0.2.254`. Keep `mode: observe` until both filters are in place.

## Checks

```
show bgp neighbor 192.0.2.10
show route receive-protocol bgp 192.0.2.10
show route 198.51.100.0/24 detail
show route community 64512:666
show route advertising-protocol bgp 192.0.2.21
show route advertising-protocol bgp 192.0.2.22
```

- The session is `Established`.
- In observe and suggest, `receive-protocol bgp 192.0.2.10` is empty.
- In inject, the active route for the prefix is from `192.0.2.10`, with `Localpref: 250`, protocol next hop `192.0.2.22`, and `Communities: 64512:666 no-export`.
- `advertising-protocol bgp` toward each transit never lists the steered prefix.

## Seeing the native path while steered

Once Packeteer's route is active, Junos stops sending the transit path to Packeteer, and Packeteer learns about a transit withdraw only at `improvement_ttl` ([routers.md](routers.md#when-the-native-path-disappears)). Junos can send more than the active path to an iBGP neighbor with `advertise-external` on the group, or with add-path (`family inet unicast add-path send path-count 2` and `add_path: true` on Packeteer's neighbor), or stream it with BMP. Packeteer's add-path and BMP support is lab-proven against FRR only.

## Rollback

On the Packeteer host, `docker stop -t 30 packeteer` withdraws every Packeteer route, then closes the session. On the router, `deactivate protocols bgp group packeteer` followed by `commit` drops the session and its routes.
