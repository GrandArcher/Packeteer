# Edge router guides

Packeteer peers with the edge over **iBGP** (the router's own ASN). It learns the paths that router advertises — one best path per prefix, unless the router is set to keep sending the native path as well — and, only in `mode: inject`, advertises improvements back on that same session:

- the decided prefix, or the configured more-specifics (`more_specific_bits`)
- next hop = the chosen provider's `next_hop`
- `local_pref` from the config
- `packeteer_community` **and** the well-known `no-export` community

Two filters are required on the router:

1. **From Packeteer**: accept only routes that carry `packeteer_community`. Reject everything else.
2. **Toward eBGP (every transit and peer)**: reject routes that carry `packeteer_community`. `no-export` is a second layer; the filter is the one you control.

Leave BGP graceful restart **off** on the Packeteer session. Packeteer never enables it, withdraws on shutdown, and the session drop is the backstop. If Packeteer disappears, the edge falls back to the paths it learned from its providers.

## When the native path disappears

On a best-path-only session the router stops advertising a prefix to Packeteer once Packeteer's route is its best path. iBGP does not send a route back to the neighbor it was learned from, and it does not send the native path while that path is not best. An eBGP-learned route has no weight advantage over Packeteer's local preference, so this is the normal case. MikroTik has no weight attribute; the same local-pref comparison applies.

Packeteer keeps that improvement. Treating the missing advertisement as "the prefix left" would withdraw the route, the router would advertise the native path again, and the next probe round would inject it again.

Packeteer withdraws immediately when the router withdraws a prefix it was **still advertising** after the improvement had been up for a few seconds, and then holds the prefix for `hold_time` so a bad reading cannot re-inject on the next round. The router is still advertising when:

- the native path stays best (FRR gives a `network` statement weight 32768, which beats local preference; the lab uses this for one of its checks), or
- the router is told to keep sending the native path anyway. On FRR: `neighbor 192.0.2.10 advertise-best-external` in the address-family. On Cisco IOS: `neighbor 192.0.2.10 advertise best-external`. That is the configuration to use on a real edge if a provider withdraw should clear the improvement at once.

If the native path is already hidden and the provider then withdraws it, a single-path session shows Packeteer nothing new. The improvement stays until flip-back or `improvement_ttl`. BGP additional-paths and BMP, which would show that withdraw too, are #26.

The examples use documentation addresses (RFC 5737 / RFC 3849) and the private ASN 64512. Replace them. MikroTik is covered in full in [mikrotik.md](mikrotik.md); the snippet below matches that recipe.

## MikroTik RouterOS 7

```routeros
/routing filter rule
add chain=packeteer-in rule="if (bgp-communities includes 64512:666) { accept }"
add chain=packeteer-in rule="reject"
add chain=ebgp-out rule="if (bgp-communities includes 64512:666) { reject }"
add chain=ebgp-out rule="accept"

/routing bgp connection
set [find where name=packeteer] input.filter=packeteer-in
# On every eBGP connection (transits, peers, IX):
set [find where remote.as!=64512] output.filter=ebgp-out
```

`output.redistribute=bgp` on the Packeteer connection stays as documented in [mikrotik.md](mikrotik.md) so Packeteer receives the router's best paths. That feed is best-path-only; see [When the native path disappears](#when-the-native-path-disappears). It is the opposite direction from `input.filter`.

## FRR

The CI lab in [lab/](../lab/) is this config with a passive iBGP neighbor and a static advertisement of `198.51.100.0/24`. For a real edge, redistribute or reflect the BGP table toward Packeteer instead of a single `network` statement, and keep the same two route-maps.

```
bgp community-list standard packeteer permit 64512:666
!
route-map packeteer-in permit 10
 match community packeteer
route-map packeteer-in deny 100
!
route-map ebgp-out deny 10
 match community packeteer
route-map ebgp-out permit 100
!
router bgp 64512
 bgp router-id 192.0.2.254
 no bgp graceful-restart
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 timers 3 9
 neighbor 192.0.2.1 remote-as 64496
 neighbor 192.0.2.1 description transit-a
 !
 address-family ipv4 unicast
  neighbor 192.0.2.10 activate
  neighbor 192.0.2.10 route-map packeteer-in in
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 route-map ebgp-out out
 exit-address-family
```

Leave the provider next hop unchanged on the session toward Packeteer. Packeteer names the current exit by that next hop. The lab advertises one static prefix and sets its next hop with a route-map (`lab/frr/frr.conf`); a router that already has the eBGP next hops can send those unchanged.

Check with `vtysh -c 'show bgp summary'` and `vtysh -c 'show bgp ipv4 unicast <prefix> json'`. An injected route shows the provider next hop, `locPrf`, and communities `64512:666` and `no-export`.

## Junos

```
policy-options {
    community packeteer members 64512:666;
    policy-statement packeteer-in {
        term tagged { from community packeteer; then accept; }
        term rest { then reject; }
    }
    policy-statement ebgp-out {
        term no-packeteer { from community packeteer; then reject; }
        term rest { then accept; }
    }
}
protocols {
    bgp {
        group packeteer {
            type internal;
            local-address 192.0.2.254;
            import packeteer-in;
            graceful-restart { disable; }
            neighbor 192.0.2.10 { description packeteer; }
        }
        group transit {
            type external;
            export ebgp-out;
            /* neighbors omitted */
        }
    }
}
```

## Cisco IOS / IOS-XE

```
ip community-list standard PACKETEER permit 64512:666
!
route-map PACKETEER-IN permit 10
 match community PACKETEER
route-map PACKETEER-IN deny 100
!
route-map EBGP-OUT deny 10
 match community PACKETEER
route-map EBGP-OUT permit 100
!
router bgp 64512
 bgp router-id 192.0.2.254
 neighbor 192.0.2.10 remote-as 64512
 neighbor 192.0.2.10 description packeteer
 neighbor 192.0.2.10 route-map PACKETEER-IN in
 no neighbor 192.0.2.10 graceful-restart
 !
 address-family ipv4
  neighbor 192.0.2.10 activate
  neighbor <transit> route-map EBGP-OUT out
 exit-address-family
```

Apply `EBGP-OUT` on every external neighbor. IOS honors `no-export` as well; the community-list is still required so a missing well-known community cannot leak a more-specific.

## Flow export

Packeteer's `flow` source learns probe targets from NetFlow v5/v9, IPFIX, or sFlow. It does not speak BGP. MikroTik's Traffic Flow setup is in [mikrotik.md](mikrotik.md). FRR does not export flows. On a Linux host running FRR, run an exporter beside it and send UDP to Packeteer.

Packeteer uses `--network host`, so `listen: "0.0.0.0:2055"` is the host's UDP/2055. Docker port publishing does not apply and is not required. Firewall that UDP port to the exporter.

[pmacct](http://www.pmacct.net/) can read a capture interface and export. `pmacctd` is the exporter here; `nfacctd` is a collector and is the wrong daemon.

```
pcap_interface: eth0
plugins: nfprobe
nfprobe_receiver: 192.0.2.10:2055
nfprobe_version: 9
```

sFlow from the same host:

```
pcap_interface: eth0
plugins: sfprobe
sfprobe_receiver: 192.0.2.10:6343
sfprobe_agentip: 192.0.2.254
```

`softflowd -i eth0 -n 192.0.2.10:2055 -v 9` is the same idea. Use documentation addresses in any config you commit; the addresses above are RFC 5737.
