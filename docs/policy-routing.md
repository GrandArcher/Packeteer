# Sourcing probes per provider (policy routing)

Packeteer measures each transit by sending probes **from that provider's `source_ip`**. The host (or the router in front of it) must make sure that traffic from each source IP leaves through the matching transit. Otherwise every provider measures the same path.

The container uses `--network host`, so it sees the host's addresses and routing tables. Configure policy routing on the host, not in the container.

```yaml
providers:
  - name: transit-a
    source_ip: 192.0.2.11    # must exist on the host
    next_hop: 192.0.2.1      # transit A gateway (also used later for injection)
  - name: transit-b
    source_ip: 198.51.100.11
    next_hop: 198.51.100.1
```

If a `source_ip` is not configured on the host, the probers return "source address unavailable". Packeteer then marks that provider **down** and leaves it out. It never guesses or probes from a different address (fail closed).

## Automatic check

The setup below is easy to get subtly wrong, and a mis-routed source silently measures another provider's path. Every `probe.path_check.interval` (default 5m) Packeteer sends one UDP probe with TTL 1 from each provider's `source_ip` toward a documentation address. The first router past the edge answers, and that reply address must be `next_hop`. A different address, no reply, or a send error marks the provider down with reason `probe path mismatch` and emits `provider.down`; a later match clears it. The provider is left out and its improvements are withdrawn while it is down, so a wrong policy route cannot keep steering traffic (fail closed). Every probe waits on `probe.rate_limit_pps`. Nothing is announced from the check.

A provider whose traffic does not leave the edge directly through `next_hop` (for example one reached across another router, or a `bgp.neighbors[].next_hops` entry) sets `path_check: false`; an exchange peer does the same. A provider in another `domain` is not checked here. A loopback `source_ip` is skipped: its traffic never leaves the host. Turn the whole check off with `probe: {path_check: {enabled: false}}`.

## Linux (probe box directly connected to each transit, or to per-transit VLANs)

```sh
# 1. Addresses: one source IP per provider, on the interface/VLAN facing it
ip addr add 192.0.2.11/24    dev eth1          # transit A
ip addr add 198.51.100.11/24 dev eth2          # transit B (or eth0.102 for a VLAN)

# 2. One routing table per provider with a default route via that provider
echo "101 transit-a" >> /etc/iproute2/rt_tables
echo "102 transit-b" >> /etc/iproute2/rt_tables
ip route add default via 192.0.2.1    dev eth1 table transit-a
ip route add default via 198.51.100.1 dev eth2 table transit-b

# 3. Rules: traffic *from* each source IP uses its provider's table
ip rule add from 192.0.2.11    lookup transit-a priority 1001
ip rule add from 198.51.100.11 lookup transit-b priority 1002

# 4. Check
ip route get 203.0.113.1 from 192.0.2.11      # -> via 192.0.2.1 dev eth1
ip route get 203.0.113.1 from 198.51.100.11   # -> via 198.51.100.1 dev eth2
```

`packeteer -pbr linux -apply` shows a diff against the host's rules and routes and changes nothing; add `-yes` to apply them, after which it checks that each source leaves through its `next_hop`. Rules for a provider you removed are cleaned up on the next apply ([onboarding.md](onboarding.md#host-policy-routing)).

IPv6 works the same way with `ip -6 addr`, `ip -6 route ... table`, and `ip -6 rule add from <src>`.

Make the setup persistent with your distribution's network configuration (netplan `routing-policy`, systemd-networkd `[RoutingPolicyRule]`, or NetworkManager `ipv4.routing-rules`).

With reverse-path filtering, replies arriving on a different interface than the default route may be dropped. Use loose mode on the probe interfaces:

```sh
sysctl -w net.ipv4.conf.all.rp_filter=2
```

## MikroTik RouterOS 7 (probe box behind the router)

This is the common setup: Packeteer runs on a small server behind the edge router, and the router has the transit sessions. Give the probe box one source IP per provider (one VLAN per provider, or several addresses on one link). The router then policy-routes each source out of its transit.

```routeros
# Routing tables, one per provider
/routing table add name=via-transit-a fib
/routing table add name=via-transit-b fib

# Default route in each table via that transit's gateway
/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.1    routing-table=via-transit-a
/ip route add dst-address=0.0.0.0/0 gateway=198.51.100.1 routing-table=via-transit-b

# Probe-box source IPs -> provider table (probe box addresses from config)
/routing rule add src-address=192.0.2.11/32    action=lookup-only-in-table table=via-transit-a
/routing rule add src-address=198.51.100.11/32 action=lookup-only-in-table table=via-transit-b
```

`lookup-only-in-table` means that when a transit is down, the probe fails instead of silently leaving through another provider. That is the fail-closed behavior Packeteer relies on.

If the probe box uses per-provider VLANs instead, point each VLAN's source subnet at the matching table with the same `/routing rule` (for example `src-address=192.0.2.8/29`). You can also mark traffic in `/ip firewall mangle` with `action=mark-routing new-routing-mark=via-transit-a` when rules alone are not enough.

Check with `/tool traceroute 203.0.113.1 src-address=192.0.2.11` on the router, or with `traceroute -s 192.0.2.11 203.0.113.1` on the probe box.

If the probe box's source IPs are not routable on the Internet, source-NAT them to each transit's address on the router (`/ip firewall nat add chain=srcnat src-address=192.0.2.11 out-interface=ether-transit-a action=masquerade`).

## Many providers on one `source_ip`

A large exchange can have hundreds of peers; one address per peer does not scale. Providers and exchange peers may share a `source_ip` when each also sets a tag that the routing can match, and no two providers on that address use the same tag (#157):

```yaml
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31, dscp: 10}
      - {name: ix-peer-b, asn: 64502, next_hop: 203.0.113.12, source_ip: 192.0.2.31, dscp: 12}
```

- `fwmark` sets a Linux `SO_MARK` on every probe socket. It is seen only by the probe host's own `ip rule`, and needs `--cap-add NET_ADMIN`.
- `dscp` (1-63) is written in the IP header, so a router in front of the probe box can match it. That allows at most 63 providers per `source_ip` behind a router. Router policy routing cannot see a Linux fwmark: give a provider a `dscp` as well when a router selects its path.

If a tag cannot be applied (no `NET_ADMIN`, not Linux), the provider is marked down like an unbindable `source_ip`; a built-in prober never probes it untagged. Every probe from the provider carries the tag: the probers, the traceroute paths, and the `probe.path_check` above, which then verifies the first hop of each tagged path. An `exec` prober receives the tag as `mark`/`dscp` and must apply it or fail; Packeteer cannot tell whether it did ([PLUGINS.md](PLUGINS.md)).

`packeteer -pbr FORMAT` prints the routing for every provider measured here and exits. FORMAT is `linux`, `frr`, `junos`, `cisco`, or `mikrotik`. It reads the config and prints text for review: it applies nothing and never connects to a router.

```sh
docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer -pbr linux
```

- `linux`: a table per provider with a default route via its `next_hop`, and an `ip rule` per provider (`from SOURCE`, plus `fwmark` when tagged). Table numbers are 1000 plus the provider's position in the list and rule priorities are 2000 plus it (clear of the 101/102 tables and 1001/1002 priorities in the example above), so reordering providers renumbers them. A provider with only a `dscp` gets an nftables rule that turns the DSCP into a mark equal to its table, because the kernel's DSCP rule selector is not available everywhere. A configured `fwmark` equal to such a mark on the same source is an error.
- `frr` (pbrd `pbr-map`), `junos` (firewall filter `next-ip`/`next-ip6`), `cisco` (extended ACL and `route-map` with `set ip next-hop`), and `mikrotik` (routing tables, plus `/routing rule` for an untagged source and a `/ip firewall mangle` `mark-routing` rule for a DSCP) match `src` and, when set, `dscp`, and set the provider's `next_hop`. A provider with `fwmark` but no `dscp` is an error for these formats. FRR `pbr-map` sequence numbers stop at 700, so more providers than that are an error. The interface that faces the probe host is left as `<probe-facing-interface>` in a comment; add the policy there.

Provider names are reduced to letters, digits, `_`, `.` and `-` in the output. Check each snippet against your platform release before use.

## Internet exchange peers

Each exchange peer (`exchanges[].peers[]`, #27) is measured from its own `source_ip`, so it needs its own table: a route via the peer's LAN address, and a rule from the source to that table. The peering LAN itself is not a probe target (#145): packets to customer prefixes still leave via that peer's `source_ip` and `next_hop`. On Linux, with the probe box on the peering LAN or behind the IX router:

```sh
echo "131 ix-peer-a" >> /etc/iproute2/rt_tables
ip route add default via 203.0.113.11 table ix-peer-a    # the peer's next_hop
ip rule add from 192.0.2.31 lookup ix-peer-a priority 1031
```

On RouterOS it is the same `/routing table` + `/routing rule` pair per peer as above, with the peer's LAN address as the gateway. A peer only carries its own routes, so probes to prefixes it does not advertise are dropped or bounced; Packeteer steers to a peer only when the router shows the peer's path for the prefix, whatever the probes say.

## Container capabilities

- `--cap-add NET_RAW` is needed for ICMP echo on raw sockets. Without it, the `icmp` prober tries an unprivileged ICMP socket, which works if `net.ipv4.ping_group_range` allows it. If that also fails, the next prober (`tcp`) is used.
- The `tcp` prober (connect to port 443 by default) needs no extra capabilities.
- The `udp` prober and the `traceroute` source also need no raw socket. ICMP port-unreachable and time-exceeded are read from the UDP socket error queue. The UDP prober counts an unreachable only when that message comes from the target, so a firewall `REJECT` on the path is loss. They still leave from `source_ip`, so the policy route has to cover UDP as well as ICMP and TCP. Traceroute discovery runs in the background and does not sit inside the probe round.
