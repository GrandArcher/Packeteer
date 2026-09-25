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

## Container capabilities

- `--cap-add NET_RAW` is needed for ICMP echo on raw sockets. Without it, the `icmp` prober tries an unprivileged ICMP socket, which works if `net.ipv4.ping_group_range` allows it. If that also fails, the next prober (`tcp`) is used.
- The `tcp` prober (connect to port 443 by default) needs no extra capabilities.
