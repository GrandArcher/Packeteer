# MikroTik RouterOS 7

This guide grows with each milestone. It currently covers:

1. **Probe sourcing**: see [policy-routing.md](policy-routing.md#mikrotik-routeros-7-probe-box-behind-the-router).
2. **iBGP session** so Packeteer can see the paths the router advertises: below.
3. **Injected routes**: accept only the Packeteer community from that session, and never export it to eBGP. FRR, Junos, and IOS snippets are in [routers.md](routers.md).
4. **Traffic Flow** (NetFlow / IPFIX) so Packeteer can pick probe targets from real traffic: below.
5. **SNMP** so Packeteer can read interface counters for 95th-percentile tracking: below. The community stays in the container environment.

## iBGP session to Packeteer

Packeteer learns the **paths this router advertises** (its best path per prefix) to know which provider each prefix uses today. It peers over iBGP with the router's own ASN. In `observe` and `suggest` it announces nothing. In `inject` it announces only allowlisted improvements, each tagged with `packeteer_community` and `no-export`.

```routeros
# Router ASN 64512, router loopback 192.0.2.254, Packeteer at 192.0.2.10.
# Community 64512:666 must match packeteer_community in config.yaml.
/routing bgp template add name=packeteer as=64512 router-id=192.0.2.254
/routing bgp connection add name=packeteer templates=packeteer \
    remote.address=192.0.2.10 remote.as=64512 local.role=ibgp \
    output.redistribute=bgp output.default-originate=never \
    input.filter=packeteer-in

# From Packeteer: accept only routes that carry the Packeteer community.
/routing filter rule add chain=packeteer-in \
    rule="if (bgp-communities includes 64512:666) { accept }"
/routing filter rule add chain=packeteer-in rule="reject"

# Toward every eBGP peer: never export that community, even if no-export
# were missing. Attach ebgp-out to each transit/peer/IX connection.
/routing filter rule add chain=ebgp-out \
    rule="if (bgp-communities includes 64512:666) { reject }"
/routing filter rule add chain=ebgp-out rule="accept"
/routing bgp connection set [find where remote.as!=64512] output.filter=ebgp-out
```

- `output.redistribute=bgp` sends the eBGP-learned best paths (the full table if you take one) to Packeteer. It is best-path-only. Once an injected route wins, RouterOS stops advertising that prefix back to Packeteer. Packeteer keeps the improvement; it does not withdraw and re-announce. A provider withdraw after that point is caught at `improvement_ttl`, not immediately. Immediate withdraw needs the router to keep sending the native path (FRR and Cisco: `advertise-best-external`; additional-paths and BMP are #26). Details: [routers.md](routers.md#when-the-native-path-disappears).
- Route reflection is not needed for a single edge. For iBGP-learned routes, make the router a route reflector for this session (`/routing bgp template set packeteer route-reflect=yes`) or use BMP later (#26).
- Keep graceful restart **off** on this session. Packeteer never enables it, so its routes can never linger after it dies.

Packeteer side (`config.yaml`):

```yaml
mode: observe                 # inject only after the filters above are in place
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250               # required for mode: inject; higher than the native paths
bgp:
  listen_port: 179            # optional: let the router connect in
  neighbors:
    - address: 192.0.2.254
      description: edge1
announcer:
  type: gobgp
```

`local_pref` and `announcer` are used only when `mode: inject`. An injected route is the exact prefix learned from this session. `more_specific_bits` is not a setting; a config that includes it is rejected. Inject also requires a non-empty allowlist, at least one BGP neighbor, a positive hold time, and positive loss and latency thresholds.

RouterOS 7 syntax changes between minor releases, so check these commands against your version.

Check the session with `/routing bgp session print`. Packeteer logs `bgp session ... state=ESTABLISHED`, then a periodic `rib ready=true prefixes=N`. In inject mode an accepted route shows up in `/routing route print where bgp-communities~"64512:666"`. Clearing it is `mode: observe` (Packeteer withdraws) or stopping the container (the session drops; graceful restart is off, so the route does not stick).

FRR, Junos, and IOS equivalents: [routers.md](routers.md).

## Traffic Flow (NetFlow / IPFIX)

RouterOS exports NetFlow v5, NetFlow v9, and IPFIX. It does not export sFlow. Point the target at Packeteer's address and at a `listen` port on the `flow` source. Packeteer runs with `--network host`, so that port is a port on the host: do not publish it with Docker `-p`.

```routeros
# Packeteer at 192.0.2.10, router at 192.0.2.254. Documentation addresses.
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=16k \
    active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target
add dst-address=192.0.2.10 port=2055 version=9 src-address=192.0.2.254 \
    v9-template-timeout=5m
```

`version=5` and `version=ipfix` (port 4739 is the usual IPFIX port) work too. v9 and IPFIX resend templates; Packeteer keeps them in memory per exporter and does not store the raw records. Check the export with `/ip traffic-flow print` and `/ip traffic-flow target print`.

Packeteer drops RFC1918 and IPv6 ULA destinations, then keeps the top prefixes by bytes over `window`. If you enable `packet-sampling`, byte totals are multiplied by the sampling interval only when the export carries it (NetFlow v5 header, or information element 34, 50, or 305). If the top prefixes look too small by a constant factor, the exporter omitted that field.

```yaml
sources:
  - type: static          # listed first: its host wins when a prefix is in both
    config:
      targets:
        - {prefix: 198.51.100.0/24, host: 198.51.100.1}
  - type: flow
    config:
      listen: ["0.0.0.0:2055"]
      window: 5m
      top_n: 100
      min_bytes: 1000000
      exclude: ["192.0.2.0/24"]
```

Allow UDP/2055 on the host firewall from the router only. The socket is not authenticated. Flow targets are probe targets: they are not announced unless they are also in the learned RIB and pass the inject checks.

## SNMP interface counters

Packeteer's `snmp` telemetry plugin reads `ifHCInOctets` and `ifHCOutOctets` (the interface name is `ifName`, which on RouterOS is `ether1` and the like). It does not announce. Put the community in `PACKETEER_SNMP_COMMUNITY` (or whatever name `community_env` uses) on the container. Do not commit it.

```routeros
# Packeteer at 192.0.2.10. Replace CHANGE-ME on the router only.
# The same string goes in the container environment, not in config.yaml.
/snmp set enabled=yes
/snmp community add name=CHANGE-ME addresses=192.0.2.10 read-access=yes write-access=no
```

Restrict `addresses` to Packeteer. Disable the default community if it is still enabled (`/snmp community print`). `interface` in the telemetry config is the RouterOS interface name. `commit_mbps` and `billing_day` are recorded for the 95th-percentile window. They do not steer traffic.

```yaml
telemetry:
  - type: snmp
    config:
      interval: 5m
      hosts:
        - name: edge1
          address: 192.0.2.254
          version: 2c
          community_env: PACKETEER_SNMP_COMMUNITY
      providers:
        - name: transit-a
          host: edge1
          interface: ether1
          commit_mbps: 1000
          billing_day: 1
          percentile: greater_separate
```

`percentile: greater_separate` is the greater of the inbound 95th and the outbound 95th. `separate` keeps the two directions apart. `greater` takes max(in, out) on each sample and then the 95th. The billing day is 00:00 UTC. The window is in memory and starts over on restart. `/api/telemetry` shows the latest rates. SNMPv3 uses `username_env`, `auth_env`, and `priv_env` the same way: names in the file, values in the environment.
