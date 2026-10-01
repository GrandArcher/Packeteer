# MikroTik RouterOS 7

This guide grows with each milestone. It currently covers:

1. **Probe sourcing**: see [policy-routing.md](policy-routing.md#mikrotik-routeros-7-probe-box-behind-the-router).
2. **iBGP session** so Packeteer can see the paths the router advertises: below.
3. **Injected routes**: accept only the Packeteer community from that session, and never export it to eBGP. The same for [FRR](frr.md), [Junos](junos.md), and [Cisco IOS](cisco.md).
4. **Traffic Flow** (NetFlow / IPFIX) so Packeteer can pick probe targets from real traffic, and optionally score failing destinations: below.
5. **Port mirroring** for the `span` source (passive problem detection): below.
6. **SNMP** so Packeteer can read interface counters for 95th-percentile tracking: below. The community stays in the container environment.

## iBGP session to Packeteer

Packeteer learns the **paths this router advertises** (its best path per prefix) to know which provider each prefix uses today. It peers over iBGP with the router's own ASN. In `observe` and `suggest` it announces nothing. In `inject` it announces only allowlisted improvements, each tagged with `packeteer_community` and `no-export`.

<!-- lab-file: lab/chr/edge.rsc (the block between its docs/mikrotik.md markers) -->
```routeros
# Router ASN 64512, router address 192.0.2.254, Packeteer at 192.0.2.10.
# Community 64512:666 must match packeteer_community in config.yaml.
/routing bgp instance add name=edge as=64512 router-id=192.0.2.254
/routing bgp connection add name=packeteer instance=edge \
    local.address=192.0.2.254 local.role=ibgp \
    remote.address=192.0.2.10 remote.as=64512 \
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
/routing bgp connection set [find where local.role=ebgp] output.filter-chain=ebgp-out
```

- `output.redistribute=bgp` sends the eBGP-learned best paths (the full table if you take one) to Packeteer. It is best-path-only. Once an injected route wins, RouterOS stops advertising that prefix back to Packeteer. Packeteer keeps the improvement; it does not withdraw and re-announce. A provider withdraw after that point is caught at `improvement_ttl`, not immediately. Immediate withdraw needs the router to keep sending the native path (FRR and Cisco: `advertise-best-external`, or add-path to Packeteer, or BMP; Packeteer receives both, see [CONFIG.md](CONFIG.md#add-path). The lab proves them on FRR only; check what your RouterOS version can send). Details: [routers.md](routers.md#when-the-native-path-disappears).
- This is the current RouterOS 7 syntax (tested on 7.23.7): the AS and router ID live on `/routing bgp instance` and each connection names its `instance`. Older 7.x releases without `/routing bgp instance` put them on `/routing bgp template` (`as=`, `router-id=`) and connections used `templates=`; the filter rules and `output.filter-chain` are the same.
- Select the eBGP connections with `local.role=ebgp`. `[find where remote.as!=64512]` (an unquoted number) matches every connection on 7.23, including the Packeteer session.
- Route reflection is not needed for a single edge. For iBGP-learned routes, make the router a route reflector for this session or feed the other paths with BMP (`rib_sources`) where the router can send it.
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

RouterOS 7 syntax changes between minor releases, so check these commands against your version. CI runs them on a free MikroTik CHR (RouterOS 7.23.7 long-term) in QEMU: see [Tested in CI](#tested-in-ci-chr-in-qemu).

Check the session with `/routing bgp session print`. Packeteer logs `bgp session ... state=ESTABLISHED`, then a periodic `rib ready=true prefixes=N`. In inject mode an accepted route shows up in `/routing route print where bgp.communities~"64512:666"` (`bgp.communities` with a dot; `bgp-communities` is the name inside filter rules and matches nothing in `print`). `/routing route print detail where dst-address=198.51.100.0/24` shows `.communities=no-export,64512:666 .local-pref=250` and `belongs-to="bgp-IP-192.0.2.10"`. Clearing it is `mode: observe` (Packeteer withdraws) or stopping the container (the session drops; graceful restart is off, so the route does not stick).

RouterOS offers the graceful-restart capability (`gr` under `local.capabilities` in the session print); Packeteer never does, so it is never negotiated. Do not add Packeteer to any graceful-restart setup.

### Tested in CI (CHR in QEMU)

`lab/e2e-chr.sh` (CI job `chr`) boots the free CHR image (downloaded from MikroTik at run time, checksum pinned, free license level, no key) in QEMU, applies [lab/chr/edge.rsc](../lab/chr/edge.rsc), which is this section's configuration plus lab transits, and runs the Packeteer image in inject mode against it. Documentation prefixes and private ASNs only; lab only. It proves that RouterOS:

- accepts Packeteer's route for the exact learned prefix, with `64512:666` and `no-export`, local preference 250, next hop of the chosen transit, and makes it the active route over the eBGP paths (RouterOS compares BGP paths by local preference first; the iBGP distance of 200 against eBGP 20 does not decide it)
- rejects an iBGP route without the community on the same `packeteer-in` chain (it shows as filtered)
- never sends Packeteer's route to an eBGP peer. While it is best, the router stops advertising that prefix to eBGP peers at all (BGP sends only the best path), and the native path returns when Packeteer withdraws. Plan for this if the edge gives a full table to customers.
- never receives an allowlisted prefix that is not in Packeteer's learned RIB
- drops the route on flip-back, on SIGTERM (Packeteer withdraws first), on a frozen process (the router's 9s hold timer expires), and on SIGKILL (the session closes)

Once Packeteer's route is best, the router stops advertising the prefix to Packeteer (best path only), as described above; the improvement stays.

FRR, Junos, and IOS equivalents: [frr.md](frr.md), [junos.md](junos.md), [cisco.md](cisco.md). The whole observe → suggest → inject sequence, with the checks at each step: [walkthrough.md](walkthrough.md).

## Exchange peers

Exchange peers (`exchanges`, #27) are used only when Packeteer sees each peer's own path for the prefix, which needs the router to send every path (BGP add-path) or a BMP feed. Check that your RouterOS version offers one of them toward Packeteer. Without it, the route check keeps every exchange peer unusable (fail closed); transits still work. Per-peer probe sources are in [policy-routing.md](policy-routing.md#internet-exchange-peers).

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

To also score failing destinations from the same export, add a `problems` block. It needs unsampled v5, v9, or IPFIX records that carry the source address, protocol, and TCP flags; leave `packet-sampling` off. An outbound record with SYN and no ACK is a handshake that was never answered, and an inbound RST is a remote reset.

```yaml
  - type: flow
    config:
      listen: ["0.0.0.0:2055"]
      problems:
        local: ["192.0.2.0/24"]   # your own networks
        failure_pct: 20
        min_flows: 10
```

## Port mirroring (span source)

The `span` source reads a mirror of the uplink on a spare port of the Packeteer host. It sees retransmissions and handshake RTT, which flow records do not carry. On RouterOS devices with a switch chip, mirror the uplink to the port the Packeteer host is plugged into:

```routeros
# ether1 is the uplink, ether5 goes to the Packeteer host's mirror NIC.
/interface ethernet switch set switch1 mirror-source=ether1 mirror-target=ether5
```

The mirror target carries only copies. Give the host's mirror NIC no address, then point the source at it. The container needs `--network host` and `--cap-add NET_RAW`.

```yaml
sources:
  - type: span
    config:
      interface: eth1              # the mirror NIC inside the container
      local: ["192.0.2.0/24", "2001:db8:1::/48"]
      window: 5m
```

Switch-chip mirroring syntax differs between models and RouterOS releases (some use `/interface ethernet switch rule` with `mirror=yes`); check yours. `/tool sniffer` streaming (TZSP) is not a mirror port and is not read by this source. Span targets are probe targets only; nothing is announced unless the normal inject checks pass.

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
