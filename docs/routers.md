# Edge router guides

Packeteer peers with the edge over **iBGP** (the router's own ASN). It learns the paths that router advertises — one best path per prefix, unless the router is set to keep sending the native path as well — and, only in `mode: inject`, advertises improvements back on that same session:

- the exact prefix learned from the router
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
- the router is told to keep sending the native path anyway. On FRR: `neighbor 192.0.2.10 advertise-best-external` in the address-family. On Cisco IOS and IOS-XE: `bgp advertise-best-external` in the address family. That is the configuration to use on a real edge if a provider withdraw should clear the improvement at once.

If the native path is already hidden and the provider then withdraws it, a single-path session shows Packeteer nothing new. The improvement stays until flip-back or `improvement_ttl`. BGP add-path (`bgp.neighbors[].add_path` with the router sending every path, e.g. FRR `neighbor <packeteer> addpath-tx-all-paths`) or BMP (`rib_sources`) keeps the native path visible, so that withdraw is seen; see [CONFIG.md](CONFIG.md#add-path).

Several edges, or a route reflector in front of them: see [route-reflector.md](route-reflector.md).

## Internet exchange peers

With `exchanges` (#27) each IX member you list is a provider whose `next_hop` is its address on the peering LAN. Packeteer steers a prefix to a member only when it sees that member's own path for the exact prefix, so the router must show Packeteer every path: FRR `neighbor <packeteer> addpath-tx-all-paths` in the address family (with `add_path: true` on the neighbor), or BMP post-policy monitoring (`rib_sources`, `bmp: prefer`). A route server is transparent, so the member's AS is the first AS on its paths. The injected route's next hop is the member's LAN address; the edge resolves it on its IX interface. The eBGP export filter for Packeteer's community applies to IX sessions like any other. Each member needs its own probe source, routed to that member ([policy-routing.md](policy-routing.md)).

## Router guides

Each guide has the session, both filters, the Packeteer side of the config, the show commands that prove each step, and the rollback. The examples use documentation addresses (RFC 5737 / RFC 3849) and documentation or private-use ASNs. Replace them.

| Router | Guide | Tested |
|---|---|---|
| MikroTik RouterOS 7 | [mikrotik.md](mikrotik.md): iBGP, filters, Traffic Flow, port mirroring, SNMP | iBGP and filters in CI on a free CHR (RouterOS 7.23.7) in QEMU: accept with community + `no-export`, untagged route rejected, no eBGP export, withdraw on flip-back, SIGTERM, frozen process, and SIGKILL ([details](mikrotik.md#tested-in-ci-chr-in-qemu)). Traffic Flow, mirroring, and SNMP are not in CI. |
| FRR | [frr.md](frr.md) | The [walkthrough](walkthrough.md) runs the guide's configuration in CI: observe, suggest, inject, export check, and withdraw on stop. The [interop matrix](#interop-matrix) covers iBGP, add-path, and BMP. The other FRR labs are in [lab/](../lab/README.md). |
| BIRD 2 and 3 | No guide. The lab edge [lab/interop/bird/bird.conf](../lab/interop/bird/bird.conf) has both filters. | In the [interop matrix](#interop-matrix): iBGP and add-path on BIRD 2 and 3; BMP on BIRD 3. |
| GoBGP | No guide. The lab edge [lab/interop/gobgp/gobgpd.toml](../lab/interop/gobgp/gobgpd.toml) has both filters. | In the [interop matrix](#interop-matrix): iBGP, add-path, and BMP. |
| Juniper Junos | [junos.md](junos.md) | Not in CI. |
| Cisco IOS / IOS-XE | [cisco.md](cisco.md) | Not in CI. |

Whatever the router, check the two filters with its show commands before you set `mode: inject`, and check them again after the first injected route appears.

## Interop matrix

The `interop` workflow (`.github/workflows/interop.yml`, #53) runs weekly, on demand, and on pull requests that touch the lab, the announcer, or the BMP station. Each cell runs `lab/e2e-interop.sh <router> <feature>`. One simulated edge of that router type (`lab/interop/`) sits between the Packeteer image (inject, mounted config) and two simulated FRR eBGP transits. The edge config is the same in every cell: accept from Packeteer only with `64512:666`, export nothing to eBGP, hold time 9s, graceful restart off, add-path send offered. Lab only, with documentation prefixes and ASNs.

| Edge | iBGP (best path) | add-path | BMP (post-policy) |
|---|---|---|---|
| FRR 10.2.4 | yes | yes | yes |
| BIRD 2 (Debian 2.17) | yes | yes | not available (built without BMP) |
| BIRD 3 (Debian 3.1) | yes | yes | yes, with one gap (below) |
| GoBGP (the version in `go.mod`) | yes | yes | yes |
| MikroTik CHR 7.23.7 | yes (`lab/e2e-chr.sh`, [details](mikrotik.md#tested-in-ci-chr-in-qemu)) | not exercised | not exercised |

Every cell checks:

- The edge's only Packeteer path is its best path. It comes from Packeteer, with the chosen provider's next hop, local-pref 250, `64512:666`, and `no-export`.
- Neither transit receives anything from the edge.
- On every sample, the edge has no Packeteer route for `203.0.113.0/24` or `198.51.100.128/25`. Both are allowlisted and probed, but no router advertises them, so they are never in the learned RIB.

What each column adds:

- **iBGP:** the route stays while the edge no longer sends the native path. Flip-back withdraws it, and restoring the probes injects it again. SIGTERM withdraws it. A frozen process (`docker pause`) keeps the route until the edge's 9s hold timer expires. SIGKILL drops it with the session.
- **add-path** (`bgp.neighbors[].add_path`): the edge sends transit-b's inactive path with a path ID. When transit-b withdraws, the route check retires the steer at once, well inside the 5m `hold_time`. The steer returns when transit-b announces again. Then SIGTERM, restart, and SIGKILL.
- **BMP** (`rib_sources`, `bmp: only`): transit-b's path reaches Packeteer only over BMP. The cell repeats the add-path withdraw, re-announce, and SIGTERM steps. After a restart, the edge must refeed the new station before SIGKILL.

Findings:

- **BIRD 3.1.7 BMP** sends peer up and routes only for BGP sessions that come up while the station is connected. After Packeteer restarts, BIRD reconnects to the station but sends no routes for sessions that were already up, and restarting those protocols does not help. Until BIRD fixes this, restart BIRD (or its BMP protocol) after Packeteer restarts, or use iBGP add-path instead. The lab starts Packeteer before the edge and skips the restart step on BIRD 3.
- **BIRD** treats iBGP sessions as multihop. Set `direct;` on the Packeteer session so that next hops on the LAN resolve without an IGP table.
- **GoBGP** has no per-neighbor import policy outside route-server mode. Both filters are global policies that match on a `neighbor-set`.

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
