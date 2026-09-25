# Deploy notes

Lab only until observe mode is stable.

## Edge requirements

- iBGP session from Packeteer (embedded GoBGP) to each edge. One session learns the RIB and, in inject mode, carries improvements.
- Injected routes are the exact prefix learned from the edge, with `local_pref` plus `packeteer_community` and NO_EXPORT.
- Input filter: accept only routes with the Packeteer community from Packeteer.
- Outbound eBGP filter: do not advertise routes with that community.
- Graceful restart off on the session. If Packeteer is gone, the edge falls back to native BGP.

Recipes: [docs/mikrotik.md](../docs/mikrotik.md) and [docs/routers.md](../docs/routers.md). The simulated-router lab is [lab/](../lab/).

Flow exports (NetFlow, IPFIX, sFlow) use the same host network. The `flow` source's listen ports are host UDP ports; there is no Docker port map. Firewall them to the exporter.
