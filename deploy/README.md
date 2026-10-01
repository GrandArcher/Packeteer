# Deploy notes

Lab only until observe mode is stable.

## Edge requirements

- iBGP session from Packeteer (embedded GoBGP) to each edge. One session learns the RIB and, in inject mode, carries improvements.
- Injected routes are the exact prefix learned from the edge, with `local_pref` plus `packeteer_community` and NO_EXPORT.
- Input filter: accept only routes with the Packeteer community from Packeteer.
- Outbound eBGP filter: do not advertise routes with that community.
- Graceful restart off on the session. If Packeteer is gone, the edge falls back to native BGP.

Recipes: [MikroTik](../docs/mikrotik.md), [FRR](../docs/frr.md), [Junos](../docs/junos.md), [Cisco](../docs/cisco.md), and [what they share](../docs/routers.md). Config keys: [docs/CONFIG.md](../docs/CONFIG.md). Install: [docs/quickstart.md](../docs/quickstart.md). Mode by mode: [docs/walkthrough.md](../docs/walkthrough.md). Problems: [docs/troubleshooting.md](../docs/troubleshooting.md). The simulated-router lab is [lab/](../lab/).

Flow exports (NetFlow, IPFIX, sFlow) use the same host network. The `flow` source's listen ports are host UDP ports; there is no Docker port map. Firewall them to the exporter.

The read-only HTTP server (dashboard, `/metrics`, `/api`) binds `http.listen`, default `127.0.0.1:8080`. The image exposes port 8080. With `--network host` that address is on the host. Set `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD` before binding a non-loopback address. `PACKETEER_HTTP_LISTEN=off` disables the server.
