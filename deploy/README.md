# Deploy notes

Lab only until observe mode is stable.

## Edge requirements

- iBGP session from Packeteer / ExaBGP / GoBGP to each edge
- Injected routes preferred over eBGP (local-pref or community map)
- Outbound eBGP filter: do not advertise routes with the Packeteer community
- If Packeteer is gone, edges must fall back to native BGP

MikroTik-specific snippets will land under `deploy/mikrotik/` in a later milestone.
