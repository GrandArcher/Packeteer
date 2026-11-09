# Non-BGP mode: flow-driven routing for a dual-ISP site

For a site with two internet links whose router has no BGP (#300). Packeteer reads NetFlow, IPFIX, or sFlow from the router to find the destinations in use, measures each over both links, and when the other link is clearly better it puts a specific static route for that destination on the router. Everything else stays on the default route. Covered by unit and daemon tests with a fake router, not by a lab job and not tested on a public edge.

Packeteer speaks no BGP here. There is no iBGP session, no RIB view, no community, and no NO_EXPORT. The default stays `mode: observe`. The mode is partial: it breaks four rules in AGENTS.md and waits on an owner decision ([design/nonbgp.md](design/nonbgp.md)). Keep it in a lab until then.

## How it works

1. The `flow` source counts each destination under a synthetic prefix. A synthetic prefix is never more specific than /24 (IPv4) or /48 (IPv6): a flow address is rounded up to that block first.
2. With a `covering` plugin the announced prefix of each block is looked up (`ripestat` asks RIPEstat network-info; one block's network address per request, at most `rate_per_minute`). That prefix is the upper bound: when flow data shows active blocks elsewhere inside it, the synthetic prefix widens to the smallest prefix that holds them, never past the announced prefix and never more than `widen_bits` bits past the floor. As blocks go idle (`idle`, default 30m) it narrows back, and it is dropped when none is left. Without a covering plugin, or while a lookup fails, a prefix stays at its floor.
3. The probe engine measures each synthetic prefix from both links (policy-routed probe sources, [policy-routing.md](policy-routing.md)). The decision engine sees the synthetic prefixes as a learned view exited through `nonbgp.default_provider`, so thresholds, `hold_time`, `confirm_rounds`, flap quarantine, and the `max_improvements` cap apply as they do for BGP.
4. In `mode: inject` the `steerer` plugin installs one static route per improvement through the other link's `next_hop`. Only prefixes inside `allowlist.prefixes` are installed.

Synthetic prefixes are labeled `synthetic` on `/api/synthetic`, on the `source` field of `/api/improvements`, in the stored improvement history, and on the Improvements page. They are never exported to a BGP peer.

## Config

```yaml
mode: observe          # inject needs steerer, allowlist, hold_time, thresholds
asn: 64496             # required by the config, not used in this mode
router_id: 192.0.2.10
providers:
  - {name: isp-a, source_ip: 192.0.2.11,    next_hop: 192.0.2.1,    asn: 64500}
  - {name: isp-b, source_ip: 198.51.100.11, next_hop: 198.51.100.1, asn: 64501}
sources:
  - type: flow
    config: {listen: "0.0.0.0:2055"}
allowlist: {prefixes: [203.0.113.0/24]}
nonbgp:
  default_provider: isp-a
  steerer:
    type: mikrotik
    config:
      url: https://192.0.2.254
      username_env: PACKETEER_ROUTER_USER
      password_env: PACKETEER_ROUTER_PASSWORD
      ca_file: /etc/packeteer/router-ca.pem
  covering: {type: ripestat}
```

| Key | Default | Meaning |
|---|---|---|
| `nonbgp.default_provider` | required | The provider the router's default route uses. |
| `nonbgp.steerer` | none | Installs the static routes. Required for `mode: inject`. |
| `nonbgp.covering` | none | Announced-prefix lookup; the upper bound for widening and what the herd may see. |
| `nonbgp.widen_bits` | 4 | Bits a synthetic prefix may widen past /24 or /48. 0 never widens; the covering lookup still runs for the herd (0 to 8). |
| `nonbgp.idle` | 30m | How long a block with no flow is kept (1m to 24h). |
| `nonbgp.max_blocks` | 10000 | Cap on tracked /24 and /48 blocks. Blocks past it are not tracked and are counted in `packeteer_truncated_total{key="nonbgp.max_blocks"}` and `dropped_blocks` on `/api/synthetic`. |

The block needs at least two providers, and `sources` may hold only `flow` entries. It refuses `bgp.neighbors`, `rib_sources`, `announcer`, `inbound`, `mitigation`, `more_specific`, `synthesize`, `external_policy`, `leak_watch`, `ixp`, `exchanges`, `ha`, and `federation`. `mode`, `allowlist`, `max_improvements`, `sources`, and `nonbgp` are restart-only here. `packeteer -check` prints the mode.

## Steerer plugins

A steerer runs in-process only (an out-of-process plugin can never change a router). Every route it installs carries a tag the router keeps, it changes and deletes only tagged routes, and it refuses a prefix the router already routes by hand, because a second route would share the traffic with it.

- `mikrotik`: RouterOS 7 REST API (`/rest/ip/route`, `/rest/ipv6/route`), routes tagged with the comment `packeteer-steer`. `url` must be https (http only to a loopback host), `username_env` and `password_env` name environment variables, `ca_file` is an absolute path to the CA that signed the router's REST certificate. Use a router user that can read and write routes only.
- `linux`: Packeteer runs on the Linux router itself (`--network host --cap-add NET_ADMIN`). It runs `ip route replace PREFIX via NEXTHOP proto 250` in the main table and lists and deletes only routes with protocol 250. No config keys.

The steered route goes in the router's main table. Probes leave through per-provider tables selected by source address, so a steered route never changes what the probes measure ([policy-routing.md](policy-routing.md)).

## Safety

- `observe` and `suggest` never call the steerer. The recommendations show on the Improvements page.
- A route is installed only inside the allowlist, only for a current synthetic prefix, never more specific than /24 or /48, and never past `max_improvements`.
- `hold_time`, the loss and RTT thresholds, and `confirm_rounds` apply before a move. A prefix that flips too often is quarantined and left on the default route.
- Packeteer removes every route it installed on SIGTERM and shutdown, and when its improvement ends, the provider is unusable, the probe source fails, measurements go stale, or the prefix ages out of the table. A removal that fails is retried on the next round.
- In inject mode, on the first round after start, tagged routes left by an earlier process (and not wanted now) are removed.
- A hard kill (SIGKILL, power loss, a crash) cannot remove routes: unlike an iBGP route, a static route does not disappear with the session. They stay until the next start removes them, or until you delete the tagged routes by hand (RouterOS: routes with comment `packeteer-steer`; Linux: `ip route flush proto 250`). Run it under a restart policy, and prefer a small `max_improvements`.
- If the router API is unreachable, Packeteer cannot remove a route; the error shows in the log and as an announce event.

## Limits

Only new connections move. Each link NATs to its own addresses, so existing connections keep their link. Inbound traffic is not steered (outbound choice sets the return path for most traffic; DNS steering with a short TTL is a separate matter). After a widen or narrow the new prefix starts its confirm rounds again; the old route is removed first.

## Herd

With `herd.enabled`, a non-BGP site may share measurements, never the flow addresses and never its synthetic prefixes. Each synthetic prefix is mapped to the announced prefix that bounds it, and only that prefix with the measurements is recorded. A synthetic prefix with no announced prefix is not shared. This needs `nonbgp.covering`, `flow` in `herd.share.sources`, and `asn` on each provider (a provider with no `asn` shares nothing). The announced prefix and its origin AS are the routing facts here, in place of a learned path. The herd preview before sharing applies as usual ([herd.md](herd.md)).

## API

`GET /api/synthetic` (viewer): `enabled`, `mode`, `default_provider`, `steerer`, `covering`, `tracked_blocks`, `pending_lookups`, `dropped_blocks`, `lookup_errors`, `last_error`, and `routes`: each synthetic prefix with `source` (`synthetic`), `upper` (announced prefix), `blocks`, `last_seen`, and, when steered, `steered_to`, `next_hop`, and `steered_since`.
