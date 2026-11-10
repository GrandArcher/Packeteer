# Non-BGP mode: flow-driven routing for a dual-ISP site

For a site with two internet links whose router has no BGP (#300). Packeteer reads NetFlow, IPFIX, or sFlow from the router to find the destinations in use, measures each over both links, and when the other link is clearly better it puts a specific static route for that destination on the router. Everything else stays on the default route. Covered by unit and daemon tests with a fake router and by the `lab/e2e-nonbgp.sh` lab job (Linux steerer); not tested on a public edge or a real RouterOS router.

> **WARNING.** The static routes this mode installs are **NOT from a learned BGP RIB view**. They are derived from flow data: a destination seen in flow records, rounded to /24 or /48 and possibly widened. Such a route can **black-hole or misroute traffic** (a wrong or dead next hop, a prefix wider than what was measured), and it **leaks into BGP if the router redistributes static routes** (or kernel routes, on Linux). Packeteer cannot see or stop that redistribution. A hard kill (SIGKILL, power loss, a crash) leaves the routes on the router until the next start. This is an owner-approved exception to the learned-RIB rule for this mode only ([design/nonbgp.md](design/nonbgp.md)). It is off by default: routes are installed only with `mode: inject` **and** `nonbgp.install_routes: true`. Keep it in a lab until you have read this page.

Packeteer speaks no BGP here. There is no iBGP session, no RIB view, and no announcer. The default stays `mode: observe`; observe and suggest install nothing and only list the routes inject would install.

## How it works

1. The `flow` source counts each destination under a synthetic prefix. A synthetic prefix is never more specific than /24 (IPv4) or /48 (IPv6): a flow address is rounded up to that block first.
2. With a `covering` plugin the announced prefix of each block is looked up (`ripestat` asks RIPEstat network-info; one block's network address per request, at most `rate_per_minute`; a block is asked again a day after its answer, so a changed announcement is picked up). That prefix is the upper bound: when flow data shows active blocks elsewhere inside it, the synthetic prefix widens to the smallest prefix that holds them, never past the announced prefix and never more than `widen_bits` bits past the floor. A widened prefix holds at least as many /24 (or /48) blocks with flow as blocks without: two active /24s far apart stay two /24 routes, but three active /24s of a /22 become one /22 that also moves the fourth, idle /24. That idle space was never measured. Set `widen_bits: 0` to keep every route at its floor. As blocks go idle (`idle`, default 30m) a prefix narrows back, and it is dropped when none is left. Without a covering plugin, or while a lookup fails, a prefix stays at its floor.
3. The probe engine measures each synthetic prefix from both links (policy-routed probe sources, [policy-routing.md](policy-routing.md)). The decision engine sees the synthetic prefixes as a learned view exited through `nonbgp.default_provider`, so thresholds, `hold_time`, `confirm_rounds`, flap quarantine, and the `max_improvements` cap apply as they do for BGP.
4. In `mode: inject` with `nonbgp.install_routes: true` the `steerer` plugin installs one static route per improvement through the other link's `next_hop`. Only prefixes inside `allowlist.prefixes` are installed.

Synthetic prefixes are labeled `synthetic` on `/api/synthetic`, on the `source` field of `/api/improvements`, in the stored improvement history, and on the Improvements page. Every page shows the warning above while the `nonbgp` block is set, and Packeteer logs it at start.

## Config

```yaml
mode: observe          # inject needs install_routes, steerer, allowlist, hold_time, thresholds, community, local_pref
asn: 64496             # required by the config, not used in this mode
router_id: 192.0.2.10
packeteer_community: "64496:666"   # for the router's export filter, see below
local_pref: 200
providers:
  - {name: isp-a, source_ip: 192.0.2.11,    next_hop: 192.0.2.1,    asn: 64500}
  - {name: isp-b, source_ip: 198.51.100.11, next_hop: 198.51.100.1, asn: 64501}
sources:
  - type: flow
    config: {listen: "0.0.0.0:2055"}
allowlist: {prefixes: [203.0.113.0/24]}
nonbgp:
  install_routes: false   # true, with mode: inject, installs routes
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
| `nonbgp.install_routes` | false | The opt-in to install static routes. `mode: inject` requires `true`; without it nothing is installed in any mode. With it, every provider's `next_hop` must be of the family of every allowlisted prefix (a provider has one gateway). |
| `nonbgp.default_provider` | required | The provider the router's default route uses. |
| `nonbgp.steerer` | none | Installs the static routes. Required for `mode: inject`. |
| `nonbgp.covering` | none | Announced-prefix lookup; the upper bound for widening. |
| `nonbgp.widen_bits` | 4 | Bits a synthetic prefix may widen past /24 or /48 (0 to 8). 0 never widens; the covering lookup still runs and its answer is shown. |
| `nonbgp.idle` | 30m | How long a block with no flow is kept (1m to 24h). |
| `nonbgp.max_blocks` | 10000 | Cap on tracked /24 and /48 blocks. Blocks past it are not tracked and are counted in `packeteer_truncated_total{key="nonbgp.max_blocks"}` and `dropped_blocks` on `/api/synthetic`. |

The block needs at least two providers, and `sources` may hold only `flow` entries. It refuses `bgp.neighbors`, `rib_sources`, `announcer`, `inbound`, `mitigation`, `more_specific`, `synthesize`, `external_policy`, `leak_watch`, `ixp`, `exchanges`, `ha`, and `federation`; herd needs `bgp.neighbors`, so it is refused too. In inject mode it also needs `packeteer_community` and `local_pref`, as BGP inject does. `mode`, `allowlist`, `max_improvements`, `sources`, and `nonbgp` are restart-only here. `packeteer -check` prints the mode.

## Steerer plugins

A steerer runs in-process only (an out-of-process plugin can never change a router). Every route it installs carries a tag the router keeps, it changes and deletes only tagged routes, and it refuses a prefix the router already routes by hand, because a second route would share the traffic with it.

- `mikrotik`: RouterOS 7 REST API (`/rest/ip/route`, `/rest/ipv6/route`), routes tagged with the comment `packeteer-steer`. `url` must be https (http only to a loopback host), `username_env` and `password_env` name environment variables, `ca_file` is an absolute path to the CA that signed the router's REST certificate. Use a router user that can read and write routes only.
- `linux`: Packeteer runs on the Linux router itself (`--network host --cap-add NET_ADMIN`). It adds each route over netlink in the main table with protocol 250 (as `ip route replace PREFIX via NEXTHOP proto 250` would), and lists, changes, and deletes only routes with protocol 250, checked in Packeteer rather than by an `ip` filter. No config keys.

The steered route goes in the router's main table. Probes leave through per-provider tables selected by source address, so a steered route never changes what the probes measure ([policy-routing.md](policy-routing.md)).

## Safety

- `observe` and `suggest` install nothing. The recommendations show on the Improvements page.
- A route is installed only with `mode: inject` and `install_routes: true`, only inside the allowlist, only for a current synthetic prefix, never more specific than /24 or /48, and never past `max_improvements`, counted on the router (routes left by an earlier run that are not removed yet count too).
- `hold_time`, the loss and RTT thresholds, and `confirm_rounds` apply before a move. A prefix that flips too often is quarantined and left on the default route.
- Packeteer removes every route it installed on SIGTERM and shutdown, and tries routes left by an earlier run once more, within the 10-second shutdown budget (a route a slow router API could not remove in time stays until the next start), and when its improvement ends: the steered link is lost (its probes fail), its probe source fails, the measurements go stale (older than three `probe.interval`s plus the probe time), or the prefix ages out of the table. A removal that fails is retried on the next round.
- Each route's router requests have their own 30-second budget, so a round never stops halfway through moving a route. A round with many routes on a slow router API takes longer instead. SIGTERM ends a round after the route in flight, so shutdown can wait up to 30 seconds for it before the 10-second withdraw: stop the container with `docker stop -t 45` (compose: `stop_grace_period: 45s`), or a slow router API can leave routes until the next start.
- **Crash cleanup.** Neither RouterOS nor Linux expires a static route, so there is no lease. At every start with a steerer configured, in any mode, Packeteer removes every tagged route on the router before the first decision round; a route it cannot remove is retried every round and counts against `max_improvements`. The limit: after SIGKILL, power loss, or a crash the routes stay on the router **until the next start**, or until you delete them by hand (RouterOS: `/ip route remove [find comment=packeteer-steer]`, and the same under `/ipv6 route`; Linux, with iproute2 on the host: `ip route flush proto 250` and `ip -6 route flush proto 250`; check `ip -V` names iproute2 first, and never run this with the container's `ip`: BusyBox ignores `proto` and would flush the whole main table). Run it under a restart policy and keep `max_improvements` small. `lab/e2e-nonbgp.sh` proves install, withdraw on probe-source failure and SIGTERM, and the sweep after `kill -9`.
- If the router API is unreachable, Packeteer cannot remove a route; the error shows in the log and as an announce event.

## Redistribution into BGP

A router that runs BGP for other reasons can export these routes. Packeteer cannot prevent it.

- RouterOS: do not add `static` to `output.redistribute` on any BGP connection. If a connection must redistribute static routes, reject the allowlisted prefixes in its output filter; they are the only prefixes Packeteer installs: `/routing filter rule add chain=ebgp-out rule="if (dst in 203.0.113.0/24) { reject }"` before the final `accept`. List Packeteer's routes with `/ip route print where comment=packeteer-steer`.
- Linux: the routes carry `proto 250` in the main table. A routing daemon that takes kernel routes into BGP (FRR `redistribute kernel`, BIRD's kernel protocol with `learn`) exports them. Do not import kernel routes, or reject the allowlisted prefixes in the BGP export filter. List them with `ip route show proto 250` (iproute2 only; BusyBox `ip` lists every route).
- If a design needs them in iBGP, the export filter must set `packeteer_community` and NO_EXPORT on them, as Packeteer's own BGP routes carry, and `local_pref`. A static route cannot carry either value itself; that is why inject mode still requires both keys.

## Limits

Only new connections move. Each link NATs to its own addresses, so existing connections keep their link. Inbound traffic is not steered (outbound choice sets the return path for most traffic; DNS steering with a short TTL is a separate matter). After a widen or narrow the new prefix starts its confirm rounds again; the old route is removed first. Herd sharing is not supported in this mode.

## API

`GET /api/synthetic` (viewer) lists the synthetic prefixes and the routes on the router; the fields are in [API.md](API.md).
