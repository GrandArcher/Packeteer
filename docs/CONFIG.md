# Configuration reference

Packeteer reads one YAML document. Unknown keys are errors. Durations use Go's form: `30s`, `15m`, `1h`, `500ms`. A bare `0` on a duration that has a default means "use the default", not "disable".

The field names below are the `yaml` tags on the controller structs in `internal/config` and on each plugin's config struct. `cmd/controller/configdoc_test.go` fails if a tag is missing from this file.

Load order:

1. `-config` (default `/etc/packeteer/config.yaml`, or `PACKETEER_CONFIG` when that variable is set and `-config` is omitted).
2. Defaults, then validation. On failure the process exits before it probes or opens a BGP session.
3. Environment overlays below, then validation again.

```sh
packeteer -check -config config.yaml
packeteer -version
```

`-check` builds and validates plugins, prints a summary, and exits. It sends no probes and opens no BGP session. `-notify-test` builds the plugins, sends one `notifier.test` event to each notifier, prints `sent`, `filtered`, or `FAILED` per notifier, and exits 1 on a failure. It sends no probes and opens no BGP session. `-version` prints `packeteer <version>` and does not read the config.

The image entrypoint is the same binary. Flags go after the image name.

## Top level

| Key | Default | Required | Meaning |
|---|---|---|---|
| `mode` | `observe` | no | `observe`, `suggest`, or `inject`. A file without `mode` (or with an empty one) observes. `inject` is never a default: it needs `mode: inject` and the [inject checklist](#inject-checklist). |
| `asn` | none | yes, non-zero | BGP ASN of this speaker. Neighbors are iBGP in this ASN. |
| `router_id` | none | yes | IPv4 address. IPv6 is rejected. |
| `packeteer_community` | empty | inject | RFC 1997 community `asn:value`. Each half is an integer 0–65535. Quote it in YAML (`"64512:666"`). |
| `local_pref` | 0 | inject | Local preference on every injected route. `0` is rejected in inject mode. Set it above the edge's native local preference. |
| `more_specific_bits` | unset | must be absent | Any value, including `0`, is an error. Packeteer announces the exact prefix it learned from the RIB. |
| `more_specific` | off | no | More-specific injection: with each improvement, also announce the more-specifics inside its prefix that a neighbor advertises in the learned RIB, under a route cap. Never a prefix that is not learned. See [`more_specific`](#more_specific). Lab-proven only. |
| `instance` | `domain` | no | This instance's name in a federation (#30). Peers expect it in its snapshot. Letters, digits, `_`, `.`, `-`, at most 64 characters. See [Multi-POP](#multi-pop-federation). |
| `domain` | empty | with `federation` | This instance's routing domain (POP). Empty is a standalone instance. |
| `inter_dc_rtt` | empty | per remote domain | Map of domain to round-trip time from this POP (for example `pop-b: 12ms`), 0–10s. Added to every path a peer in that domain measured. |
| `global_commit` | empty | no | Commits shared by providers in several domains. Needs `federation`. See [Multi-POP](#multi-pop-federation). |
| `federation` | none | no | The instance-to-instance transport plugin, one object: `type: mtls`. See [Federation `mtls`](#federation-mtls). Omitted runs the instance standalone. |
| `ha` | none | no | Active/standby elector (#31), one object: `type: lease`. Only the active instance of the pair announces. Needs `bgp.neighbors`. See [High availability](#high-availability-ha) and [Elector `lease`](#elector-lease). Omitted runs a single instance, always active. Lab-proven only. |
| `max_improvements` | 50 | no | Cap on active improvements. Integer from 1 to 10000. Biggest gains win when the cap binds, or the scorer's [`improvement_weights`](#improvement-weights) when set. |
| `hold_time` | 0 | inject: positive | Minimum life of an improvement, and the cooldown after a flip-back or a confirmed RIB leave. `0` is legal in observe and suggest (a flip can happen on the next evaluation). Negative is an error. |
| `improvement_ttl` | `1h` | no | Retire an improvement after this long so the native path is measured again. A negative duration disables the TTL. `0` selects the default `1h`. |
| `thresholds` | zeros | inject: both positive | See below. With both deltas at `0`, the decision engine records no improvement in any mode. |
| `providers` | none | at least one | Probe sources and injection next hops. |
| `exchanges` | none | no | Internet exchanges: each listed peer is a provider with its own next hop on the peering LAN, always route-checked. See [`exchanges`](#exchanges). Lab-proven only. |
| `allowlist` | empty | inject: non-empty | Prefixes that may be injected. |
| `probe` | see below | no | Timing and concurrency. |
| `log` | `info` / `text` | no | Process log. |
| `http` | `127.0.0.1:8080` | no | Read-only dashboard, API, and metrics. |
| `bgp` | no neighbors | inject: at least one neighbor | iBGP sessions. |
| `rib_sources` | none | no | Route feeds into the RIB view from outside the iBGP session: `type: bmp` is a BMP monitoring station. Needs `bgp.neighbors`. Learn-only, in-process only; does not announce. See [RIB source `bmp`](#rib-source-bmp). |
| `plugin_dir` | `/etc/packeteer/plugins` | no | Directory for out-of-process plugins. |
| `probers` | `icmp`, then `tcp` | no | Ordered. Later entries run only when an earlier one errors. |
| `sources` | none | no | Probe targets. With none, the process starts and probes nothing. |
| `scorer` | `weighted` | no | One scorer. Lower score is better. |
| `announcer` | none | inject | In-process only. `type: gobgp` publishes on the RIB session. |
| `notifiers` | none | no | Events. A failure here does not withdraw routes by itself. |
| `telemetry` | none | no | Interface counters and 95th-percentile usage. Off unless listed. Does not announce. |
| `policies` | none | no | Routing policies and maintenance windows, asked in order before each decision. Off unless listed. Does not announce. See [Policies](#policies). |
| `storage` | none | no | One storage plugin for report history (`type: sqlite`). Off unless set. Does not announce. See [Storage `sqlite`](#storage-sqlite). |
| `inbound` | none | no | Inbound commit control: steer inbound traffic for your own prefixes away from a provider over commit with prepends and TE communities. Off unless set; its own `mode` defaults to `observe`. See [`inbound`](#inbound). Lab-proven only. |
| `mitigation` | none | no | Threat mitigation: RTBH (blackhole), BGP redirect, and FlowSpec (drop, rate-limit, redirect, by source country too) for exact learned prefixes, added through `/api/mitigations`. Off unless set; its own `mode` defaults to `observe`. See [`mitigation`](#mitigation). Lab-proven only. |
| `anomaly` | none | no | Automatic traffic anomaly (DDoS) detection: a detector plugin baselines flow volumes per destination prefix and IP protocol from a `flow` source and reports anomalies; an explicit rule can turn one into a mitigation rule, rate-limited and capped. Needs `mitigation` for rules. Off unless set. See [`anomaly`](#anomaly). Lab-proven only. |
| `report_subscriptions` | none | no | Stored reports emailed as CSV on a daily, weekly, or monthly UTC schedule through an `smtp` notifier (#34). Needs `storage`. See [`report_subscriptions`](#report_subscriptions). Does not announce. |
| `troubleshoot` | looking glass only | no | Read-only operator tools: looking glass, on-demand probe, traceroute, whois. Does not announce. See [`troubleshoot`](#troubleshoot). |

`mode: observe` and `mode: suggest` use the same decision path and announce nothing. `suggest` is the checkpoint: read the log, the dashboard, and `/api/decisions` before you change `mode`. The allowlist is enforced only in `inject`.

### `thresholds`

| Key | Default | Bounds |
|---|---|---|
| `min_loss_delta_pct` | 0 | 0–100. Inject requires a value greater than 0. |
| `min_rtt_delta_ms` | 0 | Not negative. Inject requires a value greater than 0. |

A candidate wins when its score is lower and either loss improves by at least `min_loss_delta_pct`, or loss is no worse and average RTT improves by at least `min_rtt_delta_ms`.

### `providers`

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique. |
| `source_ip` | yes, except in another domain | Source address of probes. Unique across providers. Must be configured on the host. Same address family as `next_hop`. Must be empty for a provider in another `domain`. |
| `next_hop` | yes | BGP next hop used if this provider is selected. Also how a learned route is matched to a provider. For a provider in another domain, the address this POP's routers reach that POP's exit at across the backbone. |
| `domain` | no | Routing domain (POP) the provider exits in (#30). Empty or equal to the top-level `domain` is local. A provider in another domain is not probed here: the peer there measures it. Needs `federation` and an `inter_dc_rtt` entry for the domain; `bmp` and `add_path` do not apply. |
| `exclude` | no | `true`: still probe, never select for an improvement. |
| `group` | no | Load-balancing group. Empty means the provider is not in a group. Letters, digits, `_`, `.`, `-`, at most 64 characters, starting with a letter or digit. |
| `precedence` | no | Commit-control preference. Lower is preferred. `0` or omitted means 100. 0–10000. The highest precedence among providers that can take commit traffic is the last resort. |
| `cc_disable` | no | `true`: leave this provider out of commit control in both directions. Performance improvements can still select it. |
| `cost` | no | Price per Mbps, 0–1000000000, in one currency across all providers. Omitted means no cost: the `cost` scorer never moves a prefix onto this provider or off it for price. Improvements between two priced providers carry `cost_delta` and `est_savings` on `/api/improvements`. |
| `bmp` | no | How this provider uses paths from `rib_sources` (BMP): `off` (default), `prefer`, or `only`. `prefer` and `only` need a `rib_sources` entry. See [RIB source `bmp`](#rib-source-bmp). |
| `add_path` | no | `true`: apply the route check to this provider from the iBGP add-path paths. Needs a `bgp.neighbors` entry with `add_path: true`. Not allowed with `bmp: only`. See [Add-path](#add-path). |

### `allowlist`

| Key | Meaning |
|---|---|
| `prefixes` | CIDRs with no host bits. Duplicates are errors. |

A learned prefix is eligible when it is equal to an entry or more specific and inside it. Packeteer still announces that learned prefix, not a prefix it invented. An entry of `198.51.100.0/24` allows `198.51.100.0/24` and `198.51.100.128/25` when the router advertised that exact prefix. It does not allow `198.51.0.0/16`.

### `probe`

| Key | Default | Bounds |
|---|---|---|
| `interval` | `30s` | Greater than `timeout`. Also the period of the staleness check. |
| `timeout` | `2s` | Per packet. Must be shorter than `interval`. |
| `packets` | 10 | 1–1000. |
| `workers` | 8 | 1–1024 concurrent probe runs. |
| `rate_limit_pps` | 100 | 1–100000 packets per second, global. |
| `per_target_concurrency` | 2 | 1–64 concurrent runs toward one destination host. |
| `retry_loss_pct` | 0 | 0–100. `0` disables retry. Above zero, a sample whose loss is at least this percent is probed again before it is stored. |
| `retry_packets` | 0 | 0–1000. Packet count of that second probe. When `retry_loss_pct` is set and this is `0`, it becomes three times `packets`, capped at 1000. |

A measurement older than `3 * interval + packets * timeout` is stale. When retry is enabled the window is `3 * interval + (packets + retry_packets) * timeout`. That same duration is the deadline for one probe round. The decision loop also wakes every `interval`, so a round that never finishes still withdraws once results are stale.

The retry sample replaces the first one. Both waits go through `rate_limit_pps`. Targets from the `vip` source carry their own interval; the scheduler probes a prefix when that interval has elapsed and leaves the other results in place. A VIP interval can only shorten the cadence. An unset target interval means `probe.interval`, so a longer VIP interval does not slow a prefix that static or flow already listed. Sources that do not carry a shorter interval are re-read on `probe.interval`, not on every VIP wake. The `outage` source is the exception: it is read on every round, including a short VIP wake, so a pattern detected at the end of a round is a target on the next one. A new incident also wakes the probe loop immediately, and those prefixes are marked urgent for that one pass. A completed round, including one that only probed VIP prefixes, still runs the decision engine. `Run` is what the process uses. A prefix that disappears from every source is dropped on the next completed round, including a round that probes nothing because nothing is due.

### `log`

| Key | Default | Values |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` (`warning` is accepted), `error`. |
| `format` | `text` | `text` or `json`. |

### `http`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | `host:port`. Wrap IPv6 in brackets: `"[2001:db8::1]:8080"`. `""` disables the server. |
| `allow_from` | any | Client prefixes allowed to connect (#32), e.g. `[127.0.0.0/8, 192.0.2.0/24, "2001:db8::/32"]`. Others get `403` on every path, health checks included. Works with and without `auth`. Behind a reverse proxy, the proxy's address is matched (`X-Forwarded-For` is ignored). |
| `config_editor` | `false` | `true` lets an admin read, validate, and write this config file through `/api/config` and `/settings.html` (#34). Needs `auth` or basic auth; with neither it stays off. A write passes the same checks as a start and is read back through the loader; it applies on restart (or SIGHUP for `bgp.neighbors`). Turning `mode: inject` on through it needs an explicit confirmation. It never runs an `exec` plugin, and refuses a file that adds or changes one or changes `plugin_dir`. `GET /api/config` returns the file unredacted, so keep secrets in environment variables. The file must be mounted writable. See [ui.md](ui.md). |

The server does not announce routes. With `--network host`, this address is on the host. Basic auth is not a key in the file; see the environment variables. Users, roles, API tokens, and SSO are the `auth` block.

### `auth`

Users, roles, API tokens, the audit log, and optional OIDC single sign-on for the ops HTTP server (#32). Off by default. Guide: [auth.md](auth.md).

```yaml
storage:
  type: sqlite            # users, token hashes, and the audit log live here
auth:
  enabled: true
  session_ttl: 12h        # SSO sign-ins
  token_ttl: 2160h        # API tokens when the request names no ttl
  sso:                    # optional
    type: oidc
    config:
      issuer: https://idp.example.net/realms/noc
      client_id: packeteer
      client_secret_env: PACKETEER_OIDC_CLIENT_SECRET
      redirect_url: https://packeteer.example.net/auth/callback
      role_map: {noc-admins: admin, noc: operator, staff: viewer}
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns auth on. Requires `storage` (a plugin that keeps users, e.g. `sqlite`) and refuses to start with `PACKETEER_HTTP_USER` set. `false`, or no `auth` block, keeps the single basic-auth account: the rollback. |
| `session_ttl` | `12h` | Lifetime of an SSO session, `5m`–`168h`. Sessions are in memory; a restart signs everyone out. |
| `token_ttl` | `2160h` | API token lifetime when the request names none, `1h`–`8760h`. A request may ask for up to `8760h`. |
| `sso` | none | Single sign-on plugin entry (`type: oidc`). Needs `enabled: true`. |

Roles: `viewer` reads everything a dashboard or API client reads (and manages its own API tokens), `operator` also opens and closes maintenance windows, adds and removes mitigation rules, and runs the troubleshooting tools, `admin` also manages users and reads the audit log. `/healthz`, `/readyz`, and the SSO sign-in endpoints are public. The first admin comes from `PACKETEER_ADMIN_USER` and `PACKETEER_ADMIN_PASSWORD`. Auth never changes what is announced: allowlist, learned-RIB check, community, NO_EXPORT, `max_improvements`, hold time, and withdraw-on-failure are the same for every role.

### `bgp`

| Key | Default | Meaning |
|---|---|---|
| `listen_port` | 0 | `0`: do not listen; Packeteer connects out. 1–65535: accept sessions. |
| `listen_addresses` | none | Local addresses to bind when listening. Each must be an IP address. |
| `neighbors` | none | Edge routers, iBGP, same ASN as `asn`. Reloaded online on SIGHUP; see [Online reconfiguration](#online-reconfiguration). |
| `as_path` | `empty` | AS path on injected routes: `empty`, `native`, or `provider`. See [AS path](#as-path). |

Each neighbor:

| Key | Default | Meaning |
|---|---|---|
| `address` | required | Peer IP. Duplicates are errors. |
| `port` | 179 | Remote TCP port. `0` means 179. 0–65535 at validation; `0` is replaced when the session is built. |
| `local_address` | unset | Optional source address of the TCP session. |
| `passive` | false | Wait for the router to connect. Requires `listen_port`. |
| `description` | empty | Log label. |
| `add_path` | false | Ask the router for additional paths (BGP add-path, RFC 7911) on this session. Receive only; Packeteer never sends them. See [Add-path](#add-path). |
| `providers` | empty | Providers this router forwards to itself (#27). Routes toward them go to this router with the provider's `next_hop`, and the router is their egress. An exchange name stands for all of its peers. See [Multiple routers](#multiple-routers). |
| `next_hops` | empty | Map of provider name to the next hop this router uses to reach that provider through another router. Routes toward it go to this router with that next hop. An exchange name stands for all of its peers. See [Multiple routers](#multiple-routers). |

Packeteer proposes a hold time of 90 seconds and a keepalive of 30 seconds. The router's shorter hold time wins. A hold time of zero is never proposed. Graceful restart is not a config key and is never enabled. With no neighbors, the RIB view is off and decisions say ranking only: nothing is injected.

One established session is enough for the view to be ready. All sessions down drops the learned routes and withdraws injected routes.

#### Add-path

Without add-path the router sends Packeteer one path per prefix: its best. With `add_path: true` on a neighbor, Packeteer offers add-path receive for IPv4 and IPv6 unicast, and a router set to send every path (FRR: `neighbor <packeteer> addpath-tx-all-paths` under the address family) sends its inactive transit and IX paths too, on the same iBGP session. Each path is kept by its path identifier; a withdraw removes only that path. Lab-proven only (`lab/e2e-addpath.sh`).

- **Negotiation.** After the session is established Packeteer reads the router's OPEN. `/api/providers` (`bgp.peers`) shows `add_path: true` only when the router offered add-path send. If it did not, Packeteer logs a warning and the session works as a single-path session.
- **The published route (native).** Higher local preference wins, then the lower neighbor address. Among one neighbor's paths the shorter AS path wins, then the lower path identifier. Add-path does not mark the router's best, so this is an estimate. A BMP Loc-RIB feed, where you run one, is not used to correct it: the iBGP path still comes first.
- **Route check.** A provider with `add_path: true` is checked while at least one session that negotiated add-path is up: the router sends every path it has, so a provider without a path for the exact prefix is not advertising it. No new improvement goes there, and an active one is retired at once (reason `no route via provider (route check)`), ignoring hold time. Any iBGP path through the provider passes. Set it only for providers whose sessions are on routers that send you every path: a provider on an edge without add-path would be refused. With `bmp: prefer` the BMP and add-path checks both count (either passes); `bmp: only` ignores iBGP paths and cannot be combined.
- **Native path stays visible.** The router keeps sending the native path while Packeteer's route is its best, so a native withdraw during an improvement is seen and the improvement is retired, instead of waiting for `improvement_ttl`.
- **Packeteer's own route.** An iBGP path tagged with `packeteer_community` (a reflector or router sending Packeteer's route back) is ignored, with or without add-path, so an injected route never keeps its prefix learned or passes its own route check.
- **Failure.** Session loss drops every path from that neighbor, as before; with every session down the view is not ready and injected routes are withdrawn. Graceful restart stays off.

**Rollback:** remove `add_path` from the neighbor and the providers and restart. The session comes up single-path and the route check falls back to BMP (if configured) or none.

#### Multiple routers

With several `neighbors` and neither `providers` nor `next_hops` set, every neighbor gets every injected route with the provider's `next_hop` (one edge, or route reflectors). Set them to send each router only what it can forward (#27):

- A route toward a provider in the neighbor's `providers` is sent unchanged. A route toward a provider in its `next_hops` is sent with that next hop. A route toward any other provider is not sent to that neighbor.
- The neighbors that list a provider in `providers` are its egress routers. While none of them has an established session, the provider is unusable (reason `egress router down`): no new improvement goes there, an active one is retired at once and withdrawn from every router.
- One session dropping removes only that router's routes. All sessions down withdraws everything, as before.
- Once any neighbor sets either list: every name must be a provider, a provider cannot be in both lists of one neighbor, a `next_hops` value must be an IP of the provider's `next_hop` family, provider `next_hop`s must be distinct (routes are matched to a provider by next hop), and every non-excluded provider must be reached by some neighbor. A neighbor with neither list reaches every provider.
- Inbound steer routes are not affected: they keep their learned next hop and go to every neighbor.

`-check` prints each neighbor's lists. The deployment guide, including route reflectors, is [route-reflector.md](route-reflector.md). Lab-proven only (`lab/e2e-multirouter.sh`).

**Rollback:** remove `providers` and `next_hops` from every neighbor and restart (or send SIGHUP).

#### AS path

`bgp.as_path` sets the AS path Packeteer puts on injected routes (#27, IRP "AS-path behavior"). The edge's own policies (AS-path filters, origin checks, route maps) then see the same path as on the route they would otherwise use.

- `empty` (default): no AS numbers, as a locally originated route. This was the only behavior before.
- `native`: the AS path of the learned route for the prefix (the router's current best as Packeteer sees it).
- `provider`: the chosen provider's own learned path for the exact prefix (from iBGP, add-path, or BMP on the router that has the provider up). Without one, the native path.

Paths are read when the route is announced. If the router stops sending the native route once Packeteer's route wins, the path on the wire is kept rather than re-announced. When the provider's learned path changes, the route is replaced with the new one. Packeteer still adds only `packeteer_community` and NO_EXPORT, sets `local_pref`, and never prepends its own AS: the session is iBGP. Lab-proven only (`lab/e2e-ix.sh` checks `provider`).

#### Online reconfiguration

`kill -HUP` the process (`docker kill -s HUP <container>`) to reload the config file (#27, IRP "Bgpd online reconfiguration"). Only `bgp.neighbors` is applied while running:

- A new neighbor gets a session; a removed one is closed (its paths leave the view at once, as on a session loss). A neighbor whose session settings changed (`port`, `local_address`, `passive`, `add_path`) is closed and opened again. Other sessions are not touched.
- A changed per-router table (`providers`, `next_hops`) replaces the announcer's export policy on the running speaker. Every outbound route is withdrawn first (GoBGP sends a withdraw only where the current policy would send the route, so a route withdrawn after the swap could stay on a router the new table blocks) and announced again under the new table on the next evaluation, once the prefix is back in the learned RIB. Inbound steer routes are not affected. A change that leaves the table as it was (adding a neighbor with no lists to a config with no lists) withdraws nothing.
- Egress routers are recomputed, so `egress router down` follows the new lists.

Anything else that changed is refused: the log says `config reload refused` with the keys (`restart required: changed local_pref, providers`), and the running config stays. A file that does not parse or validate is refused the same way. `bgp.neighbors` cannot become empty on a reload. Comments and YAML style do not count as changes. If a reload fails after it has changed the speaker, Packeteer stops (exit status 1), which withdraws every Packeteer route; the container's restart policy brings it back with the new file. Environment overlays (`PACKETEER_LOG_LEVEL`, ...) are applied to the reloaded file as at startup. Lab-proven only (`lab/e2e-ix.sh`).

### `exchanges`

Internet exchanges (#27, IRP 1.2.11). Each peer listed on an exchange is a provider: it is probed from its own `source_ip`, and an improvement toward it uses its own `next_hop` on the peering LAN. Everything that applies to providers applies to peers (thresholds, hold time, cap, allowlist, policies, commit and cost scorers, per-router lists). What differs:

- **Every peer is route-checked.** A peer carries only its own routes, so no improvement goes to a peer unless the router shows Packeteer the peer's path for the exact prefix, and that path's first AS is the peer's `asn`. An active one is retired at once (reason `no route via provider (route check)`) when the path goes. No visible path means no route: the check fails closed. The paths come from iBGP add-path (a `bgp.neighbors` entry with `add_path: true`, the router sending every path) or BMP (`bmp: prefer` or `only`, with `rib_sources`); one of the two is required.
- **Statistics** are on `/api/exchanges` and `packeteer_exchange_*` metrics: per peer, the prefixes the router shows through its next hop, the most common first AS when it differs from `asn` (`observed_asn`, a misconfigured peer), probe-source health, and active improvements; and the next hops on the peering LAN that are not configured peers (`discovered`, with AS and prefix count). A discovered next hop is never probed or used. To use it, add it as a peer (with a probe source) and restart.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique, not a provider name. Letters, digits, `_`, `.`, `-`. May be used in `bgp.neighbors[].providers` and `next_hops` for all its peers. |
| `lans` | yes | Peering LAN prefixes. Every peer `next_hop` is inside one; `discovered` lists other next hops inside them. |
| `bmp` | no | The peers' BMP usage: `off` (default), `prefer`, or `only`, as on providers. |
| `group` | no | The peers' load-balancing group, as on providers. |
| `peers` | yes | At least one. |

Each peer:

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Provider name, unique across providers and peers. |
| `asn` | yes | The peer's AS: the first AS on the paths it advertises (a route server is transparent). |
| `next_hop` | yes | The peer's address on the peering LAN. Unique across providers. |
| `source_ip` | yes | Probe source for this peer, unique like any provider's. The host (or router) must route traffic from it to this peer's `next_hop` ([policy-routing.md](policy-routing.md)). |
| `exclude`, `precedence`, `cost` | no | As on providers. |

Peers get `add_path: true` automatically when a neighbor has `add_path` (and `bmp` is not `only`). `-check` prints each peer with its exchange and AS.

**Rollback:** remove the `exchanges` block and restart; improvements toward peers are withdrawn at shutdown.

### `troubleshoot`

Operator tools on the ops HTTP server (`/api/troubleshoot/...` and the dashboard's Troubleshooting section). None of them announces, withdraws, or changes a decision. On-demand probe results go back to the caller only; they are not stored as probe results and never reach the decision loop.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns on the tools that send traffic or query a registry: the on-demand probe (the configured prober chain from every provider's `source_ip`), traceroute (UDP from each provider's `source_ip`, `NET_RAW` not needed), and whois. The looking glass only reads the learned RIB and is always on. |
| `requests_per_minute` | `6` | Probe, traceroute, and whois requests together, 1–600. Excess requests get `429`. |
| `max_hops` | `30` | TTL limit for one traceroute, 1–64. One probe per hop, `probe.timeout` per hop. A trace stops early after six silent hops in a row. |
| `whois` | none | One whois plugin entry (`type: rdap`). Without it, whois answers `404`. |

The tools refuse loopback, link-local, multicast, broadcast, and unspecified targets. Whois accepts only an address, a prefix, or an ASN (`AS64496` or `64496`). The active tools are `POST` with a JSON body, so a cross-site page cannot trigger them. When basic auth is on, every tool needs it.

### `inbound`

Inbound optimization (#25, lab-proven only, not on a public edge). Router setup and the full contract are in [inbound.md](inbound.md). Two triggers steer inbound traffic away from a provider: `commit` (a `telemetry` plugin reports its inbound 95th percentile above `commit_mbps`) and `performance` (the probes rank it the worst-performing provider). Needs a `telemetry` plugin, `performance`, or both.

| Key | Default | Meaning |
|---|---|---|
| `mode` | `observe` | `observe` logs, `suggest` also publishes the suggestion on `/api/inbound` and as `inbound.*` events, `inject` announces steer routes. `inject` also needs top-level `mode: inject`. Setting `observe` and restarting withdraws every steer route (rollback). |
| `prefixes` | none | Required. Your own prefixes to steer. In `inject` each must be inside `allowlist.prefixes`, and a steer route is announced only while the exact prefix is in the learned RIB. Outbound improvements never use these prefixes. |
| `local_pref` | `1` | Local preference on steer routes. Keep it low so the edge prefers a steer route only when its import policy says so. |
| `release_pct` | `90` | Release a steer once the inbound 95th is at or below this percent of the commit, after `hold_time`. Greater than 0, at most 100. |
| `max_improvements` | top-level `max_improvements` | Cap on steer routes, 1 to the top-level cap. Steer routes and outbound improvements also share the top-level cap. |
| `announcer` | none | `inject`: required. In-process only: `type: gobgp` (see [Inbound announcer `gobgp`](#inbound-announcer-gobgp)). In `observe` and `suggest` it is optional and only supplies the catalog. |
| `performance` | off | Turns on the performance trigger. Keys below. `performance: {}` uses the defaults. |
| `damping` | on | Inertia against oscillation. Keys below. |
| `moderated` | `[]` | Triggers (`commit`, `performance`) whose steers are only suggested, even in `inject`: they are on `/api/inbound` and in `inbound.steered` events with `moderated: true`, and are never announced. The other trigger stays automated. |

`performance` keys. The comparison uses the prefixes every provider with a fresh probe result measured (fresh: newer than about three probe rounds; a provider whose probe source is down has none and is left out). Loss is the mean loss; RTT is the mean over paths that answered. Only the single worst provider is steered for performance.

| Key | Default | Meaning |
|---|---|---|
| `loss_pct` | `5` | A provider is degraded when its mean loss is this many points above the best other provider. At most 100. Negative disables the loss check. |
| `latency_ms` | `50` | A provider is degraded when its mean RTT is this many ms above the best other provider. Negative disables the RTT check (not both). |
| `min_prefixes` | `3` | Commonly measured prefixes needed before providers are compared. At least 1. |
| `release_pct` | `50` | Release a performance steer once both gaps are at or below this percent of their thresholds, after the steer's hold time. Greater than 0, at most 100. |

`damping` keys:

| Key | Default | Meaning |
|---|---|---|
| `disabled` | `false` | `true` turns damping off: a trigger steers on the first round and every hold is `hold_time`. |
| `confirm` | `1m` | A trigger must hold this long before the provider is steered. Not negative. |
| `backoff` | `2` | A provider steered again within `max_hold` of its release is flapping: its hold time, and so the cooldown after it, is multiplied by this per flap. 1 to 16. |
| `max_hold` | 8 × `hold_time` | Cap on the grown hold time, and the flap window. A provider released for longer than this starts over. Not shorter than `hold_time`. |

A commit steer that flaps also learns inertia: how much inbound traffic returned to the provider when it was released (`inertia_mbps` on `/api/inbound`). It is then released only when the inbound 95th plus that amount is at or below `release_pct`, so an unchanged demand no longer flips the edge back and forth.

`hold_time` is the minimum life of a steer and the cooldown after a release (damping grows both for a flapping provider). `improvement_ttl` retires a steer; the route is withdrawn for at least one round and returns only once the edge advertises the prefix again. Telemetry older than 15 minutes, a poll error, or no row releases a commit steer at once; no fresh probe results release a performance steer at once. Packeteer never steers away from every non-excluded provider.

### `mitigation`

Threat mitigation (#28, lab-proven only, not on a public edge): RTBH, BGP redirect, and FlowSpec drop, rate-limit, and redirect, optionally by source country. Router setup, the API, and the full contract are in [mitigation.md](mitigation.md). Rules are added and removed through `POST /api/mitigations` and `DELETE /api/mitigations/{id}` (basic auth required), live in memory only, and always expire.

| Key | Default | Meaning |
|---|---|---|
| `mode` | `observe` | `observe` accepts and lists rules as a dry run and announces nothing. `inject` announces them; it also needs top-level `mode: inject`. Setting `observe` and restarting withdraws every mitigation route (rollback). |
| `allowlist` | none | Required. The mitigation allowlist, separate from `allowlist.prefixes`: a rule's prefix must be inside one of these. A default route is rejected. A rule is announced only while the exact prefix is in the learned RIB. |
| `max_rules` | `10` | Cap on mitigation routes held at once, announced or waiting. 1–1000. An RTBH, redirect, or FlowSpec rule counts once; a FlowSpec rule with `source_countries` counts once per source network. The announcer enforces the same cap on its routes (RTBH, redirect, and FlowSpec together). Mitigation routes do not count toward `max_improvements`. |
| `default_ttl` | `1h` (or `max_ttl` when shorter) | Lifetime of a rule whose request names no `ttl`. At least 1s, at most `max_ttl`. |
| `max_ttl` | `24h` | Longest `ttl` a request may ask for. 1s–168h. Every rule expires. |
| `local_pref` | top-level `local_pref` | Local preference on mitigation routes. Keep it above the edge's native routes. |
| `geoip_db` | none | Absolute path to a MaxMind-format country database you mount (for example `GeoLite2-Country.mmdb`). FlowSpec rules with `source_countries` need it; each country is expanded to its networks (merged where adjacent) when the rule is added. None is shipped or downloaded. Unreadable at startup: Packeteer refuses to start. |
| `announcer` | none | `inject`: required. In-process only: `type: gobgp` (see [Mitigation announcer `gobgp`](#mitigation-announcer-gobgp)). In `observe` it is optional and only supplies the catalog (redirect targets). |

With FlowSpec configured on the announcer and `mode: inject`, every iBGP session also offers the IPv4 and IPv6 FlowSpec address families (RFC 8955). In `observe` the sessions are unchanged.

While an RTBH or redirect rule holds a prefix in `inject`, or its route is still on the wire, outbound improvements and inbound steers leave that prefix alone. When the RIB is not ready every mitigation route is withdrawn. A catalog next hop that equals a provider's `next_hop` is refused at startup.

### `anomaly`

Automatic traffic anomaly (DDoS) detection (#33, lab-proven only, not on a public edge). The full contract is in [anomaly.md](anomaly.md). Every anomaly is reported (log, `/api/anomalies`, events, history). A mitigation rule is added only when a rule below matches, only through [`mitigation`](#mitigation) (its `mode`, allowlist, `max_rules`, TTL, community, and NO_EXPORT apply; `observe` is a dry run), and only for an exact prefix in the learned RIB.

| Key | Default | Meaning |
|---|---|---|
| `detector` | none | Required. The detector plugin, one object: `type: baseline` (see [Detector `baseline`](#detector-baseline)). In-process only. |
| `source` | the only `flow` source | Name of the source that supplies flow counters. Required when several `flow` sources are listed. |
| `interval` | `10s` | Detection round, `1s`–`5m`. Each round turns the flow counter deltas into rates per destination prefix and protocol. |
| `max_actions_per_hour` | `6` | Mitigation rules the detector may add in any rolling hour, 1–1000. Past it an anomaly waits (`anomaly.held`). |
| `max_active` | `4` (at most `mitigation.max_rules`) | Mitigation rules the detector holds at once, 1 to `mitigation.max_rules`. |
| `rules` | none | Ordered; the first rule that matches an anomaly is used. No rules: detection and alerts only. At most 100. |

Each rule:

| Key | Default | Meaning |
|---|---|---|
| `name` | none | Required, unique, at most 64 characters. |
| `prefixes` | none | Required. The anomaly's destination prefix must be one of these or inside one. Each must be inside `mitigation.allowlist`; no default route, no host bits. |
| `protocols` | any | Up to 8 IP protocols (`tcp`, `udp`, `icmp`, ... or numbers) the anomaly's protocol must be one of. |
| `min_mbps` | `0` | The anomaly's rate (or its peak) must be at least this. |
| `action` | none | Required. `blackhole`, `redirect`, `flowspec_drop`, `flowspec_rate_limit`, or `flowspec_redirect`, as on `POST /api/mitigations`. A FlowSpec action matches the anomaly's protocol; RTBH and redirect cover the whole prefix. Checked against the mitigation announcer's catalog at startup. |
| `target` | none | `redirect` and `flowspec_redirect`: a catalog target name. |
| `rate_mbps` | none | `flowspec_rate_limit`: above 0, at most 100000. |
| `ttl` | `mitigation.default_ttl` | The rule's lifetime, 1s to `mitigation.max_ttl`. The rule is removed earlier when the anomaly clears. |

A rule the detector added is removed when its anomaly clears. The detector never replaces a rule someone else holds for the same key, adds nothing on an HA standby, and does not add a rule again for an anomaly whose rule expired or was deleted. When the flow source fails three rounds in a row, every anomaly clears, its rule is removed, and the baselines are learned again. Rollback: remove `rules` (alerts only) or the whole block and restart; a restart holds no rule.

### `more_specific`

More-specific injection (#56, lab-proven only, not on a public edge). Design and full rules: [design/more-specific.md](design/more-specific.md). Used only in `mode: inject`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true`: an improvement on P also announces every prefix strictly inside P that a neighbor advertises exactly in the learned RIB, is inside the allowlist, and is not held by inbound steering or mitigation. Nothing is split or computed: if no neighbor advertises a more-specific inside P, only P is announced. Each route carries the improvement's provider next hop, `local_pref`, `packeteer_community`, and `no-export`. |
| `max_routes` | `100` | Cap on routes on a router: improvements, their more-specifics, and inbound steer routes. 1–1000. A new improvement is announced whole (P and all its learned more-specifics) or not at all; a more-specific learned later is added only while there is room. Nothing on the wire is withdrawn to make room. `max_improvements` still caps improvements. |

A more-specific is withdrawn with its improvement (flip-back, TTL, policy, P leaving the RIB), when the RIB is not ready, on shutdown, and when it really leaves the RIB: the neighbor advertised it for at least 5s while Packeteer's route was on the wire and then stopped. A shorter gap is the router hiding its own path because Packeteer's route won, and the route stays. A change needs a restart (SIGHUP refuses it). Rollback: remove the block or set `enabled: false` and restart; only improvements' own prefixes are announced again.

### `report_subscriptions`

Scheduled email report subscriptions (#34). Each entry emails one stored report (the same one `/api/reports/<report>` serves) as a CSV attachment. Needs `storage` (reports come from stored history) and a notifier of type `smtp`. Times are UTC. A failed send is logged, shown on `/api/subscriptions`, and tried again at the next scheduled time; sends missed while the controller was down are not replayed. Operators can send one at once with `POST /api/subscriptions/<name>/send`. Recipients come only from this file. Does not announce. See [ui.md](ui.md).

| Key | Default | Meaning |
|---|---|---|
| `name` | none | Required, unique. 1–63 of `a-z`, `0-9`, `_`, `-`. |
| `report` | none | Required. A report name from `/api/reports` (`summary`, `improvements`, `causes`, `performance`, `providers`, `prefixes`, `asns`, `countries`, `probes`, `savings`, `mitigations`, `anomalies`). |
| `schedule` | none | Required. `daily`, `weekly`, or `monthly` (the 1st of the month). |
| `at` | `06:00` | UTC time of day, `HH:MM`. |
| `weekday` | `monday` | For `weekly` only: `monday` … `sunday`. |
| `days` | 1, 7, or 30 | The report range, ending at the send time. 1–366. |
| `notifier` | none | Required. The `name` (or `type` when unnamed) of a `notifiers` entry of type `smtp`. |
| `to` | the notifier's `to` | Up to 50 addresses that replace the notifier's recipients for this report. |

At most 50 subscriptions.

```yaml
notifiers:
  - type: smtp
    name: mail
    config: {host: smtp.example.net, from: packeteer@example.net, to: [noc@example.net]}
report_subscriptions:
  - {name: weekly-summary, report: summary, schedule: weekly, weekday: monday, at: "06:00", notifier: mail}
  - {name: monthly-savings, report: savings, schedule: monthly, notifier: mail, to: [finance@example.net]}
```

### Multi-POP (federation)

Several Packeteer instances, one per POP (routing domain), share what they measure over mutual TLS (#30, lab-proven only). Design: [multi-pop.md](multi-pop.md).

```yaml
domain: pop-a
inter_dc_rtt:
  pop-b: 12ms
providers:
  - name: x-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: x-b            # carrier X in POP B
    domain: pop-b
    next_hop: 192.0.2.253  # POP B's exit across the backbone
global_commit:
  - name: carrier-x
    commit_mbps: 1000
    providers: [x-a, x-b]
federation:
  type: mtls
  config: {...}
```

| `global_commit` key | Meaning |
|---|---|
| `name` | Unique. Letters, digits, `_`, `.`, `-`. |
| `commit_mbps` | The shared commit, decimal megabits per second, above 0 and at most 100000000. |
| `providers` | At least two configured providers, at least one in this domain. A provider is in at most one global commit. |

A provider in another domain is usable for a prefix only while its peer is fresh, its RIB is ready, it reports the provider up, and its own traffic for that exact prefix leaves through that provider. Its path is the peer's measurement plus `inter_dc_rtt`. When the peer goes stale the path disappears and an improvement onto it is retired and withdrawn. The prefix must still be in this POP's learned RIB and allowlist; the improvement counts toward `max_improvements` and carries `packeteer_community` and `no-export` like any other.

With a commit scorer, each local member's commit becomes the global commit less every other member's usage (never more than its own commit). When any member's usage is missing or its peer is stale, each provider's own commit applies, as standalone. Changes need a restart (SIGHUP refuses them). Rollback: remove `federation`, `global_commit`, and remote providers, and restart.

### High availability (`ha`)

Two instances with the same providers, allowlist, and edge sessions (each with its own `router_id` and session address) share a lease file on storage both mount (#31, lab-proven only). Guide: [ha.md](ha.md).

```yaml
ha:
  type: lease
  config:
    path: /var/lib/packeteer/ha/lease.json   # on a volume both instances mount
    id: pk-a                                  # or env PACKETEER_HA_ID
```

Only the active instance runs decisions and announces. A standby probes and keeps its iBGP sessions and RIB view, but has no route on the wire: the outbound, inbound, and mitigation announcers check the elector under their locks before every sync, and a standby withdraws anything left. An instance may lead only while its RIB view is ready; an active instance whose sessions all drop steps down and hands over. On becoming standby an instance withdraws at once, drops its decision state (improvements and cooldowns), and resigns, so the other instance takes over at its next renewal. A crashed active instance cannot resign: the standby waits until the old instance's routes are gone from the routers (its lease, plus the negotiated BGP hold time it recorded) before it announces. Allowlist, learned-RIB check, community, NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged on the active instance. `ha` changes need a restart (SIGHUP refuses them). Rollback: remove `ha` and run one instance.

`/api/ha` and `packeteer_ha_active`, `packeteer_ha_eligible`, and `packeteer_ha_takeovers` show the role; `ha.active` and `ha.standby` events report changes ([EVENTS.md](EVENTS.md)).

### Backup and restore

`packeteer -backup FILE` writes a gzip'd tar with the loaded config file and, with a `storage` plugin, a consistent copy of its history (`sqlite`: `VACUUM INTO`, safe while the controller runs). It never overwrites `FILE`, opens no BGP session, and sends no probe. Secrets are environment variables, so none are in the archive. With `auth`, the history includes users with their password hashes (PBKDF2), API token hashes (SHA-256), and the audit log: keep the archive private.

`packeteer -restore FILE` validates the archived config, then restores the history into that config's storage path. `-restore-config PATH` also writes the archived config to `PATH`. Existing history or config files are replaced only with `-force`. Stop the controller that uses the storage first.

```sh
# Running container: back up into the data volume.
docker exec packeteer packeteer -backup /var/lib/packeteer/backup-$(date +%F).tgz
# New host: restore into an empty volume, then start as usual.
docker run --rm -v packeteer-data:/var/lib/packeteer -v "$PWD:/backup" \
  ghcr.io/grandarcher/packeteer -restore /backup/backup.tgz -restore-config /backup/config.yaml
```

### Plugin entries

`probers`, `sources`, `notifiers`, `telemetry`, `policies`, and `rib_sources` are lists. `scorer` and `announcer` are single objects.

| Key | Meaning |
|---|---|
| `type` | Required. Unknown types are errors. The error names the entry and the types that are registered. |
| `name` | Optional. Defaults to `type`. Must be unique within that list. |
| `config` | Optional object. The plugin decodes it and rejects unknown keys. |

## Environment

Set these in the container. They are not keys in the YAML file. `PACKETEER_HTTP_PASSWORD` is not written to the log.

| Variable | Effect |
|---|---|
| `PACKETEER_CONFIG` | Config path when `-config` is omitted. |
| `PACKETEER_PLUGIN_DIR` | When non-empty, replaces `plugin_dir`. |
| `PACKETEER_LOG_LEVEL` | When non-empty, replaces `log.level`. |
| `PACKETEER_LOG_FORMAT` | When non-empty, replaces `log.format`. |
| `PACKETEER_HTTP_LISTEN` | When non-empty, replaces `http.listen`. The value `off` disables HTTP. An empty value does not change the file. |
| `PACKETEER_HTTP_USER` | Basic auth user. Set together with the password, or set neither. |
| `PACKETEER_HTTP_PASSWORD` | Basic auth password. |
| `PACKETEER_ADMIN_USER` | With `auth`: the first admin's name (default `admin`). |
| `PACKETEER_ADMIN_PASSWORD` | With `auth`: creates that admin at start when no user has the name (12–256 characters). An existing user is not changed, so a password set through the API survives a restart. Not written to the log. |

`${VAR}` expansion applies inside a webhook `url`, webhook `headers` values, and an `exec` plugin's `env` values. It is not applied to the rest of the file.

## Inject checklist

`mode: inject` is refused unless all of these hold:

- `allowlist.prefixes` is non-empty
- at least one `bgp.neighbors` entry
- `packeteer_community` is set and valid
- `local_pref` is non-zero
- `announcer` is set (`type: gobgp`)
- `hold_time` is positive
- both threshold deltas are positive
- `more_specific_bits` is absent (`more_specific` is the replacement; it is off by default)

The `gobgp` announcer has no `config` keys. A config block with any key is an error. Each announced route carries the provider `next_hop`, `local_pref`, `packeteer_community`, and `no-export`. The export policy accepts only routes Packeteer originated that carry the community.

The shipped example stays `mode: observe`. Put an inject config only in the file you mount on a host you control.

## Plugins

Built-in types are listed in [PLUGINS.md](PLUGINS.md). Their `config` keys:

### Prober `icmp`

| Key | Default | Values |
|---|---|---|
| `socket` | `auto` | `auto` (raw, then unprivileged datagram), `raw`, `udp`. |
| `packet_interval` | `100ms` | Not negative. Spacing between echoes in one run. |

### Prober `tcp`

| Key | Default | Values |
|---|---|---|
| `port` | 443 | 1–65535. A SYN-ACK or a RST counts as a reply. A middlebox RST is not distinguishable from the target's RST. |
| `packet_interval` | `100ms` | Not negative. |

### Prober `udp`

Not in the default chain. A UDP reply counts. An ICMP destination-unreachable counts only when the host that sent it is the target; a firewall `REJECT` (icmp-port-unreachable from another address) is loss. No raw socket. The check reads the offender from the socket error queue and is Linux-only; the container image is Linux.

| Key | Default | Values |
|---|---|---|
| `port` | 33434 | 1–65535. |
| `packet_interval` | `100ms` | Not negative. |

### Prober `fixed`

Labs and tests only. Sends no packets.

| Key | Meaning |
|---|---|
| `file` | Re-read on every probe. Same schema as this block, without `file`. Larger than 1 MiB is an error. |
| `sent` | Packets sent when a path omits `sent`. Not negative. |
| `rtt_ms` | RTT used when a path omits `rtt_ms`. Not negative. |
| `paths` | One result per provider. |

Each path:

| Key | Meaning |
|---|---|
| `provider` | Required. Must match a provider `name`. Unique in the list. |
| `sent` | Not negative. |
| `rtt_ms` | Not negative. |
| `loss_pct` | 0–100. |
| `source_down` | `true` fails that probe source closed. |

At least one of `paths`, `sent` / `rtt_ms`, or `file` is required.

### Source `static`

| Key | Meaning |
|---|---|
| `targets` | List of prefixes to probe. |

Each target:

| Key | Meaning |
|---|---|
| `prefix` | Required CIDR, no host bits. Unique in the list. |
| `host` | Optional address inside `prefix`. Default is the first address of the prefix. |
| `weight` | Optional, not negative. |
| `mbps` | Optional, 0–100000000. Declared traffic in decimal megabits per second. The `commit` scorer reads it when this source is configured. Zero omits the prefix. |

### Source `traceroute`

Off unless this source is listed. UDP traceroute toward each target. Discovery runs in the background after `Start`. `Targets` returns the last cache immediately and does not trace, so a slow hop cannot use up the probe round. One pass is capped by `budget`. The discovered host is only the address that gets probed. The prefix is unchanged, and nothing is announced from this source.

| Key | Default | Bounds |
|---|---|---|
| `targets` | none | Required. Same shape as `static` (`prefix`, optional `host` inside it, optional `weight`). |
| `max_hops` | 16 | 1–64. |
| `probes` | 3 | 1–10 probes at each TTL. |
| `min_replies` | 2 | 1–`probes`. A hop is stable when one address answers at least this many times and there is no tie. When `probes` is 1 the default is 1. |
| `timeout` | `500ms` | Per probe, `1ns`–`5s`. Zero uses the default. |
| `port` | 33434 | 1–65535. Destination UDP port. |
| `source` | unset | Local address to bind. Empty uses the kernel's default route. Must match the targets' address family. |
| `interval` | `5m` | `1s`–`24h`. How often discovery runs. |
| `budget` | `10s` | At least `timeout`, at most `30s`. Wall clock for one pass across every target. Each target gets an equal share. This is under the default round deadline (about 110s). |

Three silent TTLs after a stable hop stop the trace. When the configured host answers, it stays the probe host. Otherwise the stable hop with the highest TTL is used. A pass that finishes no target leaves the previous cache in place. Until the first pass finishes, the source contributes no prefixes. The socket calls are Linux-only; the container image is Linux, and other systems still compile.

### Source `vip`

Off unless this source is listed. Critical prefixes, and prefixes whose learned AS path contains a listed ASN, are probed on `interval`. The global `probe.rate_limit_pps` still applies.

| Key | Default | Bounds |
|---|---|---|
| `interval` | none | Required, at least `1s`. Must be shorter than the staleness window (`3 * probe.interval + packets * timeout`, plus retry packets when retry is on). The controller refuses to start otherwise. Shorter than `probe.interval` is the usual setting. |
| `prefixes` | none | CIDRs, no host bits, no default route, no duplicates. Optional `host` must sit inside the prefix. Count toward `max_targets`. |
| `asns` | none | Non-zero ASNs, no duplicates. Matched against the learned AS path only while the RIB is ready. |
| `max_targets` | 100 | 1–10000. Cap on configured prefixes plus ASN matches. The list is truncated and a warning is logged. The expansion is rebuilt only when the RIB changes. |

At least one prefix or ASN is required. The prefix list cannot be longer than `max_targets`. A prefix that is also returned by an earlier source keeps that source's host. A later interval wins only when it is shorter than the interval already chosen, and an unset interval means `probe.interval`. Listing a transit ASN does not turn the whole table into targets.

### Source `outage`

Off unless this source is listed. After each completed probe round it correlates degraded samples by learned AS path and by provider. A new incident re-queues prefixes and emits `outage.as` or `outage.circuit` (severity `critical`). Recovery emits `outage.cleared` (severity `warning`). Nothing is announced. Disable it by removing the source.

A sample is degraded when the probe failed, when loss is at least `loss_pct`, or, when `rtt_ms` is set, when average RTT is at least that many milliseconds. The newest sample for each provider and prefix inside `window` wins. A timestamp of zero is outside the window.

An ASN is sick when at least `min_prefixes` degraded prefixes contain it and every provider just measured for those prefixes is degraded. A prefix that is still healthy on another provider does not count toward the ASN: that pattern is the circuit. `ignore_asns` drops ASNs that sit on every path. iBGP paths usually omit the local ASN already.

A provider is sick when at least `min_prefixes` prefixes are degraded on it and healthy on another provider, and a sick ASN does not already explain those prefixes. With only one provider in the window, prefixes that do not share a sick ASN still count, so a dead circuit with mixed destinations is reported and a shared transit ASN is not reported twice.

The re-queue is probe targets only. An AS incident includes every learned prefix whose path contains that ASN, degraded ones first, up to `max_targets`. A circuit incident includes the prefixes that counted, then other prefixes sampled on that provider, then learned prefixes whose native provider is that circuit, up to the same cap. A default route is never added. The first pass is urgent (the probe loop wakes immediately). Later passes use `interval`. One prefix never fires, and `min_prefixes` cannot be set below 2. AS correlation is empty until the RIB is ready. The global `probe.rate_limit_pps` still applies.

| Key | Default | Bounds |
|---|---|---|
| `min_prefixes` | 3 | 2–10000. Zero uses the default. One noisy prefix is not an incident. |
| `window` | `2m` | `1s`–`24h`. Zero uses the default. |
| `loss_pct` | 20 | 0–100. Zero uses the default of 20, so loss detection stays on. A failed probe still counts when loss is below this. |
| `rtt_ms` | 0 | Not negative. Zero disables the RTT check. A positive value also treats average RTT at or above this many milliseconds as degraded. |
| `interval` | `5s` | `1s`–`24h`. Zero uses the default. Must be shorter than `probe.interval` and shorter than the staleness window. The controller refuses to start otherwise. |
| `max_targets` | 100 | 1–10000. Cap on the re-queue. Truncation is logged. Degraded prefixes are kept first. |
| `ignore_asns` | none | Non-zero ASNs, no duplicates. Skipped when looking for a sick ASN. |

### Source `flow`

Off unless this source is listed. NetFlow v5, NetFlow v9, IPFIX, and sFlow v5. Raw records are not stored.

| Key | Default | Bounds |
|---|---|---|
| `listen` | none | Required. One `host:port` or a list. Host is an IP address or empty. Duplicate addresses are errors. |
| `window` | `5m` | `1s`–`24h`. |
| `top_n` | 100 | 1–10000. |
| `min_bytes` | 0 | Drop prefixes under this byte total. |
| `aggregate_v4` | 24 | 1–32. Used when the RIB has no covering non-default prefix. |
| `aggregate_v6` | 48 | 1–128. |
| `exclude` | none | CIDRs to ignore, no host bits, no duplicates. |

With `--network host`, `listen` binds host UDP ports. Do not publish them. Each time bucket keeps at most 20000 prefixes. It also counts bytes per destination prefix and IP protocol since it started (at most 20000 keys; a key idle for an hour is forgotten), which [`anomaly`](#anomaly) reads for its baselines. The protocol comes from NetFlow v5, v9/IPFIX (information element 4), and sFlow (sampled IPv4/IPv6 records and the IP header; IPv6 extension headers are not followed); records without it count as protocol `any`. The commit scorer reads every prefix in the window as a rate (bytes × 8 / window, decimal megabits per second), including prefixes `top_n` or `min_bytes` did not offer as probe targets.

`problems` (optional, off when omitted) turns on passive problem detection from TCP flags. It reads unsampled NetFlow v5, NetFlow v9, and IPFIX records that carry the source address, protocol, and TCP flags (information elements 8 or 27, 4, and 6). An outbound record (local source, remote destination) is one flow; if its flags hold SYN without ACK, the handshake never completed and it counts as a timeout. An inbound record from a remote source with RST counts as a reset. A prefix is a problem when (timeouts + resets) / flows is at least `failure_pct` and it has at least `min_flows` flows inside `window`. Problem prefixes are listed first, worst first (weight is the ratio to the threshold), then the busiest prefixes that are not already listed. Sampled exports (a sampling rate above 1) and sFlow are skipped, because a sampled record may hold only the SYN. Retransmissions and RTT are not visible in flow records; use the `span` source for those.

| Key | Default | Bounds |
|---|---|---|
| `problems.local` | none | Required when `problems` is set. Your own networks, CIDRs, no host bits, no default route, no duplicates. |
| `problems.failure_pct` | 20 | 0–100. Zero uses the default. |
| `problems.min_flows` | 10 | Zero uses the default. |
| `problems.max_targets` | 100 | 1–10000. |

`transit` (optional, off when omitted) classifies traffic as transiting or local (#29, IRP "optimization of transiting traffic"). A flow record whose source address is inside `customers` (the customer or downstream networks behind this edge, whose traffic crosses your network to the Internet) is transit; a record with any other source is local. Records without a source address (an sFlow raw header that is not IP, or a NetFlow v9/IPFIX template without IE 8 or 27) are not classified. NetFlow v5, v9, IPFIX, and sFlow (sampled IPv4/IPv6 records and raw headers) all carry the source. Per prefix, over the same `window`, the source keeps the transit and local byte counts; a prefix whose transit share is at least `share_pct` is a `transit` prefix, otherwise `local`. The class does not change the targets or their weights. Before each decision the controller passes it to the policy chain, where `rules` with `traffic: transit` or `traffic: local` give customer-originated and local traffic separate policies (see [Policy `rules`](#policy-rules)). A prefix with no classified bytes in the window has no class, and traffic rules do not match it. Classification never announces: the allowlist, learned-RIB check, community and NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged. Rollback: remove `transit` (and the `traffic` rules).

| Key | Default | Bounds |
|---|---|---|
| `transit.customers` | none | Required when `transit` is set. Source CIDRs of the customer networks whose traffic transits. No host bits, no default route, no duplicates, at most 10000. |
| `transit.share_pct` | 50 | Above 0, at most 100. The transit share of a prefix's classified bytes at or above which it is a transit prefix. Zero uses the default. |

### Source `span`

Off unless this source is listed. It reads a SPAN or mirror port with an AF_PACKET socket (needs `--cap-add NET_RAW` and host networking) or replays a classic pcap file, follows TCP connections between `local` and remote addresses, and returns remote prefixes that look broken so they are probed first. Packets are parsed and dropped. Only per-connection sequence state (capped by `max_flows`) and per-prefix counters over `window` are kept; each time bucket holds at most 20000 prefixes. The source does not announce, and a problem prefix still needs the RIB, the allowlist, the thresholds, the cap, and hold time before anything is injected.

Per connection, it counts:

- **Retransmissions**: outbound data segments that repeat bytes already sent (a one-byte keepalive is not counted).
- **Timeouts**: a local SYN with no remote SYN-ACK, or a local SYN-ACK with no remote ACK, within `syn_timeout`.
- **Resets**: a RST from the remote side. A local RST is not a path problem and is ignored.
- **Handshake RTT**: local SYN to remote SYN-ACK, or local SYN-ACK to remote ACK, measured at the mirror. A retransmitted handshake gives no sample.

A remote prefix is a problem when retransmissions / data segments ≥ `retrans_pct` (with at least `min_segments`), (timeouts + resets) / connections ≥ `failure_pct` (with at least `min_flows`), or, when `rtt_ms` is set, average handshake RTT ≥ `rtt_ms` (with at least `min_flows` samples). The score is the largest ratio of an observed value to its threshold. The list is worst first, capped at `max_targets`, and a prefix is marked urgent on the first round it appears. The source is read on every probe round. Remote addresses are mapped to the covering learned RIB prefix when the view is ready, otherwise aggregated to `aggregate_v4` or `aggregate_v6`. Private, ULA, loopback, link-local, multicast, and `exclude` addresses are dropped, as is traffic between two local or two remote addresses. Ethernet with up to two VLAN tags, raw IP, and Linux cooked captures are decoded.

| Key | Default | Bounds |
|---|---|---|
| `interface` | none | The mirror interface inside the container (host networking). Exactly one of `interface` or `pcap_file`. |
| `pcap_file` | none | Absolute path to a classic pcap (not pcapng) mounted into the container. Replayed once at startup with its timestamps shifted to now. For labs and incident review. |
| `promiscuous` | true | Interface capture only. Promiscuous mode is a socket membership: the kernel drops it when the socket closes or the process dies. |
| `local` | none | Required. Your own networks, CIDRs, no host bits, no default route, no duplicates. |
| `exclude` | none | Remote CIDRs to ignore, no host bits, no duplicates. |
| `window` | `5m` | `10s`–`24h`. |
| `retrans_pct` | 5 | 0–100. Zero uses the default. |
| `failure_pct` | 20 | 0–100. Zero uses the default. |
| `rtt_ms` | 0 | 0–60000. Zero disables the RTT check. |
| `min_segments` | 100 | Zero uses the default. |
| `min_flows` | 10 | Zero uses the default. Also the minimum RTT samples. |
| `syn_timeout` | `3s` | `100ms`–`1m`. |
| `flow_idle` | `2m` | Longer than `syn_timeout`, at most `1h`. Idle connections are forgotten. |
| `max_flows` | 100000 | 1–10000000. A new connection beyond the cap is not tracked. |
| `max_targets` | 100 | 1–10000. |
| `aggregate_v4` | 24 | 1–32. |
| `aggregate_v6` | 48 | 1–128. |

Interface capture fails startup when the interface is missing or `NET_RAW` is not granted. A capture error after startup is logged and the source returns what it has already counted. On loopback, outgoing copies are skipped so each frame is counted once. Rollback: remove the source and restart.

### Scorer `weighted`

`score = loss_pct * loss_weight + rtt_ms * rtt_weight + jitter_ms * jitter_weight`.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |

| `improvement_weights` | none | Optional block; see [Improvement weights](#improvement-weights). Also on `commit` and `cost`. |

At least one weight must be positive. Omit the block to keep the defaults.

#### Improvement weights

`improvement_weights` (on `weighted`, `commit`, and `cost`, #34) decides which new improvements take the last `max_improvements` slots:

`weight = performance * gain + volume * volume_mbps`

`gain` is the native path's score minus the chosen path's; `volume_mbps` is the prefix's traffic from a source that reports volume (the `flow` window, or `mbps` on a `static` target; `0` when none does). Without the block, moves rank by gain alone, as before.

| Key | Default | Bounds |
|---|---|---|
| `performance` | 1 | 0 to 1000000. |
| `volume` | 0 | 0 to 1000000. With a positive value the controller reads target volumes on every decision. |

At least one must be positive. Weights order moves inside their lane: static policy pins first, then VIP moves, then other performance moves; commit and cost moves keep their relief and savings order. They never admit a prefix that is not in the learned RIB or not allowlisted, never exceed `max_improvements`, and never displace an active improvement (hold time and hysteresis stay as they are). The weight of each move is on `/api/decisions`. Lab-proven only (`lab/e2e-weights.sh`).

### Scorer `commit`

Optional. Same performance score as `weighted`, plus commit control and provider-group balancing. Select it with `scorer.type: commit`. The default scorer stays `weighted`, which does not move traffic for commit. Switching back to `weighted` withdraws improvements whose cause is `commit`.

The billable figure comes from telemetry. `greater` and `greater_separate` use `usage_mbps`. `separate` uses the outbound 95th, because this steers traffic the edge sends. A row older than `max_age`, or a row with no samples, is ignored. A zero timestamp is not aged out. Prefix volume comes from a source that implements volume reporting (the `flow` source: bytes over its window, as decimal megabits per second). A prefix with no volume is not moved for commit. The prefix must still be in the learned RIB. A commit move does not replace a performance move.

A move onto a path with higher loss is refused unless `loss_override` is true. Decide enforces that itself: a planner that does not implement the loss override is treated as refusing the move, and a move onto the native provider is not a steer. An active commit steer is withdrawn when the steered path's loss exceeds the native path by `thresholds.min_loss_delta_pct` and the score is worse. A smaller gap is probe noise and stays. That withdraw starts a `hold_time` cooldown, so the next clean sample cannot announce the same steer again. Latency alone does not withdraw a commit steer.

`cc_disable` providers are neither sources nor destinations of these moves. `balance: off` only relieves a provider whose billable figure is over its commit. `equal` shares a group's traffic evenly. `proportional` shares it in proportion to each member's commit. Balance stays inside the group and does not push a provider over its commit. When relieving over-commit, `precedence` (lower is preferred) orders destinations ahead of spare capacity. Sharing a group does not outrank a better precedence. The highest `precedence` receives traffic only when every lower precedence lacks room for that prefix.

A prefix already on a performance steer, and a performance move waiting on the cap this round, are passed to the planner as locked: that volume is taken off the native provider so commit control does not move the same traffic as well. Both causes count toward `max_improvements`. When the cap binds, the largest performance gain wins, then the largest commit relief. Equal relief breaks by prefix. A new performance move displaces the commit steer with the smallest volume if every slot is taken. That prefix takes a `hold_time` cooldown. Volumes and telemetry are read on the decision loop only when the scorer implements planning, so `weighted` does not walk the flow table.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. Same meaning as `weighted`. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |
| `loss_override` | false | `true` allows a commit move onto higher loss. |
| `balance` | `off` | `off`, `equal`, or `proportional`. |
| `balance_slack` | `0.10` | 0–1. Fractional imbalance that does not move traffic. `0` is explicit. |
| `max_age` | `15m` | Not negative. `0` uses the default. Telemetry older than this is ignored. |
| `min_mbps` | 0 | Not negative. Prefixes below this volume are not moved for commit. |
| `improvement_weights` | none | See [Improvement weights](#improvement-weights). |

At least one weight must be positive.

### Scorer `cost`

Optional. Same performance score as `weighted`, plus cost optimization. Select it with `scorer.type: cost`. It needs `cost` on at least two providers that are not `exclude`d. The default scorer stays `weighted`. Switching back to `weighted` and restarting withdraws improvements whose cause is `cost` (the rollback).

A cost move sends a prefix to the cheapest provider whose path is inside the performance floor. The floor is measured from the best path, not from native: a path is inside when its loss is at most `floor.max_loss_pct` above the lowest loss and its RTT is at most `floor.max_rtt` above the lowest RTT among usable providers that are not excluded. The destination must have a `cost` lower than the native provider's. A provider without a `cost`, an excluded provider, and a provider that is down are never destinations. A prefix whose native provider has no `cost` is not moved. The prefix must be in the learned RIB, allowlisted in inject mode, and out of cooldown, and the move counts toward `max_improvements`. Decide checks the floor and the price itself, so a planner cannot push a cost move outside them.

An active cost steer is kept while it stays inside the floor. When its path leaves the floor it is withdrawn at once, even inside `hold_time`, and the prefix takes a `hold_time` cooldown. When a cheaper path inside the floor appears, the steer moves after `hold_time`. When no cheaper path is left, it is released after `hold_time`. Equal prices keep the current provider.

`precedence` decides between performance and cost:

- `performance` (default): a performance move (the thresholds in `thresholds`) wins. Cost only moves prefixes whose native path is already best within those thresholds. After `hold_time`, a cost steer switches to a performance move when one clears the thresholds against native. When the cap binds, performance moves are admitted first and a new performance move displaces the cost steer with the smallest volume.
- `cost`: a native path inside the floor is kept even when a faster path clears the thresholds. When native is outside the floor, the cheapest path inside the floor that is cheaper than native is used (cause `cost`). If there is none, the normal performance move is made. An active cost steer is not switched for performance while it is inside the floor.

When the cap binds between cost moves, the largest estimated saving wins: the price difference times the prefix volume (flow or static `mbps`), or the price difference alone when the volume is unknown. Equal savings break by prefix.

Every improvement whose native and steered providers both have a `cost` reports `cost_delta` (native price minus steered price, per Mbps) and `est_savings` (`cost_delta` times the prefix volume when one is known) on `/api/improvements`, and `packeteer_estimated_savings` sums `est_savings`. A negative value is extra spend, for example a performance move onto a dearer provider. These are estimates for reports; they do not change a decision. This scorer does not do commit control: a cheap provider can still fill up. Use the `commit` scorer when commits bind.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. Same meaning as `weighted`. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |
| `precedence` | `performance` | `performance` or `cost`. |
| `floor` | | Block with `max_loss_pct` and `max_rtt`. |
| `max_loss_pct` | 0 | 0–100. Loss percentage points a cost path may carry above the lowest loss. |
| `max_rtt` | `10ms` | 0–10s. Latency a cost path may add over the lowest RTT. |
| `improvement_weights` | none | See [Improvement weights](#improvement-weights). |

At least one weight must be positive.

### Policies

`policies` is a chain of policy plugins. Before each decision the controller asks each policy, in list order, about every probed prefix. The first one that matches decides that prefix; later ones are not asked. Maintenance windows from every `maintenance` entry apply together. A policy only restricts or pins what the decision engine may choose. The prefix must still be in the learned RIB, allowlisted in inject mode, and under `max_improvements`, and every injected route still carries `packeteer_community` and NO_EXPORT. Removing the `policies` block and restarting is the rollback: pins are withdrawn and the normal thresholds apply again.

| Action | Effect |
|---|---|
| `ignore` | Native routing only. An active improvement is retired at once. No new improvement, and commit or cost planners do not see the prefix. |
| `allow` | Only the listed providers may carry an improvement. |
| `deny` | The listed providers never carry an improvement. |
| `static` | Pin to the one listed provider while its path is usable (fresh probe, provider up, not excluded or in maintenance) and healthy: loss at or under the rule's required `max_loss_pct`, RTT at or under `max_rtt` when set, and loss not worse than a measured native path by `thresholds.min_loss_delta_pct` or more. The check runs before the pin is announced and on every round while it is held. A pin that fails it, or whose path becomes unusable, is withdrawn at once and waits out `hold_time` before it can return. Moving an existing improvement onto the pinned provider waits until that improvement has lived `hold_time`. When the pinned provider is native, nothing is announced. A pin expires on `improvement_ttl` like any other improvement, so an upstream withdraw hidden while the pin is best is caught; it is retired without a cooldown and returns on the next round if the prefix is still in the RIB and the pin still passes the check. Cause `static`. |
| `vip` | Normal thresholds, but its performance moves are admitted ahead of other performance moves when `max_improvements` binds. Pair it with the `vip` source for faster probing. |

`allow` and `deny` never block the native provider: they decide where Packeteer may steer, not whether native routing is used. An active improvement on a provider that a policy now forbids is retired at once, even inside `hold_time`. When the cap binds, `static` pins are admitted first, then `vip` moves, then other performance moves, then commit and cost moves.

#### Policy `rules`

| Key | Default | Meaning |
|---|---|---|
| `geoip_db` | none | Path of a MaxMind-format country database (for example GeoLite2-Country) mounted into the container. Required when a rule lists `countries`. Read once at startup; restart to load a new file. Packeteer does not ship one. |
| `rules` | none | Required, 1–10000 entries. |

Each rule:

| Key | Meaning |
|---|---|
| `name` | Optional, unique. Shown in decisions and logs. Defaults to `rules[i]`. |
| `action` | Required. `ignore`, `allow`, `deny`, `static`, or `vip`. |
| `providers` | Configured provider names. `allow` and `deny` need at least one, `static` exactly one, `ignore` and `vip` none. |
| `prefixes` | CIDRs. A rule prefix matches itself and every more-specific probed prefix. |
| `asns` | Origin ASNs (the last ASN of the learned AS path). Matches only while the RIB view is ready. |
| `countries` | ISO 3166-1 alpha-2 codes. Looked up for the first address of the probed prefix, `country` first, then `registered_country`. |
| `max_loss_pct` | Required for `static`, 0–100: the highest loss the pinned path may show. Not allowed on other actions. |
| `max_rtt` | Optional for `static`: the highest average RTT the pinned path may show (for example `150ms`). 0 or unset means no latency ceiling. |
| `traffic` | Optional: `transit` or `local`. The rule then matches only prefixes of that traffic class, from a `flow` source with a `transit` block. Alone (no `prefixes`, `asns`, or `countries`) it matches every prefix of the class. A prefix no source classifies matches no traffic rule. |

A rule needs at least one of `prefixes`, `asns`, `countries`, or `traffic`, and matches when any of its prefixes, ASNs, or countries match and, when `traffic` is set, the prefix's class is that class. When several rules match one prefix, a prefix match beats an ASN match, which beats a country match, which beats a traffic-only rule. Among prefix matches the longest rule prefix wins. Remaining ties go to the rule listed first.

Transit traffic optimization (#29): with the `flow` source's `transit` block, customer-originated (transit) and local prefixes get separate policies. For example, keep customer traffic on the transits you resell (`{traffic: transit, action: allow, providers: [transit-a]}`), leave it on native routing (`{traffic: transit, action: ignore}`), or rank your own traffic first at the cap (`{traffic: local, action: vip}`). Decisions name the match (`traffic transit`, or `prefix 198.51.100.0/24, traffic transit`).

#### Policy `maintenance`

While a window is open, its providers are excluded: improvements on them are retired at once, and no move of any cause (performance, static, commit, cost) may land on them. A prefix that was steered onto the provider returns to native, and on the next evaluation it may be improved onto another provider under the normal rules. Native traffic through the provider is not moved.

| Key | Default | Meaning |
|---|---|---|
| `timezone` | `UTC` | IANA zone for `schedule`. Zone data is built into the binary. |
| `windows` | none | Configured windows (up to 1000). May be empty when only the API is used. |
| `max_api_duration` | `24h` | Longest on-demand window, 1m–7 days. |

Each window:

| Key | Meaning |
|---|---|
| `name` | Optional, unique. The window ID is `schedule-<name>`. |
| `providers` | Required. Configured provider names. |
| `schedule` | Five-field cron start time: minute, hour, day of month, month, day of week (0–7, 0 and 7 are Sunday). `*`, numbers, ranges `a-b`, steps `*/n` or `a-b/n`, and comma lists. When both day fields are restricted, either one matches; as in Vixie cron, a day field that starts with `*` (such as `*/2`) counts as unrestricted, so the fields are then AND-ed. Use with `duration`. |
| `duration` | 1m–7 days. How long each scheduled window stays open. |
| `start`, `end` | RFC 3339 timestamps for a one-off window. Use instead of `schedule` and `duration`. |
| `reason` | Optional text shown in the API. |

On-demand windows go through the ops API and live in memory only; a restart ends them, and the controller logs this at startup. Put a planned window in `windows` if it must survive a restart. The controller checks windows every 15 seconds and wakes the decision loop when a scheduled window opens or closes, so it does not wait for the next probe round. They require HTTP basic auth (`PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`); without it the API refuses to open or close windows.

```sh
curl -u "$USER:$PASS" -H 'Content-Type: application/json' \
  -d '{"providers":["transit-b"],"duration":"2h","reason":"provider ticket"}' \
  http://127.0.0.1:8080/api/maintenance
curl -u "$USER:$PASS" http://127.0.0.1:8080/api/maintenance
curl -u "$USER:$PASS" -X DELETE http://127.0.0.1:8080/api/maintenance/api-1
```

`GET /api/maintenance` lists open windows from every maintenance policy. `POST` opens a window on the first `maintenance` entry (JSON only; at most 100 open at a time). `DELETE /api/maintenance/<id>` closes an on-demand window; configured windows cannot be closed from the API.

### Notifier filters (every notifier)

Every notifier, including `exec`, accepts these keys next to its own. The controller applies them before `Notify`, and each notifier has its own queue, so a slow relay does not delay the others or the probe and decision loops. See [EVENTS.md](EVENTS.md) for the event kinds.

| Key | Default | Meaning |
|---|---|---|
| `events` | all | Kinds to deliver: an exact kind (`provider.down`), a group wildcard (`improvement.*`), or `*`. A pattern that matches no kind in the catalog is a startup error. |
| `min_severity` | `info` | `info`, `warning`, or `critical`. A resolving event (`provider.up`, `bgp.session_up`, `commit.cleared`, `outage.cleared`, ...) passes when the problem it clears would, so a `critical` pager still hears the recovery. |
| `rate_limit` | `0` | Deliveries per `rate_window` for this notifier. `0` is unlimited. At most 100000. Dropped events are counted, and the next delivered event carries `fields.suppressed`. |
| `rate_window` | `1m` | 1s to 24h. |

### Notifier `webhook`

| Key | Default | Meaning |
|---|---|---|
| `url` | none | Required absolute `http` or `https` URL, except for `preset: pagerduty`. `${VAR}` expands from the environment, so a Slack or Teams URL that is itself a secret stays out of the file. |
| `timeout` | `5s` | Not negative. |
| `headers` | none | Extra request headers. Values expand `${VAR}`. |
| `preset` | `generic` | `generic` (the event as JSON), `slack` (`{"text": ...}` for an incoming webhook), `teams` (a MessageCard for an incoming webhook), or `pagerduty` (Events API v2). |
| `routing_key_env` | none | `pagerduty` only, and required there: the name of the environment variable holding the integration key. `url` defaults to `https://events.pagerduty.com/v2/enqueue`. Problems `trigger`; resolving kinds `resolve` the same `dedup_key`. |
| `template` | none | A Go `text/template` for the body instead of a preset, for SMS and other gateways. The data is the event (`.Kind`, `.Severity`, `.Message`, `.Time`, `.Fields`); functions `json` (quote a string) and `upper`. At most 16 KiB. Only with `preset: generic`. |
| `content_type` | `application/json` | Only with `template`, e.g. `application/x-www-form-urlencoded`. |

Plus the [filter keys](#notifier-filters-every-notifier).

### Notifier `smtp`

One plain-text email per event. The relay credentials are environment variables; the file names them.

| Key | Default | Meaning |
|---|---|---|
| `host` | none | Required. Relay hostname or IP address. It is also the TLS server name. |
| `port` | `587`, `465`, or `25` | By `tls` mode. |
| `tls` | `starttls` | `starttls` (required: a relay that does not offer STARTTLS is an error, never a plaintext fallback), `tls` (implicit TLS), or `none` (a trusted local relay; credentials are rejected). |
| `ca_file` | system roots | Absolute path to a PEM bundle for a private relay CA, mounted into the container. |
| `username_env` | none | Environment variable holding the AUTH PLAIN user. Set with `password_env`, or neither. |
| `password_env` | none | Environment variable holding the password. |
| `from` | none | Required sender address. |
| `to` | none | Required, 1–50 recipient addresses. |
| `subject_prefix` | `[packeteer]` | Put before `[SEVERITY] kind: message`. An empty string removes it. |
| `helo` | `localhost` | EHLO name. |
| `timeout` | `10s` | Per message, at most 2m. |

Plus the [filter keys](#notifier-filters-every-notifier). Messages carry `X-Packeteer-Event` and `X-Packeteer-Severity` headers for mail rules. CR and LF are stripped from header values.

An `smtp` notifier also sends [`report_subscriptions`](#report_subscriptions): one multipart email per report with a text summary and the CSV attached, headers `X-Packeteer-Report` and `X-Packeteer-Subscription`. The filter keys do not apply to reports; a subscription's `to` replaces the notifier's `to`.

### Notifier `snmptrap`

One SNMPv2c or SNMPv3 trap per event to one receiver. Add another entry for a second receiver.

| Key | Default | Meaning |
|---|---|---|
| `address` | none | Required receiver hostname or IP address. |
| `port` | `162` | UDP. |
| `version` | `2c` | `2c` or `3`. |
| `community_env` | none | Required for `2c`: the environment variable holding the community. |
| `username_env` | none | Required for `3`: the environment variable holding the USM user. |
| `security_level` | `authPriv` | `3` only: `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| `auth_protocol` | `SHA` | `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, or `MD5`. |
| `auth_env` | none | Environment variable holding the auth passphrase (at least 8 characters). |
| `priv_protocol` | `AES` | `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`, or `DES`. |
| `priv_env` | none | Environment variable holding the privacy passphrase (at least 8 characters). |
| `engine_id` | none | Required for `3`: Packeteer's authoritative engine ID, 5–32 bytes of hex. Configure the same ID for the user on the receiver. |
| `enterprise_oid` | `1.3.6.1.4.1.8072.9999.9999.7717` | Base OID. The default sits under NET-SNMP's experimental `netSnmpPlaypen` arc; use your own enterprise arc in production. |
| `timeout` | `5s` | At most 1m. |

Plus the [filter keys](#notifier-filters-every-notifier). The trap OID is `<enterprise_oid>.0.<trap_id>` (trap IDs are in [EVENTS.md](EVENTS.md)). Varbinds are `sysUpTime.0`, `snmpTrapOID.0`, then strings under `<enterprise_oid>.1`: `.1.0` kind, `.2.0` severity, `.3.0` message, `.4.0` time (RFC 3339), `.5.0` fields (`k=v; k=v`, sorted), `.6.0` dedup key.

### Notifier, prober, or source `exec`

| Key | Default | Meaning |
|---|---|---|
| `command` | none | Required. Absolute path, or a path inside `plugin_dir`. `../` is rejected. The file must be executable at startup. |
| `args` | none | Arguments. |
| `timeout` | `30s` | Per call. Not negative. |
| `env` | none | Passed to the process, plus `PATH` and `PACKETEER_PLUGIN_KIND`. Values expand `${VAR}`. Names cannot contain `=` or NUL. |
| `config` | none | Forwarded verbatim in every JSON request. |

As a notifier, `exec` also takes the [filter keys](#notifier-filters-every-notifier). A prober or source rejects them.

### Telemetry `fixed`

Labs and tests only. Reports the usage in the config or the file. It does not poll, and it does not announce. A real edge uses `snmp`.

| Key | Meaning |
|---|---|
| `file` | Re-read on every snapshot. Same `providers` list as below, without `file`. Larger than 1 MiB is an error. |
| `providers` | Rows used when `file` is empty. At least one of `file` or `providers` is required. |

Each provider:

| Key | Meaning |
|---|---|
| `name` | Required. Must match a top-level provider `name`. Unique in the list. |
| `commit_mbps` | Required. Greater than 0, at most 100000000. |
| `usage_mbps` | Required. 0–100000000. Reported as the single billable figure (`greater_separate`). |
| `in_mbps` | Optional. 0–100000000. Reported as the inbound rate and inbound 95th, which `inbound` compares with `commit_mbps`. Unset is 0. |

The row's timestamp is the time of the read, so `max_age` on the commit scorer does not age it out. A file that fails to parse yields no rows for that decision.

### Telemetry `snmp`

Off unless a `telemetry` entry lists `type: snmp`. It polls IF-MIB counters and keeps 95th-percentile usage for the open billing period. It does not announce. The `commit` scorer reads the snapshot when that scorer is selected; the collector itself does not change a decision. A failed poll does not withdraw performance improvements. Samples live in memory. A restart clears the window.

The billing period is `[start, end)` in UTC, opening at 00:00 UTC on `billing_day`. `billing_day` is 1–28 so the day exists in every month.

The 95th percentile is nearest rank: sort the samples ascending and take 1-based rank ceil(0.95 × N), computed as `(95×N+99)/100`. For a multiple of 20 that is the sample left after the top 5% are discarded. For N of 10 the rank is 10.

| `percentile` | Billable figure |
|---|---|
| `separate` | Inbound 95th and outbound 95th, kept apart. No single `usage_mbps`. |
| `greater` | 95th percentile of max(in, out) at each sample. |
| `greater_separate` | The greater of the inbound 95th and the outbound 95th. |

Rates are decimal megabits per second (bits / 1e6). The first successful poll only records a counter baseline. A later poll turns the delta into a rate. A gap longer than two intervals, a backwards `sysUpTime`, or a delta above twice the reported interface speed (or above 100 Tbit/s when speed is unknown) resets the baseline and does not store a sample. 64-bit `ifHCInOctets` / `ifHCOutOctets` are preferred. 32-bit `ifInOctets` / `ifOutOctets` are used when the 64-bit counters are absent.

`interface` is an exact `ifName`, or `ifDescr` when `ifName` has no match, or a decimal `ifIndex` (`5`, not `05`).

Credentials are environment variables named in the config. The file must not contain the community or the passphrase. `-check` fails while a named variable is empty. A change to the variable is read on the next start.

| Key | Default | Bounds |
|---|---|---|
| `interval` | `5m` | `30s`–`1h`. Time between polls. |
| `timeout` | `5s` | At least `100ms`, shorter than `interval`. Per SNMP request. |
| `retries` | 1 | 0–5. Extra attempts after the first. `0` does not retry. |
| `max_samples` | 100000 | 1–1000000. Oldest samples in the open period are dropped past this. `0` uses the default. |
| `hosts` | none | Required. One SNMP agent. Several providers can share a host. |
| `providers` | none | Required. Each entry names a configured provider. |

Each host:

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique in `hosts`. |
| `address` | required | IP address or hostname. It is not resolved at startup. |
| `port` | 161 | 1–65535. |
| `version` | required | `2c` or `3`. |
| `community_env` | v2c: required | Environment variable that holds the community. v2c only. |
| `username_env` | v3: required | Environment variable that holds the v3 user name. |
| `security_level` | v3: required | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| `auth_protocol` | with auth | `MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, or `SHA512`. |
| `auth_env` | with auth | Environment variable that holds the auth passphrase (at least 8 characters). |
| `priv_protocol` | with privacy | `DES`, `AES`, `AES192`, `AES256`, `AES192C`, or `AES256C`. |
| `priv_env` | with privacy | Environment variable that holds the privacy passphrase (at least 8 characters). |
| `context_name` | empty | SNMP context. v3 only. Not a credential. |

v2c accepts `community_env` only. v3 rejects `community_env`. `noAuthNoPriv` rejects auth and privacy keys.

Each provider:

| Key | Meaning |
|---|---|
| `name` | Required. Must match a top-level provider `name`. Unique in this plugin. |
| `host` | Required. A `hosts[].name`. |
| `interface` | Required. `ifName`, `ifDescr`, or a decimal `ifIndex`. |
| `commit_mbps` | Required. Greater than 0, at most 100000000. The `commit` scorer compares the billable 95th with this. The collector does not enforce it. |
| `billing_day` | Required. 1–28. UTC. |
| `percentile` | Required. `separate`, `greater`, or `greater_separate`. |

### Storage `sqlite`

Off unless `storage.type` is `sqlite`. Keeps report history in an embedded SQLite file (pure Go, no cgo, works in the stock image). It records history only: it does not announce and does not change a decision. A write error is logged and retried on the next flush; it never delays or withdraws an improvement. The rollback is to delete the `storage` block and restart.

| Key | Default | Meaning |
|---|---|---|
| `path` | `/var/lib/packeteer/packeteer.db` | Database file. Must be absolute. The directory is created on start. Mount a volume on it (`-v packeteer-data:/var/lib/packeteer`) so history survives a container restart. |
| `retention` | `9600h` (400 days) | Rows older than this are deleted on start and once a day. `24h`–`87600h`. An improvement that is still active is kept. |

What is stored:

- Daily probe rollups per prefix and provider (UTC day): probes, failed probes, and sums of loss, RTT, and jitter. Raw probe results are not stored.
- One row per improvement, from start to end. A switch to another provider ends the row and starts a new one. Each row has the cause, reason, mode, the native provider's loss and RTT and the chosen provider's loss and RTT at the decision that started it, `cost_delta`, `est_savings`, the prefix volume when known, the origin ASN (last AS in the learned path), and the country. In observe and suggest these are recommendations; in inject they were announced.
- Per prefix: origin ASN, country, and latest volume.

The recorder buffers in memory and writes once a minute and on shutdown, after the routes are withdrawn. Rows a previous process left open are closed on start with `controller restarted (routes withdrawn)`.

It also keeps each user's custom dashboards (#34, `/api/dashboards`) with the users and tokens; retention does not prune them, and deleting a user deletes that user's dashboards.

Country comes from the first `rules` policy that has a `geoip_db`. With none, the `countries` report is empty. Volume is the flow window or a static target's `mbps`.

Reports (`/api/reports/<name>`, JSON or `?format=csv`, and the dashboard): `summary`, `improvements`, `causes` (started per UTC day by cause), `performance` (average loss and RTT before and after, by cause), `providers` (probes, failure rate, average loss, RTT, jitter, improvements onto and off each provider, hours steered onto it), `prefixes`, `asns`, `countries` (`sort=problems`, the default, then `volume` or `loss`), `probes` (per UTC day), and `savings`. `est_savings` is `cost_delta` times volume, treated as a monthly rate; `accrued` is that rate times the hours active inside the range divided by 730. Probe figures are daily rollups, so a range that starts mid-day includes that whole UTC day; improvement figures use the exact range. Query: `days` (default 7, at most 3660), or `from` and `to` (RFC 3339 or `YYYY-MM-DD`, UTC), and `limit` (1–10000; default 20, or 100 for `improvements` and `savings`).

### Whois `rdap`

Used under `troubleshoot.whois`. Asks an RDAP server (RFC 9082/9083) about an address, prefix, or ASN. No credentials. The request leaves from the container's default route, not a provider source.

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `https://rdap.org` | RDAP service. `http` or `https`, no credentials, query, or fragment. rdap.org redirects to the right registry; at most 3 redirects, and an `https` base never follows a redirect to `http`. |
| `timeout` | `5s` | Whole request, up to `1m`. |
| `max_bytes` | `262144` | Largest response accepted, 1024–4194304. |

### RIB source `bmp`

A BMP monitoring station (RFC 7854; Loc-RIB per RFC 9069). Edge routers connect to it and stream the routes they accepted from each BGP peer (post-policy Adj-RIB-In), so Packeteer sees every provider's path for a prefix, including paths the router did not select (an inactive IX or backup transit path), without a full iBGP feed. It never sends BGP and never announces. Lab-proven only (`lab/e2e-bmp.sh`).

```yaml
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21   # the router's eBGP peer address for this provider
    bmp: only
rib_sources:
  - type: bmp
    config:
      listen: ":11019"
      routers: [192.0.2.254]
```

| Key | Default | Meaning |
|---|---|---|
| `listen` | `:11019` | `host:port` of the station. The host must be an IP address. With `--network host` this is a host port; firewall it to the routers. |
| `routers` | required | Router addresses allowed to connect. A session from any other address is closed at once. A router that reconnects replaces its old session; the old session's paths are dropped first. |
| `policy` | `post` | Which Adj-RIB-In to read. Only `post` (after the router's import policy) is accepted; `pre` is a config error. Pre-policy routes include everything a peer sent before the router's import filter (bogons, RPKI-invalid routes, a hijacked more-specific), and a route the router rejected must never make a prefix learned or pass a route check. Pre-policy and Adj-RIB-Out route messages are ignored; the RIB view also drops any Adj-RIB-In paths not marked post-policy. |
| `loc_rib` | `true` | Read Loc-RIB messages (the router's selected route) when the router sends them. |
| `idle_timeout` | `0` (off) | Drop a router's session, and every path from it, when no BMP message arrives for this long. `0` or at least `10s`. BMP has no keepalive of its own, so set it above the router's statistics interval (FRR: `bmp stats interval <ms>`) or a quiet router is dropped. With it off, TCP keepalive (15s idle, then 3 probes 5s apart) notices a dead router in about 30s. |

A BMP path is attributed to a provider by its next hop (`providers[].next_hop`), like an iBGP path. The provider's `bmp` key decides how it is used:

- `off` (default): BMP paths through this provider are ignored. Only iBGP counts, as before.
- `prefer`: BMP paths through this provider count. The route check applies while a BMP session reports this provider's BGP peer (the address equal to its `next_hop`) up; without that it falls back to no check.

With several monitored edges, a BMP path counts for a provider's route check only on a router that reports that provider's BGP peer up: the router its session is on. A copy of the path on another router (relayed there over iBGP, for example) does not pass the check. With `prefer`, the iBGP path through the provider counts too.
- `only`: only BMP paths count; iBGP paths through this provider are ignored. The route check always applies, so when BMP is down the provider has no routes and gets no improvements.

**Route check.** Before a prefix is steered to a provider with `prefer` (while its peer is up) or `only`, that provider must be advertising that exact prefix. A provider without it is not usable for the prefix: no new improvement goes there, and an active improvement onto it is retired at once (reason `no route via provider (route check)`), ignoring hold time. The native provider is never refused. This check is how Packeteer notices a withdraw on the steered provider while the router hides the native path.

**Which paths count.** Only routes the router accepted: post-policy Adj-RIB-In and Loc-RIB. A route a peer sent but the router's import policy rejected never makes a prefix learned, never appears in `Routes()` (probe targets, the native provider), and never passes the route check or the announcer's RIB gate.

**The published route.** A prefix is in the learned RIB when an iBGP path or a usable BMP path has it. This is deliberate: a prefix the router accepted from a `prefer` or `only` provider, but did not send over iBGP (for example its path is inactive, or the iBGP feed is partial), is part of the learned view. It can become a probe target (for example through the `vip` source's ASN expansion) and be announced, still exact, allowlisted, tagged, and capped. Providers with `bmp: off` add nothing. The native provider comes from the iBGP path first (the router's best as it sent it), then a Loc-RIB path, then the Adj-RIB-In path with the shortest AS path (lower router and peer address on a tie). That last one is an estimate, not the router's decision process; send Loc-RIB or keep the iBGP feed where the estimate would be wrong. An Adj-RIB-In path whose next hop matches no provider is ignored. While at least one provider uses `prefer` or `only`, a Loc-RIB path whose next hop matches no provider is kept, so the native is "none" and nothing is improved. With every provider `off`, BMP paths (Loc-RIB included) change nothing.

**Packeteer's own routes.** A router reports Packeteer's injected route back over BMP: in the Adj-RIB-In of Packeteer's iBGP session and, once it wins, in Loc-RIB. Its next hop is the steered provider. Packeteer ignores every path on a peer whose BGP ID is its `router_id`, and every path tagged with `packeteer_community`, so an injected route never keeps its prefix in the view or passes its own route check. Keep `packeteer_community` on the route through the router's import policy (the lab edge does) so Loc-RIB still carries it. The own-session filter covers only the router Packeteer peers with. If Packeteer's route is reflected to another monitored router (a route reflector, whose Adj-RIB-In shows the reflector's BGP ID, not `router_id`), only the community identifies it. An import policy or reflector that strips the community would let the injected route keep its prefix learned. The controller logs a warning at startup whenever a provider uses `prefer` or `only`, as a reminder.

**Failure.** The view is ready only while an iBGP session is up (the announcer needs it); BMP never makes it ready. When a router's BMP session ends (TCP close, termination, read error, TCP keepalive timeout, `idle_timeout`, shutdown), every path from that router is dropped. A router that dies without closing TCP keeps its paths until TCP keepalive gives up (about 30s) or `idle_timeout` fires, whichever is first; during that time an `only` or `prefer` route check can still pass on those paths. A peer down drops that peer's paths. A peer whose messages cannot be decoded is treated as down until its next peer up. A peer that negotiated add-path with the router (the router's OPEN offers receive and the peer's offers send, for example an IX route server) is decoded with path identifiers: each of its paths is kept, and a withdraw removes only the path with the same identifier. Improvements that lose their provider's path then retire through the route check; a prefix that leaves the view is retired as before.

FRR sends BMP with `-M bmp` on bgpd and a `bmp targets` block (`bmp connect <station> port 11019`, `bmp monitor ipv4 unicast post-policy`, optionally `bmp monitor ipv4 unicast loc-rib`, and `bmp stats interval` if you set `idle_timeout`); see `lab/frr-bmp/frr.conf`. FRR sends peer up and peer down with the policy flag clear; the station applies them to the peer whichever table is monitored. FRR offers add-path Receive on every session by default; with a peer that does not offer send, that is not negotiated add-path and is decoded normally.

**Rollback:** set every provider's `bmp` to `off` (or remove it) and restart; the view falls back to the iBGP RIB. Remove `rib_sources` too to stop the station listening.

### Federation `mtls`

The built-in instance-to-instance transport (#30). Each instance serves its snapshot over HTTPS with mutual TLS (TLS 1.3) at `/v1/snapshot` and polls its peers the same way. It never announces and never decides. Certificates are mounted files; the plugin generates and stores nothing.

| Key | Default | Meaning |
|---|---|---|
| `listen` | empty | Address to serve this instance's snapshot on, for example `0.0.0.0:9443`. Empty serves nothing (a central-view instance that only polls). |
| `cert_file` | required | PEM certificate this instance presents, as server and as client. |
| `key_file` | required | Its PEM private key. |
| `ca_file` | required | PEM CA that signs every instance's certificate. A certificate from another CA is refused. |
| `peers` | empty | Other instances: `name`, `url`, optional `server_name`. At most 64. |
| `name` | required | The peer's `instance`. A snapshot that names another instance is refused. |
| `url` | required | `https://host:port`, no path. |
| `server_name` | peer `name` | Name checked on the peer's server certificate. |
| `allow_clients` | peer names | Certificate names (CN or DNS SAN) allowed to read this snapshot. Others get 403. |
| `poll_interval` | `2s` | How often each peer is fetched, 100ms–1m. |
| `timeout` | `poll_interval` | Bound on one fetch. At most `poll_interval`. |
| `max_age` | 3 × `poll_interval` | How long a peer's last good snapshot stays usable, `poll_interval`–10m. After that the peer is stale and this instance acts standalone. |
| `max_bytes` | 16 MiB | Cap on a fetched snapshot, 1024–1073741824. |

Times in a snapshot are converted to local time by their age at the peer, so clock skew between POPs cannot make stale data look fresh. On shutdown an instance publishes its providers down before it withdraws, so peers retire steers onto them at their next poll.

### SSO `oidc`

Used under `auth.sso` (#32). OpenID Connect authorization code flow with PKCE. The ID token's signature, issuer, audience, expiry, and nonce are checked. The discovery document is read at start; if the provider is down the controller still starts and retries at the next sign-in. It only says who a user is and which role the provider grants; it never announces.

| Key | Default | Meaning |
|---|---|---|
| `issuer` | required | Issuer URL. `https`, or `http` on a loopback host (a lab). |
| `client_id` | required | This application's client id at the provider. |
| `client_secret_env` | required | Environment variable with the client secret. The secret is never a key in the file. |
| `redirect_url` | required | `https://<packeteer>/auth/callback`, registered at the provider. `https`, or `http` on loopback. The session cookie is `Secure`, so browsers keep it only over https or on localhost. |
| `scopes` | `[email, profile]` | Scopes besides `openid`. Add `groups` if your provider needs it for the roles claim. |
| `username_claim` | `email` | Claim used as the account name (`email`, `preferred_username`, `sub`, ...). With `email`, `email_verified: false` is refused. |
| `roles_claim` | `groups` | Claim listing the user's groups (a string or a list). |
| `role_map` | none | Group → `viewer`, `operator`, or `admin`. The highest mapped role wins. |
| `default_role` | none | Role when no group maps. Empty refuses the sign-in. `role_map` or `default_role` is required. |

The role is set at every sign-in. An SSO user is stored with no password; an admin can disable it (`PATCH /api/users/<name>` `{"disabled":true}`), which ends its session and refuses later sign-ins. A local user's name cannot be taken over by SSO.

### Elector `lease`

The built-in active/standby elector (#31): a lease file on storage both instances mount (one Docker volume on one host, or a shared filesystem with working `flock`). It never announces. Every read-modify-write happens under an exclusive lock on `path` + `.lock` and replaces the record with an atomic rename.

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Lease file, absolute. The directory is created on start. Both instances must see the same file. |
| `id` | `PACKETEER_HA_ID`, then the hostname | This instance's name in the pair. Letters, digits, `_`, `.`, `-`, at most 64 characters. The two instances must differ. |
| `ttl` | `10s` | Lease time, `2s`–`5m`. The active instance stops announcing `ttl`/2 after its last successful renewal, even when its renew loop is stuck. |
| `renew` | `ttl`/5 | Renewal and standby poll interval, at least `100ms` and at most `ttl`/4. |

A standby takes a lease that is free or released at its next renewal. It takes a lease held by another instance only after the record has not changed, on its own monotonic clock, for the longer of `ttl` and `ttl`/2 + the holder's recorded BGP hold time + `renew`, so clocks need not agree. The hold time is the longest negotiated hold time of the holder's established sessions (90s when unknown), refreshed at every renewal; set a short hold timer on the edge (for example 9s) for a fast takeover after a crash. A restarted instance does not reuse its predecessor's lease. An unreadable lease file counts as held by an unknown instance.

| Variable | Effect |
|---|---|
| `PACKETEER_HA_ID` | `id` when the config does not set it. |

### Detector `baseline`

The built-in anomaly detector (#33). For each destination prefix and IP protocol it keeps an exponentially weighted mean and variance of the rate seen each round. A round is anomalous when the rate is at least `min_mbps`, at least `min_ratio` × the mean, and more than `sensitivity` standard deviations above the mean, after `warmup` rounds of learning; or, with `max_mbps` set, when the rate reaches that ceiling whatever the baseline (this also covers a key that has no baseline yet). Anomalous rounds, and every round of an open anomaly, are not learned, so an attack does not become the baseline. Baselines live in memory only. It never announces.

| Key | Default | Meaning |
|---|---|---|
| `sensitivity` | `3` | Standard deviations above the mean. Lower is more sensitive. Above 0, at most 100. |
| `min_ratio` | `3` | Times the mean the rate must reach. 1–1000. |
| `min_mbps` | `10` | Smallest rate that can be anomalous, Mbit/s. Above 0. |
| `max_mbps` | off | Static ceiling, Mbit/s; `0` is off. At least `min_mbps`. |
| `alpha` | `0.05` | Weight of each new round in the mean and variance, above 0 and at most 1. |
| `warmup` | `30` | Rounds a key learns before the baseline test applies. 1–100000. |
| `trigger_rounds` | `2` | Anomalous rounds in a row before an anomaly opens. 1–1000. |
| `clear_rounds` | `3` | Normal rounds in a row before it clears. 1–1000. |
| `max_keys` | `10000` | Keys tracked; new keys past it are not tracked. 1–100000. An idle key is forgotten once its mean decays to nothing. |

### Announcer `gobgp`

No keys. Do not set `config`.

### Inbound announcer `gobgp`

`inbound.announcer`. Publishes steer routes on the same embedded iBGP speaker, after the `gobgp` announcer has installed its export policy (startup fails otherwise). Each steer route carries the learned next hop, `inbound.local_pref`, `packeteer_community`, `marker`, the action communities of every provider being steered away from, and `no-export`. Stop withdraws only its own routes.

| Key | Meaning |
|---|---|
| `marker` | Required. Community that tags steer routes, so the edge's import policy can tell them from outbound improvements. Must differ from `packeteer_community`. |
| `providers` | Required. The action catalog, one entry per provider. A provider without an entry is never steered away from. |

Each provider:

| Key | Meaning |
|---|---|
| `provider` | Required. A top-level provider `name`. Unique in the list. |
| `name` | Optional label, up to 64 characters. |
| `prepend` | 0–10. How many times the edge's export policy toward this provider prepends when it sees `communities`. Informational: an iBGP route cannot carry the edge's own ASN, so the edge does the prepend. |
| `withhold` | `true` makes the action a selective announcement: the edge's export policy does not send the prefix to this provider at all when it sees `communities`. Informational, like `prepend`, and exclusive with it. Packeteer never steers away from every provider, so the prefix stays announced through at least one other. |
| `communities` | 1–16 `asn:value` communities: signal communities the edge maps to the prepend, and the provider's own TE communities the edge passes to that provider only. `0:x` and `65535:x` (well-known values such as `no-export`) are rejected. |

### Mitigation announcer `gobgp`

`mitigation.announcer`. Publishes RTBH, redirect, and FlowSpec routes on the same embedded iBGP speaker, after the `gobgp` announcer has installed its export policy (startup fails otherwise). Each route carries the exact learned prefix, the action's next hop, `mitigation.local_pref`, `packeteer_community`, `marker`, the action's communities, and `no-export`. A FlowSpec rule's destination is the exact learned prefix; it carries `mitigation.local_pref`, `packeteer_community`, `marker`, `no-export`, and one extended community for the action: traffic-rate 0 (drop), traffic-rate in bytes per second (rate-limit), or redirect to a route target. It checks the mitigation allowlist and `max_rules` itself on every announce. Stop withdraws only its own routes.

| Key | Meaning |
|---|---|
| `marker` | Required. Community that tags mitigation routes, so the edge's import policy can tell them from outbound improvements. Must differ from `packeteer_community`. `0:x` and `65535:x` are rejected. |
| `blackhole` | RTBH. Keys below. At least one of `blackhole`, `redirect`, and `flowspec` is required. |
| `redirect` | Up to 32 redirect targets. Keys below. |
| `flowspec` | FlowSpec. `flowspec: {}` enables drop and rate-limit; its `redirect` list adds FlowSpec redirect targets. Keys below. |

`blackhole` keys:

| Key | Meaning |
|---|---|
| `next_hop` | Required. IPv4 discard address; the edge routes it to null (for example a static `blackhole` route). |
| `next_hop_v6` | Optional IPv6 discard address. Without it IPv6 prefixes cannot be blackholed. |
| `communities` | Default `["65535:666"]` (RFC 7999 BLACKHOLE). Up to 16. `65535:666` is the only well-known value accepted. |

Each `redirect` target:

| Key | Meaning |
|---|---|
| `name` | Required. Up to 64 characters, no spaces or slashes, unique. Rules name it as `target`. |
| `next_hop` | Required. The scrubbing center or sinkhole next hop (IPv4 or IPv6; a rule's prefix must be the same family). |
| `communities` | Optional, up to 16 `asn:value`. `0:x` and `65535:x` are rejected. |

Every next hop in the catalog must be unique, unicast, and not loopback.

`flowspec` keys:

| Key | Meaning |
|---|---|
| `redirect` | Up to 32 FlowSpec redirect targets, each `name` (as for `redirect` above) and `route_target`. |
| `route_target` | Required on each target. Two-octet-AS route target `asn:value` (AS 1–65535) that the edge imports into a VRF (a scrubbing VRF). Unique. A `flowspec_redirect` rule names the target. |

## Example

[config.example.yaml](../config.example.yaml) is a valid `observe` file. Install steps: [quickstart.md](quickstart.md). Router filters: [mikrotik.md](mikrotik.md), [frr.md](frr.md), [junos.md](junos.md), [cisco.md](cisco.md), [routers.md](routers.md). Problems: [troubleshooting.md](troubleshooting.md). Probe sourcing: [policy-routing.md](policy-routing.md).
