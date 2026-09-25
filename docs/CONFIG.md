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

`-check` builds and validates plugins, prints a summary, and exits. It sends no probes and opens no BGP session. `-version` prints `packeteer <version>` and does not read the config.

The image entrypoint is the same binary. Flags go after the image name.

## Top level

| Key | Default | Required | Meaning |
|---|---|---|---|
| `mode` | none | yes | `observe`, `suggest`, or `inject`. |
| `asn` | none | yes, non-zero | BGP ASN of this speaker. Neighbors are iBGP in this ASN. |
| `router_id` | none | yes | IPv4 address. IPv6 is rejected. |
| `packeteer_community` | empty | inject | RFC 1997 community `asn:value`. Each half is an integer 0–65535. Quote it in YAML (`"64512:666"`). |
| `local_pref` | 0 | inject | Local preference on every injected route. `0` is rejected in inject mode. Set it above the edge's native local preference. |
| `more_specific_bits` | unset | must be absent | Any value, including `0`, is an error. Packeteer announces the exact prefix it learned from the RIB. |
| `max_improvements` | 50 | no | Cap on active improvements. Integer from 1 to 10000. Biggest gains win when the cap binds. |
| `hold_time` | 0 | inject: positive | Minimum life of an improvement, and the cooldown after a flip-back or a confirmed RIB leave. `0` is legal in observe and suggest (a flip can happen on the next evaluation). Negative is an error. |
| `improvement_ttl` | `1h` | no | Retire an improvement after this long so the native path is measured again. A negative duration disables the TTL. `0` selects the default `1h`. |
| `thresholds` | zeros | inject: both positive | See below. With both deltas at `0`, the decision engine records no improvement in any mode. |
| `providers` | none | at least one | Probe sources and injection next hops. |
| `allowlist` | empty | inject: non-empty | Prefixes that may be injected. |
| `probe` | see below | no | Timing and concurrency. |
| `log` | `info` / `text` | no | Process log. |
| `http` | `127.0.0.1:8080` | no | Read-only dashboard, API, and metrics. |
| `bgp` | no neighbors | inject: at least one neighbor | iBGP sessions. |
| `plugin_dir` | `/etc/packeteer/plugins` | no | Directory for out-of-process plugins. |
| `probers` | `icmp`, then `tcp` | no | Ordered. Later entries run only when an earlier one errors. |
| `sources` | none | no | Probe targets. With none, the process starts and probes nothing. |
| `scorer` | `weighted` | no | One scorer. Lower score is better. |
| `announcer` | none | inject | In-process only. `type: gobgp` publishes on the RIB session. |
| `notifiers` | none | no | Events. A failure here does not withdraw routes by itself. |
| `telemetry` | none | no | Interface counters and 95th-percentile usage. Off unless listed. Does not announce. |
| `policies` | none | no | Routing policies and maintenance windows, asked in order before each decision. Off unless listed. Does not announce. See [Policies](#policies). |

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
| `source_ip` | yes | Source address of probes. Unique across providers. Must be configured on the host. Same address family as `next_hop`. |
| `next_hop` | yes | BGP next hop used if this provider is selected. Also how a learned route is matched to a provider. |
| `exclude` | no | `true`: still probe, never select for an improvement. |
| `group` | no | Load-balancing group. Empty means the provider is not in a group. Letters, digits, `_`, `.`, `-`, at most 64 characters, starting with a letter or digit. |
| `precedence` | no | Commit-control preference. Lower is preferred. `0` or omitted means 100. 0–10000. The highest precedence among providers that can take commit traffic is the last resort. |
| `cc_disable` | no | `true`: leave this provider out of commit control in both directions. Performance improvements can still select it. |
| `cost` | no | Price per Mbps, 0–1000000000, in one currency across all providers. Omitted means no cost: the `cost` scorer never moves a prefix onto this provider or off it for price. Improvements between two priced providers carry `cost_delta` and `est_savings` on `/api/improvements`. |

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

The server accepts GET and HEAD. It does not announce routes. With `--network host`, this address is on the host. Basic auth is not a key in the file; see the environment variables.

### `bgp`

| Key | Default | Meaning |
|---|---|---|
| `listen_port` | 0 | `0`: do not listen; Packeteer connects out. 1–65535: accept sessions. |
| `listen_addresses` | none | Local addresses to bind when listening. Each must be an IP address. |
| `neighbors` | none | Edge routers, iBGP, same ASN as `asn`. |

Each neighbor:

| Key | Default | Meaning |
|---|---|---|
| `address` | required | Peer IP. Duplicates are errors. |
| `port` | 179 | Remote TCP port. `0` means 179. 0–65535 at validation; `0` is replaced when the session is built. |
| `local_address` | unset | Optional source address of the TCP session. |
| `passive` | false | Wait for the router to connect. Requires `listen_port`. |
| `description` | empty | Log label. |

Packeteer proposes a hold time of 90 seconds and a keepalive of 30 seconds. The router's shorter hold time wins. A hold time of zero is never proposed. Graceful restart is not a config key and is never enabled. With no neighbors, the RIB view is off and decisions say ranking only: nothing is injected.

One established session is enough for the view to be ready. All sessions down drops the learned routes and withdraws injected routes.

### Plugin entries

`probers`, `sources`, `notifiers`, `telemetry`, and `policies` are lists. `scorer` and `announcer` are single objects.

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
- `more_specific_bits` is absent

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

With `--network host`, `listen` binds host UDP ports. Do not publish them. Each time bucket keeps at most 20000 prefixes. The commit scorer reads every prefix in the window as a rate (bytes × 8 / window, decimal megabits per second), including prefixes `top_n` or `min_bytes` did not offer as probe targets.

### Scorer `weighted`

`score = loss_pct * loss_weight + rtt_ms * rtt_weight + jitter_ms * jitter_weight`.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |

At least one weight must be positive. Omit the block to keep the defaults.

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

At least one weight must be positive.

### Policies

`policies` is a chain of policy plugins. Before each decision the controller asks each policy, in list order, about every probed prefix. The first one that matches decides that prefix; later ones are not asked. Maintenance windows from every `maintenance` entry apply together. A policy only restricts or pins what the decision engine may choose. The prefix must still be in the learned RIB, allowlisted in inject mode, and under `max_improvements`, and every injected route still carries `packeteer_community` and NO_EXPORT. Removing the `policies` block and restarting is the rollback: pins are withdrawn and the normal thresholds apply again.

| Action | Effect |
|---|---|
| `ignore` | Native routing only. An active improvement is retired at once. No new improvement, and commit or cost planners do not see the prefix. |
| `allow` | Only the listed providers may carry an improvement. |
| `deny` | The listed providers never carry an improvement. |
| `static` | Pin to the one listed provider while its path is usable (fresh probe, provider up, not excluded or in maintenance) and healthy: loss at or under the rule's required `max_loss_pct`, RTT at or under `max_rtt` when set, and loss not worse than a measured native path by `thresholds.min_loss_delta_pct` or more. The check runs before the pin is announced and on every round while it is held. A pin that fails it, or whose path becomes unusable, is withdrawn at once and waits out `hold_time` before it can return. Moving an existing improvement onto the pinned provider waits until that improvement has lived `hold_time`. When the pinned provider is native, nothing is announced. A pin does not expire on `improvement_ttl`; the health check is what moves it off a bad path. Cause `static`. |
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

A rule needs at least one of `prefixes`, `asns`, or `countries`, and matches when any of them match. When several rules match one prefix, a prefix match beats an ASN match, which beats a country match. Among prefix matches the longest rule prefix wins. Remaining ties go to the rule listed first.

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

### Notifier `webhook`

| Key | Default | Meaning |
|---|---|---|
| `url` | none | Required absolute `http` or `https` URL. `${VAR}` expands from the environment. |
| `timeout` | `5s` | Not negative. |
| `headers` | none | Extra request headers. Values expand `${VAR}`. |
| `min_severity` | `info` | `info`, `warning`, or `critical`. |

### Notifier, prober, or source `exec`

| Key | Default | Meaning |
|---|---|---|
| `command` | none | Required. Absolute path, or a path inside `plugin_dir`. `../` is rejected. The file must be executable at startup. |
| `args` | none | Arguments. |
| `timeout` | `30s` | Per call. Not negative. |
| `env` | none | Passed to the process, plus `PATH` and `PACKETEER_PLUGIN_KIND`. Values expand `${VAR}`. Names cannot contain `=` or NUL. |
| `config` | none | Forwarded verbatim in every JSON request. |

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

### Announcer `gobgp`

No keys. Do not set `config`.

## Example

[config.example.yaml](../config.example.yaml) is a valid `observe` file. Annotated install steps are in the [README](../README.md). Router filters: [mikrotik.md](mikrotik.md), [routers.md](routers.md). Probe sourcing: [policy-routing.md](policy-routing.md).
