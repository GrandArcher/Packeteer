# Plugins

Packeteer's core is small. The pieces that differ between deployments are **plugins** behind small Go interfaces. You select them by `type` in config. Every key is listed in [CONFIG.md](CONFIG.md).

```yaml
plugin_dir: /etc/packeteer/plugins   # default; env PACKETEER_PLUGIN_DIR overrides it
probers:                             # ordered: later ones are fallbacks
  - type: icmp
  - type: tcp
sources:
  - type: static
    config: { ... }
  - type: exec
    name: cmdb
    config:
      command: cmdb-targets.sh
notifiers:
  - type: webhook
    config:
      url: https://hooks.example.invalid/packeteer
      headers:
        Authorization: "Bearer ${HOOK_TOKEN}"   # read from the container env
      min_severity: warning
      rate_limit: 30        # per minute
announcer:
  type: gobgp
telemetry:                           # optional; does not announce
  - type: snmp
    config:
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

Each entry has `type` (required), an optional `name` (defaults to the type and must be unique within its list), and an optional `config` block. The plugin decodes `config` itself, strictly: unknown fields are errors. **All plugins are built and validated at startup.** If a type is unknown or a config is invalid, Packeteer refuses to start and prints an error naming the entry, e.g. `notifiers[0] (nope): unknown notifier type "nope" (available: exec, smtp, snmptrap, webhook)`.

## Extension points (`pkg/plugin`)

| Kind | Interface | Built-ins | Out-of-process |
|---|---|---|---|
| `prober` | `Probe(ctx, ProbeRequest) (ProbeResult, error)` | `icmp`, `tcp`, `udp`, `fixed` (labs) | `exec` |
| `source` | `Targets(ctx) ([]Target, error)` | `static`, `flow`, `traceroute`, `vip`, `outage`, `span` | `exec` |
| `scorer` | `Score(PathStats) float64` (lower is better). `commit` also plans commit and group moves; `cost` plans moves to the cheapest provider inside a performance floor. Optional `plugin.ImprovementWeigher` (`ImprovementWeights()`, `ImprovementWeight(WeightInput)`) orders new moves for the `max_improvements` cap (#34); all three built-ins take `improvement_weights` | `weighted`, `commit`, `cost` | none |
| `announcer` | `Announce`, `Withdraw`, `WithdrawAll`; `BindRouters(srv, community, []RouterExport)` (`plugin.RouterAnnouncer`) is required when `bgp.neighbors` set `providers`/`next_hops` (#27); `SetRouters(ctx, []RouterExport)` (`plugin.RouterReloader`) lets a SIGHUP replace that table; `Route.ASPath` carries `bgp.as_path` | `gobgp` | **never** |
| `announcer` (inbound) | `Action(provider)`, `Announce(InboundRoute)`, `Withdraw`, `WithdrawAll`. One instance under `inbound.announcer:`; registry `plugin.InboundAnnouncers` | `gobgp` (marker + per-provider prepend/withhold/TE community catalog) | **never** |
| `announcer` (mitigation) | `Catalog()`, `Announce(MitigationRoute)`, `Withdraw`, `WithdrawAll`; optionally `plugin.FlowSpecAnnouncer` (`FlowSpecCatalog()`, `AnnounceFlowSpec(FlowSpecRoute)`, `WithdrawFlowSpec(key)`). One instance under `mitigation.announcer:`; registry `plugin.MitigationAnnouncers`. Bound with its own allowlist and rule cap, which it enforces on every announce, FlowSpec included (#28) | `gobgp` (marker + blackhole next hop/communities + redirect targets + FlowSpec) | **never** |
| `detector` | `Observe(now, []TrafficSample) []Anomaly`, `Tracked()`, `Reset()`. Traffic anomaly detection (#33); one instance under `anomaly.detector:`; registry `plugin.Detectors`. Fed per-prefix, per-protocol rates from a source that implements `plugin.FlowCounterSource` (`flow`). Reports anomalies only: the core turns one into a mitigation rule for an explicit `anomaly.rules` entry, through the mitigation controller | `baseline` (EWMA mean/variance per key) | **never** |
| `notifier` | `Notify(ctx, Event) error`, optional `EventGate()` (filters and rate limit), optional `plugin.ReportSender` (`SendReport(ctx, ReportMail)`: sends `report_subscriptions`, #34) | `webhook` (generic, `slack`, `teams`, `pagerduty`, templates), `smtp` (also sends reports), `snmptrap` | `exec` |
| `telemetry` | `Snapshot(ctx) ([]Usage, error)` | `snmp` | none |
| `policy` | `Match(PolicySubject) (PolicyVerdict, bool)`, optional `Maintenance.Active(now)`. The filter chain in front of the scorer | `rules`, `maintenance` | none |
| `storage` | `Write(ctx, HistoryBatch)`, `Read(ctx, HistoryQuery)`, optional `Backup`/`Restore` (`plugin.StorageBackup`, used by `-backup`/`-restore`). Report history; one instance under `storage:`. Optional `plugin.UserStore` and `plugin.AuditStore` keep HTTP users, API token hashes, and the audit log (#32); `auth` requires them. Optional `plugin.DashboardStore` keeps each user's custom dashboards (#34) | `sqlite` | none |
| `rib_source` | `SetRIBSink(func(RIBEvent))`. Feeds the RIB view (peer up/down, router down, paths) from outside the iBGP session. Learn-only; list under `rib_sources:` | `bmp` (BMP monitoring station) | **never** |
| `sso` | `AuthURL(ctx, state, nonce, verifier) (string, error)`, `Exchange(ctx, code, nonce, verifier) (SSOIdentity, error)`. Single sign-on for the ops API (#32); one instance under `auth.sso:`. Says who a user is and which role the provider grants; it never announces | `oidc` (OpenID Connect, code flow + PKCE) | none |
| `whois` | `Lookup(ctx, query) (WhoisResult, error)`. Troubleshooting registry lookups; one instance under `troubleshoot.whois:` | `rdap` | none |
| `elector` | `SetCandidate(func() Candidacy)`, `OnChange(func())`, `Active() bool`, `Resign(ctx)`, `Status()`. Active/standby leader election (#31); one instance under `ha:`. The core gates every announcer on `Active` and withdraws when it turns false | `lease` (lease file on a shared volume) | **never** |
| `federation` | `Publish(InstanceSnapshot)`, `Peers(now) []PeerState`. Instance-to-instance transport for multi-POP (#30); one instance under `federation:`. Transport only: the core merges fresh peer data into decisions | `mtls` (mutual TLS) | **never** |

An elector never announces and never picks routes. It only answers whether this instance may announce now. `Active` must turn false before any other instance can turn true, even when the plugin's own goroutine is stuck, because the outbound, inbound, and mitigation controllers check it under their locks before every sync. The core reports candidacy on each renewal (`Eligible`: the RIB view is ready; `RouteHold`: the longest negotiated BGP hold time, so a standby can wait until a crashed instance's routes are gone) and calls `Resign` only after it withdrew. It is in-process only. Built-in `lease`: see [CONFIG.md](CONFIG.md#elector-lease) and [ha.md](ha.md).

A detector never announces and never adds a mitigation rule. It keeps baselines and returns the keys far above them; the core adds a mitigation rule only when an explicit `anomaly.rules` entry matches, rate-limited (`max_actions_per_hour`) and capped (`max_active`), only for an exact prefix in the learned RIB, and only through the mitigation controller, which keeps its own mode, allowlist, `max_rules`, TTL, community, and NO_EXPORT. It is in-process only, because its output can lead to an announcement. Built-in `baseline`: see [CONFIG.md](CONFIG.md#anomaly) and [anomaly.md](anomaly.md).

Improvement weights (#34) only order moves Decide has already accepted. A weigher never sees a prefix that is not in the learned RIB or not allowlisted, cannot raise `max_improvements`, and cannot displace an active improvement; it is part of an in-process scorer. A `ReportSender` and a `DashboardStore` only send mail and keep UI layouts; neither can change a decision. See [ui.md](ui.md).

A federation plugin never announces and never decides. What it hands the core (peer snapshots) can only make a provider in another POP usable for a prefix the local RIB and allowlist already accept; the core still applies the community, NO_EXPORT, cap, hold time, and withdraw rules. It is in-process only, because peer data feeds decisions. Built-in `mtls`: see [CONFIG.md](CONFIG.md#federation-mtls) and [multi-pop.md](multi-pop.md).

Push exporters (Prometheus remote-write, OTLP) are not built; Prometheus metrics are built into the ops surface (#9) for scraping, and report history is the `storage` plugin (#23). Interface usage from the `snmp` telemetry plugin is on `/api/telemetry` and in `packeteer_telemetry_*` gauges. The `commit` scorer reads that snapshot and per-prefix flow volume. The telemetry plugin does not announce.

The probe engine remembers which prober got a reply from each host and starts the next round there. Every `probe.prober_recheck_rounds` (default 10) that host is measured from the first prober again. See [CONFIG.md](CONFIG.md#probe).

Probers return raw results (packets sent plus one RTT per reply). The core computes loss, RTT min/avg/max, and jitter the same way for every prober. A prober that cannot use its source address must return an error, not "100% loss", so the core can fail closed.

Announcers, inbound ones included, run **in-process only**, so an external process can never inject routes. RIB sources are in-process only too: what they feed decides which prefixes may be announced. They must withdraw everything on `Stop` and must not use BGP graceful restart.

## Lifecycle

1. **Factory (Init).** `func(cfg plugin.Config, env plugin.Env) (T, error)`. It decodes and validates config with `cfg.Decode(&myStruct)`. It must do no network I/O. `env` provides the instance name, a scoped `slog` logger, the plugin dir, and `Getenv`. When `env.CheckOnly` is set (the config editor checking a candidate file, #34), the instance is thrown away: validate the config, but start no process, open no connection, and write no file.
2. **`Start(ctx)`.** Begins background work in goroutines and must not block. Plugins start in this order: storage, SSO, RIB sources, sources, detector, probers, scorer, policies, telemetry, notifiers, federation, whois, elector, announcer, inbound announcer, mitigation announcer. If one fails, the ones already started are stopped.
3. **`Stop(ctx)`.** Releases everything before `ctx` expires. Plugins stop in reverse order, so the announcer stops first and routes are withdrawn early.

Embed `plugin.Base` for no-op `Start`/`Stop`.

### Built-in configuration

- `icmp`: `socket: auto|raw|udp` (default `auto`, which tries raw and then unprivileged datagram), `packet_interval` (default 100ms).
- `tcp`: `port` (default 443), `packet_interval` (default 100ms). A SYN-ACK or a RST both count as a reply. A middlebox RST is not distinguishable from the target's RST, because the kernel only reports `ECONNREFUSED`. A firewall that rejects with `tcp-reset` can look like a healthy path.
- `udp`: `port` (default 33434), `packet_interval` (default 100ms). A UDP reply counts. An ICMP destination-unreachable counts only when the error-queue offender is the target, so a firewall `REJECT` with icmp-port-unreachable is loss rather than a low-latency success. The kernel reports that on the connected socket, so this prober does not need a raw socket. The offender check is Linux-only; the container image is Linux. It is not in the default chain; add it after `tcp` when you want that fallback.
- `fixed`: returns configured results and **sends no packets**. For labs and tests (`lab/`), not for measuring a transit. `paths: [{provider, target?, count?, sent?, rtt_ms?, rtts_ms?, loss_pct?, source_down?}]`, plus optional top-level `sent` and `rtt_ms`. `target` (an IP) and `count` (the packet count, 0 matches any) narrow the match; the first most-specific path wins, and the same provider may appear more than once when `target` or `count` differs. `rtts_ms` is one reply RTT per entry and cannot be combined with `rtt_ms` or `loss_pct`. `source_down: true` fails the probe source closed. `file` is re-read on every probe (same schema, without `file`) so a lab can flip results without a restart.
- `static`: `targets: [{prefix, host?, weight?, mbps?}]`. `host` must be inside `prefix`. When set, it is the only probe target; when empty, the engine picks a few addresses in the prefix and the provider next hop. A prefix inside an exchange peering LAN, or an explicit host on one, is omitted (#145). `mbps` (0–100000000) is an optional declared rate, decimal megabits per second, for the `commit` scorer. Zero omits the prefix. This does not announce.
- `traceroute`: discovers the probe host for each configured prefix. `targets` is required (`prefix`, optional `host` inside the prefix, optional `weight`). `max_hops` (default 16, 1–64), `probes` per hop (default 3, 1–10), `min_replies` (default 2, or `probes` when that is smaller; a hop is stable only when one address answers at least this many times and there is no tie), `timeout` per probe (default 500ms, max 5s; zero uses the default), `port` (default 33434), `source` (optional local address; empty uses the default route), `interval` (default 5m, 1s–24h), `budget` (default 10s, at least `timeout`, at most 30s). Discovery runs in the background. `Targets` returns the last cache immediately and never traces, so a slow hop cannot consume the probe round. `budget` caps one pass; each target gets an equal share. The default budget is under the default round deadline (about 110s). When the configured host answers, it stays the probe host. Otherwise the highest stable TTL is used, which is the responsive hop closest to the destination. Three silent hops after a stable one end the trace. Loopback, link-local, multicast, and unspecified answers are ignored unless they are the destination. A hop on an exchange peering LAN is not adopted; the configured host is used when it is not on that LAN. A prefix or host inside a LAN is not traced (#145). The prefix on the target does not change, and the discovered address is not announced. If `source` is set and that address cannot be bound before any cache exists, the source fails for the round and the other sources continue. The socket calls are Linux-only; other systems still compile.
- `vip`: prefixes and ASNs probed on their own interval. `interval` is required (at least 1s) and must be shorter than the staleness window or the controller will not start. `max_targets` (default 100, 1–10000) caps configured prefixes plus ASN matches; truncation is logged, and the expansion is cached until the RIB generation changes. At least one of `prefixes` (`prefix`, optional `host` inside it) or `asns` (non-zero, no duplicates) is required. A default route is rejected. Configured prefixes are always returned, and the prefix list itself cannot exceed `max_targets`. ASN entries expand to learned prefixes whose AS path contains a listed ASN, and only while the RIB view is ready. The same prefix from another source keeps that source's host. A prefix inside an exchange peering LAN is omitted, including one added by ASN expansion (#145). A later interval wins only when it is shorter; an unset interval means `probe.interval`, so a longer VIP interval does not slow a prefix static or flow already listed. The global probe rate limit applies. This source does not announce.
- `outage`: correlates completed probe rounds by learned AS path and by provider. `min_prefixes` (default 3, minimum 2) and `window` (default 2m) are the pattern. A sample is degraded when the probe failed, loss is at least `loss_pct` (default 20; zero keeps that default), or average RTT is at least `rtt_ms` when that is set (zero disables the RTT check). The newest in-window sample wins. An ASN is sick when enough degraded prefixes contain it and every measured provider for those prefixes is degraded. A prefix that is healthy on another provider counts toward that provider's circuit instead, unless a sick ASN already explains it. With one provider in the window, mixed destinations still open a circuit and a shared ASN is not opened twice. `ignore_asns` skips ASNs that sit on every path. On a new incident the source returns the affected prefixes with `interval` (default 5s) and marks them urgent for one round; the probe loop wakes immediately. An AS incident also includes other learned prefixes whose path contains the ASN, up to `max_targets` (default 100), degraded ones first. A circuit incident then adds other prefixes sampled on that provider and learned prefixes whose native exit is that provider, under the same cap. A default route is never added. Events are `outage.as` and `outage.circuit` (`critical`) and `outage.cleared` (`warning`). The controller delivers them to the configured notifiers without blocking the probe loop. `interval` must be shorter than `probe.interval` and the staleness window. This source is read every round. A prefix inside an exchange peering LAN is not re-queued (#145). It does not announce. AS matches wait until the RIB is ready. The global probe rate limit applies.
- `flow`: UDP collector for NetFlow v5, NetFlow v9, IPFIX, and sFlow v5. Off unless the source is listed. `listen` (required, one `host:port` or a list), `window` (default 5m), `top_n` (default 100, the priority tier), `max_targets` (default `top_n`, at most 10000), `min_bytes` (default 0, off), `min_pct` (default 0, off), `tail_interval` (required when `max_targets` is greater than `top_n`), `aggregate_v4` / `aggregate_v6` (default 24 and 48), `exclude` (prefixes to ignore). A prefix stays eligible when its bytes reach `min_bytes` or its share of the window reaches `min_pct`; with both at zero every prefix with bytes is eligible and `top_n` still cuts the list (#118). The first `top_n` are probed every `probe.interval`. The rest, up to `max_targets`, carry `tail_interval`, which must be longer than `probe.interval` and shorter than the staleness window or the controller will not start. Problem prefixes stay ahead of that list and keep the normal interval. Each destination is summed over the window and mapped to the covering prefix in the RIB view when that view is ready and the match is not a default route; otherwise it is aggregated to `aggregate_v4` or `aggregate_v6`. Up to three of the busiest destinations inside the prefix are probe candidates, not pins (#113, #119). Each time bucket keeps its own three, and a destination that never makes a bucket's three is not recovered when the window is summed. A problem prefix lists the address the failures were seen on first, then those destinations, still at most three. The engine probes the named addresses first and adds the automatic in-prefix addresses only when fewer than three were named; a usable provider next hop still takes the last of the four slots. A silent or unqualified candidate (`probe.min_replies`, `probe.dispersion_ms`) drops out of the score when another address inside the prefix qualifies. An operator host on `static`, `vip`, or `traceroute` stays a pin and is the only address probed. `weight` is the byte total. The same window is exposed as a per-prefix rate (bytes × 8 / window, decimal megabits per second) for the `commit` scorer, including prefixes the floor or the cap left off the probe list. Private, ULA, loopback, link-local, multicast, and exchange peering LAN addresses are dropped and are not aggregated (#145). Raw records are not stored. Each time bucket keeps at most 20000 prefixes. NetFlow v9/IPFIX templates are kept in memory per exporter address and observation domain (capped) and are not written out. With `--network host` the listen ports are host ports; do not publish them. Firewall UDP to the exporter. See [mikrotik.md](mikrotik.md) and [routers.md](routers.md). An optional `problems` block (`local`, `failure_pct`, `min_flows`, `max_targets`) scores remote prefixes from TCP flags on unsampled NetFlow v5/v9 and IPFIX records (outbound SYN without ACK is a timeout, an inbound RST is a reset) and lists problem prefixes ahead of the busiest ones. sFlow and sampled exports are skipped. An optional `transit` block (`customers`, `share_pct`, #29) classifies each prefix's bytes by source address as transit (from a customer network) or local and exposes the class (`plugin.TrafficClassifier`) to the policy chain, where `rules` with `traffic` match it. Classification does not change targets and does not announce. An optional `subranges` block (`bits_v4`, `bits_v6`, `max_subranges`, `max_total`, #121) attaches the busiest sub-ranges of a wider prefix to its target (`plugin.Target.Subranges`); the engine scores each and uses their traffic-weighted mean for the prefix, and `/api/decisions` flags a heterogeneous prefix. A sub-range whose probe errors counts as full loss for that provider. When more than one source sends sub-ranges for the same prefix, the first source that sent them wins and later lists are ignored; a pin from any source removes them. A retained prefix no source lists any more is measured without sub-ranges. Sub-ranges are measured, never announced.
- `span`: passive problem detection from a SPAN or mirror port (AF_PACKET, needs `NET_RAW`) or a replayed classic pcap (`pcap_file`, absolute path). Exactly one of `interface` or `pcap_file`; `local` (your networks) is required. Follows TCP connections between local and remote addresses and counts outbound retransmissions, handshake timeouts (`syn_timeout`, default 3s), remote resets, and handshake RTT. A remote prefix is a problem when retransmissions reach `retrans_pct` (default 5, with `min_segments`, default 100), timeouts plus resets reach `failure_pct` (default 20, with `min_flows`, default 10) of connections, or, when set, average RTT reaches `rtt_ms`. Worst first, capped at `max_targets` (default 100), urgent on first appearance, read every round. Packets are not stored; connections are capped by `max_flows` and forgotten after `flow_idle`. Prefix mapping and address filters match `flow`, including exchange peering LANs (#145). It does not announce. See [CONFIG.md](CONFIG.md#source-span).
- `weighted`: `loss_weight`, `rtt_weight`, `jitter_weight`. Lower score is better. This is the default scorer. It does not move traffic for commit.
- `commit`: performance score with the same weights, plus commit control and group balancing. `loss_override` (default false) is the only way a commit move may increase loss. Decide refuses a higher-loss move from any planner that does not allow it, and refuses a move onto the native provider. A commit steer whose loss exceeds the native path by `min_loss_delta_pct` is withdrawn at once and waits out `hold_time` before it can return. A smaller gap stays. `balance` is `off` (default), `equal`, or `proportional`. `balance_slack` (default 0.10), `max_age` (default 15m), `min_mbps` (default 0). Provider `group`, `precedence`, and `cc_disable` are on the provider, not in this block. Precedence orders relieve destinations; sharing a group does not outrank it. Balance moves stay in the group. Improvements are tagged `performance` or `commit` and share `max_improvements`. A new performance move can displace the smallest commit steer when the cap is full. The scorer does not announce. See [CONFIG.md](CONFIG.md).
- `cost`: performance score with the same weights, plus cost optimization. Moves a prefix to the cheapest provider (`providers[].cost`, per Mbps) whose path is inside `floor` (`max_loss_pct`, default 0, and `max_rtt`, default 10ms, above the best loss and best RTT). `precedence` is `performance` (default: performance moves win) or `cost` (a native path inside the floor stays; otherwise the cheapest path inside the floor that is cheaper than native wins). The plugin implements `plugin.Planner` and `plugin.CostPolicy`; Decide re-checks the floor and the price, withdraws a cost steer at once when it leaves the floor, and applies the allowlist, RIB, cap, and cooldown. Improvements are tagged `cost`. The scorer does not announce. See [CONFIG.md](CONFIG.md).
- `rules` (policy): routing policies by prefix, origin ASN, country (GeoIP, from a MaxMind-format database you mount; none ships with Packeteer), or traffic class (`traffic: transit|local`, from the `flow` source's `transit` block; `PolicySubject.Traffic`). Actions `ignore`, `allow`, `deny`, `static`, and `vip`. A prefix match beats an ASN match, which beats a country match, which beats a traffic-only rule; the longest rule prefix wins; ties go to the rule listed first. The first policy in `policies` that matches a prefix decides it. Decide applies the verdict and still enforces the RIB, allowlist, cap, and withdraw rules. It does not announce. See [CONFIG.md](CONFIG.md#policies).
- `maintenance` (policy): windows during which providers carry no improvements. Recurring (five-field cron `schedule` plus `duration`, in `timezone`), one-off (`start`/`end`), or opened on demand through `POST /api/maintenance` (basic auth required, in memory only). Matches no prefixes. It does not announce.
- `exec`: see below.
- `webhook`: `url`, `timeout`, `headers`, `preset` (`generic`, `slack`, `teams`, `pagerduty` with `routing_key_env`), or `template` and `content_type` for SMS and other gateways. See [CONFIG.md](CONFIG.md#notifier-webhook).
- `smtp`: one plain-text email per event. `host`, `port`, `tls` (`starttls` by default and required; `tls`; or `none` for a trusted local relay without credentials), `ca_file`, `username_env` and `password_env`, `from`, `to`, `subject_prefix`, `helo`, `timeout`. See [CONFIG.md](CONFIG.md#notifier-smtp).
- `snmptrap`: one SNMPv2c or SNMPv3 trap per event. `address`, `port` (162), `version`, `community_env` or the v3 USM keys and `engine_id`, `enterprise_oid`, `timeout`. See [CONFIG.md](CONFIG.md#notifier-snmptrap).
- Every notifier, `exec` included, takes `events`, `min_severity`, `rate_limit`, and `rate_window`. The controller applies them in `internal/notify`, which gives each notifier its own bounded queue so a slow one never blocks probing, decisions, withdrawals, or other notifiers. Event kinds, severities, trap IDs, and dedup keys are in [EVENTS.md](EVENTS.md). Notifiers never announce.
- `gobgp`: no plugin config block. It publishes on the iBGP speaker the RIB view already opened. `local_pref` (optional `local_pref_cause` and `providers[].local_pref` override it) and `packeteer_community` are top-level controller settings. The announcer stamps the local preference it is given. Each route is the exact prefix learned from the RIB; a config that sets `more_specific_bits` is rejected. With the top-level `more_specific` block on, the controller also sends it the learned more-specifics inside each improvement (exact RIB prefixes, capped by `more_specific.max_routes`); the announcer applies the same community, NO_EXPORT, and export policy to them. Every route gets the community plus NO_EXPORT. The export policy accepts only Packeteer's own routes that carry the community. `Stop` withdraws them. Graceful restart is never turned on. Required, along with `local_pref`, when `mode: inject`.
- `gobgp` (mitigation, #28): under `mitigation.announcer`. `marker` (required), `blackhole` (`next_hop`, optional `next_hop_v6`, `communities`, default `65535:666`), `redirect` targets (`name`, `next_hop`, `communities`), and `flowspec` (drop and rate-limit; `redirect` targets by `name` and `route_target`); at least one of the three. Publishes RTBH, redirect, and FlowSpec (RFC 8955) routes on the same speaker, after the `gobgp` announcer's export policy is installed. Each route is the exact learned prefix with the action's next hop and communities (FlowSpec: the prefix as the destination component and the action as an extended community), the packeteer community, the marker, and NO_EXPORT. It refuses a prefix outside the mitigation allowlist and a new route past `max_rules` (RTBH, redirect, and FlowSpec together) itself. `Stop` withdraws only its own routes. Lab-proven only. See [mitigation.md](mitigation.md).
- `baseline` (detector, #33): under `anomaly.detector`. Per destination prefix and IP protocol, an exponentially weighted mean and variance (`alpha`, default 0.05). A round is anomalous at or above `min_mbps` (10), `min_ratio` (3) × the mean, and `sensitivity` (3) standard deviations above it after `warmup` (30) rounds, or at `max_mbps` (off) whatever the baseline. `trigger_rounds` (2) and `clear_rounds` (3) are the hysteresis; anomalous rounds are not learned. `max_keys` (10000) bounds memory. In memory only. It never announces. Lab-proven only. See [anomaly.md](anomaly.md).
- `snmp`: polls `ifHCInOctets` and `ifHCOutOctets` (or the 32-bit octet counters when the 64-bit ones are absent) and tracks 95th-percentile usage for the open UTC billing period. `percentile` is `separate` (inbound and outbound 95ths kept apart), `greater` (95th of max(in, out) per sample), or `greater_separate` (the greater of the two 95ths). The community and v3 passphrases are environment variables named by `community_env`, `auth_env`, and `priv_env`. They are not config values. A failed poll keeps the samples already stored. With a storage plugin configured, samples are written per binding and billing period and the open period is loaded on start (#127); without storage a restart clears the window. Closed periods stay until storage retention. `max_samples` caps the open period in memory. The plugin does not announce. The `commit` scorer is what spends the snapshot. See [CONFIG.md](CONFIG.md).
- `bmp` (rib_source): a BMP monitoring station (RFC 7854, Loc-RIB per RFC 9069). `listen` (default `:11019`), `routers` (required: addresses allowed to connect; others are closed), `policy` (`post` only: pre-policy routes the router may have rejected never count), `loc_rib` (default true), `idle_timeout` (default off; TCP keepalive notices a dead router in about 30s). Each provider's `bmp` key (`off`, `prefer`, `only`) decides whether its BMP paths count and whether the route check applies: a provider that is not advertising the exact prefix gets no improvement for it, and an active one is retired. A router's paths are dropped when its session ends; a peer's when it goes down or cannot be decoded. A peer that negotiated add-path with the router is decoded with path identifiers, so each of its paths is kept. It never announces. See [CONFIG.md](CONFIG.md#rib-source-bmp).
- `lease` (elector, #31): `path` (required, absolute, on a volume both instances mount), `id` (default `PACKETEER_HA_ID`, then the hostname), `ttl` (default 10s, 2s–5m), `renew` (default `ttl`/5, at most `ttl`/4). The active instance stops announcing `ttl`/2 after its last successful renewal. A standby takes a released lease at its next renewal, and a held one only after it has not changed for `ttl`/2 + the holder's recorded BGP hold time + `renew` (at least `ttl`), on its own monotonic clock. Locking is `flock` on `path.lock` with an atomic rename. It never announces. Lab-proven only. See [ha.md](ha.md).
- `rdap` (whois): RDAP lookups for the troubleshooting API. `base_url` (default `https://rdap.org`), `timeout` (default `5s`), `max_bytes` (default 256 KiB). The core validates the query (address, prefix, or ASN only) and rate-limits it. It reads only and does not announce. See [CONFIG.md](CONFIG.md#whois-rdap).
- `sqlite` (storage): report history in an embedded SQLite file. `path` (default `/var/lib/packeteer/packeteer.db`, absolute; mount a volume on the directory) and `retention` (default 400 days, `24h`–`87600h`). Daily probe rollups, one row per improvement with before/after loss and RTT, and per-prefix origin ASN, country, and volume. It also keeps SNMP 95th-percentile samples (#127): the open billing period is reloaded on start, and a closed period stays until `retention`. The controller buffers report rows and writes once a minute, so a slow disk never delays a decision or a withdraw. Sample writes happen when a poll is accepted and do not announce. Reports are built from the history rows by the core (`/api/reports`, CSV, dashboard). A `rules` policy with `geoip_db` supplies countries (`plugin.CountryLookup`). It does not announce. See [CONFIG.md](CONFIG.md#storage-sqlite).
- `fixed`: reports `usage_mbps` and `commit_mbps` from config or from a file re-read on every snapshot. Labs and tests only. It does not poll and it does not announce. A deployment uses `snmp`.

## Writing a Go plugin (compiled in)

```go
package myprober

import "github.com/GrandArcher/Packeteer/pkg/plugin"

type Config struct{ Port int `yaml:"port"` }

type Prober struct{ plugin.Base; port int }

func init() {
	plugin.Probers.Register("myprober", func(c plugin.Config, e plugin.Env) (plugin.Prober, error) {
		var cfg Config
		if err := c.Decode(&cfg); err != nil {
			return nil, err
		}
		return &Prober{port: cfg.Port}, nil
	})
}
```

Built-ins live under `internal/plugins/<kind>/<name>` and are linked through `internal/plugins/all`. A third-party build blank-imports its package the same way.

## `exec` plugins (work with the stock image)

An `exec` plugin is any executable in the plugin dir: a static binary, a POSIX `sh` script (the image is alpine), or anything else you ship in a derived image.

```yaml
sources:
  - type: exec
    name: example
    config:
      command: static-targets.sh   # relative = inside plugin_dir; absolute paths allowed
      args: []
      timeout: 30s                 # per call (default 30s)
      env:                         # only PATH and these are passed; ${VAR} expands from Packeteer's env
        API_TOKEN: ${CMDB_TOKEN}
      config:                      # forwarded verbatim to the plugin
        site: lab
```

### Protocol `packeteer-exec/v1`

For **every call**, Packeteer starts the process, writes **one JSON request** to stdin, closes stdin, and reads **one JSON response** from stdout. Stderr is logged at debug level. Output is capped at 1 MiB. The call fails on a non-zero exit, on the timeout, or on `{"error": "..."}`. The process gets `PATH`, `PACKETEER_PLUGIN_KIND`, and the configured `env`, and nothing else from Packeteer's environment.

Request:

```json
{"protocol":"packeteer-exec/v1","kind":"source","method":"targets","name":"example","config":{"site":"lab"},"params":null}
```

Response: `{"result": ...}` or `{"error": "message"}`.

| kind | method | params | result |
|---|---|---|---|
| any | `init` | none | `{}`, or an error if the config is unacceptable. Called once at startup. Never called by the config editor, which does not run exec plugins ([ui.md](ui.md)). |
| `prober` | `probe` | `{"provider","source","target","count","timeout_ms"}` | `{"sent": 10, "rtts_ms": [12.1, 11.8]}`, one RTT per reply, in send order |
| `source` | `targets` | none | `{"targets":[{"prefix":"198.51.100.0/24","host":"198.51.100.1","weight":1}]}` (`host` must be inside `prefix`; `host` and `weight` are optional) |
| `notifier` | `notify` | an event: `{"time","kind","severity","message","fields"}` | `{}` |

A minimal working example is in [examples/plugins/static-targets.sh](../examples/plugins/static-targets.sh).

Mount a plugin directory into the container:

```sh
docker run ... -v "$PWD/plugins:/etc/packeteer/plugins:ro" ghcr.io/grandarcher/packeteer:edge
```

### Security

- Relative commands cannot leave the plugin dir (`../` is rejected).
- Mount the plugin dir read-only. Treat plugins like any code you run as root in the container.
- Secrets reach plugins only through the explicit `env` mapping.

## Roadmap

- Long-running out-of-process plugins over gRPC ([hashicorp/go-plugin](https://github.com/hashicorp/go-plugin)), for probers that keep state or run at high rates.
- Exporter plugins (InfluxDB, OTLP).
