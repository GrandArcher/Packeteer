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
| `mode` | `observe` | no | `observe`, `suggest`, or `inject`. A file without `mode` (or with an empty one) observes. `inject` is never a default: it needs `mode: inject` and the [inject checklist](#inject-checklist). An [`ixp`](#ixp) block refuses `inject`. |
| `lookup` | absent | no | Read-only PeeringDB / IX-F directory (#153). One plugin, `type: peeringdb`. Announces nothing. See [`lookup`](#lookup). |
| `ixp` | absent | no | Exchange-operator mode (#160). `ixp: {}` refuses inject, announcer, mitigation, inbound, synthesize, and more_specific. Optional `members` imports an IX-F list, `routeservers` polls Birdseye, and `correlate` tells a fabric problem from a member problem; none announces (#161, #164, #163). No `bgp.neighbors` required. See [`ixp`](#ixp). |
| `asn` | none | yes, non-zero | BGP ASN of this speaker. Neighbors are iBGP in this ASN. |
| `router_id` | none | yes | IPv4 address. IPv6 is rejected. |
| `packeteer_community` | empty | inject | Standard community `asn:value` (each half 0-65535) or a large community `global:data1:data2` (RFC 8092, each part 0-4294967295). Quote it in YAML (`"64512:666"`). The export policy matches only this community. A two-part value above 16 bits is rejected; write a 4-byte ASN as a large community (`"70000:1:0"`). |
| `local_pref` | 0 | inject | Local preference on an injected route when no cause or provider override is set. `0` is rejected in inject mode. Set it above the edge's native local preference. See [`local_pref_cause`](#local_pref_cause). |
| `communities_cause` | none | no | Extra outbound communities per improvement cause (#132). Added after `packeteer_community`. See [`communities_cause`](#communities_cause). |
| `more_specific_bits` | unset | must be absent | Any value, including `0`, is an error. Packeteer announces the exact prefix it learned from the RIB. |
| `more_specific` | off | no | More-specific injection: with each improvement, also announce the more-specifics inside its prefix that a neighbor advertises in the learned RIB, under a route cap. Never a prefix that is not learned. See [`more_specific`](#more_specific). Lab-proven only. |
| `synthesize` | off | no | Opt-in synthesized more-specific injection (#122): announce a measured sub-range of a learned prefix, which is itself NOT in the learned RIB. Read the WARNING in [`synthesize`](#synthesize) first. Lab-proven only. |
| `rpki` | off | no | Shared RPKI origin validation (#158, #200): read the operator's RPKI cache over RTR or VRP JSON and label each learned path's origin valid, invalid, not found, or unknown, with the source and its data age. `avoid_invalid` refuses a new improvement onto an invalid path. Never announces and never changes the learned RIB. See [`rpki`](#rpki). Not on a public edge. |
| `instance` | `domain` | no | This instance's name in a federation (#30). Peers expect it in its snapshot. Letters, digits, `_`, `.`, `-`, at most 64 characters. See [Multi-POP](#multi-pop-federation). |
| `domain` | empty | with `federation` | This instance's routing domain (POP). Empty is a standalone instance. |
| `inter_dc_rtt` | empty | per remote domain | Map of domain to round-trip time from this POP (for example `pop-b: 12ms`), 0-10s. Added to every path a peer in that domain measured. |
| `global_commit` | empty | no | Commits shared by providers in several domains. Needs `federation`. See [Multi-POP](#multi-pop-federation). |
| `federation` | none | no | The instance-to-instance transport plugin, one object: `type: mtls`. See [Federation `mtls`](#federation-mtls). Omitted runs the instance standalone. |
| `ha` | none | no | Active/standby elector (#31), one object: `type: lease`. Only the active instance of the pair announces. Needs `bgp.neighbors`. See [High availability](#high-availability-ha) and [Elector `lease`](#elector-lease). Omitted runs a single instance, always active. Lab-proven only. |
| `max_improvements` | 50 | no | Cap on active improvements. Integer from 0 to 10000. `0` retires every improvement on the next decision. Biggest gains win when the cap binds, or the scorer's [`improvement_weights`](#improvement-weights) when set. |
| `hold_time` | 0 | inject: positive | Minimum life of an improvement, and the cooldown after a flip-back or a confirmed RIB leave. `0` is legal in observe and suggest (a flip can happen on the next evaluation). Negative is an error. |
| `improvement_ttl` | `1h` | no | Retire an improvement after this long so the native path is measured again. A negative duration disables the TTL. `0` selects the default `1h`. While it is active the prefix stays a probe target after its source drops it. |
| `flap_quarantine` | on | no | Parks a prefix that keeps changing its chosen provider (#228). See [`flap_quarantine`](#flap_quarantine). |
| `verify` | off | no | Checks that an outbound improvement or an inbound steer moved traffic, and can back it out (#305). See [`verify`](#verify). |
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
| `probers` | `icmp`, then `tcp` | no | Ordered. For each address, the next prober runs when an earlier one errors or gets no reply at all. Every probe run starts again at the first prober. |
| `sources` | none | no | Probe targets. With none, the process starts and probes nothing. |
| `scorer` | `weighted` | no | One scorer. Lower score is better. |
| `announcer` | none | inject | In-process only. `type: gobgp` publishes on the RIB session. |
| `notifiers` | none | no | Events. A failure here does not withdraw routes by itself. |
| `exporters` | none | no | Push events, decisions, and flow records to Kafka, NATS, OTLP, or IPFIX (#207). Off when empty. See [Exporters](#exporters). |
| `telemetry` | none | no | Interface counters and 95th-percentile usage. Off unless listed. Does not announce. |
| `policies` | none | no | Routing policies and maintenance windows, asked in order before each decision. Off unless listed. Does not announce. See [Policies](#policies). |
| `storage` | none | no | One storage plugin for report history (`type: sqlite`). Off unless set. Does not announce. See [Storage `sqlite`](#storage-sqlite). |
| `inbound` | none | no | Inbound commit control: steer inbound traffic for your own prefixes away from a provider over commit with prepends and TE communities. Off unless set; its own `mode` defaults to `observe`. See [`inbound`](#inbound). Lab-proven only. |
| `mitigation` | none | no | Threat mitigation: RTBH (blackhole), BGP redirect, and FlowSpec (drop, rate-limit, redirect, by source country too) for exact learned prefixes, added through `/api/mitigations`. Off unless set; its own `mode` defaults to `observe`. See [`mitigation`](#mitigation). Lab-proven only. |
| `anomaly` | none | no | Automatic traffic anomaly (DDoS) detection: a detector plugin baselines flow volumes per destination prefix and IP protocol from a `flow` source and reports anomalies; an explicit rule can turn one into a mitigation rule, rate-limited and capped. Needs `mitigation` for rules. Off unless set. See [`anomaly`](#anomaly). Lab-proven only. |
| `upgrade` | off | no | Version check, one-click upgrade, and rollback in Settings (#196). Needs `public_key`. See [`upgrade`](#upgrade). Never upgrades without an admin's confirmation; does not announce. |
| `leak_watch` | none | no | Watches for Packeteer's routes outside the AS and withdraws a leaked route (one prefix, never in bulk), holding it out until an operator clears it. Off unless `enabled: true`. See [`leak_watch`](#leak_watch) and [leak-watch.md](leak-watch.md). Lab-proven only. |
| `linkouts` | defaults | no | Which "open in" links the prefix, ASN, and provider pages show, custom URL templates, and `hide_internal` (#211). Display only; Packeteer requests none of those sites. See [`linkouts`](#linkouts). |
| `report_subscriptions` | none | no | Stored reports emailed as CSV on a daily, weekly, or monthly UTC schedule through an `smtp` notifier (#34). Needs `storage`. See [`report_subscriptions`](#report_subscriptions). Does not announce. |
| `ring_lg` | off | no | Opt-in "Seen from NLNOG RING" panel on the prefix page, rate limited and cached (#283). Display only. See [`ring_lg`](#ring_lg). |
| `atlas` | off | no | Opt-in RIPE Atlas measurements of a prefix's test address with your own key and credits, on demand or once after a move, shown on the prefix page (#213). Hard credit and rate caps. Display only. See [`atlas`](#atlas) and [atlas.md](atlas.md). |
| `troubleshoot` | looking glass only | no | Read-only operator tools: looking glass, on-demand probe, traceroute, whois. Does not announce. See [`troubleshoot`](#troubleshoot). |

`mode: observe` and `mode: suggest` use the same decision path and announce nothing. `suggest` is the checkpoint: read the log, the dashboard, and `/api/decisions` before you change `mode`. The allowlist is enforced only in `inject`.

### `local_pref_cause`

Optional. A local preference per improvement cause (#132). The global `local_pref` is used when the cause is omitted here and the provider does not set its own. A provider `local_pref` wins over the cause, and the cause wins over the global value. An improvement with an empty cause is `performance`. Each value that is set must be a non-zero integer. `0` is rejected in every mode, the same rule as `local_pref` in inject: set it above the edge's native local preference. Unknown keys are rejected. These keys do not change which prefix Decide announces or withdraws. A cause change on a route already on the wire replaces that route with the new local preference. A learned more-specific uses its improvement's resolved value.

| Key | Default |
|---|---|
| `performance` | global `local_pref` |
| `static` | global `local_pref` |
| `commit` | global `local_pref` |
| `cost` | global `local_pref` |

```yaml
local_pref: 250
local_pref_cause:
  performance: 300
  static: 400
  commit: 220
  cost: 210
```

### `communities_cause`

Optional. Extra outbound communities per improvement cause (#132). They are added to `packeteer_community`, then a provider's `communities` are added. They do not replace it, and the export policy matches only `packeteer_community`. An improvement with an empty cause uses `performance`. An omitted cause adds none. An unknown key is rejected.

Each entry is a standard community (`asn:value`, each half 0-65535) or a large community (`global:data1:data2`, RFC 8092, each part 0-4294967295). A list holds at most 16. Empty strings, duplicates (after canonical form, so `64512:0100` is `64512:100`), a value equal to `packeteer_community`, and well-known standard communities (`0:x` and `65535:x`, including NO_EXPORT and BLACKHOLE) are rejected. `packeteer_community` itself may be one of those well-known values. A two-part value above 16 bits is rejected. Leading zeros are rewritten to canonical decimal text. These keys do not change which prefix Decide announces or withdraws. A cause change on a route already on the wire replaces that route. A learned more-specific uses its improvement's community list. Changing this block requires a restart.

| Key | Default |
|---|---|
| `performance` | none |
| `static` | none |
| `commit` | none |
| `cost` | none |

```yaml
packeteer_community: "64512:666"
communities_cause:
  performance: ["64512:100"]
  static: ["64512:200"]
  commit: ["64512:300"]
  cost: ["64512:1:40"]
```

### `flap_quarantine`

| Key | Default | Bounds |
|---|---|---|
| `disabled` | `false` | `true` turns the quarantine off and releases anything parked on the next decision. |
| `max_flips` | 6 | At least 1. A prefix is parked when one more change would make it more than this many in `window`. |
| `window` | `1h` | Positive. Changes older than this no longer count. |
| `cooldown` | `15m` | Positive. How long the first quarantine lasts. |
| `max_cooldown` | `4h` | Not shorter than `cooldown` (default raised to `cooldown` when that is longer). Caps the grown cool-down, and a prefix quiet for longer than this after its release starts over at `cooldown`. |

A change is a new improvement (any cause), a performance switch to another provider, or a flip-back to the native path. The change that would pass `max_flips` is not made: the improvement is withdrawn (or never announced) and the prefix stays on the router's native path until the cool-down ends, even while another provider keeps measuring better. Each repeat offense doubles the cool-down, up to `max_cooldown`. It only withdraws and blocks; it never announces, and `hold_time`, `confirm_rounds`, the cap, the allowlist, and the route check apply as before. The quarantine is in memory: a restart or an HA handover clears it.

A start and an end are logged (`flap quarantine started`, `flap quarantine released`), emitted as `flap.quarantined` and `flap.released` ([EVENTS.md](EVENTS.md)), and written to the audit log as the `system` actor (`flap.quarantine`, `flap.release`). `GET /api/quarantine` lists the parked prefixes (`prefix`, `since`, `until`, `flips`, `strikes`); `/api/prefixes` rows and the prefix page carry the same `quarantine` object. `POST /api/quarantine/release` with `{"prefix": "..."}` (operator role, auth required) ends one early and is audited; a prefix that flips again is parked again for longer. Metrics: `packeteer_flap_quarantined` (count) and `packeteer_flap_quarantine{prefix,strikes}`. `flap_quarantine` applies on a SIGHUP reload without a restart.

### `verify`

Steer verification (#305). Off by default. After Packeteer announces an outbound improvement or an inbound steer, it waits one window and then reads the interface counters of the providers involved (a `telemetry` plugin: `snmp`, or `fixed` for a lab). It reports the steer as `verified`, `partial`, `not_moved`, or `unknown`. A steer that is `partial` or `not_moved` is a routing anomaly: a `steer.unverified` event ([EVENTS.md](EVENTS.md)). Only a steer that was actually announced is checked: not observe or suggest, not a moderated inbound steer. A check is dropped, not judged, if its route leaves the wire first (a mode change, an allowlist change, a failed sync, a release or retire). Unknown keys are errors, and a change needs a restart.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` turns verification on. Other keys need it. |
| `outbound_window` | `5m` | How long after an outbound improvement the traffic must show on the new provider. 10s to 1h. |
| `inbound_window` | `10m` | The same for an inbound steer. Longer, because inbound telemetry lags more. 10s to 1h. |
| `verified_pct` | `50` | The share of the expected traffic that must have moved for `verified`. Above 0, at most 100. |
| `moved_pct` | `10` | Below this share nothing moved (`not_moved`); between the two it is `partial`. Above 0 and below `verified_pct`. |
| `min_mbps` | `1` | The least expected traffic worth judging. With less (or no flow volume for the prefix) the steer is `unknown`, because counter noise would decide it. |
| `backout` | `[inbound]` | Directions whose steer is undone when it is `not_moved`: `inbound`, `outbound`, both, or `[]` for report only. Outbound is only reported by default. |
| `backoff` | `30m` | How long a backed-out steer is held off. It doubles for each consecutive back-out of the same target (the prefix, or the provider), up to `max_backoff`, and starts over after a verified steer. |
| `max_backoff` | `4h` | Not shorter than `backoff`. |

What is compared:

- **Outbound.** The expected traffic is the prefix's volume at the steer (the `flow` window, or `mbps` on a `static` target). What moved is the smaller of the fall in the old provider's outbound rate and the rise in the new provider's, so demand falling or an unrelated flow does not pass for a move. With only one of the two providers on telemetry, that side alone is used and the detail says so. The new path's loss and RTT before and after are compared with the `thresholds` rule read backwards: a path that got worse under the new load sets `path_degraded` and is named in the detail. The withdraw of a degraded path is the existing decision rule (the native path is better again, after `hold_time`); verification does not add a second one.
- **Inbound.** The expected traffic is the steered-away provider's inbound rate at the steer. What moved is the smaller of its fall and the rise on the other providers.
- A counter must have been read after half the window, or the check waits one more window and is then `unknown`. An `unknown` steer sends no event and undoes nothing.

A back-out goes through the controller that made the steer. An inbound back-out releases the steer (the route is withdrawn on the same round) and blocks it for the back-off, shown under `blocked` on `/api/inbound` with a `verification` reason. An outbound back-out retires the improvement and keeps the prefix from being improved again until the back-off ends. Both are logged (`steer backed out`) and emitted (`improvement.removed`, `inbound.released`). Nothing here announces: verification only judges, and the safety rules (allowlist, community, NO_EXPORT, `max_improvements`, `hold_time`, withdraw on shutdown) are unchanged. The results are `GET /api/verification` and the Improvements page ([ui.md](ui.md)). Rollback: remove the block and restart.

```yaml
verify:
  enabled: true
  outbound_window: 5m
  inbound_window: 10m
  backout: [inbound]
```

### `thresholds`

| Key | Default | Bounds |
|---|---|---|
| `min_loss_delta_pct` | 0 | 0-100. Inject requires a value greater than 0. |
| `min_rtt_delta_ms` | 0 | Not negative. Inject requires a value greater than 0. |
| `min_rtt_delta_pct` | 0 | 0-100. 0 is off. Not required for inject. |
| `confirm_rounds` | 1 | 1-100. Omitted or 0 means 1. Not required for inject. |
| `require_evidence` | `false` | `true` refuses a new performance move or performance switch unless both compared samples rest on more than ICMP (#202). Off by default. |
| `med_tie_break` | `true` | `false` turns off the MED tie break (#303). |
| `med_margin` | 20 | Not negative. The score difference inside which the MED decides. |

A candidate wins when its score is lower and either loss improves by at least `min_loss_delta_pct`, or loss is no worse and average RTT improves by at least `min_rtt_delta_ms`. A loss win does not use `min_rtt_delta_pct`. When `min_rtt_delta_pct` is greater than 0, an RTT win must also be at least that percent of the current path's RTT; both the milliseconds and the percent have to be true. If `min_rtt_delta_ms` is 0, an RTT win never fires.

`confirm_rounds` is how many consecutive fresh probe rounds a new performance move, or a switch onto a better provider, must win before it is created. 1 announces on the first fresh win. A stale round does not count and does not reset the streak. The same measurements seen again (a RIB change, or the staleness ticker) are not a new round. When this instance's fresh results for the prefix come from different probe rounds (a timed-out round stored some providers and left another on its previous result), no performance move or switch is made for it and the streak neither starts nor extends, at every `confirm_rounds` value including 1 (#381). Above 1, a round extends the streak only when every fresh result this instance measured for the prefix is newer than its results at the last counted round. Paths from federation peers are not part of either check: a peer probes on its own schedule. A fresh round that does not win resets the streak, including a performance switch off a commit or cost steer. Wins on every performance switch count during `hold_time`; the switch is created only after `hold_time` has elapsed and the streak is complete.

`require_evidence` is the opt-in rule of #202. Routers rate-limit and deprioritize ICMP, so ping loss is often not real loss. With it on, a performance move (a new improvement, or a switch onto a better provider) is made only when the current path's sample and the challenger's sample each rest on more than ICMP: a reply to the `tcp`, `udp`, or `https` prober, or passive agreement (see the probe section on confidence). An `icmp`, `exec`, or other prober type is not known to be more than ICMP. The decision then reads `require_evidence: no evidence beyond ICMP for <provider> (<evidence>)`, the `evidence` gate of `GET /api/decisions/<prefix>` fails, and the confirm streak does not start. The rule is checked after the cooldown, the allowlist, and cost precedence, and the `evidence` gate fails only on a move it refused. Flip-back to the native path, static pins, and commit or cost moves do not use it: under `precedence: cost` a native path inside the floor is still kept, and the planner may still steer the prefix to a cheaper path inside the floor. A refused performance switch off a commit or cost steer leaves the steer to its planner; the `evidence` gate names the refusal. The rule never announces. With it off (the default) behavior is unchanged.

`med_tie_break` makes the MED a neighbor AS sends a tie break between its own exits (#303), for links to one transit and for exchange members, including MEDs a route server passes on. It reads the MED and first AS of each provider's learned path for the exact prefix, so both exits need a path in the RIB view (add-path or BMP); a provider whose paths have no MED or disagree takes no part. MEDs are compared only between exits with the same first AS. With the weighted scorer's defaults, a `med_margin` of 20 is 20 ms of RTT or 0.2 points of loss. For a new performance move or a performance switch:

- Among exits of one neighbor AS that score within `med_margin` of the best, the one with the lowest MED is taken, if it still beats the current path on the thresholds.
- When the native exit is the one the neighbor prefers by MED and the challenger scores within `med_margin` of it, nothing moves. The decision reads `med: AS64496 prefers ...; native path kept` and the `med` gate of `GET /api/decisions/<prefix>` fails.
- A move onto an exit with a higher MED than another usable exit of the same AS, past the margin, is an override: the improvement, the decision, and `/api/prefixes` carry `med_override`, the prefix card shows it, and a `med.overridden` event is sent ([EVENTS.md](EVENTS.md)).

Flip-back, static pins, and commit or cost moves do not read the MED. The RIB view's own path selection never does. The tie break never announces anything a performance move would not.

While the streak is short and this evaluation compared the paths, that prefix is probed again after a quarter of its probe interval; those packets still wait on `probe.rate_limit_pps`. A round that cannot compare (native provider down or unusable, RIB next hop matches no provider, a static pin, a cooldown, or a native path inside the cost floor) keeps the streak and does not ask for that early probe. Flip-back does not wait: when the native path is better again, the improvement retires on the first fresh round after `hold_time`. A static pin, a commit move, and a cost move are not confirmed.

### `providers`

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique. |
| `source_ip` | yes, except in another domain | Source address of probes. Unique across providers unless every provider on it sets a distinct `fwmark` or `dscp`. Must be configured on the host. Same address family as `next_hop`. Must be empty for a provider in another `domain`. |
| `next_hop` | yes | BGP next hop used if this provider is selected. Also how a learned route is matched to a provider. For a provider in another domain, the address this POP's routers reach that POP's exit at across the backbone. |
| `asn` | no | The provider's own AS, 1 to 4294967295. A label: the Providers page shows it with the type and AS search finds the provider by it. No decision reads it. `0` or omitted is not set. |
| `type` | no | `transit`, `peer`, or `customer`. A label shown on the Providers page; no decision reads it. Omitted is not set. |
| `local_pref` | no | Local preference on routes steered to this provider (#132). Wins over `local_pref_cause` and the global `local_pref`. Omit it to use those. `0` is rejected in every mode. Set it above the edge's native local preference. |
| `communities` | no | Extra communities on routes steered to this provider (#132), added after the cause's. The export policy does not match them. The same rules as [`communities_cause`](#communities_cause): at most 16, standard or large, no duplicates, not `packeteer_community`, and no `0:x` or `65535:x`. Omit it for none. An unknown provider name is rejected. Changing it requires a restart. |
| `domain` | no | Routing domain (POP) the provider exits in (#30). Empty or equal to the top-level `domain` is local. A provider in another domain is not probed here: the peer there measures it. Needs `federation` and an `inter_dc_rtt` entry for the domain; `bmp` and `add_path` do not apply. |
| `exclude` | no | `true`: still probe, never select for an improvement. |
| `group` | no | Load-balancing group. Empty means the provider is not in a group. Letters, digits, `_`, `.`, `-`, at most 64 characters, starting with a letter or digit. |
| `precedence` | no | Commit-control preference. Lower is preferred. `0` or omitted means 100. 0-10000. The highest precedence among providers that can take commit traffic is the last resort. |
| `cc_disable` | no | `true`: leave this provider out of commit control in both directions. Performance improvements can still select it. |
| `cost` | no | Price per Mbps, 0-1000000000, in one currency across all providers. Omitted means no cost: the `cost` scorer never moves a prefix onto this provider or off it for price. Improvements between two priced providers carry `cost_delta` and `est_savings` on `/api/improvements`. |
| `interface_capacity_threshold_pct` | no | Overload protection (#307), 1-100. See [Interface capacity limit](#interface-capacity-limit). `0` or omitted is off. Needs a `telemetry` entry that binds the provider to an interface. |
| `bmp` | no | How this provider uses paths from `rib_sources` (BMP): `off` (default), `prefer`, or `only`. `prefer` and `only` need a `rib_sources` entry. See [RIB source `bmp`](#rib-source-bmp). |
| `add_path` | no | `true`: apply the route check to this provider from the iBGP add-path paths. Needs a `bgp.neighbors` entry with `add_path: true`. Not allowed with `bmp: only`. See [Add-path](#add-path). |
| `path_check` | no | First-hop probe-path check (#150). `true` or omitted checks; `false` opts out. See [`probe.path_check`](#probepath_check). |
| `fwmark` | no | Linux fwmark set on this provider's probe sockets (#157), so providers can share a `source_ip`. 0 or omitted: no mark. Needs `--cap-add NET_ADMIN`; without it the provider is down. Unique per `source_ip`. |
| `dscp` | no | DSCP, 1-63, set on this provider's probe packets (#157). 0 or omitted: none. Unique per `source_ip`. Must be empty for a provider in another `domain`, like `fwmark`. See [policy-routing.md](policy-routing.md#many-providers-on-one-source_ip). |

### Interface capacity limit

Commit control only moves traffic off a provider that is over its commit. A provider with no commit can still be overloaded by performance steers piling onto it. `providers[].interface_capacity_threshold_pct` (for example `85`, #307) limits the share of the provider's interface capacity its outbound rate may reach, whether or not it has a commit.

- **Reading.** The provider's [telemetry](#telemetry-snmp) row gives the latest outbound rate and the capacity: `capacity_mbps` on the binding, else the speed the agent reports (`ifHighSpeed`, else `ifSpeed`). A binding needs no `commit_mbps`, `billing_day`, or `percentile` for this. A reading older than 15 minutes counts as missing, so keep the SNMP `interval` below that.
- **Refusal.** A new performance steer (including a switch) onto the provider is refused when the rate plus the steer's flow volume would pass the limit. A steer made after the latest sample and announced is added to that sample's rate, and so is each steer allowed earlier in the same round. A prefix with no known volume is judged on the current rate alone. A missing, stale, capacity-less, or not yet sampled reading refuses every new steer onto the provider, because its headroom is unknown. Static policy pins and commit or cost steers are not refused.
- **Shedding.** While the rate is past the limit, performance steers onto the provider are withdrawn, lowest gain first (the score difference to the native path; larger volume first on a tie), until the rate less their volume is back inside the limit. A steer younger than `hold_time` stays. A shed prefix waits `hold_time` before it can be steered again. A provider is shed once per telemetry sample, and not again until `hold_time` has passed since the last shed, because the sample does not hold the effect of a shed yet. Set `hold_time` at least as long as the telemetry `interval`.
- **Observe.** Recommendations are judged like announced steers, with every recommendation on the provider counted because none of them moves traffic, so observe shows what inject would do. No route is announced.
- **Reporting.** A refused decision says `overload: ...` in its reason, shows a failed `overload` gate on the Why? panel, and is listed with `overload.refused`; a shed sends `overload.shed`; `overload.cleared` follows when the provider is back inside the limit ([EVENTS.md](EVENTS.md)). `/api/telemetry` and the Commit & Cost page show `capacity_mbps`, `utilization_pct`, `capacity_threshold_pct`, and `overloaded`.

The flow volume is read like commit control reads it (a source with traffic data, such as `flow`). The key needs a restart to change, like the other `providers` keys.

### `allowlist`

| Key | Meaning |
|---|---|
| `prefixes` | CIDRs with no host bits. Duplicates are errors. |

A learned prefix is eligible when it is equal to an entry or more specific and inside it. Packeteer still announces that learned prefix, not a prefix it invented. An entry of `198.51.100.0/24` allows `198.51.100.0/24` and `198.51.100.128/25` when the router advertised that exact prefix. It does not allow a shorter prefix that covers the entry. An entry that overlaps any `exchanges[].lans` prefix is a load error in every mode, including `observe`: equal to the LAN, more specific and inside it, or a supernet that contains it. Adjacent prefixes do not overlap.

### `probe`

| Key | Default | Bounds |
|---|---|---|
| `interval` | `30s` | Greater than `timeout`. Also the period of the staleness check. |
| `timeout` | `2s` | Per packet. Must be shorter than `interval`. |
| `packets` | 10 | 1-1000. |
| `workers` | 8 | 1-1024 concurrent probe runs. A free worker takes the next job for the provider with the fewest jobs running, so a provider whose probes time out holds at most its share of the workers while the others have work (#381). |
| `rate_limit_pps` | 100 | 1-100000 packets per second, global. |
| `per_target_concurrency` | 2 | 1-64 concurrent runs toward one destination host. |
| `retry_loss_pct` | 0 | 0-100. `0` disables loss retry. Above zero, a sample whose loss is at least this percent is probed again before it is stored. |
| `retry_packets` | 0 | 0-1000. Packet count of that second probe. When `retry_loss_pct` or `dispersion_ms` is set and this is `0`, it becomes three times `packets`, capped at 1000. A value set while both of those are `0` does not run a second probe and does not extend the staleness window. |
| `min_replies` | 1 | 1-1000. `0` uses the default. A host qualifies only with at least this many replies. Fewer replies drop it from the score the way a silent host does. They do not start a retry. |
| `dispersion_ms` | 0 | 0-600000 milliseconds. `0` disables the spread check. Otherwise a host qualifies only when its RTT spread (the slowest reply minus the fastest, not a standard deviation) is at most this. A spread equal to the limit qualifies. One reply has a spread of zero. A wider spread drops the host the way a silent host does and probes the prefix again with `retry_packets`. |
| `degraded_loss_pct` | 5 | Greater than 0, at most `down_loss_pct`. `0` uses the default. A provider whose mean loss over its measured prefixes is at least this shows `degraded` on the dashboard (#343). A probe that errored counts as 100% loss. Label only: no decision uses it. |
| `down_loss_pct` | 50 | At most 100. `0` uses the default. At or above this mean loss a provider shows `down`; a provider that got no reply on any prefix is always `down`. |
| `prober_recheck_rounds` | 10 | 1-10000. `0` uses the default. Probe 1, 11, 21, ... of a host starts at the first prober when this is 10. `1` starts every probe at the first prober. |
| `prober_memory` | 100000 | 1-1000000 hosts. `0` uses the default. Least recently probed hosts are dropped past the cap. |
| `indirect` | off | Per-provider indirect probing for silent prefixes (#123). See [`probe.indirect`](#probeindirect). |
| `reorder` | off | Packet reordering per provider path (RFC 4737, #224). See [`probe.reorder`](#probereorder). |
| `path_check` | on | First-hop probe-path check per provider (#150). See [`probe.path_check`](#probepath_check). |
| `exclude` | none | `prefixes` (CIDR, no host bits) and `asns` (non-zero) that no target source may probe (#203). See [`probe.exclude`](#probeexclude). |
| `per_asn_pps` | 0 | 0-`rate_limit_pps`. Probe and trace packets per second toward one destination origin ASN. `0` is no per-ASN cap. See [`probe.exclude`](#probeexclude). |

### `probe.exclude`

`probe.exclude` keeps probe packets away from networks that must not be probed (#203). It applies to every target source (`static`, `flow`, `vip`, `outage`, `span`, `traceroute`, and an `exec` source), to a prefix a retained improvement keeps measured, and to the operator's probe queue. A `prefixes` entry excludes every target equal to or inside it and every probe address inside it, a provider's `next_hop` included; a target that covers an entry keeps its other addresses. An `asns` entry excludes every destination (a `next_hop` too) whose longest learned covering route it originates, read from the RIB view when the target list is built and again before each probe; until the view is ready only the prefix list applies. The `traceroute` source does not trace an excluded target, and neither it nor `probe.indirect` adopts a hop that is excluded. The exchange-LAN rule (#145) is unchanged and runs first. The troubleshooting tools probe the operator's target unfiltered; their indirect fallback does not adopt an excluded hop. Excluded targets are counted in the debug log and get no result, also on a round where a target source timed out. An address whose origin moves into an excluded ASN after the target list was built gets no packet and counts as a silent host; the prefix's other addresses and the provider's `next_hop` are still probed and can score it, and no `probe.indirect` trace heads for that address.

`per_asn_pps` caps the packets per second toward one destination origin ASN. It covers the prober chain, `probe.indirect` traces, the `traceroute` source's discovery traces, and the troubleshooting indirect fallback; a trace packet counts against the ASN of the destination it is traced toward. Each packet waits on its ASN's cap first, then on `rate_limit_pps`; the `traceroute` source does not wait on `rate_limit_pps`, as before. A `traceroute` target whose wait outlasts its share of `budget` keeps the hops it already has, or its previous host, and the pass moves on to the next target. The troubleshooting tools' own probes and traces of the operator's target, and the `probe.path_check` packet, are not capped per ASN. A destination with no learned origin is not capped here. A reload that raises `probe.packets` or `retry_packets` is paced by the cap, not refused. Both keys need a restart. [operating.md](operating.md#probing-options) suggests how to name the probe source addresses so a probed network can find you.

When a target names no host, each provider is measured at a few addresses inside the prefix (at most three: the first host, and on a larger prefix a quarter point and a halfway point) and at that provider's `next_hop` when it is a usable far-side address (unicast, same family, not the probe source). At most four addresses. A host set on `static`, `vip`, or `traceroute` is a pin and is the only target. A flow prefix names up to three destinations (see [Source `flow`](#source-flow)). Those are probed first. Automatic addresses are added only when fewer than three were named, and a usable next hop still takes the last slot.

A host with fewer than `min_replies` replies, or with an RTT spread wider than `dispersion_ms` when that is set, is left out of the loss and latency when another address inside the prefix qualifies, the same way a silent address is. When no address qualifies, every measured host still counts, so the loss is reported. The next hop is part of that score only when no in-prefix address qualified. It is not a provider, and picking it announces nothing. Traceroute hop times are not the score. `targets` on each probe result lists every address tried.

A measurement older than `3 * interval + packets * timeout` is stale. When a second probe can run (`retry_loss_pct` or `dispersion_ms` is set, so `retry_packets` is in use) the window is `3 * interval + (packets + retry_packets) * timeout`. `min_replies` alone does not extend it. That same duration is the deadline for one probe round. The decision loop also wakes every `interval`, so a round that never finishes still withdraws once results are stale.

A completed round stores every result at once. A round that hits the deadline stores every probe that finished (#125, #381), together and only when the round ends, so one measurement round counts once toward `confirm_rounds`. A provider whose probe is still running keeps its previous result for that prefix, so a provider that never answers does not cost the others their results, and its result goes stale on its own. Each stored result carries `round`, the time the round that stored it ended. While a prefix's fresh results differ in `round`, no performance move or switch is made for it (see `confirm_rounds` above). A prefix with at least one finished probe counts as probed: its unfinished provider is tried again at the prefix's next interval. A prefix with no finished probe keeps all its previous results and stays due. A timed-out round still drops a prefix that left every source. The next pass continues with prefixes that are still due and does not wait out the interval of one that already finished.

A job probes the hosts of one prefix on one provider in turn. A provider looks down when none of its jobs got a reply in the last round where one finished, and none of its finished jobs in this round got one either. Its later jobs in that round skip the remaining in-prefix hosts after two hosts get no reply (a probe error counts as no reply) and none has answered (#381), and skip `probe.indirect` for that prefix: no trace is queued and no cached hop is probed. The provider's far-side gateway is still probed, because it scores the prefix when no in-prefix host answers. `targets` on the result lists the hosts that were probed. A provider that got any reply in its last round probes every host, so a third host that answers is not skipped.

Due prefixes are ordered urgent first (a confirm streak, or a source that marked the target), then a shorter interval than `probe.interval` (VIP), then the engine interval (flow `top_n` and ordinary targets), then a longer interval (the flow tail). Prefixes in one tier keep the order the sources returned. The decision engine runs when the round stored at least one prefix, including a round the deadline cut short. It does not run when the deadline hits before any prefix finishes; those previous results stay, and the staleness check still withdraws them once they age out. Every packet still waits on `rate_limit_pps`.

The retry sample replaces the first one. It runs when loss is at least `retry_loss_pct`, or when any host's RTT spread is over `dispersion_ms`. Too few replies do not start it. It runs once. Both waits go through `rate_limit_pps`.

Every stored result carries a `confidence` (#202): `level` (`high`, `medium`, `low`, or `none` for a failed probe), `score` (0 to 1), `protocol` (the type of the prober that produced it; `federation` for a path a peer POP measured, which is not evidence beyond ICMP on its own), `replies` and `sent`, `indirect` (a traceroute hop), `wide_spread` (the RTT spread is over `dispersion_ms`, or over the mean RTT when that is not set; needs two replies), and `passive` (`agree` or `disagree`). The score starts at 1 and halves for each weakness: a prober that is not `tcp`, `udp`, or `https` without passive agreement, a traceroute hop, a wide spread, and passive disagreement; one reply halves it, two replies take a quarter, no reply takes three quarters. `high` is at least 0.75, `medium` at least 0.4. Passive agreement comes from a `span` source or a `flow` source with a `problems` block: for a prefix with enough TCP traffic in that window to judge, the sample on the provider that carries the traffic (the native provider; in inject with an active improvement, that improvement's provider) agrees when the probe shows loss and the traffic is over the source's problem thresholds, or shows none and the traffic is clean, and disagrees otherwise. Agreement counts as evidence beyond ICMP. Confidence is shown on `/api/probes`, `/api/prefixes`, `/api/decisions`, and the prefix card; it changes no decision unless `thresholds.require_evidence` is on.

The engine remembers, per destination host, the prober that got a reply and starts the next round there (#120). The chain then moves forward: a later prober runs when the remembered one errors or gets no replies. Earlier probers run when the probe number of that host modulo `prober_recheck_rounds` is 1 (the 1st, 11th, 21st, ... measurement at the default of 10), so a host that begins answering ICMP is noticed. Every provider shares that memory, and the rounds compare them with one probe type. When providers in one round first get replies from different probers, the later prober in the chain is remembered.

A retry (loss or dispersion) uses the same start as the sample it rechecks and does not count as another probe toward the schedule. Every prober that runs still waits on `rate_limit_pps`; a prober that is skipped sends nothing. Hosts that are no longer in the target list are dropped on the next completed round, including a round that probes nothing because nothing is due. A prefix an improvement still keeps probed keeps its host's prober. Past `prober_memory`, the least recently probed hosts are dropped and their next measurement starts at the first prober.

On-demand troubleshooting walks the full chain and does not read or update this memory. Nothing is announced.

Targets from the `vip` source carry their own interval; the scheduler probes a prefix when that interval has elapsed and leaves the other results in place. A VIP interval can only shorten the cadence. An unset target interval means `probe.interval`, so a longer VIP interval does not slow a prefix that static or flow already listed. Sources that do not carry a shorter interval are re-read on `probe.interval`, not on every VIP wake. The `outage` source is the exception: it is read on every round, including a short VIP wake, so a pattern detected at the end of a round is a target on the next one.

A new incident also wakes the probe loop immediately, and those prefixes are marked urgent for that one pass. A completed round, including one that only probed VIP prefixes, still runs the decision engine. `Run` is what the process uses. A prefix that disappears from every configured source is dropped on the next completed round, including a round that probes nothing because nothing is due, unless an improvement for it is still active. While the improvement is active the engine keeps the prefix as a probe target, with the last host and interval, even after every source has stopped listing it (for example it falls out of flow `top_n`).

That does not retire the improvement. It retires on flip-back, `improvement_ttl`, a provider that is down, excluded, or otherwise unusable, a confirmed RIB leave, policy, or the allowlist, and when the prefix has no measurement at all. The retained set is applied on every completed round, including one that only probes a shorter cadence, and it is not cached for `probe.interval`. After the improvement retires, if no source lists the prefix, the next completed round drops the target. Nothing new is announced: the prefix was already an improvement, and every announce still goes through the decision engine.

#### `probe.indirect`

Off unless this block is present with `enabled: true`. When every address probed inside a prefix is silent for a provider (no replies on any prober), that prefix is queued for a UDP traceroute from **that provider's** `source_ip`. The highest stable hop on that trace becomes the provider's indirect host for the prefix, so each provider is measured at its own last responding router toward the destination instead of at its `next_hop`, which only measures the access link. It applies to every target source (static, flow, VIP, outage, span, traceroute), but not to a pin outside the prefix, such as a hop the `traceroute` source already picked.

| Key | Default | Bounds |
|---|---|---|
| `enabled` | `false` | `true` turns it on. Omitting the block is the same as `false`. |
| `max_hops` | 16 | 1-64. |
| `probes` | 3 | 1-10 probes at each TTL. |
| `min_replies` | 2 | 1-`probes`. A hop is stable when one address answers at least this many times and there is no tie. When `probes` is 1 the default is 1. |
| `timeout` | `500ms` | `1ms`-`5s` per trace packet. |
| `port` | 33434 | 1-65535. Destination UDP port. |
| `budget` | `10s` | At least `timeout`, at most `30s`. Wall clock for one background pass across every queued trace. Each trace gets an equal share, at least `timeout`. Traces the pass did not reach stay queued. |
| `cache_ttl` | `30m` | `1m`-`24h`. How long a hop, or a trace that found none, is reused before the prefix is traced again. |
| `max_queue` | 1024 | 1-100000. Traces waiting for a pass. Past this, a silent prefix is asked for again on a later round. |

Tracing runs in the background and never inside a probe round. A pass starts when a trace is queued, and passes are at least `probe.interval` apart. The first round that finds a prefix silent keeps the normal result (the `next_hop` or full loss); once the trace finishes, later rounds probe the cached hop with the normal prober chain and `packets`. When the hop qualifies under `min_replies` and `dispersion_ms`, it defines that provider's score, `indirect` is `true` on the probe result, `target` is the hop, and `targets` lists the silent in-prefix addresses followed by the hop. The dashboard labels that row `indirect`.

A hop that stops answering is not scored as 100% loss: the entry is dropped, the normal result stands, and the prefix is traced again. When any address inside the prefix answers again, the direct score wins and the cached hop is dropped. The destination itself, the provider's own source address, loopback, link-local, multicast, and any address on an `exchanges[].lans` peering LAN are never adopted. Hops of a prefix that leaves every source are dropped on the next completed round. A provider whose `source_ip` cannot be bound fails that trace without caching it; its normal probes already fail closed.

Indirect results skip the loss and dispersion retry.

The stable hop addresses, in TTL order, stay in the cache and are copied onto the probe result (`hops`) while the trace is fresh, including when the best hop is not adopted as an indirect host. The `outage` source maps those addresses to origin ASNs. Dropping the cache drops the hop list. Every trace packet waits on `probe.rate_limit_pps`, as does every probe of an indirect hop. The trace shape matches the `traceroute` source (three silent TTLs after a stable hop end it). The socket calls are Linux-only; the container image is Linux. Measurement only: nothing is announced for a hop, and the learned-RIB check, allowlist, `max_improvements`, community and NO_EXPORT, hold time, and withdraw rules are unchanged.

#### `probe.reorder`

Off unless this block is present. Trains of sequence-numbered packets go from every provider's `source_ip` to each responder, and the arrival order of the replies gives the RFC 4737 reordered ratio, reordering extent, and n-reordering per train ([reordering.md](reordering.md)). Every packet of a train leaves one socket, so a train keeps one 5-tuple and stays on one ECMP member; `flows` trains per responder, each from a new source port, sample the members, and the provider's reading is the worst flow. A `twamp` responder is a TWAMP-Light reflector you run (`packeteer-reflector`), and its reading is a measurement. An `icmp` responder is any host that answers echo; its reading is an estimate, labelled as such everywhere, sent as one train, and never an input to a decision. Measurement only: nothing is announced, and a reading enters the score only through a scorer's `reorder_weight`.

| Key | Default | Bounds |
|---|---|---|
| `packets` | 20 | 2-200. Packets per train. |
| `spacing` | `20ms` | `1ms`-`1s`. Gap between the packets of a train. Reordering closer than this is not visible. |
| `timeout` | `probe.timeout` | `1ms`-`30s`. How long the last packet's reply is waited for. |
| `interval` | `probe.interval` | `1s` to three times `probe.interval`. Time between measurements; the next starts when the last ends if that is later. |
| `flows` | 4 | 1-16. Trains per `twamp` responder and provider, each on a new socket. An `icmp` responder gets one. |
| `responders` | required | 1-64 entries: `address` (an IP), `type` (`twamp`, the default, or `icmp`), and for `twamp` a `port` (default 862). An `icmp` entry takes no port. No duplicates, and no address inside a `probe.exclude` prefix. |

Every train waits on `per_asn_pps` and `rate_limit_pps` for its packets, and `packets` may exceed `rate_limit_pps` (one train is one wait). The trains of a measurement run one at a time. Validation takes the longest measurement (every train `packets` times `spacing` plus `timeout`, plus all its packets at `per_asn_pps`, or `rate_limit_pps` without it) and refuses a config where the larger of that and `interval`, plus that again, exceeds three times `probe.interval`, since a reading could then go stale before the next. Probe engine packets on the same budget can still delay a measurement; a stale reading is dropped from the score. The monitor builds its own `twamp` and `icmp` probers with their defaults; the options of a `probers` entry do not apply to the trains. A responder whose origin ASN is in `probe.exclude` gets no packet and reports `excluded by probe.exclude`. A provider in another `domain` is not measured here. The block is restart-only.

#### `probe.path_check`

Each provider expects probes from its `source_ip` to leave through its `next_hop` (see [policy-routing.md](policy-routing.md)). A mis-routed source silently measures another provider's path. Every `interval`, one UDP probe with TTL 1 is sent from the provider's `source_ip` toward a documentation address; the reply comes from the first router past the edge, which must be that `next_hop`. A different reply address, no reply, or a send error marks the provider down with reason `probe path mismatch` and emits `provider.down`; a later match clears it and emits `provider.up`. A provider that is down is excluded and its improvements are withdrawn ([EVENTS.md](EVENTS.md)). Measurement only: nothing is announced, and the learned-RIB check, allowlist, `max_improvements`, community and NO_EXPORT, hold time, and withdraw rules are unchanged.

| Key | Default | Bounds |
|---|---|---|
| `enabled` | `true` | `false` stops the checks. |
| `interval` | `5m` | `1s` to `24h`. How often every provider is checked. |

A provider opts out with `path_check: false`; an exchange peer does the same. Opt out when the source's traffic does not leave the edge directly through `next_hop`, for example a provider reached across another router. A provider in another `domain` is not checked here. A loopback `source_ip` is skipped: its traffic never leaves the host. The probe waits on `probe.rate_limit_pps` and uses `probe.timeout`. The probe destination is a documentation address (TTL one, so it is never reached), so the check sends nothing toward a customer prefix. The socket calls are Linux-only; on other systems the check does not run. A `source_ip` that cannot be bound is reported by the normal probes and is not re-labelled a path mismatch.

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
| `config_editor` | unset | Unset: the editor and wizard are on for an admin only while the first-run setup is pending (#416), and only with `auth` or basic auth. Setup is pending only when no setup state is saved (no storage file and no `first-run-setup-pending` file next to it) and every provider `source_ip` is in 192.0.2.0/24, the placeholders in `config.example.yaml`. A config with a real provider keeps the editor off, so an upgrade, or a container re-created without its volume, never reopens it. It stays pending until an admin saves a config through the editor or wizard, or presses Skip setup, and the editor stays on until the next restart; the state is that file, so it survives restarts with the `/var/lib/packeteer` volume. Storage with no file (memory) has no saved state, so the placeholder check alone decides on each start. The federation settings-push receiver ([multi-pop.md](multi-pop.md)) never follows this default: it needs an explicit `true`, and an accepted push ends a pending setup like a save. `false` turns the editor off. `true` lets an admin read, validate, and write this config file through `/api/config` and `/settings.html` (#34). Needs `auth` or basic auth; with neither it stays off. A write passes the same checks as a start and is read back through the loader. When every change is an [online key](#online-reconfiguration), the running controller applies it on the write (#128). Anything else applies on restart. Turning `mode: inject` on through it needs an explicit confirmation. It never runs an `exec` plugin, and refuses a file that adds or changes one or changes `plugin_dir`. `GET /api/config` returns the file unredacted, so keep secrets in environment variables. The file must be mounted writable. See [ui.md](ui.md). |

The server does not announce routes. With `--network host`, this address is on the host. Basic auth is not a key in the file; see the environment variables. With neither basic auth nor an explicit `auth.enabled`, sign-in is on. Users, roles, API tokens, and SSO are the `auth` block.

### `auth`

Users, roles, API tokens, the audit log, and optional OIDC single sign-on for the ops HTTP server (#32). On by default since #328 when the HTTP server runs. Guide: [auth.md](auth.md).

```yaml
storage:
  type: sqlite            # users, token hashes, and the audit log live here
auth:
  enabled: true
  session_ttl: 12h        # sign-in page and SSO sessions
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
| `enabled` | `true` | Unset, it is `true` and `storage` defaults to `sqlite` when the HTTP server runs and `PACKETEER_HTTP_USER` is not set (#328). An explicit `true` requires `storage` (a plugin that keeps users, e.g. `sqlite`) and refuses to start with `PACKETEER_HTTP_USER` set. An explicit `false` keeps the single basic-auth account, or no sign-in at all: the rollback. It logs a warning at start and the UI shows a banner. |
| `session_ttl` | `12h` | Lifetime of a session from the sign-in page or SSO, `5m`-`168h`. Sessions are in memory; a restart signs everyone out. |
| `token_ttl` | `2160h` | API token lifetime when the request names none, `1h`-`8760h`. A request may ask for up to `8760h`. |
| `sso` | none | Single sign-on plugin entry (`type: oidc`). Needs `enabled: true`. |

Roles: `viewer` reads everything a dashboard or API client reads (and manages its own API tokens), `operator` also opens and closes maintenance windows, adds and removes mitigation rules, and runs the troubleshooting tools, `admin` also manages users and reads the audit log. `/healthz`, `/readyz`, the sign-in page and endpoints, and the SSO endpoints are public. The first admin comes from `PACKETEER_ADMIN_USER` and `PACKETEER_ADMIN_PASSWORD`; without a password, the first start generates one ([auth.md](auth.md#first-run)). Auth never changes what is announced: allowlist, learned-RIB check, community, NO_EXPORT, `max_improvements`, hold time, and withdraw-on-failure are the same for every role.

### `bgp`

| Key | Default | Meaning |
|---|---|---|
| `listen_port` | 0 | `0`: do not listen; Packeteer connects out. 1-65535: accept sessions. |
| `listen_addresses` | none | Local addresses to bind when listening. Each must be an IP address. |
| `neighbors` | none | Edge routers, iBGP, same ASN as `asn`. Reloaded online on SIGHUP; see [Online reconfiguration](#online-reconfiguration). |
| `as_path` | `empty` | AS path on injected routes: `empty`, `native`, or `provider`. See [AS path](#as-path). |
| `not_established_after` | 5m | Not negative. `0` uses the default. A neighbor that has not reached Established this long after Packeteer first saw it raises `bgp.session_not_established` once ([EVENTS.md](EVENTS.md#catalog), #347). A session that came up and dropped raises `bgp.session_down` instead. Restart-only. |

Each neighbor:

| Key | Default | Meaning |
|---|---|---|
| `address` | required | Peer IP. Duplicates are errors. |
| `port` | 179 | Remote TCP port. `0` means 179. 0-65535 at validation; `0` is replaced when the session is built. |
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
- **Packeteer's own route.** An iBGP path tagged with `packeteer_community`, standard or large (a reflector or router sending Packeteer's route back) is ignored, with or without add-path, so an injected route never keeps its prefix learned or passes its own route check. An extra community does not mark a path as Packeteer's.
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

Paths are read when the route is announced. If the router stops sending the native route once Packeteer's route wins, the path on the wire is kept rather than re-announced. When the provider's learned path changes, the route is replaced with the new one. Packeteer still adds `packeteer_community`, any extra communities from `communities_cause` and the provider, and NO_EXPORT, sets `local_pref`, and never prepends its own AS: the session is iBGP. Lab-proven only (`lab/e2e-ix.sh` checks `provider`).

#### Online reconfiguration

`kill -HUP` the process (`docker kill -s HUP <container>`), or `PUT /api/config` when every change is online, reloads the config file (#27, #128). The next decision uses the new values. Nothing on the wire changes except what that decision withdraws or announces, plus an immediate withdraw when mode leaves inject.

Applied while running:

- `thresholds`, `flap_quarantine`, `hold_time`, `improvement_ttl`, and `max_improvements`. Lowering the cap, including to `0`, retires the lowest-ranked improvements on the next decision, inside `hold_time` and without a cooldown. Planned moves go first, then performance, then VIP, then static pins. Inside a rank the smallest gain goes first, and a larger prefix before a smaller one. Survivors keep their slots. Raising the cap can admit a retired prefix on the next round. With `inbound` configured, `max_improvements` is restart-only: the inbound controller shares the cap and reads it at start, so a reload that changes it is refused (`changed max_improvements (shared with inbound)`).
- `policies` and `sources`. An unchanged instance keeps running. A new or changed one is built and started; a removed one is stopped. The others are not touched. Replacing the flow source the anomaly detector was built with is refused. A source that listens (flow) is stopped and the new one binds the same address when the first start finds it busy.
- Probe timing: `probe.interval`, `probe.timeout`, `probe.packets`, `probe.retry_loss_pct`, and `probe.retry_packets`. The staleness window follows them. `probe.workers`, `probe.rate_limit_pps`, `probe.per_asn_pps`, `probe.exclude`, `probe.per_target_concurrency`, `probe.min_replies`, `probe.dispersion_ms`, `probe.degraded_loss_pct`, `probe.down_loss_pct`, `probe.prober_recheck_rounds`, `probe.prober_memory`, `probe.indirect`, and `probe.path_check` need a restart.
- `mode` and `allowlist`. Leaving inject withdraws every Packeteer route before the mode changes, so a concurrent sync cannot announce again. Entering inject runs the same inject checks as a start, then binds the speaker the process started with. The announcer's mode, allowlist, and cap change only after the plugins swap, so a refused reload never announces. That works only when `packeteer_community`, `local_pref`, the allowlist, the announcer, and the neighbors were already valid: changing those is still a restart, so a file that only flips mode was already able to inject. Shrinking the allowlist retires a prefix that is no longer covered (`not allowlisted`) on the next decision, and the announcer withdraws it.
- `inbound.mode` and `mitigation.mode` (#233). `inject` for either needs `mode: inject` in the same file. `hold_time` and `improvement_ttl` reach the inbound controller: a changed `improvement_ttl` applies to steers already running, a changed `hold_time` to steers created after the reload, and a shrunk `allowlist` withdraws an inbound steer it no longer covers. Entering inject runs the same checks as a start and binds the inbound or mitigation announcer on the running speaker; if the reload is then refused, the speaker keeps the inbound import policy, which announces nothing. If leaving inject fails after one controller already withdrew, the reload is fatal: the process stops and withdraws everything. Leaving inject withdraws that controller's routes under its lock before the mode changes. A mitigation rule held outside inject is dropped on entering it, so a dry-run rule never reaches the edge because a mode flipped. Entering mitigation inject with a FlowSpec catalog is refused (`restart required`) unless the process started in inject with it: the sessions negotiate FlowSpec only at start. Every other `inbound` or `mitigation` key stays restart-only.
- `bgp.neighbors`, as before (#27). A new neighbor gets a session; a removed one is closed (its paths leave the view at once, as on a session loss). A neighbor whose session settings changed (`port`, `local_address`, `passive`, `add_path`) is closed and opened again. Other sessions are not touched. A changed per-router table (`providers`, `next_hops`) replaces the announcer's export policy on the running speaker. Every outbound route is withdrawn first (GoBGP sends a withdraw only where the current policy would send the route, so a route withdrawn after the swap could stay on a router the new table blocks) and announced again under the new table on the next evaluation, once the prefix is back in the learned RIB. Inbound steer routes are not affected. A change that leaves the table as it was (adding a neighbor with no lists to a config with no lists) withdraws nothing. Egress routers are recomputed, so `egress router down` follows the new lists. `bgp.neighbors` cannot become empty on a reload. `bgp.listen_port`, `bgp.listen_addresses`, `bgp.as_path`, and `bgp.not_established_after` need a restart.

The announcer plugin, providers, probers, and every other key stay restart-only. `more_specific`, `synthesize`, `lookup`, and `ixp` (including `ixp.members`, `ixp.vantages`, `ixp.fabric`, `ixp.routeservers`, and `ixp.correlate`) are restart-only. A reload that changes any restart-only key is refused whole, including the online keys in the same file: the log says `config reload refused` with the keys (`restart required: changed local_pref`), and the running config stays. A file that does not parse or validate is refused the same way, before anything is applied. Comments and YAML style do not count as changes. The audit log records each apply (`config.reload`, with the keys) and each refusal.

If a reload fails after it has changed the speaker, Packeteer stops (exit status 1), which withdraws every Packeteer route; the container's restart policy brings it back with the new file. The learned-RIB check, community, NO_EXPORT, and withdraw rules are unchanged. A prefix that is not in the learned RIB is never announced. Environment overlays (`PACKETEER_LOG_LEVEL`, ...) are applied to the reloaded file as at startup. Lab-proven only (`lab/e2e.sh` for a threshold that keeps the route and a cap of 0 that withdraws it; `lab/e2e-ix.sh` for neighbors).

### `ixp`

Exchange-operator mode (#160, [design/ixp.md](design/ixp.md)). Not the [`exchanges`](#exchanges) block, which is an edge network's own peers.

`ixp: {}` turns it on. The keys are `members` (#161), `vantages` and `fabric` (#162), `routeservers` (#164), `correlate` (#163), and `core` and `core_links` (#167). Any other key is an error. Omitted, or `ixp: null`, leaves the file as an edge controller. `mode` stays `observe`. `mode: suggest` is accepted and announces nothing.

`ixp.members` is one plugin (`type: ixf`). It GETs an IX-F 1.0 member list and announces nothing. It is not a RIB source and not an input to Decide. `config.url` is the IXP Manager origin or the member-export path (a subdirectory install ends in `/api/v4/member-export/ixf/1.0`; a bare origin uses that path), or one other IX-F JSON URL. On the manager URL the only query keys kept are `ignore_missing_ixfid=1` and `ixfid_<digits>=<digits>`. `apikey`, `access_key`, and any other query key are refused. Redirects are not followed. The API key is `PACKETEER_IXP_MANAGER_API_KEY`, sent only as `X-IXP-Manager-API-Key`. This import sends it only to the manager URL. A URL that contains the key, including a percent-encoded form, is refused. `key_expires` (`YYYY-MM-DD`, quote it) is required with the key; a date more than 366 days ahead is refused. The controller warns when 14 days or fewer remain. `refresh` (default 15m, 1m-24h), `timeout` (default 30s, 1s-2m), `max_bytes` (default 8 MiB, 1024 to 32 MiB). A failed refresh keeps the last good list until three refresh intervals have passed, then the served list is empty. `GET /api/ixp/members` reads it.

With the block set, validation refuses `mode: inject`, `announcer`, `mitigation` (including `mode: observe`), `inbound` (including `mode: observe`), `synthesize`, and `more_specific` (including `enabled: false`). `bgp.neighbors` is not required. With no neighbors the process does not build a RIB view. Route-server data (`routeservers`) is a separate read-only store and does not enter the RIB view or a decision.

`vantages` lists IX-owned monitoring addresses, at most 64. Each entry has `name` (a letter or digit, then letters, digits, `.`, `_`, or `-`, at most 64 characters), `vlan_id` (the IX-F vlan id, 1 to 1000000), optional `ixp_id` (required when that vlan id is on more than one IXP; omit it when the id is unique), and `address`. The address is unicast and not loopback or link-local. A private peering LAN is allowed. It must sit inside that VLAN's prefix or the vantage probes nobody.

`fabric` is one plugin. The only type is `icmp`. It probes each member LAN address on a vantage's VLAN from that vantage and records loss, RTT, and jitter. It is not a provider, not an input to Decide, and it announces nothing. `vantages` and `fabric` are set together, and `fabric` requires `members`. `interval` (default 1m, 10s to 1h), `timeout` (default 1s, 100ms to 5s, per packet), `packets` (default 5, 1 to 20), `workers` (default 4, 1 to 64), `rate_limit_pps` (default 20, 1 to 10000, global), `member_pps` (default 1, 1 to 10000, per member ASN, and not above `rate_limit_pps`).

Only connection states `active`, `connected`, and `operational` are probed, and only an address inside the VLAN prefix. The vantage address itself is not a target. `can_ping: false` on an IX-F address is an opt-out. When the import is the IXP Manager export, each round also GETs `/admin/api/v4/nagios/customers/{vlanid}/4` or `/6` on that same origin, including a subdirectory install. `vlanid` is the VLAN database id. That is the only extra path. The template suffix and every other nagios route are not called. The same `X-IXP-Manager-API-Key` header is used. The key's user must be a superuser. Redirects are not followed. A host is probed only when a service uses `ixp-manager-member-ping-service` (busy: `ixp-manager-member-ping-busy-service`). The busy template uses the looser warning (1000ms or 80% loss; otherwise 250ms or 20% loss). The busy critical RTT (2000ms) is the minimum per-packet timeout for that host. A failed fetch (a 401 included) keeps the last successful list for three `interval`s after that successful fetch; then that VLAN is not probed until a fetch succeeds. With no successful list, that VLAN is not probed, because the member export omits `can_ping`. A named IX-F URL is not the manager export, so that GET is not made. `GET /api/ixp/probes` serves the round. The metrics are `packeteer_ixp_fabric_up`, `packeteer_ixp_fabric_targets`, `packeteer_ixp_fabric_opt_out`, `packeteer_ixp_fabric_past_tolerance`, and `packeteer_ixp_fabric_age_seconds`. The per-member series (`packeteer_ixp_member_rtt_ms`, `packeteer_ixp_member_loss_pct`, `packeteer_ixp_member_jitter_ms`, labels `asn`, `vlan`, `vantage`, `family`, #166) and the `/ixp/member/{asn}` page need no key; see [design/ixp.md](design/ixp.md#member-pages).

`routeservers` is one plugin. The only type is `birdseye`. It polls Birdseye on each route server with GET only and keeps a history per member session. It reads `api/status`, `api/protocols/bgp`, `api/routes/count/protocol/{protocol}`, and `api/routes/lc-zwild/protocol/{protocol}/{asn}/1101`, and with `route_signals` `api/routes/protocol/{protocol}`, and nothing else. Birdseye is read without a key: the IXP Manager API key is never sent to it, and a `url` with userinfo or a query is refused. Redirects are not followed. `members` is optional; with it, a session's ASN, name, and `max_prefix` come from the IX-F entry for its neighbor address, and without it `max_prefix` is Birdseye's import limit. `servers` lists at most 8 route servers, each with `name` (as for a vantage), `url` (the Birdseye origin, or a subdirectory install), and `asn` (the route server's ASN, the first part of the `asn:1101:x` tag IXP Manager puts on a filtered route). `interval` (default 5m, 1m to 1h), `timeout` (default 15s, 1s to 2m), `workers` (default 4, 1 to 8, concurrent session reads per server), `max_bytes` (default 8 MiB, 1024 to 32 MiB, per response; a larger response leaves that session uncounted), `max_prefix_warn_pct` (default 90, 1 to 100), `filtered_warn_pct` (default 50, 1 to 100), `spike_min` (default 10, 1 to 1048576), `spike_factor` (default 2, 1 to 1000), `burst_min` (default 20, 1 to 250000), and `route_signals` (default false, below).

Per session: `received` is the route count of the session's protocol, `filtered` is the number of routes with an `asn:1101:x` tag, `accepted` is the difference, and `reasons` counts each tag by `x`. Each poll adds a sample to the session's history (up to 288, in memory; a restart empties it; about 16 KiB per session). A server holds at most 2048 sessions. A failed poll keeps the last sessions; after three intervals without a success the server is stale and shows none. The events are `ixp.rs_*` ([EVENTS.md](EVENTS.md)). `GET /api/ixp/routeservers` and `GET /api/ixp/routeservers/history` serve the data; the metrics are `packeteer_ixp_rs_up`, `packeteer_ixp_rs_sessions_established`, `packeteer_ixp_rs_sessions_down`, `packeteer_ixp_rs_filtered_routes`, and `packeteer_ixp_rs_age_seconds`. Each session read asks Birdseye for the session's routes, so a large table costs the route server a `show route` per interval; Birdseye caches for a few minutes.

Signals (#165). `ixp.rs_filter_spike` fires when the routes tagged `asn:1101:x` for `x` 9, 10 (IRR), 13 (RPKI invalid), or 14 (transit-free ASN) rise by at least `spike_min` and to at least `spike_factor` times the highest count of the last 12 polls. It closes at the same threshold, measured against the level from before the spike. A session's first poll has no level and raises nothing. `route_signals: true` also reads `api/routes/protocol/{protocol}` for each Established session, which Birdseye refuses above its own `max_routes` (the session is then not listed and `scan_error` says so). From that listing: `blackhole` counts routes with the RFC 7999 community `65535:666` (kept in the history); `ixp.rs_origin_change` fires when a session announces a prefix with an origin AS (the last AS of the path) that no other member's accepted route for it has; `ixp.rs_morespecific_burst` fires when at least `burst_min` routes new in one poll are more-specifics of a prefix another member announces, with another origin. Routes tagged `asn:1101:x`, blackhole routes, and paths ending in an AS set are left out of the last two. Two sessions of one ASN are one member; sessions with ASN 0 (unknown) are separate members. The first listing of a session that is there at the first poll is the baseline: only changes after it alert, and a session that joins later is judged from its first listing. A session with no listing in a poll (down, not listed, or over the tracked limit) drops its table, so its routes leave the comparison, its origin and more-specific alerts close, and it is judged afresh when it is listed again. Each server keeps at most 250000 accepted prefix and origin pairs in memory; a session that would pass that is not listed (`scan_error`). The signals are hints for a human: they never change route-server config or member routing.

`correlate` is one plugin. The only type is `topology`. It requires `fabric` and reads only the fabric prober's latest round; it sends no probes and no requests. Each round it groups the measured member addresses by the switches on their connection (`switch`), the colo of those switches (`colo`), and the `bundles` you list (`bundle`). The IX-F export has no core bundle, so a bundle is a name and the IX-F switch ids behind it. An address is degraded when every vantage that measured it saw it past the ping tolerance; a probe error is not a measurement. A member is degraded in a group when all of its measured addresses behind that group are degraded. A group is a fabric problem when at least `min_members` members (default 3, 2 to 1000) and at least `degraded_pct` percent of its measured members (default 50, 1 to 100) are degraded; it raises `ixp.fabric_degraded`. A member that is degraded on every measured address and is in no such group raises `ixp.member_degraded`; one that is in such a group is part of the fabric event, not a member problem. A condition has to hold for `rounds` fabric rounds in a row (default 2, 1 to 10) before its event, and has to clear for as many before the resolving event, so one noisy round raises nothing. A switch and its colo, or a switch and a bundle, can all fire for one fault. An address behind two switches counts in both. A round with a stale member list has no samples, so open events resolve. `bundles` lists at most 64 entries, each with `name` (as for a vantage), optional `ixp_id` (switch ids are per IXP; 0 or omitted matches any), and `switches` (1 to 256 IX-F switch ids). Open events are held in memory; a restart starts clean. `GET /api/ixp/correlation` serves the latest evaluation; the metrics are `packeteer_ixp_fabric_groups_degraded` and `packeteer_ixp_members_degraded`. The events are `ixp.fabric_*` and `ixp.member_*` ([EVENTS.md](EVENTS.md)).

Multi-site fabric health (#167). Run one IXP-mode instance per site and join them with the top-level [`federation`](#multi-pop-federation) block (each instance needs its own `domain`; `instance` names the site). Each site then publishes, over the same mutual-TLS snapshot, its latest fabric round reduced to one path per member, VLAN, vantage, and address family (the worst address), its vantages, the correlator's groups, how many route servers do not answer, and its core links. The site view pushes nothing. `core` is one plugin (`type: icmp`; `interval` default 1m, 10s to 1h; `timeout` default 1s, 100ms to 5s; `packets` default 5, 1 to 20) that pings, from this site, the address of each other site in `core_links` (at most 64) and records loss, RTT, and jitter. It needs `core_links` and `federation`; it sends nothing else and announces nothing. Each link has `name` (as for a vantage), `peer` (the other site's federation instance name; not this instance), `address` (an address at the other site, reached across the core), optional `source` (the local address to ping from; omitted lets the kernel choose), `max_loss_pct` (default 10; the link is degraded above it), and optional `max_rtt` (0 or omitted is no RTT limit; at most 10s). A link with no reply, or one that cannot be probed, is degraded. `GET /api/ixp/sites` and `/ixp/sites` list each site's health, the core links, and the incidents, with the site each is at. The snapshot grows with members x vantages x families, so raise the federation `poll_interval` (for example 15s) on a large exchange. Rollback: remove `core` and `core_links`, or `federation`, and restart.

Adding or removing `ixp`, including `members`, `vantages`, `fabric`, `routeservers`, `correlate`, and `core`, needs a restart. Rollback: remove `core` and `core_links`, or `correlate`, or `routeservers`, or `vantages` and `fabric`, or the `ixp` block, and restart. Nothing was announced.

### `lookup`

A read-only directory (#153). It GETs PeeringDB and keeps the answer in memory; it does not announce, is not a RIB source, and is not an input to Decide. It works in an edge controller and in [`ixp`](#ixp) mode.

```yaml
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: example-ix, ix_id: 1}
```

`config.exchanges` (required, at most 32) lists the exchanges: `name` (a letter or digit, then letters, digits, `.`, `_`, or `-`, at most 64 characters; use the same name as in [`exchanges`](#exchanges)), `ix_id` (the PeeringDB `ix` id, positive, unique), and optional `ixf_url` (one IX-F 1.0 member document for that exchange, an http or https URL with no userinfo or query; it is fetched without the API key). `base_url` (default `https://www.peeringdb.com`; https is required when a key is set, and a URL that holds the key is refused). `refresh` (default 24h, 1h-24h), `timeout` (default 30s, 1s-2m), `max_bytes` (per response, default 8 MiB, 1024 to 32 MiB). The API key is `PACKETEER_PEERINGDB_API_KEY`, sent only as `Authorization: Api-Key ...` to `base_url`; it is optional and without it PeeringDB rate-limits the anonymous requests. Redirects are not followed.

Each refresh reads `ix` for the configured ids, `netixlan` for those exchanges, then `net` and `org` for the networks on them, and each IX-F document. The requests are at least 3 seconds apart (2 seconds with a key). PeeringDB rows are capped at 20000 networks and 20000 attachments; a refresh over a cap or with a malformed response is refused as a whole and the last good cache stays. A failed IX-F document is recorded on its exchange (`ixf_error`) and does not clear the PeeringDB rows. After three refresh intervals without a success the served lists are empty and `stale` is true. `GET /api/lookup` reads the cache (`?asn=` keeps one network and its attachments). The metrics are `packeteer_lookup_networks`, `packeteer_lookup_memberships`, `packeteer_lookup_up`, and `packeteer_lookup_age_seconds`.

Adding, changing, or removing `lookup` needs a restart. Rollback: remove `lookup` and restart. Nothing was announced.

### `herd`

Opt-in sharing of probe measurements with other operators' Packeteer instances (#260, [design](design/herd.md), [herd.md](herd.md)). Off by default; with `enabled: false` or no block nothing is stored, served, or pulled. Herd never announces and no herd data reaches `Decide`. It needs `storage` type `sqlite` and `bgp.neighbors` (records are built from learned routes), cannot be combined with `ixp`, and refuses the `fixed` prober. Any change needs a restart.

```yaml
herd:
  enabled: true
  share:
    granularity: origin_asn         # default; "route" names exact learned prefixes
    classes: [measurements]         # required; "paths" adds the AS path
    sources: [static, vip, outage]  # default; flow and span need an explicit entry and cannot be shared at route level
    discovery: query_only           # default; "listing" lets a puller page through everything
    exclude:
      prefixes: [203.0.113.0/24]    # equal, inside, or covering routes are never shared
      asns: [64501]                 # as origin or anywhere in the AS path
  retention_days: 90                # 30 to 365
  vantage: {country: US}            # ISO 3166-1 alpha-2, declared
  listen: 0.0.0.0:9444              # pull API, apart from http.listen
  key_file: /var/lib/packeteer/herd/node.key   # created (0600) on first start
  peers:
    - url: https://192.0.2.30:9444
      key: ed25519:<base64 of the 32-byte public key>
  hub:                              # optional seed list, see herd-hub.md
    url: https://hub.example.net/herd.json
    refresh: 6h                     # 10m to 168h
    max_peers: 16                   # 1 to 64
  outside:                          # optional, each source off until chosen; dashboard only
    atlas: {enabled: true, measurements: [1001], probes: [6001], refresh: 15m}
    ris: true                       # needs leak_watch with a rislive source
    rpki: true                      # needs rpki
    links: true                     # link-outs, no request is made
```

`share` chooses what leaves the box: `granularity` (`origin_asn` or `route`), `classes` (`measurements`, `paths`), `sources` (target source types), `discovery` (`query_only` or `listing`), and `exclude` with `prefixes` and `asns`. `retention_days` is how long records are kept and served. `vantage.country` is the code you declare. `key_file` is this node's Ed25519 key. Each of `peers` has a `url` and the `key` you pin. With `preview_only` set to `true` it stores records and serves the preview on `GET /api/herd/preview`, but listens and pulls nothing; it takes no `listen` or `peers`. Otherwise `listen` and either 1 to 16 `peers` or a `hub` are required. `hub.url` is an https address of a hub list ([herd-hub.md](herd-hub.md)); its entries are verified here and added as peers (at most `max_peers`) next to the static ones, and their keys may connect to the pull API (trust: herd-hub.md). `hub` is refused with `preview_only`. `GET /api/herd` shows this node's `public_key` to give to the peers that pin it. Private-use and reserved ASNs are removed from shared AS paths. The operator's own and customer prefixes (the `inbound` prefixes, the `flow` source's `transit.customers` and `problems.local`, and the `span` source's `local`) are never shared.

`outside` picks the outside intelligence on the [herd page](herd.md#dashboard), each source on its own switch and off by default. `atlas` reads public RIPE Atlas data without an API key: up to 4 public `measurements` (ping results only) and up to 4 of your own hosted `probes`, every `refresh` (default 15m, 15m to 24h); it needs `enabled: true` and at least one id. `ris` shows what the `leak_watch` `rislive` sources saw and needs one; `rpki` shows the origin validation of a route from the `rpki` block and needs it; `links` shows the `linkouts` sites for the chosen prefix or ASN. A source whose block is missing is a config error. None of this is herd data, a vantage, or an input to `Decide`.

`limits` holds the local resource limits; a value outside its range is an error and 0 takes the default (default, range): `rate_per_identity` (60/min, 1 to 100000), `rate_global` (600/min), `rate_per_address` (120/min), `max_conns` (64), `max_conns_per_peer` (4), `max_handshakes` (8), `max_requests_per_conn` (100), `max_request_bytes` (4096, 512 to 65536), `page_records` (200, 1 to 5000), `response_bytes` (1 MiB), `timeout` (10s), `idle_timeout` (30s), `pull_interval` (5m, 30s to 24h), `pull_timeout` (20s), `max_pulls` (2), `pull_requests` (64 per interval), `peer_requests` (16 per peer and interval), `pull_bytes` (2 MiB), `pull_records` (500), `peer_records_per_pull` (5000), `peer_records_total` (200000), `backoff_max` (1h), `queue` (256 rounds), `local_bytes` and `pulled_bytes` (512 MiB each). The defaults are starting points; the lab ([lab/README.md](../lab/README.md)) exercises them but does not tune them. Every tripped limit is counted in `GET /api/herd` and `packeteer_herd_limit_trips_total`.

Rollback: set `enabled: false` (or remove the block) and restart. The listener closes and pulling stops. The `herd_records` table stays in the storage file, unread and no longer pruned; remove it with `DROP TABLE herd_records` or by deleting the file.

### `exchanges`

Internet exchanges (#27, IRP 1.2.11). Each peer listed on an exchange is a provider: it is probed from its own `source_ip`, and an improvement toward it uses its own `next_hop` on the peering LAN. Everything that applies to providers applies to peers (thresholds, hold time, cap, allowlist, policies, commit and cost scorers, per-router lists). What differs:

- **Every peer is route-checked.** A peer carries only its own routes, so no improvement goes to a peer unless the router shows Packeteer the peer's path for the exact prefix, and that path's first AS is the peer's `asn`. An active one is retired at once (reason `no route via provider (route check)`) when the path goes. No visible path means no route: the check fails closed. The paths come from iBGP add-path (a `bgp.neighbors` entry with `add_path: true`, the router sending every path) or BMP (`bmp: prefer` or `only`, with `rib_sources`); one of the two is required.
- **Statistics** are on `/api/exchanges` and `packeteer_exchange_*` metrics: per peer, the prefixes the router shows through its next hop, the most common first AS when it differs from `asn` (`observed_asn`, a misconfigured peer), probe-source health, and active improvements with the Mbps they move (`moved_mbps`, `moves`); and the next hops on the peering LAN that are not configured peers (`discovered`, with AS and prefix count). A discovered next hop is never probed or used. To use it, add it as a peer (with a probe source) and restart; the settings form's Discovered members list starts that draft row.
- **LAN health** (#149). Each probe interval, every peer's `next_hop` is probed from that peer's `source_ip` with the configured prober chain and `probe.packets`. Every packet waits on `probe.rate_limit_pps`, so a large exchange spends the same budget as any other probe. `/api/exchanges` shows per peer `reach`: `state` (`reachable`, `unreachable` when nothing answered, or `unknown` before the first probe, with `health` off, or when no prober could run), `loss_pct`, `rtt_ms`, and `degraded`. The metrics are `packeteer_exchange_peer_reachable`, `_peer_rtt_seconds`, `_peer_loss_percent`, and `packeteer_exchange_degraded`. A peer is degraded when its loss is at least `loss_pct`, or its mean RTT is above `rtt_ms` (when set), and stays degraded for `window` after its last such probe. An exchange is degraded, and `exchange.degraded` fires ([EVENTS.md](EVENTS.md)), when at least `min_peers` peers are (never fewer than two, and never more than the exchange has), or, with `min_percent`, that share of its peers: that points at the exchange or our port, not one member. `exchange.recovered` follows once too few peers are degraded. A probe that could not run (no prober, unusable `source_ip`) is not a degraded peer. The probes are measurement only: they do not change the provider's probe-source state, a decision, or a route.
- **Session type** (`via` on each learned path, and on each peer in `/api/exchanges`): `route_server`, `bilateral`, or `unknown` (#146). There is no config key. A BMP path whose neighbor is inside `lans` and is not the path's next hop came through a route server; the MED label names that neighbor, not the member. A neighbor equal to the next hop is bilateral. An iBGP add-path path, and a Loc-RIB path, stay `unknown` until the BMP paths for that same next hop agree. When both types are seen, the peer's `via` is `unknown`. A peer with no path is `unknown`. MED is an input to the exit only through `thresholds.med_tie_break` (#303). The route check is unchanged: it still requires the peer's own path for the exact prefix (first AS = `asn`).
- **Per-peer session monitor** (#147). When the router sends BMP, the station decodes each peer's session events and its Adj-RIB-In route count (RFC 7854 Statistics Report type 7, the router's own tally). `exchange.peer_up` and `exchange.peer_down` fire with the decoded reason, including `Cease subcode 1 (maximum number of prefixes reached)` from the session's BGP Notification. When a peer sets `max_prefix`, `exchange.max_prefix` fires once its count reaches `max_prefix_warn_pct` of it, and `exchange.max_prefix_cleared` when it falls back. `/api/exchanges` carries the count as `adj_rib_in` and `packeteer_exchange_peer_adj_rib_in` exposes it (summed over the routers that report the peer). State is kept per router and peer, so two routers with a session to one peer alert separately and carry a `router` field. Read-only: nothing is announced, withdrawn, or steered.
- **Shared port** (#151). With a `port` block the peers draw from one interface instead of being independent providers. The commit and cost scorers never plan a move onto a peer that would push the port past `capacity_mbps` or `commit_mbps`; the port's usage is one `telemetry` binding named like the exchange (see below). `port` is not a provider, probe target, or announcement; it only limits what those two scorers plan.
- **The peering LAN is not a probe target** (#145). A target whose prefix is inside `lans` is dropped. A pinned host on a LAN is not probed. Flow and span destinations on a LAN are not aggregated into a probe prefix, so a /64 LAN does not become an `aggregate_v6` prefix. Traceroute does not adopt a hop on a LAN. It does not trace a prefix or a configured host that is inside one; when the only stable hops are on the LAN and the configured host is not, that host is used. A traceroute host on the LAN, including the default first address of the prefix, is not probed. The peer's `next_hop` on the LAN is still the far-side gateway probe. `packeteer_exchange_lan_targets_dropped` counts the omissions, once per collection for each omitted prefix or LAN, not per packet. Nothing is announced. `allowlist.prefixes` may not overlap a LAN. The learned-RIB check, improvement cap, community and NO_EXPORT, hold time, and withdraw rules are unchanged.

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique, not a provider name. Letters, digits, `_`, `.`, `-`. May be used in `bgp.neighbors[].providers` and `next_hops` for all its peers. |
| `lans` | yes | Peering LAN prefixes. Every peer `next_hop` is inside one; `discovered` lists other next hops inside them. |
| `bmp` | no | The peers' BMP usage: `off` (default), `prefer`, or `only`, as on providers. |
| `group` | no | The peers' load-balancing group, as on providers. |
| `peers` | yes | At least one. |
| `port` | no | The shared IX port (#151); see below. |
| `max_prefix_warn_pct` | `90` | Share of a peer's `max_prefix` at which `exchange.max_prefix` fires. 1 to 100. A peer with no `max_prefix` is not warned. |

Each peer:

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Provider name, unique across providers and peers. |
| `asn` | yes | The peer's AS: the first AS on the paths it advertises (a route server is transparent). |
| `next_hop` | yes | The peer's address on the peering LAN. Unique across providers. |
| `source_ip` | yes | Probe source for this peer. Unique like any provider's, or shared with other peers that each set a distinct `fwmark` or `dscp`. The host (or router) must route traffic from it to this peer's `next_hop` ([policy-routing.md](policy-routing.md)). |
| `exclude`, `precedence`, `cost` | no | As on providers. |
| `max_prefix` | no | The router's `maximum-prefix` limit on this peer's session, when known. 0 (default) disables the `exchange.max_prefix` warning. Read-only: Packeteer never sets or changes it. |
| `path_check` | no | First-hop probe-path check (#150), as on providers. `false` opts the peer out. |
| `fwmark`, `dscp` | no | Probe tag (#157), as on providers. Hundreds of peers can share one `source_ip` with `fwmark` on a Linux probe host; `dscp` allows 63 per source, which is the limit behind a router. |

`port` (#151):

| Key | Required | Meaning |
|---|---|---|
| `capacity_mbps` | yes | Port speed, greater than 0, at most 100000000. |
| `commit_mbps` | no | The port's commit on its billable 95th, 0 (default) for none. At most `capacity_mbps`. |
| `port_cost` | no | Flat monthly fee, 0 to 1000000000. Set, every peer's marginal cost is 0 per Mbps while the port has room, and a peer may not set its own `cost`. Unset, peers keep their own `cost`. |

The port's usage is a `telemetry` binding whose `name` is the exchange name (an `snmp` `providers[]` entry with the port's `host` and one `interface`, or a `fixed` row). That binding's `billing_day`, `percentile`, and 95th are the port's billing period; its own `commit_mbps` is required by the plugin and is a placeholder. The telemetry read replaces it with `port.commit_mbps`, so `commit.exceeded` and `commit.cleared`, `packeteer_telemetry_commit_bps`, and `/api/commit` judge the port against that (no alert when it is 0). The scorers read the binding unchanged. The load used for capacity is the larger of the latest outbound rate and the billable 95th; commit is judged on the 95th.

The `commit` and `cost` scorers book every planned move against the port: a destination peer is allowed only while load plus the prefix's volume stays within capacity and, when set, the 95th plus that volume stays within `commit_mbps`. Moves between peers of one port do not change its load; a performance steer and an active steer are counted where they sit. The scorers fail closed: a port with no fresh reading (no binding, a row older than the commit scorer's `max_age` or, for `cost`, 15 minutes, or no billable figure) and a prefix with no reported volume take no move onto the port's peers. With `cost` an unpriced peer is a destination only through `port_cost`. `/api/exchanges` shows `port` with `state` (`ok`, `stale`, or `no_telemetry`, judged with the `commit` scorer's `max_age`, or 15 minutes under any other scorer), the limits, `load_mbps`, `p95_mbps`, and `headroom_mbps`. Limits: performance moves and `static` policy pins onto a peer are not checked against the port, nothing is moved off a port that is already over its commit, and `cost` always uses the 15 minute limit. A performance steer that is locked is booked on its provider ahead of the telemetry; once its traffic shows in the port's outbound rate it is counted twice, which only makes the scorers refuse sooner. Observe stays the default; nothing is announced differently. Rollback: remove `port` (and its binding) and restart.

`health` (optional, per exchange; a change needs a restart):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` stops the next-hop probes and the alert for this exchange. |
| `loss_pct` | `50` | Loss at or above which a peer is degraded. Above 0, at most 100. |
| `rtt_ms` | `0` (off) | A mean RTT above this also degrades a peer. Up to 60000. |
| `min_peers` | `3` | Degraded peers that make the exchange degraded. At least 2; capped at the number of peers. |
| `min_percent` | `0` (off) | Also degrade the exchange when this share of its peers is degraded. 0 to 100. |
| `window` | `5m` | How long a degraded probe counts, and so how long the alert holds after recovery. Between `probe.interval` and 24h. A reload that breaks this is refused. |

Peers get `add_path: true` automatically when a neighbor has `add_path` (and `bmp` is not `only`). `-check` prints each peer with its exchange and AS.

**Rollback:** remove the `exchanges` block and restart; improvements toward peers are withdrawn at shutdown. To stop only the next-hop probes, set `health.enabled: false` and restart.

### `troubleshoot`

Operator tools on the ops HTTP server (`/api/troubleshoot/...` and the dashboard's Troubleshooting section). None of them announces or withdraws a route. On-demand probe results go back to the caller only and are not stored as probe results. The one write is `POST /api/troubleshoot/optimize` (operator): it adds a learned prefix to the probe set for a while, so the decision engine can then improve it under its usual rules (below).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns on the tools that send traffic or query a registry: the on-demand probe (the configured prober chain from every provider's `source_ip`) and probe and optimize, traceroute (UDP from each provider's `source_ip`, `NET_RAW` not needed), and whois. The looking glass only reads the learned RIB and is always on. |
| `requests_per_minute` | `6` | Probe, probe and optimize, traceroute, and whois requests together, 1-600. Excess requests get `429`. Probe and optimize checks its setup (queue, learned RIB ready) first, so a refused request spends no token. |
| `max_hops` | `30` | TTL limit for one traceroute, 1-64. One probe per hop, `probe.timeout` per hop. A trace stops early after six silent hops in a row. Each hop answer carries its `origin_as` (from the learned RIB) and, when the container's resolver has a PTR record, its `name`; the PTR lookups share a three-second limit. |
| `whois` | none | One whois plugin entry (`type: rdap`). Without it, whois answers `404`. |

The probe and probe-and-optimize targets are an IP address or a hostname. A hostname is resolved through the container's resolver (five-second limit); addresses that are loopback, link-local, multicast, broadcast, or unspecified are dropped, and the first remaining address whose family a provider `source_ip` can use is probed. The answer lists every address and the one used. A provider whose probes get no reply is traced from its `source_ip` with the `probe.indirect` trace settings (the defaults when `probe.indirect` is off) and the highest stable hop is probed instead, marked `indirect`. Every indirect trace packet waits on `probe.rate_limit_pps`, the same global budget as probing, so a request that finds silent providers is paced rather than sending a burst of up to `max_hops` x `probes` packets per provider. `best` is the answering provider with the lowest score from the configured scorer; `current` is the provider of the covering learned route.

`POST /api/troubleshoot/optimize` takes the same target and queues the longest learned prefix that covers it (never the default route, and never a prefix the RIB view does not hold) as an urgent probe target for 10 minutes, at most 64 at once (`409` past that). The prefix is probed on the next round, then on its normal interval until the 10 minutes end; the next completed round after that drops it unless a source lists it or an improvement keeps it. Queuing changes nothing on the wire. A move still needs the decision engine's rules: exact learned prefix, allowlist (inject), `max_improvements`, thresholds, `hold_time`, and the same withdraw triggers. In `observe` the result is a recommendation. Each request is audited with the queued prefix. A prefix inside an `exchange` LAN is not probed: the request is refused with `422` (`prefix is inside an exchange LAN and is not probed`) and nothing is queued.

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
| `max_hold` | 8 x `hold_time` | Cap on the grown hold time, and the flap window. A provider released for longer than this starts over. Not shorter than `hold_time`. |

A commit steer that flaps also learns inertia: how much inbound traffic returned to the provider when it was released (`inertia_mbps` on `/api/inbound`). It is then released only when the inbound 95th plus that amount is at or below `release_pct`, so an unchanged demand no longer flips the edge back and forth.

`hold_time` is the minimum life of a steer and the cooldown after a release (damping grows both for a flapping provider). `improvement_ttl` retires a steer; the route is withdrawn for at least one round and returns only once the edge advertises the prefix again. Telemetry older than 15 minutes, a poll error, or no row releases a commit steer at once; no fresh probe results release a performance steer at once. Packeteer never steers away from every non-excluded provider.

### `mitigation`

Threat mitigation (#28, lab-proven only, not on a public edge): RTBH, BGP redirect, and FlowSpec drop, rate-limit, and redirect, optionally by source country. Router setup, the API, and the full contract are in [mitigation.md](mitigation.md). Rules are added and removed through `POST /api/mitigations` and `DELETE /api/mitigations/{id}` (basic auth required), live in memory only, and always expire.

| Key | Default | Meaning |
|---|---|---|
| `mode` | `observe` | `observe` accepts and lists rules as a dry run and announces nothing. `inject` announces them; it also needs top-level `mode: inject`. Setting `observe` and restarting withdraws every mitigation route (rollback). |
| `allowlist` | none | Required. The mitigation allowlist, separate from `allowlist.prefixes`: a rule's prefix must be inside one of these. A default route is rejected. A rule is announced only while the exact prefix is in the learned RIB. |
| `max_rules` | `10` | Cap on mitigation routes held at once, announced or waiting. 1-1000. An RTBH, redirect, or FlowSpec rule counts once; a FlowSpec rule with `source_countries` counts once per source network. The announcer enforces the same cap on its routes (RTBH, redirect, and FlowSpec together). Mitigation routes do not count toward `max_improvements`. |
| `default_ttl` | `1h` (or `max_ttl` when shorter) | Lifetime of a rule whose request names no `ttl`. At least 1s, at most `max_ttl`. |
| `max_ttl` | `24h` | Longest `ttl` a request may ask for. 1s-168h. Every rule expires. |
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
| `interval` | `10s` | Detection round, `1s`-`5m`. Each round turns the flow counter deltas into rates per destination prefix and protocol. |
| `max_actions_per_hour` | `6` | Mitigation rules the detector may add in any rolling hour, 1-1000. Past it an anomaly waits (`anomaly.held`). |
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

### `leak_watch`

Leak watch (#199, not on a public edge). Contract: [leak-watch.md](leak-watch.md). Leak sources report routes seen outside the iBGP sessions. A route that carries `packeteer_community` (or, with `as_path_rule`, an injected prefix with `asn` in its path) is held out of outbound improvements and inbound steers and reported (`leak.detected`, `/api/leaks`) until `POST /api/leaks/clear` releases it.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` turns the watch on. A block that is not enabled is ignored, sources included. Needs `packeteer_community` and at least one source. |
| `as_path_rule` | `false` | Also flag an injected prefix seen outside with `asn` in its AS path. Leave off if you export transit routes to customers or list a customer router as a source: every injected prefix would match. |
| `sources` | none | Leak source plugins, each `type` (and optional `name`, `config`): `bmp` ([Leak source `bmp`](#leak-source-bmp)) or `rislive` ([Leak source `rislive`](#leak-source-rislive)). In-process only. A source that is down is reported unknown and never blocks a withdraw. |

An outbound route is withdrawn at once. An inbound steer is held and removed at the next inbound sync, and the leak shows `action: held`. Holds are in memory. Rollback: `enabled: false` and restart. The block is restart-only.

### `more_specific`

More-specific injection (#56, lab-proven only, not on a public edge). Design and full rules: [design/more-specific.md](design/more-specific.md). Used only in `mode: inject`.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true`: an improvement on P also announces every prefix strictly inside P that a neighbor advertises exactly in the learned RIB, is inside the allowlist, and is not held by inbound steering or mitigation. Nothing is split or computed: if no neighbor advertises a more-specific inside P, only P is announced. Each route carries the improvement's provider next hop, that improvement's resolved `local_pref`, and that improvement's communities (`packeteer_community`, the cause's, the provider's) and `no-export`. |
| `max_routes` | `100` | Cap on routes on a router: improvements, their more-specifics, and inbound steer routes. 1-1000. A new improvement is announced whole (P and all its learned more-specifics) or not at all; a more-specific learned later is added only while there is room. Nothing on the wire is withdrawn to make room. `max_improvements` still caps improvements. |

A more-specific is withdrawn with its improvement (flip-back, TTL, policy, P leaving the RIB), when the RIB is not ready, on shutdown, and when it really leaves the RIB: the neighbor advertised it for at least 5s while Packeteer's route was on the wire and then stopped. A shorter gap is the router hiding its own path because Packeteer's route won, and the route stays. A change needs a restart (SIGHUP refuses it). Rollback: remove the block or set `enabled: false` and restart; only improvements' own prefixes are announced again.

### `synthesize`

> **WARNING: synthesized more-specifics are NOT in the learned RIB.** Misused, they can cause hijack-like effects, RPKI-invalid announcements, and route leaks. Turn this on only for address space you operate or are authorised to steer, on an edge that honours NO_EXPORT and filters the marker community. Lab-proven only (`lab/e2e-synthesize.sh`), not on a public edge. Never in a shipped example.

Synthesized more-specific injection (#122). Design and rails: [design/more-specific.md](design/more-specific.md#synthesized-sub-ranges-synthesize-opt-in). With it on, a sub-range measured by a flow source's [`subranges`](#source-flow) block becomes a decision of its own when a neighbor advertises its covering prefix exactly in the learned RIB. It is moved under the same `thresholds` (including `confirm_rounds`), `hold_time`, flip-back cooldown, and `max_improvements` as a performance move, with the covering prefix's native provider. In `mode: inject` the route is announced. In `observe` and `suggest` nothing is announced: `/api/decisions` and the prefix card list it with `covering` set as a would-be route, and the blast-radius preview lists it as synthesized. A WARN line is logged at start, and every page of the UI shows the warning while it is on.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` turns synthesize on. Requires `leak_watch` enabled, `covering_prefixes`, and `marker_community`. |
| `covering_prefixes` | none | Containers for covering prefixes. Each must be inside `allowlist.prefixes`; anything else is rejected at load. No host bits, no default route, no duplicates. A covering prefix C that a neighbor advertises exactly must sit inside one of them; the sub-ranges split from C are not learned prefixes. |
| `max_bits` | `1` | How far past C's length a sub-range may go. 1-8. |
| `max_prefix_len` | `{v4: 24, v6: 48}` | Longest synthesized route per family. `v4` 1-32, `v6` 1-128. A /25 inside a /24 needs `v4: 25`. |
| `marker_community` | none | Added to every synthesized route, after `packeteer_community` and the cause's and provider's communities, so the edge can accept exact-prefix routes and refuse synthesized ones ([routers.md](routers.md)). Required when enabled. Standard or large; not `packeteer_community`, not `0:x` or `65535:x`. |
| `no_advertise` | `false` | `true` also adds NO_ADVERTISE, so the edge does not pass the route to any peer. NO_EXPORT is always attached. |

A sub-range S of C is never announced when:

- C is not inside `covering_prefixes` or the allowlist, S is not strictly inside C, or S is past `max_bits` or `max_prefix_len`;
- a neighbor advertises a prefix inside C that overlaps S (that one is [`more_specific`](#more_specific)'s), or S is held by inbound steering, a mitigation rule, or the leak watch;
- with [`rpki`](#rpki) on, S would be `invalid` with the origin it is announced with: the last AS of its path, or `asn` when `bgp.as_path` is empty (the default). A ROA whose max length stops short of S refuses it, and so does a ROA for another AS when no ROA covers S for that origin: with an empty path, a covering prefix whose ROAs name only other ASes is synthesized only with `bgp.as_path: native` or `provider`;
- C is under a `static` or `ignore` policy, or a source lists S as a target of its own.

Synthesized routes count toward `more_specific.max_routes` (100 when the `more_specific` block is absent), which then caps every outbound and inbound route on a router, `more_specific.enabled: false` included. A new one waits while the cap is full. Each carries the provider's next hop, the resolved `local_pref`, `packeteer_community`, the cause's and provider's communities, the marker, NO_EXPORT, and NO_ADVERTISE when chosen. With `bgp.as_path` set it carries C's path.

A synthesized route is withdrawn with its decision (flip-back, TTL), the round C is missing from the learned RIB (no 5s confirm window: S never hides C from the router), when S stops being measured or a rail above fails, when the RIB is not ready (session loss), on SIGTERM, on an HA standby, and when the leak watch sees it outside the AS. A SIGKILL or crash drops the session and the router removes it; graceful restart stays off. While Packeteer steers C itself, the router stops sending C to Packeteer, so C missing is not read as a leave; S then goes with C's own decision (retire, TTL, or the same leave rule). The block is restart-only. Rollback: `synthesize.enabled: false` and restart.

### `rpki`

Shared RPKI origin validation (#158, #200, not on a public edge). Off by default. A source reads the operator's RPKI cache (Routinator, rpki-client, StayRTR, FORT) over RTR or as VRP JSON and labels each learned path's origin: `valid`, `invalid`, `notfound`, or `unknown`. The learned RIB is never changed and nothing is announced. Validity is shown on `/api/decisions` candidates and the prefix card's learned paths, each with the source that answered and its data time, and on leak watch entries with the source. The exchange peers show validity counts only. Every learned path of a probed prefix is recorded per provider and origin AS in history (`storage`), shown on the prefix timeline. `avoid_invalid` only refuses a new improvement; it never blocks a withdraw, and the learned-RIB rule, allowlist, cap, community + NO_EXPORT, hold time, and withdraw rules are unchanged.

A source that was answering and goes stale or empty emits `rpki.stale` (warning) and `rpki.fresh` when it recovers ([EVENTS.md](EVENTS.md)); its lookups are `unknown` meanwhile, so decisions continue and withdraws never wait. `/metrics` has `packeteer_rpki_source_up`, `packeteer_rpki_vrps`, and `packeteer_rpki_cache_age_seconds` per source.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` turns the source on. A block that is not enabled is ignored, sources included. |
| `sources` | none | Origin-validation plugins, tried in order. The first with a fresh, non-empty cache answers, including one whose server is unreachable but whose data time (`rpki_updated`) is inside `staleness`; a stale or empty source is skipped, so a second server takes over. Each is a plugin entry (`type`, optional `name`, `config`): `rtr` ([RPKI source `rtr`](#rpki-source-rtr)) or `json` ([RPKI source `json`](#rpki-source-json)). At least one is required when enabled. `ripestat` is refused here. |
| `avoid_invalid` | `false` | `true` refuses a new improvement onto a provider with an `invalid` learned path for the prefix. With several paths from one provider (add-path, or BMP from several routers), the decision candidate carries the worst state, so one invalid path is enough. An active improvement on a path that becomes invalid is retired through the normal path. Off changes nothing. |
| `display_fallback` | none | A plugin entry asked only for the learned paths on `/api/prefixes` and the prefix card, and only when no source has fresh data. Only `ripestat` is accepted ([RPKI display fallback `ripestat`](#rpki-display-fallback-ripestat)). Its answers never reach decisions, `avoid_invalid`, leak watch, or the exchange counts. |

### `irr`

IRR origin check per provider path (#214, not on a public edge). Off by default. Each learned path of a probed prefix is labelled `registered` (a route or route6 object for exactly the prefix names the path's origin AS), `not_registered` (every source answered and none does), or `unknown` (no source answered, or the answer is older than `staleness`). It is shown beside RPKI on the prefix card and `/api/prefixes` (with the source, the IRR database of the matching object, the data time, every origin registered for the prefix, the provider's as-set membership, and the origin's aut-num `as-name`), and on `/api/decisions` candidates. The System page has one row per source. Lookups answer from a cache and never wait on the network: a miss is `unknown` until a background lookup asks every source in order, one lookup at a time. A source that fails keeps its last answers until `staleness` and is asked again after a minute. Each cache holds at most 100,000 keys. Objects of IRRd's `RPKI` pseudo-source (built from ROAs) are not counted. Nothing is announced and the learned RIB is unchanged; with `prefer_registered` off it changes no decision. The learned-RIB rule, allowlist, cap, community + NO_EXPORT, hold time, and withdraw rules are unchanged. A change needs a restart.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` turns the check on. A block that is not enabled must not set any other key. |
| `sources` | none | IRR plugins, in order: `whois` ([IRR source `whois`](#irr-source-whois)) or `file` ([IRR source `file`](#irr-source-file)). A path is `registered` when any source has a matching object; the first such source is named. At least one is required when enabled; instance names must differ. |
| `refresh` | `6h` | How old a cached answer gets before it is looked up again in the background. It is served meanwhile. 1m-720h. |
| `staleness` | `24h` (`refresh` when longer) | How long an answer is used after its data time (the lookup time for `whois`, the file's modification time for `file`). Older is `unknown`. At least `refresh`, at most 720h. |
| `as_sets` | none | Provider name to as-set (for example `transit-a: AS-EXAMPLE` or `AS64500:AS-CUSTOMERS`). Each path of that provider shows whether its origin is in the set, expanded recursively. Display only. The provider must be configured. |
| `prefer_registered` | `false` | `true` refuses a new improvement onto a provider whose learned path for the prefix is `not_registered` (candidate `why` "IRR not registered"). With several paths from one provider the worst state counts. `unknown` never blocks, and the native path is never refused. An active improvement whose path becomes not registered is retired through the normal path. |

### `linkouts`

The "open in" links on the prefix, ASN, and exchange-peer views (#211). Display only: the controller makes no request to any listed site. Every key is checked at load, and unknown keys are errors. A change needs a restart. See [ui.md](ui.md#link-outs).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `he`, `he_lg`, `ripestat`, `peeringdb`, `bgptools`, `cloudflare_radar`, `irr_explorer` | Built-in sites to show: those names plus `nlnog_ring` (off unless listed). A name twice or unknown is an error. `[]` shows no built-in site. |
| `custom` | none | Up to 20 entries of `name` (1-40 printable characters, unique) and `url`. The URL must be `https` with a host, hold exactly one of `{prefix}` or `{asn}` (any other `{...}` is an error), carry no credentials or fragment, and keep the placeholder out of the host. `{prefix}` is the CIDR with `/` and `:` unescaped; `{asn}` is decimal digits. Custom links are always shown. |
| `hide_internal` | `true` | No link for an RFC 1918, ULA, loopback, or link-local prefix or a private-use AS. `false` links them too. |

```yaml
linkouts:
  enabled: [he, ripestat, bgptools, nlnog_ring]
  custom:
    - {name: internal LG, url: "https://lg.example.net/route?prefix={prefix}"}
```

### `ring_lg`

The opt-in "Seen from NLNOG RING" panel on the prefix page (#283). With `enabled: false` (the default) nothing calls RING. Display only: the answer never feeds a decision. Every key is checked at load, and unknown keys are errors. A change needs a restart. Limits, the availability note, and the no-SSH rule are in [ui.md](ui.md#nlnog-ring-panel).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` lets the prefix page ask the public NLNOG RING looking glass API. |
| `requests_per_minute` | `6` | Most upstream calls in any 60 seconds, across all prefixes and viewers. 1 to 30. |
| `cache_ttl` | `10m` | How long an answer for a prefix is reused. 1m to 24h. |
| `timeout` | `10s` | Bound on one call. Up to 30s. |

```yaml
ring_lg:
  enabled: true
  requests_per_minute: 6
  cache_ttl: 10m
```

### `atlas`

The opt-in RIPE Atlas integration (#213). With `enabled: false` (the default), or with `PACKETEER_ATLAS_API_KEY` unset, nothing calls Atlas. The key comes only from that environment variable, is sent only in the `Authorization` header, and is never logged or returned by the API. Atlas results are display only: they never feed a decision, a scorer, or an announcer, and nothing here moves a route. Every key is checked at load, and unknown keys are errors. A change needs a restart. Credit costs, the panel, and hosting your own probe are in [atlas.md](atlas.md).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | `true` allows measurements, status reads, and the prefix page panel. Other keys need it. |
| `probe_id` | none | Your own hosted probe. Its status shows on the System page (the credit balance shows whenever the integration is on), and while it is connected it joins every measurement. |
| `source` | `{type: area, value: WW}` | Which probes the measurement runs from. `type` is `area`, `country`, or `asn`. `value` is an Atlas area (`WW`, `West`, `North-Central`, `South-Central`, `North-East`, `South-East`), an upper-case two-letter country code, or an AS number. |
| `probes` | `3` | How many probes `source` picks per measurement. 1 to 10. |
| `after_move` | `false` | `true` also runs one ping once after Packeteer announces a move for a prefix (`mode: inject` only). |
| `after_move_delay` | `3m` | How long to wait after the move so the route has propagated. 1m to 1h. |
| `max_credits_per_day` | `500` | Hard cap on the estimated credits booked in any 24 hours. Up to 100000. |
| `max_measurements_per_hour` | `4` | Hard cap on measurements created in any hour. Up to 60. |
| `state_file` | `/var/lib/packeteer/atlas.json` | The spend ledger and recent results, so a restart does not reset the caps. Mount a volume on `/var/lib/packeteer` to keep it. |

```yaml
atlas:
  enabled: true
  probe_id: 6001
  source: {type: area, value: WW}
  probes: 3
  after_move: true
  max_credits_per_day: 500
  max_measurements_per_hour: 4
```

### `report_subscriptions`

Scheduled email report subscriptions (#34). Each entry emails one stored report (the same one `/api/reports/<report>` serves) as a CSV attachment. Needs `storage` (reports come from stored history) and a notifier of type `smtp`. Times are UTC. A failed send is logged, shown on `/api/subscriptions`, and tried again at the next scheduled time; sends missed while the controller was down are not replayed. Operators can send one at once with `POST /api/subscriptions/<name>/send`. Recipients come only from this file. Does not announce. See [ui.md](ui.md).

| Key | Default | Meaning |
|---|---|---|
| `name` | none | Required, unique. 1-63 of `a-z`, `0-9`, `_`, `-`. |
| `report` | none | Required. A report name from `/api/reports` (`summary`, `improvements`, `exchanges`, `causes`, `performance`, `providers`, `prefixes`, `asns`, `countries`, `probes`, `probe_asns`, `scorecard`, `savings`, `timeseries`, `mitigations`, `anomalies`). |
| `schedule` | none | Required. `daily`, `weekly`, or `monthly` (the 1st of the month). |
| `at` | `06:00` | UTC time of day, `HH:MM`. |
| `weekday` | `monday` | For `weekly` only: `monday` ... `sunday`. |
| `days` | 1, 7, or 30 | The report range, ending at the send time. 1-366. |
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

### `upgrade`

Version check, one-click upgrade, and rollback on the Settings page (#196). Off unless `enabled: true`; the page then only shows the running version. Nothing upgrades by itself: a check only lists GitHub releases, and an upgrade or rollback needs an admin's explicit confirmation (`confirm`) over `POST /api/upgrade/apply` or `/rollback`, with auth or basic auth on. Every key is checked at load, and unknown keys are errors. Does not announce; the switch withdraws first. See [ui.md](ui.md#upgrade-from-the-ui).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turns the feature on. Requires `public_key`. |
| `public_key` | none | Required when enabled. The Ed25519 public key (base64, 32 bytes) that signs each release's `SHA256SUMS`. A release whose signature or checksum does not verify is never switched to. |
| `repo` | `GrandArcher/Packeteer` | `owner/name` whose GitHub releases are read. |
| `api_url` | `https://api.github.com` | GitHub API base. Must be `https`, or `http` on a loopback address (a local mirror). Asset downloads follow the same rule. |
| `dir` | `/var/lib/packeteer/upgrade` | Absolute path where staged versions and the switch state are kept. In the container, mount a volume on `/var/lib/packeteer` to keep a staged version when the container is recreated. |
| `check_interval` | `0` (off) | `0`, or 1h to 720h. A background check that only notifies: the Settings page shows the newer release and the log says so. It never upgrades. Needs `enabled`. |
| `allow_prerelease` | `false` | List pre-releases too. |

```yaml
upgrade:
  enabled: true
  public_key: "xbP7Os7YIqfBhu36+E+WK0xvTizFyPROA1QCAseqEkA="   # not a secret
  # check_interval: 24h
```

#### Release signing key

Releases from v0.6.0 on are signed with this Ed25519 public key (not a secret):

```
xbP7Os7YIqfBhu36+E+WK0xvTizFyPROA1QCAseqEkA=
```

Each release carries `SHA256SUMS` (the SHA-256 of every binary) and `SHA256SUMS.sig`, a base64 Ed25519 signature over `SHA256SUMS`. The upgrade checks the signature against `upgrade.public_key`, then the binary against its `SHA256SUMS` entry. The same key is listed in each release's notes; compare it with this page before you pin it.

Key rotation: a new key is announced in the release notes and this page at least one release before it is used. During the change, update `upgrade.public_key`; a release signed with a key you have not pinned is refused and nothing changes. If a key is ever compromised, the notes say so, the old key must be removed, and releases signed with it are not trusted.

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

Only the active instance runs decisions and announces. A standby probes and keeps its iBGP sessions and RIB view, but has no route on the wire: the outbound, inbound, and mitigation announcers check the elector under their locks before every sync, and a standby withdraws anything left. An instance may lead only while its RIB view is ready; an active instance whose sessions all drop steps down and hands over. On becoming standby an instance withdraws at once, drops its decision state (improvements and cooldowns), and resigns, so the other instance takes over at its next renewal.

A crashed active instance cannot resign: the standby waits until the old instance's routes are gone from the routers (its lease, plus the negotiated BGP hold time it recorded) before it announces. Allowlist, learned-RIB check, community, NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged on the active instance. `ha` changes need a restart (SIGHUP refuses them). Rollback: remove `ha` and run one instance.

`/api/ha` and `packeteer_ha_active`, `packeteer_ha_eligible`, and `packeteer_ha_takeovers` show the role; `ha.active` and `ha.standby` events report changes ([EVENTS.md](EVENTS.md)).

### Backup and restore

`packeteer -backup FILE` writes a gzip'd tar with the loaded config file and, with a `storage` plugin (including the `sqlite` that default sign-in adds), a consistent copy of its history (`sqlite`: `VACUUM INTO`, safe while the controller runs). It never overwrites `FILE`, opens no BGP session, and sends no probe. Secrets are environment variables, so none are in the archive. With `auth`, the history includes users with their password hashes (PBKDF2), API token hashes (SHA-256), and the audit log: keep the archive private.

`packeteer -restore FILE` validates the archived config, then restores the history into that config's storage path. The restoring host's environment applies first (`PACKETEER_HTTP_LISTEN`, `PACKETEER_HTTP_USER`), so whether default sign-in adds `sqlite`, and so the target store, can differ from the backup host. `-restore-config PATH` also writes the archived config to `PATH`. Existing history or config files are replaced only with `-force`. Stop the controller that uses the storage first.

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
| `PACKETEER_ATLAS_API_KEY` | Your RIPE Atlas API key for the [`atlas`](#atlas) block (#213). Sent only in the `Authorization` header to the Atlas API, never logged or returned. Unset: the integration makes no request. |
| `PACKETEER_ADMIN_PASSWORD` | With `auth`: creates that admin at start when no user has the name (12-256 characters). An existing user is not changed, so a password set through the API survives a restart. Not written to the log. |

`${VAR}` expansion applies inside a webhook `url`, webhook `headers` values, and an `exec` plugin's `env` values. It is not applied to the rest of the file.

## Inject checklist

`mode: inject` is refused unless all of these hold:

- `allowlist.prefixes` is non-empty
- at least one `bgp.neighbors` entry
- `packeteer_community` is set and valid (standard or large)
- `local_pref` is non-zero. Any `local_pref_cause` value and any `providers[].local_pref` that is set is non-zero too (`0` is rejected in every mode)
- any `communities_cause` list and any `providers[].communities` list follows the rules under [`communities_cause`](#communities_cause)
- `announcer` is set (`type: gobgp`)
- `hold_time` is positive
- both threshold deltas are positive
- `more_specific_bits` is absent (`more_specific` is the replacement; it is off by default). `synthesize` does not change this
- `ixp` is absent (`ixp` refuses `mode: inject`)

The `gobgp` announcer has no `config` keys. A config block with any key is an error. Each announced route carries the provider `next_hop`, the resolved `local_pref` (the provider's, else the cause's, else the global value), `packeteer_community`, the cause's extra communities, the provider's extra communities, and `no-export`. The export policy accepts only routes Packeteer originated that carry `packeteer_community`. An extra community alone does not match.

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
| `port` | 443 | 1-65535. A SYN-ACK or a RST counts as a reply. A middlebox RST is not distinguishable from the target's RST. |
| `packet_interval` | `100ms` | Not negative. |

### Prober `https`

Not in the default chain: it sends a full HTTPS request per packet, so use it for pinned hosts (`static` or `vip` with `host`) that serve HTTPS. The chain tries the next prober when one gets no replies, so a host whose every request fails the status check is then measured by the next prober, and a prober listed before `https` that answers means `https` never runs. For the status check to count as loss, list `https` last, or alone, in `probers` for those targets. The connection goes to the probe address on the provider's source address; redirects are not followed. The reply RTT is connect, TLS handshake, and time from the request to the first response byte added together, and the three means are `connect_ms`, `handshake_ms`, and `ttfb_ms` on `/api/probes`. A connect or handshake failure, a certificate error, a timeout, or a status outside `status_min`-`status_max` is loss. A reply counts as evidence beyond ICMP for `require_evidence`.

| Key | Default | Values |
|---|---|---|
| `port` | 443 | 1-65535. |
| `method` | `GET` | `GET` or `HEAD`. |
| `path` | `/` | Request path and query, starts with `/`. |
| `server_name` | the probe address | SNI, certificate name to verify, and `Host` header. |
| `status_min`, `status_max` | 200, 399 | Each defaults on its own. 100-599, `status_min` not above `status_max`. |
| `ca_file` | system roots | PEM file with the CA certificates to trust, for a private CA. |
| `packet_interval` | `500ms` | Not negative. Gap between the requests of one run. |
| `targets` | none | Per probe address: `address` (an IP, listed once), and optional `server_name`, `path` (both default to the values above), and `insecure_skip_verify` (default false). Skipping verification is possible only here, for the named address, and logs a warning at start. |

### Prober `udp`

Not in the default chain. A UDP reply counts. An ICMP destination-unreachable counts only when the host that sent it is the target; a firewall `REJECT` (icmp-port-unreachable from another address) is loss. No raw socket. The check reads the offender from the socket error queue and is Linux-only; the container image is Linux.

| Key | Default | Values |
|---|---|---|
| `port` | 33434 | 1-65535. |
| `packet_interval` | `100ms` | Not negative. |

### Prober `twamp`

Not in the default chain: it needs a TWAMP-Light Session-Reflector (RFC 5357, unauthenticated mode) at the target, such as `packeteer-reflector`. It is the sender behind `probe.reorder` `twamp` responders, which set the port and spacing per request. Every packet of a run leaves one UDP socket, so a run keeps one 5-tuple. The result carries the arrival order of the replies. A closed port (ICMP port unreachable on the connected socket) is an error, not loss.

| Key | Default | Values |
|---|---|---|
| `port` | 862 | 1-65535. |
| `packet_interval` | `20ms` | Not negative. |
| `padding` | 27 | 27-1400 octets after the 14-octet header, so the 41-octet reflected packet is not truncated (RFC 5357 section 4.2.1). |

### Prober `fixed`

Labs and tests only. Sends no packets.

| Key | Meaning |
|---|---|
| `file` | Re-read on every probe. Same schema as this block, without `file`. Larger than 1 MiB is an error. |
| `sent` | Packets sent when a path omits `sent`. Not negative. |
| `rtt_ms` | RTT used when a path omits `rtt_ms`. Not negative. |
| `paths` | Results. The first most-specific path for a provider, `target`, and `count` wins. |

Each path:

| Key | Meaning |
|---|---|
| `provider` | Required. Must match a provider `name`. Unique together with `target` and `count`. |
| `target` | Optional IP address. Empty matches any target. Stored in canonical form. |
| `count` | 0-1000. `0` matches any packet count. A positive value matches only a probe that asks for that many packets. |
| `sent` | Not negative. With `rtts_ms`, `0` uses the request count, then at least the number of replies. |
| `rtt_ms` | Not negative. Not together with `rtts_ms`. |
| `rtts_ms` | Optional reply RTTs in milliseconds, at most 1000, each not negative. One entry per reply, so a lab can set a spread. Not together with `rtt_ms` or a non-zero `loss_pct`. |
| `loss_pct` | 0-100. |
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
| `host` | Optional address inside `prefix`. When set, it is the only probe target. When empty, the engine picks a few addresses in the prefix and, when it can, the provider next hop. |
| `weight` | Optional, not negative. |
| `mbps` | Optional, 0-100000000. Declared traffic in decimal megabits per second. The `commit` scorer reads it when this source is configured. Zero omits the prefix. |

### Source `traceroute`

Off unless this source is listed. UDP traceroute toward each target. Discovery runs in the background after `Start`. `Targets` returns the last cache immediately and does not trace, so a slow hop cannot use up the probe round. One pass is capped by `budget`. The discovered host is only the address that gets probed. The prefix is unchanged, and nothing is announced from this source.

| Key | Default | Bounds |
|---|---|---|
| `targets` | none | Required. Same shape as `static` (`prefix`, optional `host` inside it, optional `weight`). |
| `max_hops` | 16 | 1-64. |
| `probes` | 3 | 1-10 probes at each TTL. |
| `min_replies` | 2 | 1-`probes`. A hop is stable when one address answers at least this many times and there is no tie. When `probes` is 1 the default is 1. |
| `timeout` | `500ms` | Per probe, `1ns`-`5s`. Zero uses the default. |
| `port` | 33434 | 1-65535. Destination UDP port. |
| `source` | unset | Local address to bind. Empty uses the kernel's default route. Must match the targets' address family. |
| `interval` | `5m` | `1s`-`24h`. How often discovery runs. |
| `budget` | `10s` | At least `timeout`, at most `30s`. Wall clock for one pass across every target. Each target gets an equal share. This is under the default round deadline (about 110s). |

Three silent TTLs after a stable hop stop the trace. When the configured host answers, it stays the probe host. Otherwise the stable hop with the highest TTL is used. A pass that finishes no target leaves the previous cache in place. Until the first pass finishes, the source contributes no prefixes. The socket calls are Linux-only; the container image is Linux, and other systems still compile.

### Source `vip`

Off unless this source is listed. Critical prefixes, and prefixes whose learned AS path contains a listed ASN, are probed on `interval`. The global `probe.rate_limit_pps` still applies.

| Key | Default | Bounds |
|---|---|---|
| `interval` | none | Required, at least `1s`. Must be shorter than the staleness window (`3 * probe.interval + packets * timeout`, plus retry packets when retry is on). The controller refuses to start otherwise. Shorter than `probe.interval` is the usual setting. |
| `prefixes` | none | CIDRs, no host bits, no default route, no duplicates. Optional `host` must sit inside the prefix. Count toward `max_targets`. |
| `asns` | none | Non-zero ASNs, no duplicates. Matched against the learned AS path only while the RIB is ready. |
| `max_targets` | 100 | 1-100000. Cap on configured prefixes plus ASN matches. The list is truncated and a warning is logged. The expansion is rebuilt only when the RIB changes. |

At least one prefix or ASN is required. The prefix list cannot be longer than `max_targets`. A prefix that is also returned by an earlier source keeps that source's host. A later interval wins only when it is shorter than the interval already chosen, and an unset interval means `probe.interval`. Listing a transit ASN does not turn the whole table into targets.

### Source `outage`

Off unless this source is listed. After each completed probe round it correlates degraded samples by learned AS path, by traceroute hop origin, by other providers' learned paths, and by provider. A new incident re-queues prefixes and emits `outage.as` or `outage.circuit` (severity `critical`). Recovery emits `outage.cleared` (severity `warning`). Nothing is announced. Disable it by removing the source.

A sample is degraded when the probe failed, when loss is at least `loss_pct`, or, when `rtt_ms` is set, when average RTT is at least that many milliseconds. The newest sample for each provider and prefix inside `window` wins. A timestamp of zero is outside the window.

An ASN is sick when at least `min_prefixes` degraded prefixes contain it and every provider just measured for those prefixes is degraded. The ASNs are the native AS path, each measured provider's other learned path (add-path or BMP, when that path is not the selected route's own), and the origin ASN of each stable traceroute hop. A hop address maps to the last ASN of the longest matching learned prefix. A default route is not a match, and nothing outside the learned RIB is consulted. Hops come from per-provider indirect traces ([`probe.indirect`](#probeindirect)) while a trace is cached. With no traces and no other learned paths the correlation is the native AS path alone.

A prefix that is still healthy on another provider does not count toward that rule: that pattern is the circuit, unless the ASN appears only on the degraded provider's path (an alternate learned path, or a hop origin that is not on the native path). That incident is an `outage.as` attributed to the degraded provider (`providers` lists it), and those prefixes do not also open a circuit. `ignore_asns` drops ASNs that sit on every path, including a hop origin. Listing a provider ASN there keeps a one-sided failure as a circuit. iBGP paths usually omit the local ASN already.

A provider is sick when at least `min_prefixes` prefixes are degraded on it and healthy on another provider, and a sick ASN does not already explain those prefixes. With only one provider in the window, prefixes that do not share a sick ASN still count, so a dead circuit with mixed destinations is reported and a shared transit ASN is not reported twice.

The re-queue is probe targets only. An AS incident includes every learned prefix whose native path, alternate path, or hop-ASN path contains that ASN, degraded ones first, up to `max_targets`. A circuit incident includes the prefixes that counted, then other prefixes sampled on that provider, then learned prefixes whose native provider is that circuit, up to the same cap. A default route is never added. The first pass is urgent (the probe loop wakes immediately). Later passes use `interval`. One prefix never fires, and `min_prefixes` cannot be set below 2. AS correlation is empty until the RIB is ready. The global `probe.rate_limit_pps` still applies. Outage re-queues probes only.

| Key | Default | Bounds |
|---|---|---|
| `min_prefixes` | 3 | 2-100000. Zero uses the default. One noisy prefix is not an incident. |
| `window` | `2m` | `1s`-`24h`. Zero uses the default. |
| `loss_pct` | 20 | 0-100. Zero uses the default of 20, so loss detection stays on. A failed probe still counts when loss is below this. |
| `rtt_ms` | 0 | Not negative. Zero disables the RTT check. A positive value also treats average RTT at or above this many milliseconds as degraded. |
| `interval` | `5s` | `1s`-`24h`. Zero uses the default. Must be shorter than `probe.interval` and shorter than the staleness window. The controller refuses to start otherwise. |
| `max_targets` | 100 | 1-100000. Cap on the re-queue. Truncation is logged. Degraded prefixes are kept first. |
| `ignore_asns` | none | Non-zero ASNs, no duplicates. Skipped when looking for a sick ASN. |

### Source `flow`

Off unless this source is listed. NetFlow v5, NetFlow v9, IPFIX, and sFlow v5. Raw records are not stored.

| Key | Default | Bounds |
|---|---|---|
| `listen` | none | Required. One `host:port` or a list. Host is an IP address or empty. Duplicate addresses are errors. |
| `window` | `5m` | `1s`-`24h`. |
| `top_n` | 100 | 1-100000, and at most `max_prefixes`. Priority tier, probed every `probe.interval`. |
| `max_targets` | `top_n` | 0 matches `top_n`. Otherwise from `top_n` through 100000, and at most `max_prefixes`. Cap on the probed set. |
| `max_prefixes` | 20000 | 1-250000 (#217). Exact prefix cells per time bucket, and anomaly counter keys. A cell the window buckets refuse or evict is counted in `packeteer_truncated_total{limit="max_prefixes"}` (counter keys are not). A cell costs about 220 bytes and a 5-minute window has 30 buckets, so the default can hold 127 MiB and 250000 about 1.5 GiB. See [performance](performance.md#limits-at-large-tables). |
| `workers` | 4 | 1-16 (#385). Goroutines that map decoded records to prefixes and count them. Each reader decodes in arrival order (so NetFlow v9 and IPFIX templates are learned before their data) and queues the records, up to 256 datagrams per worker. A full queue drops the datagram and counts it in `packeteer_truncated_total{limit="workers"}`. A stall in the window (a large read, a collector pause) then fills the queue instead of the kernel socket buffer, where `RcvbufErrors` counts the loss. |
| `min_bytes` | 0 | Absolute floor, in bytes over `window`. 0 disables this bar. |
| `min_pct` | 0 | 0-100, in steps of 0.0001. Percent of the bytes counted in the window. 0 disables this bar. |
| `tail_interval` | 0 | `1s`-`24h` when set. Required when `max_targets` is greater than `top_n`. Must be longer than `probe.interval` and shorter than the staleness window. |
| `aggregate_v4` | 24 | 1-32. Used when the RIB has no covering non-default prefix. |
| `aggregate_v6` | 48 | 1-128. |
| `exclude` | none | CIDRs to ignore, no host bits, no duplicates. |

A destination inside an `exchanges[].lans` prefix is ignored the same way as `exclude` (#145): it is not aggregated, and it is not the candidate host. That includes an address no learned route covers, which would otherwise become `aggregate_v4` or `aggregate_v6`. Those bytes are not in the window, the volume, or the anomaly counters.

With `--network host`, `listen` binds host UDP ports. Do not publish them. Each time bucket keeps at most `max_prefixes` prefixes (20000 by default). Those exact cells are what become probe targets and what the commit scorer reads as volume. It also counts bytes per destination prefix and IP protocol since it started (at most `max_prefixes` keys; a key idle for an hour is forgotten), which [`anomaly`](#anomaly) reads for its baselines. Each bucket also keeps a fixed HyperLogLog (4096 registers, 4 KiB) of every prefix offered to it, including ones the exact map refused (#125). A 5-minute window is about 30 buckets, about 120 KiB.

The window merges the live buckets into `packeteer_flow_prefixes_tracked`. The sketch does not add probe targets and is not the commit scorer's volume. The protocol comes from NetFlow v5, v9/IPFIX (information element 4), and sFlow (sampled IPv4/IPv6 records and the IP header; IPv6 extension headers are not followed); records without it count as protocol `any`. The commit scorer reads the busiest prefixes, up to `max_prefixes`, as a rate (bytes x 8 / window, decimal megabits per second), including prefixes the floor or the cap did not offer as probe targets. A prefix past that set is not a volume. Its bytes still count toward `min_pct`.

Merging the window builds a destination list only for those prefixes and for a problem prefix outside the set.

A prefix is eligible when it clears at least one enabled floor (#118). `min_bytes` above 0 is an absolute total. `min_pct` above 0 is that percent of every byte the window counted. When both are above 0, either one is enough: a busy prefix under the percent still qualifies, and a smaller prefix that is a large share of the window still qualifies. When both are 0, every prefix with bytes is eligible and `top_n` still cuts the list, which is the previous behavior. Eligible prefixes are largest first. An equal total breaks by prefix text, and that order does not change between reads.

`top_n` is the priority tier. Those targets leave their interval unset, so the engine probes them every `probe.interval`. `max_targets` is the larger set. 0 or omitted means the same number as `top_n`, so the default list is unchanged. It cannot be set below `top_n` or above 100000, or above `max_prefixes`. Prefixes past `top_n`, up to that cap, are still returned and carry `tail_interval`. That key is required only then. The controller refuses to start when `tail_interval` is not longer than `probe.interval` or is not shorter than the staleness window (`3 * probe.interval + packets * timeout`, plus retry packets when a second probe can run). A slower tail would be stale on every decision, and stale data withdraws an improvement. Problem prefixes stay ahead of this list, keep the normal interval, and a problem prefix that also clears the floor still uses one slot.

Up to three destinations on a flow target are probe candidates, not pins (#113, #119). They are the destinations with the most bytes in the prefix over the window, busiest first. Each time bucket keeps only its own three busiest destinations, and a destination that never makes a bucket's three is not recovered when the window is summed. A problem prefix lists the address the failures were seen on first, then those destinations, still at most three. The engine probes the named addresses first. When fewer than three were named, it fills with the automatic in-prefix addresses (the first host, a quarter point, and a halfway point).

When three were named, it does not add those automatic addresses. A usable provider `next_hop` still takes the last of the four slots. A host that sends no reply, or that does not qualify under `probe.min_replies` and `probe.dispersion_ms`, is left out of the loss and latency when another address inside the prefix qualifies. When none qualify, every measured host still counts. The addresses tried are on the probe result (`targets`). An operator `host` on `static`, `vip`, or `traceroute` for the same prefix is still the only address probed.

An active improvement whose prefix falls off this list (below both floors, or past `max_targets`) stays on that last host and interval until the improvement retires. This does not announce. Every packet still waits on `probe.rate_limit_pps`.

`problems` (optional, off when omitted) turns on passive problem detection from TCP flags. It reads unsampled NetFlow v5, NetFlow v9, and IPFIX records that carry the source address, protocol, and TCP flags (information elements 8 or 27, 4, and 6). An outbound record (local source, remote destination) is one flow; if its flags hold SYN without ACK, the handshake never completed and it counts as a timeout. An inbound record from a remote source with RST counts as a reset. A prefix is a problem when (timeouts + resets) / flows is at least `failure_pct` and it has at least `min_flows` flows inside `window`. Problem prefixes are listed first, worst first (weight is the ratio to the threshold), then the busiest prefixes that are not already listed. Sampled exports (a sampling rate above 1) and sFlow are skipped, because a sampled record may hold only the SYN. Retransmissions and RTT are not visible in flow records; use the `span` source for those.

| Key | Default | Bounds |
|---|---|---|
| `problems.local` | none | Required when `problems` is set. Your own networks, CIDRs, no host bits, no default route, no duplicates. |
| `problems.failure_pct` | 20 | 0-100. Zero uses the default. |
| `problems.min_flows` | 10 | Zero uses the default. |
| `problems.max_targets` | 100 | 1-100000. |

`transit` (optional, off when omitted) classifies traffic as transiting or local (#29, IRP "optimization of transiting traffic"). A flow record whose source address is inside `customers` (the customer or downstream networks behind this edge, whose traffic crosses your network to the Internet) is transit; a record with any other source is local. Records without a source address (an sFlow raw header that is not IP, or a NetFlow v9/IPFIX template without IE 8 or 27) are not classified. NetFlow v5, v9, IPFIX, and sFlow (sampled IPv4/IPv6 records and raw headers) all carry the source.

Per prefix, over the same `window`, the source keeps the transit and local byte counts; a prefix whose transit share is at least `share_pct` is a `transit` prefix, otherwise `local`. The class does not change the targets or their weights. Before each decision the controller passes it to the policy chain, where `rules` with `traffic: transit` or `traffic: local` give customer-originated and local traffic separate policies (see [Policy `rules`](#policy-rules)). A prefix with no classified bytes in the window has no class, and traffic rules do not match it.

Classification never announces: the allowlist, learned-RIB check, community and NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged. Rollback: remove `transit` (and the `traffic` rules).

| Key | Default | Bounds |
|---|---|---|
| `transit.customers` | none | Required when `transit` is set. Source CIDRs of the customer networks whose traffic transits. No host bits, no default route, no duplicates, at most 10000. |
| `transit.share_pct` | 50 | Above 0, at most 100. The transit share of a prefix's classified bytes at or above which it is a transit prefix. Zero uses the default. |

`subranges` (optional, off when omitted) measures parts of a wide prefix separately (#121, IRP prefix splitting). A learned /16 that spans metros otherwise gets one score. With this block the source also counts bytes per sub-range of `bits_v4` or `bits_v6` (a /24 inside a /16, a /48 inside a /32) for every prefix wider than that length, and each target carries its `max_subranges` busiest sub-ranges, each with its own busiest destination as the probe address and its bytes as the weight. A prefix with traffic in fewer than two sub-ranges is not split. `max_total` caps sub-ranges across the whole list, busiest prefixes first; a prefix that would get fewer than two from what is left gets none. Each time bucket tracks at most twice `max_subranges` sub-ranges per prefix, the same way it keeps three destinations, so a sub-range that never makes a bucket's set is not recovered later.

The probe engine then measures each sub-range's address per provider, instead of the prefix's own candidate and automatic addresses, with a loss or dispersion retry per sub-range when those are on. The prefix result is the traffic-weighted mean of its sub-ranges: loss over every measured sub-range, RTT and jitter over those that answered. A sub-range with no reply, or whose probe errored, counts as full loss for that provider, so every provider is scored over the same sub-ranges and one that fails on the busiest sub-range cannot look better by leaving it out. The decision for the prefix uses that aggregate exactly as it uses any other result.

When no sub-range could be measured, the prefix addresses are probed as before. A pinned `host` on `static`, `vip`, or `traceroute` for the same prefix ignores sub-ranges, and a sub-range address on an `exchanges[].lans` prefix is not probed. Every packet still waits on `probe.rate_limit_pps`; the default of four sub-ranges sends about as many packets as the four prefix addresses it replaces.

Sub-ranges of one prefix are probed one after another, like the prefix addresses, so a large `max_subranges` toward silent addresses takes longer per prefix; keep it small enough that a round still finishes inside its deadline (about three `probe.interval`s). The same holds for `max_total`: across the list, sub-ranges can mean up to four times the probe work of the prefix addresses alone at `max_subranges: 16`, plus a retry each when retries are on.

A round that runs past the staleness window fails safe (stale data withdraws an improvement), but lower `max_total` or `max_subranges`, or raise `probe.rate_limit_pps`, if `/api/probes` shows results going stale. When two sources send sub-ranges for the same prefix, the first source in `sources` order wins and the later list is ignored. A prefix that only the decision state still keeps in the probe set (an active improvement no source lists any more) is measured on its addresses, not on its last sub-ranges.

`/api/decisions` lists the sub-ranges on the decision (`subranges`: prefix, weight, each provider's score, and `best`), and sets `heterogeneous: true` when two of them have different best providers. The dashboard prefix card shows a "heterogeneous" badge and the sub-range table. Sub-ranges are measured only and never announced: the decision still steers only the learned prefix, and the allowlist, learned-RIB check, community and NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged. Announcing a sub-range is the separate, opt-in `synthesize` design (#122), which this block does not turn on. Rollback: remove `subranges` and restart.

| Key | Default | Bounds |
|---|---|---|
| `subranges.bits_v4` | 24 | 1-32. IPv4 sub-range length. A prefix this long or longer is not split. |
| `subranges.bits_v6` | 48 | 1-128. IPv6 sub-range length. |
| `subranges.max_subranges` | 4 | 2-16. Busiest sub-ranges measured per prefix. |
| `subranges.max_total` | 1000 | 2-10000. Sub-ranges across every target in one list. Each is probed per provider, so a large value lengthens a round; keep rounds inside the staleness window (see above). |

### Source `span`

Off unless this source is listed. It reads a SPAN or mirror port with an AF_PACKET socket (needs `--cap-add NET_RAW` and host networking) or replays a classic pcap file, follows TCP connections between `local` and remote addresses, and returns remote prefixes that look broken so they are probed first. Packets are parsed and dropped. Only per-connection sequence state (capped by `max_flows`) and per-prefix counters over `window` are kept; each time bucket holds at most 20000 prefixes. The source does not announce, and a problem prefix still needs the RIB, the allowlist, the thresholds, the cap, and hold time before anything is injected.

Per connection, it counts:

- **Retransmissions**: outbound data segments that repeat bytes already sent (a one-byte keepalive is not counted).
- **Timeouts**: a local SYN with no remote SYN-ACK, or a local SYN-ACK with no remote ACK, within `syn_timeout`.
- **Resets**: a RST from the remote side. A local RST is not a path problem and is ignored.
- **Handshake RTT**: local SYN to remote SYN-ACK, or local SYN-ACK to remote ACK, measured at the mirror. A retransmitted handshake gives no sample.

A remote prefix is a problem when retransmissions / data segments >= `retrans_pct` (with at least `min_segments`), (timeouts + resets) / connections >= `failure_pct` (with at least `min_flows`), or, when `rtt_ms` is set, average handshake RTT >= `rtt_ms` (with at least `min_flows` samples). The score is the largest ratio of an observed value to its threshold. The list is worst first, capped at `max_targets`, and a prefix is marked urgent on the first round it appears. The source is read on every probe round. Remote addresses are mapped to the covering learned RIB prefix when the view is ready, otherwise aggregated to `aggregate_v4` or `aggregate_v6`. Private, ULA, loopback, link-local, multicast, `exclude`, and exchange peering LAN addresses are dropped before that aggregation (#145), as is traffic between two local or two remote addresses. A LAN address is not in the window. Ethernet with up to two VLAN tags, raw IP, and Linux cooked captures are decoded.

| Key | Default | Bounds |
|---|---|---|
| `interface` | none | The mirror interface inside the container (host networking). Exactly one of `interface` or `pcap_file`. |
| `pcap_file` | none | Absolute path to a classic pcap (not pcapng) mounted into the container. Replayed once at startup with its timestamps shifted to now. For labs and incident review. |
| `promiscuous` | true | Interface capture only. Promiscuous mode is a socket membership: the kernel drops it when the socket closes or the process dies. |
| `local` | none | Required. Your own networks, CIDRs, no host bits, no default route, no duplicates. |
| `exclude` | none | Remote CIDRs to ignore, no host bits, no duplicates. |
| `window` | `5m` | `10s`-`24h`. |
| `retrans_pct` | 5 | 0-100. Zero uses the default. |
| `failure_pct` | 20 | 0-100. Zero uses the default. |
| `rtt_ms` | 0 | 0-60000. Zero disables the RTT check. |
| `min_segments` | 100 | Zero uses the default. |
| `min_flows` | 10 | Zero uses the default. Also the minimum RTT samples. |
| `syn_timeout` | `3s` | `100ms`-`1m`. |
| `flow_idle` | `2m` | Longer than `syn_timeout`, at most `1h`. Idle connections are forgotten. |
| `max_flows` | 100000 | 1-10000000. A new connection beyond the cap is not tracked and is counted in `packeteer_truncated_total{limit="max_flows"}`. |
| `max_targets` | 100 | 1-100000, and at most `max_prefixes`. |
| `max_prefixes` | 20000 | 1-250000 (#217). Prefix cells per time bucket. A new prefix past it is counted in `packeteer_truncated_total{limit="max_prefixes"}`. |
| `aggregate_v4` | 24 | 1-32. |
| `aggregate_v6` | 48 | 1-128. |

Interface capture fails startup when the interface is missing or `NET_RAW` is not granted. A capture error after startup is logged and the source returns what it has already counted. On loopback, outgoing copies are skipped so each frame is counted once. Rollback: remove the source and restart.

### Scorer `weighted`

`score = loss_pct * loss_weight + rtt_ms * rtt_weight + jitter_ms * jitter_weight + reorder_pct * reorder_weight`.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |
| `reorder_weight` | 0 | Not negative. Points per percent of the provider path's RFC 4737 reordered ratio from `probe.reorder` `twamp` responders (#224). `0` leaves reordering out of the score. An `icmp` estimate is never scored. |

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
| `reorder_weight` | 0 | Not negative. As on `weighted`. |
| `loss_override` | false | `true` allows a commit move onto higher loss. |
| `balance` | `off` | `off`, `equal`, or `proportional`. |
| `balance_slack` | `0.10` | 0-1. Fractional imbalance that does not move traffic. `0` is explicit. |
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
| `reorder_weight` | 0 | Not negative. As on `weighted`. |
| `precedence` | `performance` | `performance` or `cost`. |
| `floor` | | Block with `max_loss_pct` and `max_rtt`. |
| `max_loss_pct` | 0 | 0-100. Loss percentage points a cost path may carry above the lowest loss. |
| `max_rtt` | `10ms` | 0-10s. Latency a cost path may add over the lowest RTT. |
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
| `rules` | none | Required, 1-10000 entries. |

Each rule:

| Key | Meaning |
|---|---|
| `name` | Optional, unique. Shown in decisions and logs. Defaults to `rules[i]`. |
| `action` | Required. `ignore`, `allow`, `deny`, `static`, or `vip`. |
| `providers` | Configured provider names. `allow` and `deny` need at least one, `static` exactly one, `ignore` and `vip` none. |
| `prefixes` | CIDRs. A rule prefix matches itself and every more-specific probed prefix. |
| `asns` | Origin ASNs (the last ASN of the learned AS path). Matches only while the RIB view is ready. |
| `countries` | ISO 3166-1 alpha-2 codes. Looked up for the first address of the probed prefix, `country` first, then `registered_country`. |
| `max_loss_pct` | Required for `static`, 0-100: the highest loss the pinned path may show. Not allowed on other actions. |
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
| `max_api_duration` | `24h` | Longest on-demand window, 1m-7 days. |

Each window:

| Key | Meaning |
|---|---|
| `name` | Optional, unique. The window ID is `schedule-<name>`. |
| `providers` | Required. Configured provider names. |
| `schedule` | Five-field cron start time: minute, hour, day of month, month, day of week (0-7, 0 and 7 are Sunday). `*`, numbers, ranges `a-b`, steps `*/n` or `a-b/n`, and comma lists. When both day fields are restricted, either one matches; as in Vixie cron, a day field that starts with `*` (such as `*/2`) counts as unrestricted, so the fields are then AND-ed. Use with `duration`. |
| `duration` | 1m-7 days. How long each scheduled window stays open. |
| `start`, `end` | RFC 3339 timestamps for a one-off window. Use instead of `schedule` and `duration`. |
| `reason` | Optional text shown in the API. |

On-demand windows go through the ops API and live in memory only; a restart ends them, and the controller logs this at startup. Put a planned window in `windows` if it must survive a restart. The controller checks windows every 15 seconds and wakes the decision loop when a scheduled window opens or closes, so it does not wait for the next probe round. They require HTTP basic auth (`PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`); without it the API refuses to open or close windows.

```sh
curl -u "$USER:$PASS" -H 'Content-Type: application/json' \
  -d '{"providers":["transit-b"],"duration":"2h","reason":"provider ticket"}' \
  http://127.0.0.1:8080/api/maintenance
curl -u "$USER:$PASS" -H 'Content-Type: application/json' \
  -d '{"providers":["transit-b"],"start":"2026-10-20T01:00:00Z","end":"2026-10-20T03:00:00Z"}' \
  http://127.0.0.1:8080/api/maintenance
curl -u "$USER:$PASS" http://127.0.0.1:8080/api/maintenance
curl -u "$USER:$PASS" -X DELETE http://127.0.0.1:8080/api/maintenance/api-1
```

`GET /api/maintenance` lists `windows` open now from every maintenance policy, `upcoming` windows (configured one-off and on demand), and `finished` ones (configured one-off, and on-demand ones for 24 hours; at most 50). A recurring window is listed only while it is open. `POST` opens a window on the first `maintenance` entry (JSON only; at most 100 open or upcoming at a time). Give `duration` (a window from now) or both `start` and `end` (RFC 3339); the length is 1 minute to `max_api_duration`, `end` must be ahead, and `start` at most 7 days ahead. A window that has not started excludes nothing. `DELETE /api/maintenance/<id>` closes an on-demand window; configured windows cannot be closed from the API.

### Exporters

`exporters` is a list like `notifiers`: `type`, optional `name`, `config`. Unknown keys are errors, and a failing sink never stops Packeteer. Streams, records, and rollback: [export.md](export.md). Secrets are environment variable names, never values.

| Type | Key | Default | Meaning |
|---|---|---|---|
| `kafka` | `brokers` | required | Seed brokers, `host:port`. |
| | `topic_prefix` | `packeteer` | Topics are `<prefix>.events`, `.decisions`, `.flows`. Letters, digits, `.`, `_`, `-`. |
| | `streams` | `events`, `decisions` | Any of `events`, `decisions`, `flows`. |
| | `tls`, `ca_file` | off | TLS to the brokers; `ca_file` is an absolute PEM path and needs `tls`. |
| | `sasl` | none | `plain`, `scram-sha-256`, or `scram-sha-512`. Needs `tls: true`, `username_env`, and `password_env`. |
| `nats` | `urls` | required | `nats://` or `tls://` server URLs, no credentials in them. |
| | `subject_prefix` | `packeteer` | Subjects are `<prefix>.events`, `.decisions`, `.flows`. |
| | `streams` | `events`, `decisions` | As for `kafka`. |
| | `tls`, `ca_file` | off | As for `kafka`; a `tls://` URL needs `tls: true`. |
| | `username_env`, `password_env` | none | Both or neither; need `tls: true`. |
| `otlp` | `endpoint` | required | OTLP/HTTP base URL, for example `http://collector.example.net:4318`; `/v1/traces` is added. |
| | `headers` | none | Request headers; values may use `${VAR}`, and an unset variable is an error. |
| | `ca_file` | system roots | PEM for an `https` endpoint. |
| | `service_name` | `packeteer` | The `service.name` resource attribute. |
| `ipfix` | `address` | required | Collector `host:port`, UDP. Takes `flows` only. |
| | `observation_domain` | `1` | Sent in every message. |
| | `template_interval` | `1m` | How often templates are sent again. |

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
| `to` | none | Required, 1-50 recipient addresses. |
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
| `engine_id` | none | Required for `3`: Packeteer's authoritative engine ID, 5-32 bytes of hex. Configure the same ID for the user on the receiver. |
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
| `commit_mbps` | Optional. 0-100000000. Omitted or `0`: no commit, so no billable figure (see [Interface capacity limit](#interface-capacity-limit)). |
| `capacity_mbps` | Optional. 0-100000000. The interface speed `providers[].interface_capacity_threshold_pct` judges `out_mbps` against. Unset is unknown. |
| `usage_mbps` | Required. 0-100000000. Reported as the single billable figure (`greater_separate`). |
| `in_mbps` | Optional. 0-100000000. Reported as the inbound rate and inbound 95th, which `inbound` compares with `commit_mbps`. Unset is 0. |
| `out_mbps` | Optional. 0-100000000. Reported as the latest outbound rate, which [`verify`](#verify) reads. Unset is 0. |

The row's timestamp is the time of the read, so `max_age` on the commit scorer does not age it out. A file that fails to parse yields no rows for that decision.

### Telemetry `snmp`

Off unless a `telemetry` entry lists `type: snmp`. It polls IF-MIB counters and keeps 95th-percentile usage for the open billing period. It does not announce. The `commit` scorer reads the snapshot when that scorer is selected; the collector itself does not change a decision. A failed poll does not withdraw performance improvements. Samples for the open period live in memory. When `storage` is configured, each accepted sample is also written to that database, per provider binding and billing period, and the open period is loaded on start so the 95th matches after a restart. Without `storage`, a restart clears the window. A closed period is left in the database until `retention` deletes it (the period has ended, and its end is older than retention). A failed write keeps the sample in memory and does not change a decision. `Updated` on reload is the time of the last stored sample, so commit control still ignores a reading older than `max_age`.

The billing period is `[start, end)` in UTC, opening at 00:00 UTC on `billing_day`. `billing_day` is 1-28 so the day exists in every month.

The 95th percentile is nearest rank: sort the samples ascending and take 1-based rank ceil(0.95 x N), computed as `(95xN+99)/100`. For a multiple of 20 that is the sample left after the top 5% are discarded. For N of 10 the rank is 10.

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
| `interval` | `5m` | `30s`-`1h`. Time between polls. |
| `timeout` | `5s` | At least `100ms`, shorter than `interval`. Per SNMP request. |
| `retries` | 1 | 0-5. Extra attempts after the first. `0` does not retry. |
| `workers` | 4 | 1-16. Hosts polled at once. A slow or unreachable host holds one worker for at most its request timeouts and does not delay the other hosts. `0` uses the default. |
| `max_samples` | 100000 | 1-1000000. Oldest samples in the open period are dropped past this, in memory and in storage. `0` uses the default. |
| `hosts` | none | Required. One SNMP agent. Several providers can share a host. |
| `providers` | none | Required. Each entry names a configured provider. |

Each host:

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique in `hosts`. |
| `address` | required | IP address or hostname. It is not resolved at startup. |
| `port` | 161 | 1-65535. |
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
| `commit_mbps` | Optional, at most 100000000. The `commit` scorer compares the billable 95th with this. The collector does not enforce it. Omitted or `0`: no commit, so no billable figure; the rates and capacity are still reported. |
| `capacity_mbps` | Optional, at most 100000000. The interface speed `providers[].interface_capacity_threshold_pct` judges the outbound rate against. Omitted or `0` uses the agent's `ifHighSpeed`, else `ifSpeed`. |
| `billing_day` | Required with `commit_mbps`. 1-28. UTC. Defaults to 1 without a commit. |
| `percentile` | Required with `commit_mbps`. `separate`, `greater`, or `greater_separate`. Defaults to `separate` without a commit. |

### Storage `sqlite`

Off unless `storage.type` is `sqlite`. Keeps report history in an embedded SQLite file (pure Go, no cgo, works in the stock image). It records history only: it does not announce and does not change a decision. A write error is logged and retried on the next flush; it never delays or withdraws an improvement. The rollback is to delete the `storage` block and restart.

| Key | Default | Meaning |
|---|---|---|
| `path` | `/var/lib/packeteer/packeteer.db` | Database file. Must be absolute. The directory is created on start. Mount a volume on it (`-v packeteer-data:/var/lib/packeteer`) so history survives a container restart. |
| `retention` | `9600h` (400 days) | Rows older than this (audit records and events included) are deleted on start and once a day. `24h`-`87600h`. An improvement that is still active is kept. |
| `round_retention` | `0` (off) | Keeps the input of the decision rounds this long so `packeteer whatif` and `POST /api/whatif` can replay it (#204; [onboarding.md](onboarding.md#replay-history)). `0` or `1h`-`720h`. Rounds are pruned on each write; at `0` nothing is pruned, so rounds stored earlier stay until the database is deleted. A round is about 65 KB per 1000 prefixes with three providers (gzip; a test on synthetic data holds it under 80 KB). A round is kept for each probe round and for each evaluation that changes something; evaluations on a RIB change in between are kept at most twice per `probe.interval`. Probe rounds come about once per `probe.interval`, plus early re-probes while `confirm_rounds` is above 1 or a per-prefix interval is shorter, so at 30s it is about 190 MB a day for 1000 prefixes, up to twice that with RIB-change rounds, and more with early re-probes. The interval is read at start; a reload does not change it. Size it to the window you want to replay. Backup copies the rounds with the rest of the file. |

What is stored:

- With `round_retention`, one row per decision round: its time and the gzip'd JSON input Decide saw (probe results, provider health, learned native providers, volumes, telemetry, policy verdicts, leak-watch holds). Synthesized sub-ranges (#122) are not stored.
- Daily probe rollups per prefix and provider (UTC day): probes, failed probes, and sums of loss, RTT, and jitter. Raw probe results are not stored.
- One row per improvement, from start to end. A switch to another provider ends the row and starts a new one. Each row has the cause, reason, mode, the native provider's loss and RTT and the chosen provider's loss and RTT at the decision that started it, `cost_delta`, `est_savings`, the prefix volume when known, the origin ASN (last AS in the learned path), and the country. In observe and suggest these are recommendations; in inject they were announced.
- Per prefix: origin ASN, country, and latest volume.
- Recent events (#173) for the Events page: time, kind, severity, message, and fields. Pruned by `retention`. Without `storage` the page keeps the newest 1000 in memory.
- SNMP 95th-percentile samples (#127), when a `telemetry` plugin of type `snmp` is configured: one row per provider binding and sample time (inbound and outbound bits per second, and the billing period). The collector loads the open period on start. A closed period stays until `retention` (rows whose period has ended by the cutoff). This does not announce. Without `storage`, those samples stay in memory and a restart clears them.

The recorder buffers in memory and writes once a minute and on shutdown, after the routes are withdrawn. Rows a previous process left open are closed on start with `controller restarted (routes withdrawn)`.

It also keeps each user's custom dashboards (#34, `/api/dashboards`) with the users and tokens; retention does not prune them, and deleting a user deletes that user's dashboards.

Country comes from the first `rules` policy that has a `geoip_db`. With none, the `countries` report is empty. Volume is the flow window or a static target's `mbps`.

Reports (`/api/reports/<name>`, JSON or `?format=csv`, and the dashboard): `summary`, `improvements`, `exchanges` (#148: one row per `exchanges` peer with improvements started, active now, prefixes, Mbps moved, and hours steered), `causes` (started per UTC day by cause), `performance` (average loss and RTT before and after, by cause), `providers` (probes, failure rate, average loss, RTT, jitter, improvements onto and off each provider, hours steered onto it), `prefixes`, `asns`, `countries` (`sort=problems`, the default, then `volume` or `loss`), `probes` (per UTC day), `timeseries` (#129: per UTC day and bucket, the native provider's average loss and RTT beside the chosen provider's, from the daily rollups; buckets `all`, `problem`, `better_20`, `better_50`; not cut by `limit`; see [ui.md](ui.md#graphs)), and `savings`.

`est_savings` is `cost_delta` times volume, treated as a monthly rate; `accrued` is that rate times the hours active inside the range divided by 730. Probe figures are daily rollups, so a range that starts mid-day includes that whole UTC day; improvement figures use the exact range. Query: `days` (default 7, at most 3660), or `from` and `to` (RFC 3339 or `YYYY-MM-DD`, UTC), and `limit` (1-10000; default 20, or 100 for `improvements` and `savings`).

### Whois `rdap`

Used under `troubleshoot.whois`. Asks an RDAP server (RFC 9082/9083) about an address, prefix, or ASN. No credentials. The request leaves from the container's default route, not a provider source.

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `https://rdap.org` | RDAP service. `http` or `https`, no credentials, query, or fragment. rdap.org redirects to the right registry; at most 3 redirects, and an `https` base never follows a redirect to `http`. |
| `timeout` | `5s` | Whole request, up to `1m`. |
| `max_bytes` | `262144` | Largest response accepted, 1024-4194304. |

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

**Packeteer's own routes.** A router reports Packeteer's injected route back over BMP: in the Adj-RIB-In of Packeteer's iBGP session and, once it wins, in Loc-RIB. Its next hop is the steered provider. Packeteer ignores every path on a peer whose BGP ID is its `router_id`, and every path tagged with `packeteer_community` (a standard community or a large community), so an injected route never keeps its prefix in the view or passes its own route check. Keep `packeteer_community` on the route through the router's import policy (the lab edge does) so Loc-RIB still carries it. The own-session filter covers only the router Packeteer peers with. If Packeteer's route is reflected to another monitored router (a route reflector, whose Adj-RIB-In shows the reflector's BGP ID, not `router_id`), only the community identifies it. An import policy or reflector that strips the community would let the injected route keep its prefix learned. The controller logs a warning at startup whenever a provider uses `prefer` or `only`, as a reminder.

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
| `poll_interval` | `2s` | How often each peer is fetched, 100ms-1m. |
| `timeout` | `poll_interval` | Bound on one fetch. At most `poll_interval`. |
| `max_age` | 3 x `poll_interval` | How long a peer's last good snapshot stays usable, `poll_interval`-10m. After that the peer is stale and this instance acts standalone. |
| `max_bytes` | 16 MiB | Cap on a fetched snapshot, 1024-1073741824. |
| `accept_settings_from` | empty | Certificate names (CN or DNS SAN) allowed to push `thresholds` and `policies` to this instance at `/v1/settings` (#137). Empty refuses every push. Separate from `allow_clients`. Needs `listen`, and `http.config_editor: true`, because a push is written to the mounted file. See [Pushing settings](multi-pop.md#pushing-settings). |

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
| `role_map` | none | Group -> `viewer`, `operator`, or `admin`. The highest mapped role wins. |
| `default_role` | none | Role when no group maps. Empty refuses the sign-in. `role_map` or `default_role` is required. |

The role is set at every sign-in. An SSO user is stored with no password; an admin can disable it (`PATCH /api/users/<name>` `{"disabled":true}`), which ends its session and refuses later sign-ins. A local user's name cannot be taken over by SSO.

### Elector `lease`

The built-in active/standby elector (#31): a lease file on storage both instances mount (one Docker volume on one host, or a shared filesystem with working `flock`). It never announces. Every read-modify-write happens under an exclusive lock on `path` + `.lock` and replaces the record with an atomic rename.

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Lease file, absolute. The directory is created on start. Both instances must see the same file. |
| `id` | `PACKETEER_HA_ID`, then the hostname | This instance's name in the pair. Letters, digits, `_`, `.`, `-`, at most 64 characters. The two instances must differ. |
| `ttl` | `10s` | Lease time, `2s`-`5m`. The active instance stops announcing `ttl`/2 after its last successful renewal, even when its renew loop is stuck. |
| `renew` | `ttl`/5 | Renewal and standby poll interval, at least `100ms` and at most `ttl`/4. |

A standby takes a lease that is free or released at its next renewal. It takes a lease held by another instance only after the record has not changed, on its own monotonic clock, for the longer of `ttl` and `ttl`/2 + the holder's recorded BGP hold time + `renew`, so clocks need not agree. The hold time is the longest negotiated hold time of the holder's established sessions (90s when unknown), refreshed at every renewal; set a short hold timer on the edge (for example 9s) for a fast takeover after a crash. A restarted instance does not reuse its predecessor's lease. An unreadable lease file counts as held by an unknown instance.

| Variable | Effect |
|---|---|
| `PACKETEER_HA_ID` | `id` when the config does not set it. |

### Leak source `bmp`

A BMP station for the leak watch (#199). It listens on its own port, separate from the [RIB source `bmp`](#rib-source-bmp), and nothing it receives enters the RIB view. It reads only post-policy tables: the Adj-RIB-In of `external_routers` (routers outside your AS) and the Adj-RIB-Out (RFC 8671) of `own_routers` toward eBGP peers. Pre-policy tables, Adj-RIB-Out of external routers, Adj-RIB-In of your own routers, and, in the Adj-RIB-Out of `own_routers`, sessions to a peer in your own AS are ignored. Healthy while at least one router has a session.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `:11020` | `host:port` for the station. |
| `external_routers` | none | Addresses of routers outside the AS allowed to connect. |
| `own_routers` | none | Addresses of your edge routers allowed to connect. An address cannot be in both lists, and at least one list is required. |
| `idle_timeout` | off | Drop a router's session after this long without a BMP message (at least 10s). |

### Leak source `rislive`

Reads the public [RIPE RIS Live](https://ris-live.ripe.net) HTTP stream (#199). The subscription asks for UPDATE announcements whose AS path contains `asn`. The only request is the GET that opens the stream. A lost stream is retried after 5s, doubling to 5m; it is unhealthy meanwhile. A stream silent for 15 minutes is treated as lost and reopened, since the endpoint sends no keepalive. It needs the local `asn`. A route is seen only after it left the AS and propagated, so it complements a router-side source.

| Key | Default | Meaning |
|---|---|---|
| `url` | `https://ris-live.ripe.net/v1/stream/` | Stream endpoint, `http` or `https`, without a query (`format=json` and `client` are added). |
| `client` | `packeteer-leak-watch` | Client name sent to the service. |

### RPKI source `rtr`

Connects read-only to an RPKI-to-Router server (RFC 8210) such as the operator's Routinator, caches the validated ROA payloads, and validates origin ASNs (RFC 6811). It never announces and never changes the learned RIB. The cache is in memory and holds at most 2,000,000 payloads; a server that exceeds that is dropped. A lost or stalled connection is retried with backoff. When the cache is older than `staleness`, every lookup is `unknown` (fail open). A reset or serial response reaches the cache only at End of Data, so an Error Report or a dropped connection before it leaves the last complete cache in place, and the session is retried. A Serial Notify is answered with the client's last serial, or a Reset Query when the session ID differs, and is ignored while a reset or serial response is in flight.

| Key | Default | Meaning |
|---|---|---|
| `address` | none | Required. The server as `host:port` (for example `routinator.example.net:3323`). An IPv6 host needs brackets. |
| `refresh` | `5m` | How often a healthy session is polled for changes. 1s-24h. |
| `staleness` | `1h` | How long the cache is served after the last complete fetch. At least `refresh`, at most 24h. Older or missing data is `unknown`. |
| `timeout` | `30s` | Dial, TLS or SSH handshake, and read wait. 1s-5m. |
| `tls` | off | RTR over TLS (RFC 8210 section 9.2). `ca_file`: PEM CAs that sign the server certificate (empty: the system roots). `server_name`: the name checked in the certificate (empty: the `address` host). `tls: {}` uses both defaults. |
| `ssh` | off | RTR over SSH (RFC 8210 section 9.1), subsystem `rpki-rtr`. `user`, `key_file` (an unencrypted private key), and `known_hosts` (an OpenSSH known_hosts file with the server's key) are all required; a host key not in it is refused. Mount the files; not with `tls`. |

The tests replay the RTR answers recorded from Routinator 0.15.1, StayRTR 0.6.4, and FORT 1.6.8 (`internal/plugins/rpki/rtr/testdata`); TLS and SSH are tested against in-process servers.

### RPKI source `json`

Polls a VRP set published as JSON over HTTP: Routinator's `/json` endpoint or the `json` file rpki-client writes with `-j` (served by any web server). ASNs may be `"AS64496"` or `64496`. It validates origins from its own cache (RFC 6811), so a lookup never waits on the network. The data time is the document's `metadata.generated` (Routinator) or `metadata.buildtime` (rpki-client), else the fetch time, so a cache that keeps serving an old file goes stale. A failed fetch or a document that does not parse keeps the last good cache until `staleness`. At most 2,000,000 payloads and 512 MiB per document.

Because the data time is the publisher's, a document is already up to one publisher cycle old when fetched, and up to that plus `refresh` just before the next poll. `staleness` must be well above the publisher's regeneration cycle plus `refresh`, not merely at least `refresh`: Routinator regenerates every 10m by default, and rpki-client is usually run hourly from cron, so its `buildtime` advances about once an hour plus the run time. A lower `staleness` makes every lookup `unknown` or flaps `rpki.stale`/`rpki.fresh` each cycle. The controller refuses a `staleness` below `refresh` plus 1h, and logs a warning when a fetched document would go stale before the next poll.

| Key | Default | Meaning |
|---|---|---|
| `url` | none | Required. `http` or `https`, without credentials (for example `http://routinator.example.net:8323/json`). |
| `refresh` | `5m` | Poll interval. 1s-24h. |
| `staleness` | `2h` (`refresh` plus 1h when that is longer) | How long data is served after the document's time. At least `refresh` plus 1h, at most 24h. See above. |
| `timeout` | `30s` | One fetch. 1s-5m. |

### RPKI display fallback `ripestat`

Display-only last resort (#200). When no `rpki.sources` entry has fresh data, the learned paths on `/api/prefixes` and the prefix card are looked up with the public RIPEstat `rpki-validation` data call, by prefix and origin AS. Each lookup sends that prefix and origin AS to RIPE NCC. A miss shows `unknown` and is queued; lookups wait on `rate_per_minute`, a full queue drops the request until the card asks again, and answers are cached for `ttl` (at most 10,000). RIPEstat's `unknown` is `notfound`; `invalid_asn` and `invalid_length` are `invalid`. The answer is labeled with this entry's name and its lookup time. It is never used by decisions, `avoid_invalid`, leak watch, or the exchange counts.

| Key | Default | Meaning |
|---|---|---|
| `rate_per_minute` | `10` | Lookups sent per minute. 1-60. |
| `ttl` | `1h` | How long an answer is shown before it is looked up again. 1m-24h. |

### IRR source `whois`

Queries one whois server on TCP (port 43) per lookup: route/route6 objects for exactly the prefix, as-set members, and the aut-num `as-name`. Each lookup sends the prefix, as-set name, or AS number to that server. Every connection waits on a `rate_per_minute` slot, and `timeout` bounds one TCP connection: the dial, then the query and answer, so one connection can take up to about twice `timeout` of wall time. With `dialect: irrd` a lookup is one connection. With `dialect: ripe` an as-set lookup opens one connection per set it expands (bounded, see below), each with its own `timeout` and rate slot. A server error, a refused database, or a timeout is a failed lookup (the source did not answer); nothing found is an answer.

`dialect: irrd` uses the IRRd commands (`!!`, `!s`, `!r`, `!i<set>,1`, `!maut-num`), for any IRRd v4 instance, including an operator's own, and mirrors such as `rr.ntt.net`, which through `!s` serves RADB, RIPE, ARIN, APNIC, AFRINIC, LACNIC, NTTCOM, ALTDB, LEVEL3, and the other databases it lists for `!s-lc`. `dialect: ripe` uses RIPE database flags (`-r -s <databases> -x -T route,route6`, `-T as-set`, `-T aut-num`), for `whois.ripe.net`, `whois.apnic.net`, and `whois.afrinic.net`; as-sets are expanded set by set (at most 1,000 sets, 8 levels deep). `%ERROR:101` (no entries) is nothing found; any other `%ERROR` fails the lookup.

| Key | Default | Meaning |
|---|---|---|
| `address` | none | Required. `host:port`, for example `rr.ntt.net:43`. |
| `dialect` | `irrd` | `irrd` or `ripe`. |
| `databases` | server default | IRR databases to query, in priority order (sent as `!s` or `-s`; upper-cased, at most 32). Objects are listed in this order, so the first database named is the one shown. List them explicitly: some mirrors include the `RPKI` pseudo-source by default, whose objects are skipped. |
| `timeout` | `10s` | One TCP connection: the dial, then the query and answer (up to about twice this in wall time). Each connection of a `ripe` as-set expansion gets its own. 1s-1m. |
| `rate_per_minute` | `60` | Connections opened per minute. 1-600. |

The tests replay answers in the shape seen from rr.ntt.net (IRRd 4) and the RIPE database (`internal/plugins/irr/whois/testdata`) against in-process servers; no test queries a live IRR.

### IRR source `file`

Reads a mounted file and answers from memory. It is read again when its size or modification time changes; a file that does not parse keeps the last good data (with its old data time, so it ages out at `irr.staleness`). A missing file is logged at start and fails lookups until it appears. At most 4 GiB and 10,000,000 routes.

`format: rpsl` is RPSL objects as in an IRR database dump: route and route6 (exact prefix), as-set (expanded recursively), and aut-num (`as-name`). `format: bgpq4` is one or more concatenated `bgpq4 -j` documents whose list is named after the origin AS, for example `bgpq4 -j -l AS64500 AS64500`; an entry with `greater-equal`/`less-equal` covers those lengths. bgpq4 output has no as-sets or aut-nums, so those lookups are left to the next source.

| Key | Default | Meaning |
|---|---|---|
| `path` | none | Required. The file inside the container, for example `/etc/packeteer/irr/routes.db`. |
| `format` | `rpsl` | `rpsl` or `bgpq4`. |

### Detector `baseline`

The built-in anomaly detector (#33). For each destination prefix and IP protocol it keeps an exponentially weighted mean and variance of the rate seen each round. A round is anomalous when the rate is at least `min_mbps`, at least `min_ratio` x the mean, and more than `sensitivity` standard deviations above the mean, after `warmup` rounds of learning; or, with `max_mbps` set, when the rate reaches that ceiling whatever the baseline (this also covers a key that has no baseline yet). Anomalous rounds, and every round of an open anomaly, are not learned, so an attack does not become the baseline. Baselines live in memory only. It never announces.

| Key | Default | Meaning |
|---|---|---|
| `sensitivity` | `3` | Standard deviations above the mean. Lower is more sensitive. Above 0, at most 100. |
| `min_ratio` | `3` | Times the mean the rate must reach. 1-1000. |
| `min_mbps` | `10` | Smallest rate that can be anomalous, Mbit/s. Above 0. |
| `max_mbps` | off | Static ceiling, Mbit/s; `0` is off. At least `min_mbps`. |
| `alpha` | `0.05` | Weight of each new round in the mean and variance, above 0 and at most 1. |
| `warmup` | `30` | Rounds a key learns before the baseline test applies. 1-100000. |
| `trigger_rounds` | `2` | Anomalous rounds in a row before an anomaly opens. 1-1000. |
| `clear_rounds` | `3` | Normal rounds in a row before it clears. 1-1000. |
| `max_keys` | `10000` | Keys tracked; new keys past it are not tracked. 1-1000000. An idle key is forgotten once its mean decays to nothing. |

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
| `prepend` | 0-10. How many times the edge's export policy toward this provider prepends when it sees `communities`. Informational: an iBGP route cannot carry the edge's own ASN, so the edge does the prepend. |
| `withhold` | `true` makes the action a selective announcement: the edge's export policy does not send the prefix to this provider at all when it sees `communities`. Informational, like `prepend`, and exclusive with it. Packeteer never steers away from every provider, so the prefix stays announced through at least one other. |
| `med` | 1-4294967295. The MED the edge's export policy sets on this provider's session when it sees `communities` (#303), for one of several links to the same AS. Informational, like `prepend`, and exclusive with `prepend` and `withhold`. The provider needs another non-excluded provider with the same `asn`, or the config is refused. See [inbound.md](inbound.md#med-across-links-to-one-provider). |
| `communities` | 1-16 `asn:value` communities: signal communities the edge maps to the prepend, and the provider's own TE communities the edge passes to that provider only. `0:x` and `65535:x` (well-known values such as `no-export`) are rejected. |

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
| `route_target` | Required on each target. Two-octet-AS route target `asn:value` (AS 1-65535) that the edge imports into a VRF (a scrubbing VRF). Unique. A `flowspec_redirect` rule names the target. |

## Example

[config.example.yaml](../config.example.yaml) is a valid `observe` file. Install steps: [quickstart.md](quickstart.md). Router filters: [mikrotik.md](mikrotik.md), [frr.md](frr.md), [junos.md](junos.md), [cisco.md](cisco.md), [routers.md](routers.md). Problems: [troubleshooting.md](troubleshooting.md). Probe sourcing: [policy-routing.md](policy-routing.md).
