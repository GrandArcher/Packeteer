# Events and notifications

Packeteer emits the events below to every configured notifier (`notifiers:` in the config). Notifiers are plugins: `webhook` (with `slack`, `teams`, and `pagerduty` presets, or a custom template for SMS and chat gateways), `smtp`, `snmptrap`, and out-of-process `exec`. Keys are in [CONFIG.md](CONFIG.md#notifier-filters-every-notifier).

The same events, except `audit.recorded`, are kept for the Events page ([ui.md](ui.md#events-and-audit-log)), with or without a notifier. With storage, the write queue holds 256 events; when it is full, new events are dropped and logged.

Notifications are read-only. A notifier never announces or withdraws a route, and a notifier that fails or is slow does not change a decision or delay a withdraw. Events are emitted in every mode. In `observe` and `suggest` an improvement event says the route was not announced.

## Event shape

```json
{"time":"2026-01-01T00:00:00Z","kind":"provider.down","severity":"critical",
 "message":"probe source for transit-a is down; its improvements are withdrawn",
 "fields":{"provider":"transit-a","source":"192.0.2.10","reason":"bind: address not available"}}
```

The same object is the `generic` webhook body and the `exec` `notify` params.

## Catalog

| Kind | Severity | Trap ID | Key fields | Fires when |
|---|---|---|---|---|
| `controller.started` | info | 1 | | The controller started and its plugins are running. Resolves `controller.stopping`. |
| `controller.stopping` | warning | 2 | | Shutdown (SIGTERM, SIGINT). Sent after Packeteer routes are withdrawn; `fields.withdrawn` is `false` and `fields.error` is set when the withdraw failed. When no mode announces (`mode`, `inbound.mode`, and `mitigation.mode` are not `inject`) and the withdraw did not fail, nothing was announced, so the event is `info` and the message says so. |
| `improvement.added` | info | 3 | `prefix` | A prefix was steered to a better provider. In observe and suggest the message reads "Recommends moving X from A to B (not announced, observe mode)" because the router's path did not change. Fields: `provider`, `native`, `cause` (`performance`, `commit`, `cost`), `reason`, `mode`. |
| `improvement.switched` | info | 4 | `prefix` | An improvement moved to another provider. Adds `previous`. |
| `improvement.removed` | info | 5 | `prefix` | An improvement was retired; `reason` says why (native recovered, stale data, RIB loss, provider down, policy, maintenance, TTL). Resolves the prefix. |
| `provider.down` | critical | 6 | `provider` | A provider is down: its probe source failed, or its TTL-1 path check found its probes leaving through another first hop (`reason` is `probe path mismatch`, #150), or every probe through it got no reply or errored (`reason` is `100% loss` or `no answer`), or its mean loss is at or above `probe.down_loss_pct` (`reason` is that loss). The measured states use the Overview's rules ([CONFIG.md](CONFIG.md#probe), #343, #347). A failed probe source also excludes the provider and withdraws improvements onto it (fail closed); loss alone changes no decision. Fields: `state`, `source`, `reason`, `loss_pct` (measured cases). |
| `provider.degraded` | warning | 61 | `provider` | A provider's mean loss is at or above `probe.degraded_loss_pct` and below `probe.down_loss_pct` (#347). Fields as for `provider.down`. Resolved by `provider.up`. |
| `provider.up` | info | 7 | `provider` | The provider is healthy again: probe source back, probe path matching `next_hop` again, and loss below `probe.degraded_loss_pct`. Resolves `provider.down` and `provider.degraded`. |
| `bgp.session_down` | critical | 8 | `neighbor` | An Established iBGP session went down. |
| `bgp.session_up` | info | 9 | `neighbor` | An iBGP session reached Established. Resolves `bgp.session_down` and `bgp.session_not_established`. |
| `bgp.session_not_established` | critical | 62 | `neighbor` | A configured iBGP session has not reached Established `bgp.not_established_after` (default 5m) after Packeteer first saw it (#347). With no session Packeteer sees no routes and makes no recommendations. Sent once per neighbor; a session that came up and then dropped is `bgp.session_down` instead. Fields: `neighbor`, `state`, `after`, `description`. |
| `commit.exceeded` | warning | 10 | `provider` | The billable 95th percentile for the open billing period is above `commit_mbps` (telemetry plugin required). Fields: `usage_mbps`, `commit_mbps`, `percentile`. |
| `commit.cleared` | info | 11 | `provider` | The billable 95th percentile is back at or below the commit. |
| `announce.failed` | critical | 12 | | Syncing improvements to the announcer failed. Sent once per failure streak. |
| `announce.recovered` | info | 13 | | Sync succeeded after a failure. |
| `outage.as` | critical | 14 | `asn` | The `outage` source found several prefixes crossing one ASN degraded together. The ASN may be on the native path, on another provider's learned path, or the origin of a traceroute hop. `providers` lists who saw it. |
| `outage.circuit` | critical | 15 | `provider` | The `outage` source found several prefixes degraded on one provider only. |
| `outage.cleared` | warning | 16 | `asn` or `provider` | The AS or circuit incident recovered. |
| `notifier.test` | info | 17 | | Sent only by `packeteer -notify-test`, to check delivery. |
| `inbound.steered` | warning | 18 | `provider` | Inbound optimization ([inbound.md](inbound.md)) steers inbound traffic away from a provider whose inbound 95th is over commit (`trigger` `commit`) or that is the worst-performing provider (`trigger` `performance`). Fields: `trigger`, `in_mbps_95`, `commit_mbps`, `action`, `prepend`, `withhold` (selective announcement), `communities`, `hold`, `flaps`, `moderated`, `mode`, `reason`. In `observe` and `suggest`, and when `moderated` is `true`, it is a suggestion; nothing is announced. |
| `inbound.released` | info | 19 | `provider` | The steer was released (under `release_pct` after its hold time, stale telemetry or probe results, or `improvement_ttl`); `reason` says which. |
| `mitigation.added` | warning | 20 | `rule` | A threat mitigation rule ([mitigation.md](mitigation.md)) was added through the API, or replaced one with the same key. Fields: `prefix`, `action`, `target`, `match`, `source_countries`, `rate_mbps`, `routes`, `expires`, `reason`, `mode`. In `observe` it is a dry run and nothing is announced. |
| `mitigation.announced` | warning | 21 | `rule` | Every route of the rule (one, or one per source network of a country rule) is on the wire. Same fields. |
| `mitigation.withdrawn` | warning | 22 | `rule` | The rule's routes were withdrawn while the rule is still held: RIB session loss, shutdown, or an announce that failed. `detail` says why when known. It goes back on the wire (and `mitigation.announced` fires again) once the cause clears, before the rule expires. |
| `mitigation.ended` | info | 23 | `rule` | The rule ended: `end` is `expired`, `removed` (DELETE), or `replaced` (a new rule with the same key). Its routes are withdrawn within a decision round. Resolves the rule. |
| `ha.standby` | warning | 24 | | This instance stopped being the active one of its HA pair ([ha.md](ha.md)) and withdrew its routes. Fields: `id`, `holder` (the instance that holds the lease, when known), `detail` (lease held by another instance, renewal failed, RIB not ready, resigned), `withdrawn`. Sent by the instance that stepped down. |
| `ha.active` | warning | 25 | | This instance became the active one of its HA pair and may announce. Fields: `id`, `detail`, `takeovers`. Resolves `ha.standby` (one dedup key for the pair). |
| `audit.recorded` | info | 26 | | One audit log record ([auth.md](auth.md)): a change through the API (maintenance, mitigation, troubleshooting tools, users, tokens), a change refused for lack of role, an SSO sign-in (or a refused one) and sign-out, the admin created from the environment, or a SIGHUP config reload. Fields: `id`, `actor`, `role`, `method` (`password`, `token`, `sso`, `basic`, `system`), `remote`, `action` (e.g. `POST /api/mitigations`, `auth.login`, `config.reload`), `target`, `result` (`ok`, `denied`, `failed`), `status`, `detail`. Secrets are never included. Sent with and without `auth`. |
| `anomaly.detected` | critical | 27 | `anomaly` | Traffic toward a destination prefix and IP protocol is far above its learned baseline ([anomaly.md](anomaly.md)). Fields: `prefix`, `protocol`, `mbps`, `peak_mbps`, `baseline_mbps`, `since`, `reason`. Fires whether or not a rule matches; with no rule it is the only action. |
| `anomaly.mitigated` | warning | 28 | `anomaly` | An anomaly rule matched and the detector added a mitigation rule (`rule`, `mitigation`, `action`). The mitigation events follow for that rule; in `mitigation.mode: observe` it is a dry run. |
| `anomaly.held` | warning | 29 | `anomaly` | An anomaly rule matched but no mitigation rule was added, or the one added ended while the anomaly lasts. `detail` says why: not an exact prefix in the learned RIB, HA standby, `max_active`, `max_actions_per_hour`, `mitigation.max_rules`, refused (for example another rule holds the key), or ended (expired or deleted; not added again for this anomaly). Fires once per state. |
| `anomaly.cleared` | info | 30 | `anomaly` | The anomaly ended: traffic back within its baseline, or flow data unavailable for three rounds. The mitigation rule it added, if any, is removed. Resolves the anomaly. |
| `leak.detected` | critical | 31 | `prefix` | A route carrying `packeteer_community` (or, with `as_path_rule`, an injected prefix with the local ASN in its path) was seen outside the AS ([leak-watch.md](leak-watch.md)). Fields: `prefix`, `reason` (`community`, `as_path`), `action` (`withdrawn`, `withdraw_failed`, `held`), `source`, `seen`, `as_path`, and `rpki` (the origin's validity, with the `rpki` block on, #200). An outbound route is withdrawn alone; the prefix is held out until an operator clears it. |
| `leak.cleared` | info | 32 | `prefix` | An operator cleared the hold on a leaked prefix; it may be announced again. Resolves the leak. |
| `flap.quarantined` | warning | 33 | `prefix` | A prefix changed its chosen provider too often ([CONFIG.md](CONFIG.md#flap_quarantine)). Its route is withdrawn and it stays on the native path until `until`. Fields: `prefix`, `reason`, `flips`, `strikes`, `until`. |
| `flap.released` | info | 34 | `prefix` | A flap quarantine ended: the cool-down elapsed, an operator released it, or `flap_quarantine` was turned off. Same fields. Resolves the quarantine. |
| `steer.unverified` | warning | 66 | `kind`, `target` | Routing anomaly (#305, `verify`): after an outbound improvement or an inbound steer, less than `verified_pct` of the expected traffic moved on the interface counters (`status` is `partial` or `not_moved`). `target` is the prefix (outbound) or the provider steered away from (inbound). Fields: `provider`, `expected_mbps`, `moved_mbps`, `moved_pct`, `backed_out`, `detail`, and for outbound `prefix` and `path_degraded`. When `backed_out` is `true` the steer was also withdrawn and held off. |
| `steer.verified` | info | 67 | `kind`, `target` | The traffic moved after a steer. Same fields. Resolves `steer.unverified`. A steer with too little traffic or no fresh counters to judge (`unknown`) sends no event; it is in the log and on `/api/verification`. |
| `overload.refused` | warning | 68 | `provider` | A performance steer onto `provider` was refused ([CONFIG.md](CONFIG.md#providers), `interface_capacity_threshold_pct`, #307): its interface is at the limit, the steer's flow volume would push it past, or its interface reading is missing or stale. Sent once per prefix and provider until the steer is allowed. Fields: `provider`, `prefix`, `action`, `used_pct`, `projected_pct`, `limit_pct`, `volume_mbps`. |
| `overload.shed` | warning | 69 | `provider` | `provider`'s interface is past the limit, so a performance steer onto it was withdrawn, lowest gain first. One event per steer. Same fields. |
| `overload.cleared` | info | 70 | `provider` | A provider that refused or shed steers is at or below the limit again with nothing refused. Resolves `overload.refused` and `overload.shed`. |
| `exchange.degraded` | warning | 35 | `exchange` | Enough peers of one exchange fail the next-hop probe inside `exchanges[].health.window` ([CONFIG.md](CONFIG.md#exchanges)): the exchange or our port, not one member. Fields: `exchange`, `degraded_peers` (comma separated), `degraded`, `peers`. Measurement only. |
| `exchange.recovered` | info | 36 | `exchange` | Too few peers are degraded for the alert to hold. Same fields. Resolves `exchange.degraded`. |
| `exchange.peer_down` | warning | 37 | `exchange`, `peer`, `router` | A monitored router reported the exchange peer's BGP session down over BMP. `reason` is the decoded RFC 7854 reason and, when the session ended with a BGP Notification, its error code and subcode (`Cease subcode 1 (maximum number of prefixes reached)` is the peer's max-prefix limit). Read-only; no route changes. |
| `exchange.peer_up` | info | 38 | `exchange`, `peer`, `router` | The router reported the exchange peer's BGP session up. Resolves `exchange.peer_down`. |
| `exchange.max_prefix` | warning | 39 | `exchange`, `peer`, `router` | The peer's Adj-RIB-In route count reached `max_prefix_warn_pct` of its `max_prefix` (from a BMP Statistics Report). Fields: `prefixes`, `max_prefix`. Read-only. |
| `exchange.max_prefix_cleared` | info | 40 | `exchange`, `peer`, `router` | The count fell back below that share. Same fields. Resolves `exchange.max_prefix`. |
| `ixp.api_key_expiring` | warning | 41 | `identifier` | The IXP Manager API key has 14 days or fewer left, or is already past `key_expires`. `identifier` is the key id. The secret is not included. |
| `ixp.api_key_ok` | info | 42 | `identifier` | The same key has more than 14 days left. Resolves `ixp.api_key_expiring`. |
| `ixp.rs_unreachable` | warning | 43 | `server` | Birdseye on a route server failed two polls in a row (`ixp.routeservers`, #164). Sessions keep their last state until the server's data is stale. Field: `error`. |
| `ixp.rs_reachable` | info | 44 | `server` | Birdseye answered again. Resolves `ixp.rs_unreachable`. |
| `ixp.rs_session_down` | warning | 45 | `server`, `session` | A member session on a route server is not Established. Fields: `asn`, `neighbor`, `state`. |
| `ixp.rs_session_up` | info | 46 | `server`, `session` | The session is Established again, is no longer on the route server, or its server is stale. Resolves `ixp.rs_session_down`. |
| `ixp.rs_max_prefix` | warning | 47 | `server`, `session` | Accepted routes reached `max_prefix_warn_pct` of the member's `max_prefix`. Fields: `asn`, `accepted`, `max_prefix`. |
| `ixp.rs_max_prefix_cleared` | info | 48 | `server`, `session` | Accepted routes fell back below that share, the session is gone, or its server is stale. Not sent while the session is down, because a dropped session has no routes. Resolves `ixp.rs_max_prefix`. |
| `ixp.rs_filtered` | warning | 49 | `server`, `session` | At least `filtered_warn_pct` of a session's routes carry an `rs-asn:1101:x` tag. Fields: `asn`, `received`, `filtered`. |
| `ixp.rs_filtered_cleared` | info | 50 | `server`, `session` | The filtered share fell back below that, the session is gone, or its server is stale. Not sent while the session is down. Resolves `ixp.rs_filtered`. |
| `ixp.rs_origin_change` | warning | 55 | `server`, `session` | With `route_signals`, a session announces a prefix with an origin AS that no other member's accepted route for that prefix has (#165). Fields: `asn`, `count`, `prefix` (the lowest), `origin`. Stays open while those routes stay; closes when the session is down or not listed. |
| `ixp.rs_origin_change_cleared` | info | 56 | `server`, `session` | The conflicting routes are gone, or the session is gone or its server is stale. Resolves `ixp.rs_origin_change`. |
| `ixp.rs_morespecific_burst` | warning | 57 | `server`, `session` | With `route_signals`, at least `burst_min` routes new in one poll lie inside a prefix another member announces, with another origin AS (#165). Fields: `asn`, `count`, `prefix` (the lowest), `origin`. |
| `ixp.rs_morespecific_burst_cleared` | info | 58 | `server`, `session` | Those routes are gone, or the session is gone or its server is stale. Resolves `ixp.rs_morespecific_burst`. |
| `ixp.rs_filter_spike` | warning | 59 | `server`, `session`, `reason` | The routes tagged `rs-asn:1101:x` for `x` 9, 10, 13 (RPKI invalid), or 14 (transit-free ASN) rose by at least `spike_min` and to `spike_factor` times the highest of the last 12 polls (#165). Not sent for a session's first poll. Fields: `asn`, `reason`, `count`, `baseline`. |
| `ixp.rs_filter_spike_cleared` | info | 60 | `server`, `session`, `reason` | The count fell below that threshold, or the session is gone or its server is stale. Resolves `ixp.rs_filter_spike`. |
| `herd.restarted` | info | 63 | | A herd goroutine (the recorder or the puller) panicked and was restarted with backoff (#260). Probing, decisions, and the announcer are not affected. |
| `rpki.stale` | warning | 64 | `source` | An `rpki.sources` entry that was answering has no fresh data: older than its `staleness`, or empty (#200). Its lookups are `unknown` (the next source answers if it can), decisions continue, and withdraws never wait on RPKI. Fields: `source`, `vrps`, `updated`, `error`. Not sent for a source that never had data. |
| `rpki.fresh` | info | 65 | `source` | The source has fresh data again. Resolves `rpki.stale` and is sent only after one. Fields: `source`, `vrps`, `updated`. |
| `ixp.fabric_degraded` | warning | 51 | `scope`, `ixp_id`, `group` | At least `min_members` members behind one switch, colo, or core bundle, and at least `degraded_pct` of the members measured there, are past the ping tolerance on every address, for `rounds` fabric rounds in a row (`ixp.correlate`, #163). `scope` is `switch`, `colo`, or `bundle`. `group` is the switch id, the colo name, or the bundle name. Fields: `name` (the display name), `members`, `degraded`, `asns` (the first 10). |
| `ixp.fabric_recovered` | info | 52 | `scope`, `ixp_id`, `group` | The group stayed below those thresholds, or had no measured member, or the fabric data went stale, for `rounds` rounds. Resolves `ixp.fabric_degraded`. |
| `ixp.member_degraded` | warning | 53 | `asn` | One member is past the ping tolerance on every measured address and is in no degraded group, for `rounds` rounds. Fields: `name`, `addresses`. |
| `ixp.member_recovered` | info | 54 | `asn` | The member is back within tolerance, is now part of a degraded group, or the fabric data went stale. Resolves `ixp.member_degraded`. |

Problems and the events that resolve them share a **dedup key**: `packeteer/<group>/<key>=<value>`, for example `packeteer/provider/provider=transit-a` for both `provider.down` and `provider.up`. The `pagerduty` preset uses it as `dedup_key`, and `snmptrap` sends it as a varbind.

State events (`provider.*`, `bgp.*`, `commit.*`, `announce.*`, `inbound.*`, `mitigation.*`, `anomaly.*`, `ha.*`, `flap.*`, `exchange.*`, `ixp.rs_*`, `ixp.fabric_*`, `ixp.member_*`, `ixp.api_key_*`) fire on transitions only. Except `exchange.*`, `ixp.rs_*`, `ixp.fabric_*`, `ixp.member_*`, and `ixp.api_key_*`, they are checked on every decision (each probe round, each RIB change, and at least every `probe.interval`); `exchange.degraded` and `exchange.recovered` are checked once per `probe.interval` in the exchange health loop, `exchange.peer_*` and `exchange.max_prefix*` when the BMP RIB source reports a session event or a statistics count, `ixp.api_key_expiring` and `ixp.api_key_ok` when the member import starts and on each refresh, `ixp.rs_*` on each route-server poll, `ixp.fabric_*` and `ixp.member_*` on each new fabric probe round, and commit at most once a minute. They are not repeated while the state holds. `leak.*` events fire on the first sighting of a prefix and when its hold is cleared.

## Testing delivery

```sh
docker run --rm --network host -e PACKETEER_SMTP_USER -e PACKETEER_SMTP_PASSWORD \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer -notify-test
```

It sends one `notifier.test` event to each notifier directly (no queue, no rate limit), prints `sent`, `filtered`, or `FAILED` per notifier, and exits 1 if any failed. It sends no probes and opens no BGP session.

## Filtering and rate limits

Each notifier filters on its own:

```yaml
notifiers:
  - type: webhook
    name: pager
    config:
      preset: pagerduty
      routing_key_env: PAGERDUTY_ROUTING_KEY
      min_severity: critical       # provider.up etc. still resolve the page
  - type: smtp
    name: noc-mail
    config:
      host: smtp.example.net
      username_env: PACKETEER_SMTP_USER
      password_env: PACKETEER_SMTP_PASSWORD
      from: packeteer@example.net
      to: [noc@example.net]
      events: ["provider.*", "bgp.*", "commit.*", "outage.*"]
      rate_limit: 20               # at most 20 mails per minute
```

A resolving kind passes `min_severity` when the problem it clears would. When `rate_limit` drops events, the next one delivered carries `fields.suppressed` with the number dropped. Each notifier has a bounded queue (256 events). When it is full, new events for that notifier are dropped and logged; probing, decisions, and withdrawals never wait on a notifier.

## Secrets

Secrets come from the container environment, never from the config file: `routing_key_env`, `username_env`, `password_env`, `community_env`, `auth_env`, and `priv_env` name a variable, and webhook `url` and `headers` expand `${VAR}`.

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PAGERDUTY_ROUTING_KEY -e PACKETEER_SMTP_USER -e PACKETEER_SMTP_PASSWORD \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

## SNMP traps

The notification OID is `<enterprise_oid>.0.<trap ID>` from the table. The varbinds after `sysUpTime.0` and `snmpTrapOID.0` are strings under `<enterprise_oid>.1`: `.1.0` kind, `.2.0` severity, `.3.0` message, `.4.0` time, `.5.0` fields, `.6.0` dedup key. Trap IDs are stable; new kinds get new numbers.

## SMS and other gateways

Use `webhook` with a `template`. For a gateway that takes a form post:

```yaml
  - type: webhook
    name: sms
    config:
      url: https://sms.example.invalid/send
      headers:
        Authorization: "Bearer ${SMS_TOKEN}"
      content_type: application/x-www-form-urlencoded
      template: 'to=%2B15550100&body={{urlquery .Kind}}%20{{urlquery .Message}}'
      min_severity: critical
      rate_limit: 5
```
