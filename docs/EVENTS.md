# Events and notifications

Packeteer emits the events below to every configured notifier (`notifiers:` in the config). Notifiers are plugins: `webhook` (with `slack`, `teams`, and `pagerduty` presets, or a custom template for SMS and chat gateways), `smtp`, `snmptrap`, and out-of-process `exec`. Keys are in [CONFIG.md](CONFIG.md#notifier-filters-every-notifier).

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
| `controller.stopping` | warning | 2 | | Shutdown (SIGTERM, SIGINT). Sent after Packeteer routes are withdrawn; `fields.withdrawn` is `false` and `fields.error` is set when the withdraw failed. |
| `improvement.added` | info | 3 | `prefix` | A prefix was steered to a better provider. Fields: `provider`, `native`, `cause` (`performance`, `commit`, `cost`), `reason`, `mode`. |
| `improvement.switched` | info | 4 | `prefix` | An improvement moved to another provider. Adds `previous`. |
| `improvement.removed` | info | 5 | `prefix` | An improvement was retired; `reason` says why (native recovered, stale data, RIB loss, provider down, policy, maintenance, TTL). Resolves the prefix. |
| `provider.down` | critical | 6 | `provider` | A provider's probe source failed. The provider is excluded and improvements onto it are withdrawn (fail closed). |
| `provider.up` | info | 7 | `provider` | The probe source recovered. |
| `bgp.session_down` | critical | 8 | `neighbor` | An Established iBGP session went down. A session that never came up is not reported. |
| `bgp.session_up` | info | 9 | `neighbor` | An iBGP session reached Established. |
| `commit.exceeded` | warning | 10 | `provider` | The billable 95th percentile for the open billing period is above `commit_mbps` (telemetry plugin required). Fields: `usage_mbps`, `commit_mbps`, `percentile`. |
| `commit.cleared` | info | 11 | `provider` | The billable 95th percentile is back at or below the commit. |
| `announce.failed` | critical | 12 | | Syncing improvements to the announcer failed. Sent once per failure streak. |
| `announce.recovered` | info | 13 | | Sync succeeded after a failure. |
| `outage.as` | critical | 14 | `asn` | The `outage` source found several prefixes behind one ASN degraded on every provider. |
| `outage.circuit` | critical | 15 | `provider` | The `outage` source found several prefixes degraded on one provider only. |
| `outage.cleared` | warning | 16 | `asn` or `provider` | The AS or circuit incident recovered. |
| `notifier.test` | info | 17 | | Sent only by `packeteer -notify-test`, to check delivery. |
| `inbound.steered` | warning | 18 | `provider` | Inbound commit control ([inbound.md](inbound.md)) steers inbound traffic away from a provider whose inbound 95th is over commit. Fields: `in_mbps_95`, `commit_mbps`, `action`, `prepend`, `communities`, `mode`, `reason`. In `observe` and `suggest` it is a suggestion; nothing is announced. |
| `inbound.released` | info | 19 | `provider` | The steer was released (under `release_pct` of commit after `hold_time`, stale telemetry, or `improvement_ttl`); `reason` says which. |

Problems and the events that resolve them share a **dedup key**: `packeteer/<group>/<key>=<value>`, for example `packeteer/provider/provider=transit-a` for both `provider.down` and `provider.up`. The `pagerduty` preset uses it as `dedup_key`, and `snmptrap` sends it as a varbind.

State events (`provider.*`, `bgp.*`, `commit.*`, `announce.*`, `inbound.*`) fire on transitions only. They are checked on every decision (each probe round, each RIB change, and at least every `probe.interval`); commit is checked at most once a minute. They are not repeated while the state holds.

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
