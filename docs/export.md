# Exporting decisions, events, and flow data

`exporters` push what Packeteer decides to an external pipeline (#207) and, as metric snapshots, what it measures (#287). They are off unless the list is set. They only read: nothing here announces, changes a decision, or touches the allowlist, the cap, the community, NO_EXPORT, hold time, or withdraw rules. Each exporter has its own bounded queue, so a slow or dead sink drops its own records (counted) and never delays probing, a decision, or a withdraw. The sink is not needed to start.

```yaml
exporters:
  - type: kafka
    name: pipeline
    config:
      brokers: ["kafka.example.net:9092"]
      streams: [events, decisions, flows]
```

| Type | Streams | Carries |
|---|---|---|
| `kafka` | `events`, `decisions`, `flows` (default `events`, `decisions`) | JSON, topic `<topic_prefix>.<stream>` |
| `nats` | `events`, `decisions`, `flows` (default `events`, `decisions`) | JSON, core NATS subject `<subject_prefix>.<stream>` |
| `otlp` | `decisions` (default), `events`, `metrics` | OTLP/HTTP JSON: a span per decision change (`/v1/traces`), a log record per event (`/v1/logs`), gauges and sums per metrics snapshot (`/v1/metrics`) |
| `influxdb` | `events`, `decisions` (default), `metrics` | line protocol to the InfluxDB v2 write API (`/api/v2/write`) |
| `ipfix` | `flows` | IPFIX (RFC 7011) over UDP, readable by pmacct, GoFlow2, ElastiFlow, Kentik and other collectors |

Keys are in [CONFIG.md](CONFIG.md#exporters). Credentials come from environment variables named in the config.

## Streams

- `events`: every event in [EVENTS.md](EVENTS.md), as the notifiers get it before their filters. `improvement.*` events carry `improvement_id`.
- `decisions`: one record per change to an improvement (`improve`, `switch`, `retire`), in every mode. In `observe` and `suggest` it is a recommendation (`mode` says which); nothing was announced. Fields: `time`, `id`, `action`, `mode`, `prefix`, `provider`, `native`, `cause`, `reason`, `since`, and for a switch `previous` and `previous_id`. The `id` is 16 hex digits hashed from the prefix, the chosen provider, and the start time; a move to another provider is a new improvement with a new `id`. Shutdown and a step down to standby withdraw routes without `retire` records; the sink sees `controller.stopping` (shutdown) or `ha.standby` (step down) on the events stream.
- `flows`: one record per flow the `flow` source counted toward a prefix: `time`, `src`, `dst`, `proto`, `bytes`, `prefix`, `provider`, `improvement_id`. `provider` is the provider traffic to that prefix uses now: the improvement's provider when its injected route is on the wire (`mode: inject`; an improvement whose route is not installed for that provider is not used; tags refresh each decision round and clear on shutdown), else the learned RIB's provider for the destination. `improvement_id` is empty on a native prefix, and always in `observe` and `suggest`, where a recommendation moves nothing (see the `decisions` stream). Only destinations the source keeps as probe targets appear; private, loopback, link-local, multicast, and exchange LAN destinations are dropped, as for probing. Ports and packet counts are not exported. Sampled exports keep their scaled byte counts. The stream is per record, so enable it only when the sink can take the rate.
- `metrics`: a snapshot of every series [`GET /metrics`](API.md#metrics) renders, taken every 30 seconds (the interval is fixed), as one record. Each series keeps its name, labels, and value; counters stay counters. It is opt-in and it needs `http.listen`; Packeteer refuses to start with a `metrics` exporter and the HTTP server off. A snapshot can hold one series per provider and prefix, so size the sink for that; a series with a non-finite value is skipped. `kafka` and `nats` do not take it.

## OpenTelemetry

Each decision change is a span named `packeteer.decision.<action>` with attributes `packeteer.improvement.id`, `packeteer.action`, `packeteer.mode`, `packeteer.prefix`, `packeteer.provider`, `packeteer.native`, and, when set, `packeteer.cause`, `packeteer.reason`, `packeteer.previous_provider`. The trace ID is derived from the improvement ID, so the `improve` and `retire` spans of one improvement share a trace; the `retire` span runs from the start to the end of the improvement and is a child of the `improve` span. A `switch` starts a new improvement, so it is a new trace with a link to the previous one.

With `events` in `streams`, each event is a log record: the message is the body, `severity` maps to the OTLP severity (`info` 9, `warning` 13, `critical` 17), the attribute `event.name` is the kind, and each event field is the attribute `packeteer.field.<key>`. With `metrics`, a counter is a cumulative monotonic sum that starts when the exporter was built (the process start), and every other series is a gauge; labels are attributes. Each signal is its own request, so a collector without a logs or metrics pipeline fails only that signal. All three carry the resource attribute `service.name`.

## InfluxDB

Points go to the v2 write API with nanosecond precision and the header `Authorization: Token <token>`; InfluxDB 1.8 and 3 accept the same call. The token is read from the environment variable `token_env` names; use an `https` URL unless the server is on a trusted network.

| Measurement | Tags | Fields |
|---|---|---|
| `packeteer_event` | `kind`, `severity` | `message`, and each event field as the string `field_<key>` |
| `packeteer_decision` | `action`, `mode`, `prefix`, `provider`, `native` | `improvement_id`, `cause`, `reason`, `previous`, `previous_id` (those last four when set), `since_ns` (integer) |
| one per metric, named as in `/metrics` | its labels | `value` |

Empty tags are left out, and a newline in a value becomes a space. Two events of one kind at the same nanosecond share a series and timestamp, so the second overwrites the first.

## IPFIX

Templates 256 (IPv4) and 257 (IPv6) are sent first and every `template_interval`. Fields: `flowEndMilliseconds` (153), `sourceIPv4Address` (8) or `sourceIPv6Address` (27), `destinationIPv4Address` (12) or `destinationIPv6Address` (28), `protocolIdentifier` (4), `octetDeltaCount` (1), `destinationIPv4PrefixLength` (13) or `destinationIPv6PrefixLength` (30), `flowId` (148), `interfaceName` (82). The provider tag is in `interfaceName` and the improvement ID in `flowId` (0 on a native prefix; the same 64-bit value as the 16 hex digits of `improvement_id`). Most collectors need a field mapping to show those two; [lab/exporters/goflow2-mapping.yaml](../lab/exporters/goflow2-mapping.yaml) is an example for GoFlow2. A source address the record did not carry is sent as the unspecified address. Messages are at most 1400 bytes.

## Dashboards

[deploy/grafana](../deploy/grafana) has three dashboards (CI imports them into Grafana 11): `packeteer-overview.json` (decisions, improvements, BGP, caps), `packeteer-providers.json` (probe RTT, loss, jitter, interface rates), and `packeteer-export.json` (records sent, failed, and dropped per exporter). In Grafana use Dashboards, Import, and pick your Prometheus data source for `DS_PROMETHEUS`. They read `/metrics` as scraped by Prometheus ([API.md](API.md#metrics)). A test checks every metric and label they use against what `/metrics` renders.

`/metrics` has `packeteer_export_records_total{exporter,stream,result}` with `result` `sent`, `failed` (the sink refused or timed out), or `dropped` (the queue was full), only when an exporter is configured.

## Safety and limits

- Exporters are restart-only keys; SIGHUP does not change them. A flow source added by a reload gets the flow tap.
- Delivery is at most once. A full queue (4096 records) or a down sink loses records; nothing is retried or stored.
- Records name documentation-range prefixes in tests only; in use they hold your prefixes and provider names, so protect the sink like the config.
- Rollback: remove `exporters` and restart. Nothing else changes.

## Tests

Unit tests cover each exporter against fakes, a local UDP socket, and an HTTP test server. The CI `exporters` job runs the `sink` tests against real containers: Redpanda (Kafka), NATS, the OpenTelemetry collector (contrib, file exporters for spans, logs, and metrics), InfluxDB 2 (read back with a Flux query), and GoFlow2 (IPFIX, with the mapping above), and reads the records back from each.
