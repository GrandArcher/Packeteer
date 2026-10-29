# Monitoring with SNMP and syslog

For operators whose NMS speaks SNMP or reads syslog (#212). All of it is opt-in and off by default, it only reports, and it never announces, withdraws, or moves a route. Mode, allowlist, community, NO_EXPORT, `max_improvements`, hold time, and withdraw rules are unchanged. Nothing here is specific to one NMS: any tool that loads a MIB can use it.

| Need | Use |
|---|---|
| Poll Packeteer's state | the `snmpagent` exporter and [PACKETEER-MIB](../deploy/mib/PACKETEER-MIB.txt) |
| Be told when something happens (SNMP) | the `snmptrap` notifier: traps, or informs with `inform: true` |
| Be told when something happens (log) | the `syslog` notifier |

Keys are in [CONFIG.md](CONFIG.md#exporters) (`snmpagent`), [CONFIG.md](CONFIG.md#notifier-snmptrap), and [CONFIG.md](CONFIG.md#notifier-syslog). Secrets are environment variables named in the config, never values.

## The MIB

[deploy/mib/PACKETEER-MIB.txt](../deploy/mib/PACKETEER-MIB.txt) is SMIv2. Packeteer has no enterprise number, so the module sits under NET-SNMP's experimental arc `1.3.6.1.4.1.8072.9999.9999.7717`, the default `enterprise_oid`. For production, change the one `packeteer MODULE-IDENTITY` assignment to an arc you own and set `enterprise_oid` on the agent and on the `snmptrap` notifier to match. A test checks the file against the agent and against the event catalog, and the CI `snmp` job compiles it with net-snmp.

Under the root `<enterprise_oid>`:

| Arc | Content |
|---|---|
| `.0.<trap_id>` | one notification per event kind ([EVENTS.md](EVENTS.md) lists the numbers) |
| `.1.1` to `.1.6` | the notification objects: kind, severity, message, time, fields, dedup key |
| `.2` | status scalars (`.0` instance) |
| `.3.1.<column>.<index>` | the provider table |

Status scalars:

| Object | Meaning |
|---|---|
| `pktrVersion`, `pktrMode` | version; `observe`, `suggest`, or `inject` |
| `pktrReady` | TruthValue: started and, with BGP configured, the RIB view is ready |
| `pktrHaRole` | `standalone`, `active`, or `standby` |
| `pktrImprovementsActive` | active improvements (recommendations in observe and suggest) |
| `pktrRibPrefixes` | prefixes in the learned RIB view; absent without BGP |
| `pktrProbeRate` | prefix measurements stored per minute between the last two snapshots; absent until there are two |
| `pktrDataAge` | seconds since the snapshot the other objects come from |

Provider table, one row per provider, numbered by sorted provider name (the index changes when a provider is added or removed; read `pktrProviderName`): `pktrProviderProbeUp`, `pktrProviderLossPermille` (tenths of a percent), `pktrProviderRttMicros`, `pktrProviderJitterMicros` (the mean over the destinations last probed), and, for a provider with a telemetry binding, `pktrProviderTelemetryUp`, `pktrProviderInKbps`, `pktrProviderOutKbps`, `pktrProviderIn95Kbps`, `pktrProviderOut95Kbps`, `pktrProviderUsageKbps` (the single billable figure, when the percentile mode gives one), and `pktrProviderCommitKbps`. A reading Packeteer does not have is absent, not zero: a walk shows a gap and a graph shows a gap. Rate columns are absent while the last poll failed.

## The agent

```yaml
exporters:
  - type: snmpagent
    config:
      listen: 192.0.2.10:161            # an address on this host
      username_env: PACKETEER_SNMP_USER # v3 (authPriv unless security_level says otherwise)
      auth_env: PACKETEER_SNMP_AUTH     # at least 8 characters
      priv_env: PACKETEER_SNMP_PRIV
      allow_from: [192.0.2.0/24]
```

```
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_SNMP_USER=nms -e PACKETEER_SNMP_AUTH=... -e PACKETEER_SNMP_PRIV=... \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
snmpwalk -v3 -l authPriv -u nms -a SHA -A ... -x AES -X ... -M +deploy/mib -m +PACKETEER-MIB 192.0.2.10 pktrStatus
```

- Read only. A SET gets `notWritable`; GET, GETNEXT, and GETBULK are answered. A wrong community, a wrong user or key, or a request below the configured security level gets no answer.
- Set `community_env` for v2c, `username_env` for v3, or both on the one UDP port. One of them is required: the agent is never open to anyone. Prefer v3 `authPriv`: v2c sends the community and the data in clear text. `allow_from` limits who is answered.
- It serves the newest snapshot of [`GET /metrics`](API.md#metrics), taken every 30 seconds, so it needs `http.listen`, and it has no data for the first 30 seconds after start (every object answers noSuchObject). Poll no faster than every 30 seconds. `pktrDataAge` above 90 means the snapshots stopped.
- Port 161 is privileged. The image runs as root; run elsewhere with a port above 1023 or the capability to bind it.
- The v3 engine boots counter is the number of seconds since 2020-01-01 at start, so it grows across restarts without a state file. Time windows are not enforced, so a captured request can be replayed and gets the same read-only answer; `allow_from` and a firewall are the control.
- A failure to bind the port is a startup error. A failing agent never changes a decision or a withdraw.

## Traps and informs

`snmptrap` sends one notification per event that passes its filter ([EVENTS.md](EVENTS.md)): `outage.as`, `outage.circuit`, `outage.cleared`, `improvement.added`, `improvement.removed`, `bgp.session_down`, `ha.standby`, `ha.active`, `leak.detected`, and the rest of the catalog. The OID is `<enterprise_oid>.0.<trap_id>` and the varbinds are in the MIB.

With `inform: true` the receiver acknowledges each one; an unacknowledged inform is sent again twice within `timeout` and then counted as a failed delivery. For v3 traps Packeteer is the authoritative engine, so set `engine_id` and create the user on the receiver with that engine ID; for v3 informs the receiver is, so set no `engine_id`. [examples/monitoring/snmptrapd.conf](../examples/monitoring/snmptrapd.conf) is a net-snmp `snmptrapd` template for all four cases. The CI `snmp` job runs it.

## Syslog

`syslog` sends RFC 5424 over UDP (RFC 5426), TCP (octet-counting, RFC 6587), or TLS (RFC 5425). One event is one message:

```
<130>1 2026-10-29T10:00:00.000000Z edge1 packeteer - provider.down [packeteer@32473 kind="provider.down" severity="critical" dedup="packeteer/provider/provider=transit-a"][fields@32473 provider="transit-a"] probe source for transit-a is down
```

The priority is `facility * 8 + severity` (`info` 6, `warning` 4, `critical` 2), the message ID is the event kind (cut to 32 characters), and the fields are structured data a collector can match. Audit records (`audit.recorded`) are events too, so an `events: ["audit.*"]` syslog notifier ships the audit log. `32473` is the documentation enterprise number of RFC 5612. [examples/monitoring/rsyslog-packeteer.conf](../examples/monitoring/rsyslog-packeteer.conf) is an rsyslog receiver.

TCP and TLS keep one connection and open a new one after the collector closes it. There is no spool: while the collector is down, deliveries fail and the events are lost to it (the log and the Events page still have them). Use `tls` off a trusted network.

## Rollback

Remove the `snmpagent` exporter, the `inform` key, or the `syslog` notifier and restart. Nothing else depends on them.
