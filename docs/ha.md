# High availability (active/standby) and backup

Issue #31. Lab-proven only (`lab/e2e-ha.sh`), not on a public edge. The default stays a single instance in `mode: observe`. The lab's SIGTERM check reads the lease file (`lab/checklease`, #190): the watch is armed before the signal, the instance has to release the record during that watch, and a release that never arrives fails when the timeout elapses. One pass over the container log is not the check.

## Model

Two Packeteer instances run the same config apart from `router_id`, the session address, and the HA `id`. Both keep iBGP sessions to the edge routers and both probe, so the standby's RIB view and measurements are warm. One instance is **active**: it runs decisions and announces. The other is **standby**: it runs no decisions and has no route on the wire.

An elector plugin (`ha:`, [PLUGINS.md](PLUGINS.md)) decides which instance is active. The built-in `lease` elector keeps a lease file on storage both instances mount. The outbound, inbound, and mitigation announcers check the elector under their own locks before every sync, so a standby never announces, even for one round.

```
             shared volume (lease.json)
              /                     \
   pk-a (active)                 pk-b (standby)
   iBGP, probes, decisions,      iBGP, probes,
   announcements                 no decisions, nothing announced
              \                     /
                 edge router(s)
```

## Failover

| Event | What happens | Takeover |
|---|---|---|
| Active stops cleanly (SIGTERM) | It withdraws every Packeteer route, waits 1s, and releases the lease. | The standby's next renewal (`renew`, default 2s), plus 1s. |
| Active loses every iBGP session | Its RIB view is not ready: it withdraws, steps down, and releases the lease. Its routes are gone with the sessions anyway. | Next renewal of a standby whose own sessions are up. |
| Active cannot renew the lease (storage lost) | It stops announcing and withdraws `ttl`/2 after its last renewal. | After the standby's wait (below). |
| Active crashes (SIGKILL, host loss) or freezes | Nothing is withdrawn. Graceful restart is never enabled, so each router drops its routes when the session's hold timer expires. | After the standby's wait (below). |

The standby's wait for a lease that is still held by another instance is the longer of `ttl` and `ttl`/2 + the holder's BGP hold time + `renew`, measured from the last time the standby saw the record change. The holder writes its longest negotiated hold time into every renewal. Once that time has passed, the old instance has stopped announcing and every router has dropped its routes, so the edge never carries routes from both instances. With the edge's hold timer at 9s and the defaults, a crash takeover takes about 16s; with the 90s BGP default it takes about 97s. Set a short hold timer on the edge sessions to Packeteer.

Safety does not depend on clocks: the active instance measures its deadline on its own monotonic clock, and the standby measures record changes on its own.

On taking over, an instance starts with empty decision state: no improvement, cooldown, or intent carries over from a previous term, and nothing is copied from the other instance. The first decision after takeover announces whatever the fresh measurements justify, under the same allowlist, exact learned-RIB check, `packeteer_community` + NO_EXPORT, `max_improvements`, thresholds, and hold time. Threat mitigation rules are in memory on the instance that received them; they are not replicated, so re-add them after a failover.

## Deploy

On one host, two containers share a named volume:

```sh
docker volume create packeteer-ha
docker run -d --name pk-a --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_HA_ID=pk-a -v "$PWD/pk-a.yaml:/etc/packeteer/config.yaml:ro" \
  -v packeteer-ha:/var/lib/packeteer/ha ghcr.io/grandarcher/packeteer
docker run -d --name pk-b ... -e PACKETEER_HA_ID=pk-b -v "$PWD/pk-b.yaml:/etc/packeteer/config.yaml:ro" \
  -v packeteer-ha:/var/lib/packeteer/ha ghcr.io/grandarcher/packeteer
```

```yaml
ha:
  type: lease
  config:
    path: /var/lib/packeteer/ha/lease.json
    ttl: 10s
    renew: 2s
```

On two hosts, `path` must be on a shared filesystem where `flock` works across hosts (for example NFSv4). If the two instances do not see the same file, both become active: check `/api/ha` on both (`holder` must be the same instance) before switching to `mode: inject`.

The edge must accept both sessions with the same import policy (accept only `packeteer_community`, never export it to eBGP, [routers.md](routers.md)). Give each instance its own `router_id` and session address. Keep `max_improvements`, the allowlist, and thresholds identical.

## Operate

- `GET /api/ha`: `role` (`active` or `standby`), `holder`, `eligible`, `detail` (why a standby waits), `takeovers`.
- `/metrics`: `packeteer_ha_active`, `packeteer_ha_eligible`, `packeteer_ha_takeovers`.
- Events: `ha.standby` (warning) when an instance steps down, `ha.active` when one takes over ([EVENTS.md](EVENTS.md)).
- `-check` prints `ha: lease id=...`.

Rollback: remove `ha` from the config and run one instance.

## Upgrading a pair

With `upgrade.enabled` ([ui.md](ui.md#upgrade-from-the-ui), #196) upgrade the standby first. The upgrade refuses on a standby when no node holds the lease, and on the active node unless the request confirms (`standby_upgraded`) that the standby already runs the target version. The active node's shutdown withdraws its routes and releases the lease after the withdraw, so the upgraded standby takes over; the restarted node comes back as the standby. Never both at once: the lease serializes announcing, and a node being replaced has no route on the wire when it restarts.

## Backup and restore

```sh
# Running container (history is copied consistently while it runs):
docker exec pk-a packeteer -backup /var/lib/packeteer/backup-2026-09-30.tgz
# Restore on a new host, with the controller stopped:
docker run --rm -v packeteer-data:/var/lib/packeteer -v "$PWD:/backup" \
  ghcr.io/grandarcher/packeteer -restore /backup/backup-2026-09-30.tgz -restore-config /backup/config.yaml
```

The archive holds the config file as loaded and, with `storage: sqlite`, a copy of the report history. Environment variables (SNMP communities, passwords, tokens) are not in it. `-backup` never overwrites; `-restore` replaces existing history or a config file only with `-force`. The lease file is not backed up: it is recreated. Details: [CONFIG.md](CONFIG.md#backup-and-restore).

## Limits

- One elector type (`lease`). A VRRP-style elector over the LAN would be another plugin behind the same interface.
- A frozen active instance (process stopped, host hung) keeps its routes until each router's hold timer runs out; the standby waits that long. If the frozen process resumes, its elector reports standby at once and it withdraws within `renew`/2, but a BGP session it re-establishes in that window can briefly carry its old routes. Stop a frozen instance rather than resuming it.
- Mitigation rules and on-demand maintenance windows are not replicated.
