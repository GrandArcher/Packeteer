# Registry hygiene

Packeteer sees what the network announces and where it peers, so it can say where IRR, RPKI, the as-set, and PeeringDB disagree (#289). The scan reads. A change reaches a registry only through a push that an admin confirmed after seeing its diff, and pushing is off by default. Nothing here announces a route or changes the learned RIB. Not for a public edge: lab-checked against fixtures only.

## What it finds

Each finding has a severity (`error`, `warning`, `info`), the registry it is about, and a diff: the exact RPSL or field change that would fix it.

| Kind | Meaning | Fix |
|---|---|---|
| `irr_missing` | A learned prefix originated by `registry.asns` has no route or route6 object for that origin in any `irr.sources` database. | RPSL to create; a push when `registry.irr.source` is `RIPE` and a `ripe` source is set |
| `irr_stale` | A route object names a configured ASN for a prefix that is no longer announced. | RPSL to delete; a push for the object in the RIPE database when a `ripe` source is set |
| `irr_conflict` | Another origin is registered for an announced prefix. | Text only |
| `irr_duplicate` | The same object is in more than one database (for example RADB after a move to RIPE). | Text only |
| `rpki_missing` | No ROA covers an announced prefix. | Text only (RIR portal) |
| `rpki_maxlength`, `rpki_origin` | The prefix is RPKI invalid: the ROA's maxLength is shorter than the announcement, or no ROA names the origin. | Text only (RIR portal) |
| `asset_missing` | An ASN seen after `registry.asns` on learned AS paths (a customer seen as transit) is not in `registry.as_set`. | Text only |
| `asset_unseen` | An as-set member never appears on a learned path. | Text only |
| `pdb_net_missing`, `pdb_facility_missing` | No PeeringDB network record, or no facility listed. | Text only |
| `pdb_maxprefix` | `info_prefixes4` or `info_prefixes6` is below the announced count plus `headroom_percent`. Peers size their max-prefix limit from it. | Field diff; a push for a `peeringdb` source |
| `pdb_ix_missing`, `pdb_ix_stale` | A configured exchange session has no PeeringDB connection, or PeeringDB lists a connection no session uses. Needs the exchange's `ix_id` in the `lookup` block. | Text only |
| `pdb_ix_speed` | PeeringDB lists a port speed that differs from the exchange's `port.capacity_mbps`. | Field diff; a push for a `peeringdb` source |
| `pdb_contact_missing`, `pdb_contact_old` | No contact visible to this reader, or one not updated for two years. Without an API key only public contacts are visible. | Text only |

ROAs are suggest-only: they are created in an RIR portal. A source that cannot answer is listed as `error` or `skipped` in the scan section and produces no findings, so an unreachable registry is never read as clean. IRR findings need the learned RIB and every `irr.sources` entry to have answered. At most 500 prefixes are looked up per scan.

IRR detection queries every configured `irr.sources` entry, so several registries (RADB, RIPE, ARIN, APNIC, AFRINIC, LACNIC, NTTCOM, ALTDB, LEVEL3) are compared in one scan; see [CONFIG.md](CONFIG.md#irr-source-whois).

## Push

`registry.push_enabled: true` plus a `registry.sources` entry lets an admin push a finding that has a change. Only these can be pushed:

- `ripe`: create or delete a `route` or `route6` object in the RIPE database (or its TEST database). Credentials: `PACKETEER_RIPE_USER` and `PACKETEER_RIPE_PASSWORD`.
- `peeringdb`: set `info_prefixes4`, `info_prefixes6`, or a connection `speed`. Credential: `PACKETEER_PEERINGDB_API_KEY`.

Other IRR databases (RADB, ARIN, and the rest) get the RPSL to submit by hand. Credentials come only from the environment, are read when a change is pushed, and are never in the config, the API, the logs, or the audit record.

Each push is `POST /api/registry/push` with the finding `id` and the `digest` of the diff that was shown. It needs the admin role and an authenticated API. The server refuses a digest that no longer matches the last scan, a finding already pushed, and one without a change. The plugin re-reads the record first and refuses when the field no longer holds the value the diff showed. Every outcome, refusals and failures included, is in the audit log with the change. The Registry page shows the diff, asks for a second click, and then posts.

## Configure

See [CONFIG.md](CONFIG.md#registry) and `config.example.yaml`. Read-only needs no credentials:

```yaml
registry:
  enabled: true
  asns: [64496]
  as_set: AS-EXAMPLE
  sources:
    - type: peeringdb
```

Default interval is 24h; the first scan runs a minute after start so the RIB can learn. `registry` cannot be combined with `ixp`.

## UI and API

The Registry page (`/registry.html`, [ui.md](ui.md#registry)) lists the scan sections and each finding. `GET /api/registry` returns the same (viewer role).

## Rollback

Set `registry.enabled: false` and restart. A pushed change is a change in the registry: undo it there (delete the object, or set the PeeringDB field back). The audit entry holds the old and new values.
