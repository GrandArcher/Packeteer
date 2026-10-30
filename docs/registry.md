# Registry hygiene

Packeteer sees what the network announces and where it peers, so it can say where IRR, RPKI, the as-set, and PeeringDB disagree (#289). The scan reads. A change reaches a registry only through a push that an admin confirmed after seeing its diff, and pushing is off by default. Nothing here announces a route or changes the learned RIB. Not for a public edge: tested on fixtures only, not lab-proven.

## What it finds

Each finding has a severity (`error`, `warning`, `info`), the registry it is about, and a diff: the exact RPSL or field change that would fix it.

| Kind | Meaning | Fix |
|---|---|---|
| `irr_missing` | A learned prefix originated by `registry.asns` has no route or route6 object for that origin in any `irr.sources` database. | RPSL to create; a push when `registry.irr.source` is `RIPE` (or `TEST`) and a `ripe` source is set |
| `irr_stale` | A route object names a configured ASN for a prefix that is no longer announced. | The stored object as the source returned it, to delete; a push for an object in the database the `ripe` source writes to, offered only when the previous scan showed it too. Stale means the learned RIB has no such prefix and origin; a prefix originated where Packeteer has no session or BMP feed looks stale, so read the diff before pushing |
| `irr_conflict` | Another origin is registered for an announced prefix. | Text only |
| `irr_duplicate` | The same object is in more than one database beside the one in `registry.irr.source` (for example RADB after a move to RIPE). | The stored copy as text, never pushed |
| `rpki_missing` | No ROA covers an announced prefix. | Text only (RIR portal) |
| `rpki_maxlength`, `rpki_origin` | The prefix is RPKI invalid: the ROA's maxLength is shorter than the announcement, or no ROA names the origin. | Text only (RIR portal) |
| `asset_missing` | An ASN seen after `registry.asns` on learned AS paths (a customer seen as transit) is not in `registry.as_set`. When `asn` is in `registry.asns`, every ASN of a path through a provider with `type: customer` also counts; route-server members and unlisted peers do not. With no such provider the as-set check is skipped and says why. | Text only |
| `asset_unseen` | An as-set member never appears on a learned path. | Text only |
| `pdb_net_missing`, `pdb_facility_missing` | No PeeringDB network record, or no facility listed. | Text only |
| `pdb_maxprefix` | `info_prefixes4` or `info_prefixes6` is below the announced count plus `headroom_percent`. Peers size their max-prefix limit from it. | Field diff; a push for a `peeringdb` source |
| `pdb_ix_missing`, `pdb_ix_stale` | An address in the exchange's `local_lan_addrs` has no PeeringDB connection, or PeeringDB lists a connection at that exchange with no address in `local_lan_addrs`. Needs the exchange's `ix_id` in the `lookup` block. Without `local_lan_addrs` the exchange is not compared and `pdb_ix_unchecked` says so. | Text only |
| `pdb_ix_speed` | PeeringDB lists a port speed for an address in `local_lan_addrs` that differs from the exchange's `port.capacity_mbps`. | Field diff; a push for a `peeringdb` source |
| `pdb_contact_missing`, `pdb_contact_old` | No contact visible to this reader, or one not updated for two years. Without an API key only public contacts are visible. | Text only |

ROAs are suggest-only: they are created in an RIR portal. A source that cannot answer is listed as `error` or `skipped` in the scan section and produces no findings, so an unreachable registry is never read as clean. IRR findings need the learned RIB and an `irr.sources` entry that lists route objects by origin; if one of those fails, the IRR part is an `error` and shows no finding. At most 500 announced prefixes and 500 stale objects are checked per scan, each against every source, and the section says so when it cuts. A delete is never offered on the first sighting: the learned RIB counts as ready once one session is up, so a scan right after a session flap could call live objects stale. The "-" diff of `irr_stale` and `irr_duplicate` is the object the `irr.sources` entry returned (a `whois` source; the `ripe` dialect asks unfiltered). When the object cannot be read, from a `file` source or a source that failed, the finding says so and has no diff and no delete.

IRR detection queries every configured `irr.sources` entry, so several registries (RADB, RIPE, ARIN, APNIC, AFRINIC, LACNIC, NTTCOM, ALTDB, LEVEL3) are compared in one scan; see [CONFIG.md](CONFIG.md#irr-source-whois).

## Push

`registry.push_enabled: true` plus a `registry.sources` entry lets an admin push a finding that has a change. Only these can be pushed:

- `ripe`: create or delete a `route` or `route6` object in the one database the source writes to (RIPE, or TEST for the RIPE test database). An object in the other of the two is text only. Credentials: `PACKETEER_RIPE_USER` and `PACKETEER_RIPE_PASSWORD`.
- `peeringdb`: set `info_prefixes4`, `info_prefixes6`, or a connection `speed`. Credential: `PACKETEER_PEERINGDB_API_KEY`.

Other IRR databases (RADB, ARIN, and the rest) get the RPSL to submit by hand. Credentials come only from the environment and are never in the config, the API, the logs, or the audit record. The RIPE credentials are read when a change is pushed; the PeeringDB key is read at start and also sent on scan reads (the public data needs no key).

Each push is `POST /api/registry/push` with the finding `id` and the `digest` of the diff that was shown. It needs the admin role and an authenticated API. The server refuses a digest that no longer matches the last scan, a change already pushed (a later scan that needs a different value is open again), and a finding without a change. Before a field update the `peeringdb` plugin re-reads the record and refuses when the field no longer holds the value the diff showed. Before a delete the `ripe` plugin reads the object from the REST API, unfiltered, and refuses unless it is the object shown, attribute by attribute; a copy whose attributes differ from the stored object (for example a filtered copy that lost `notify` or `e-mail`) is refused, while `#` comments such as `# Filtered` are not compared. A push request from an authenticated caller is in the audit log with its result, refusals included, and names the registry, class, and key once the request reaches the plugin; a success also holds the field values or the RPSL object. The Registry page shows the diff, asks for a second click, and then posts.

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

Set `registry.enabled: false` and restart. A pushed change is a change in the registry: undo it there (delete the object, or set the PeeringDB field back). The audit entry of a push holds the old and new field values, or the RPSL object that was created or deleted, so a deleted object can be put back from it.
