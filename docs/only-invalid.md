# RPKI-invalid only paths

Strict route origin validation (ROV) drops every RPKI-invalid route. When the invalid route is the only route Packeteer learned to a destination, dropping it black-holes that destination. If the cause is a stale ROA or a wrong maxLength and not a hijack, users see an outage. `rpki.only_invalid` (#401) finds these routes, classes each one from evidence, and reports it. It needs the `rpki` block, is off by default, and is not on a public edge.

Detection only reports. Nothing here announces, withdraws, or changes a decision or the learned RIB. The one write is an approved SLURM exception (below), which changes the validation data the RTR cache serves, so the edge's routers stop dropping that route. The learned-RIB rule, allowlist, `max_improvements`, community + NO_EXPORT, hold time, and withdraw rules are unchanged. Packeteer sees invalid routes only if the router passes them on, for example with ROV that tags instead of drops, or BMP pre-policy.

## Detection

Every 5 minutes, starting 1 minute after start, Packeteer scans the selected routes of the learned RIB. A prefix is a case when:

- its selected route is `invalid`, and every learned path for the prefix (add-path and BMP included) is `invalid`, and
- no less specific learned route has a path that is `valid`, `notfound`, or `unknown`.

A path the edge originates (empty AS path) or one with no RPKI answer is not invalid. The scan inspects at most the first 1000 invalid selected routes, in prefix order, and says so in `note`. Open cases past the last inspected route stay open as last seen (up to 1000) and do not clear. While the RIB is not ready or no `rpki.sources` entry has fresh data, it skips and keeps the open cases, so an outage is never read as cases clearing.

## Evidence and class

Each case lists its paths (provider, AS path, learn time), the ROAs covering it, and these signals. Positive points count toward a stale ROA, negative toward a hijack:

| Signal | Points | Meaning |
|---|---|---|
| `irr_route` | +2 / -2 / -1 / 0 | The origin has a route object for exactly the prefix (`irr`) / route objects name other origins / no route object / no answer or `irr` off. |
| `irr_as_set` | +1 / -1 / 0 | The origin is / is not in the provider's `irr.as_sets` entry / no answer. Only with `irr.as_sets`. |
| `origin_stable` | +2 / 0 | The oldest learned path with the origin is at least `stable_after` old / younger. A young path is neutral because a session reset makes every path young. |
| `roa_same_origin` | +1 / 0 | A ROA authorizes the same origin for a covering prefix with a maxLength shorter than the route, so the covering prefix is valid for that origin / no ROA names the origin. Weak alone: a forged-origin sub-prefix hijack (RFC 9319) looks the same. |
| `providers` | +1 / -2 / 0 | Two or more providers carry the same origin / another learned path ends in a different origin (conflicting origin) / one provider. |
| `hijack_feeds` | -4 / +1 / 0 | A feed reports an incident for the prefix with this origin or no origin / every feed that answered reports none / no feed configured or none answered. |

A score of 3 or more is `stale_roa` when `irr_route` or `origin_stable` is positive, and `unclear` without that support. -2 or less is `hijack`; anything between is `unclear`. Each case has a suggested action: contact the prefix holder, or keep dropping and report it.

Public collector agreement (RIS, RouteViews) is not a signal yet.

## Hijack feeds

`hijack_feeds` are `hijack_feed` plugins ([PLUGINS.md](PLUGINS.md)). The built-in `file` type reads a mounted JSON file of incidents, read again when it changes:

```json
{"incidents": [{"prefix": "198.51.100.0/24", "origin": 64511, "detail": "possible origin hijack"}]}
```

`origin` (optional) is the AS the monitor saw, and `detail` (optional) is shown in the evidence. An incident counts for a case when its prefix overlaps the case, so an incident on a covering block counts for every case inside it. A missing file is no evidence either way, also after it was read once; a file that does not parse keeps the last good list. At most 16 MiB and 100,000 incidents.

## SLURM exceptions

With `rpki.only_invalid.slurm`, Packeteer can propose a SLURM (RFC 8416) local exception for a case, and an admin can approve it. Nothing is written without that approval.

1. An operator proposes one for an open case: `POST /api/rpki/only-invalid/propose` with `{"prefix":"198.51.100.0/24"}`, or **Propose exception** on the Registry page. Only a case classed `stale_roa` and inside `slurm.prefixes` qualifies. The answer has the exact SLURM JSON to be added, the evidence, the validity before and after (computed from the covering ROAs), and a digest. Nothing is written.
2. An admin reviews the JSON and the evidence and approves: `POST /api/rpki/exceptions` with `{"id":"<proposal id>","digest":"<digest>"}`, or **Approve and write**. The case must still be open and classed `stale_roa`, and the entries built from the current ROAs must still match the digest; if the ROAs changed, approval is refused and the operator proposes again. A proposal can be approved for 1 hour.
3. Packeteer adds the entries to `slurm.path`, replacing the file atomically, mode 0644. Entries already in the file, including ones written by hand, are kept. A file that is not valid RFC 8416 is never overwritten: proposals and approvals are refused until it is fixed.
4. `DELETE /api/rpki/exceptions/<id>` (admin) removes one entry.

The entry is a `prefixAssertion` for exactly the prefix and the observed origin (`maxPrefixLength` is the prefix length), which keeps every other origin invalid. When every ROA covering the prefix is AS0 (RFC 7607), the stale data is those payloads, and the entry is a `prefixFilter` for each AS0 ROA's prefix with `asn` 0, which makes the route `notfound`. A filter drops every payload under the ROA's prefix, so a case whose AS0 ROA is wider than `slurm.prefixes` is refused. `slurm` is refused with an `ixp` block: IXP mode may not change member routing.

Each entry's `comment` is `packeteer audit=<id> date=<time>: ...`, where `<id>` is the audit record of the proposal. The proposal, approval, write, and removal are each in the audit log ([auth.md](auth.md#audit-log)) with the evidence (an approval whose write failed is recorded as `failed`): actions `rpki.slurm.propose`, `rpki.slurm.approve`, `rpki.slurm.write`, and `rpki.slurm.remove`. The HTTP request is audited as well.

The RTR cache reads the file from a shared volume: Routinator with `--exceptions <path>`, StayRTR with `-slurm <path>`, FORT with `--slurm <path>`. `GET /api/rpki/slurm` returns the file (or an empty RFC 8416 document) for an operator who installs it by hand. Once the cache serves the exception, the route turns valid (not found for an AS0 filter) and the case clears.

Each Packeteer exception older than `slurm.review_after` (default 720h) raises `rpki.slurm_review` once per run, counted from the date in its comment, and the exception shows `review_due`. Once a case clears, Packeteer does not look at its prefix again, so a later hijack feed incident or IRR change raises nothing; the reminder is the check.

## Config

```yaml
rpki:
  enabled: true
  sources:
    - type: rtr
      config: {address: "192.0.2.20:3323"}
  only_invalid:
    enabled: true
    stable_after: 720h
    hijack_feeds:
      - type: file
        name: radar-export
        config: {path: /etc/packeteer/hijacks.json}
    slurm:
      path: /var/lib/packeteer/slurm/slurm.json
      prefixes: [198.51.100.0/24]
      review_after: 720h
```

Keys are in [CONFIG.md](CONFIG.md#rpkionly_invalid). Events are `rpki.only_invalid`, `rpki.only_invalid_cleared`, and `rpki.slurm_review` ([EVENTS.md](EVENTS.md)).

## Rollback

Remove `rpki.only_invalid` and restart. The exceptions stay in the SLURM file, and the RTR cache keeps serving them, until they are deleted: delete them with the API first, or remove the SLURM file and let the RTR cache reload it.

## Tests

Unit tests use recorded fixtures with documentation prefixes and ASNs, never live IRR, RPKI, or feed lookups: a stale ROA with IRR and history in agreement, the same prefix from a conflicting origin with a hijack feed hit, a valid alternative path, a valid covering route, the SLURM rules, propose and approve with the audit records, the AS0 filter, the reminder, and a stub RTR cache that serves its ROAs with the approved file applied to the `rtr` plugin, which turns the fixture route from invalid to valid. Not lab-proven against a real Routinator.
