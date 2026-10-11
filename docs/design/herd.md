# Herd: opt-in shared measurements between Packeteer instances (#87)

Status: investigation. Nothing in this file is implemented, no config key
exists, and no issue other than #87 authorizes work on it. Names and
numbers below are proposals for review. None of them were measured.

A herd is a set of Packeteer instances run by different operators that
choose to share the probe results they already compute (loss, RTT,
jitter, the AS path they see) so each member gets a wider view of
Internet paths than its own edge gives it, in the spirit of
ThousandEyes. There is no central collector and no central dataset:
every member stores its own measurements, decides what to share, and
serves them to other members, which pull them.

Herd data is a multi-vantage view for understanding events. Every
vantage point legitimately sees something different, so nothing is
merged into one "true" value and no member's data overrides another's.
The operator reads the views side by side and interprets them. Trust is
about who said it and when (identity and provenance), not about whose
numbers win.

Herd must never be able to hurt the instance that runs it. A member
that is broken, overloaded, or hostile can make herd data missing or
wrong for its peers; it must not be able to exhaust their memory, disk,
CPU, connections, or probe budget, and herd failing or overloading must
never affect routing, probing, or the announcer.

## Herd is not federation

Multi-POP federation ([multi-pop.md](../multi-pop.md), #30) connects one
operator's own instances. Herd connects strangers. The two share some
mechanics and nothing about trust.

| | Federation (`mtls`) | Herd |
|---|---|---|
| Members | One operator's POPs | Other operators' instances |
| Trust | Full: same config, same CA | Identity and provenance only; no member's numbers are taken as true |
| Membership | Static `peers` list | Seeds, then peer exchange; one identity per ASN |
| Auth | Mutual TLS, one shared CA | Mutual TLS with self-signed certs pinned to per-member keys, plus signed responses; identity bound to an ASN through RPKI |
| Data | Snapshot of providers, paths, exits, improvements, usage | Measurement records per origin ASN (default) or per learned route (opt-in), shown per vantage, nothing about decisions or traffic |
| Load | A few trusted peers | Untrusted peers; every limit is enforced locally (see Resource protection) |
| Effect | Feeds Decide: a remote provider can become usable | Never feeds Decide. Probe hints, annotations, and warnings only |
| Storage | Latest snapshot in memory | Each member's own records, kept 1 month to 1 year |

Reused from federation: an in-process transport plugin that never
announces and never decides; HTTPS pull on an interval with a timeout;
JSON documents with a schema version; a `Publish` that does not block on
I/O; freshness by age, with times converted the way `ShiftSnapshot`
does (a time is trusted only as an age relative to the document's own
`generated_at`, so clock skew cannot make stale data look fresh); and a
peer that goes stale simply stops counting.

Not reused: the shared CA. Strangers have no common CA, so each member
has its own key, its certificate is self-signed, and peers pin the key
from a verified identity instead of trusting an issuer.

## Goals

- Let an operator who opts in share loss, RTT min/avg/max, jitter, and
  the AS path seen, per provider ASN, with other members: per origin ASN
  by default, or per exact learned route as a separate opt-in.
- Let a member pull those records from every active member and show
  them per vantage (member ASN, location, provider ASN), with summaries
  that count agreement across independent vantages, never a single
  verdict.
- Use that view locally in three advisory ways: raise probe priority for
  a prefix others see degrading; tell "my upstream" apart from "the
  destination"; give outage detection a second opinion.
- Later, warn about route-visibility problems (selective announcement,
  leak or hijack hints) seen across members.
- Keep every member in control of what leaves its box, with a preview
  of the exact bytes before anything is served.
- Keep each member safe from the others: hard, local limits on peers,
  requests, response sizes, memory, and disk, isolated from the core.

## Non-goals

- No central collector, central dataset, or public bulk download run by
  the project. (Seeds hold addresses only, see Discovery.)
- No traffic movement, announcement, or withdrawal from herd data, ever.
  See Hard rules.
- No sharing of flow data, volumes, configs, decisions, or anything on
  the never-shared list.
- No re-serving: a member serves only its own measurements, never data
  it pulled from others.
- No merged "true" value, global reputation, or score that suppresses
  a member's data for everyone.
- No reliance on remote attestation (TPM and similar). See Trust.
- Not a replacement for RouteViews, RIPE RIS, or RIPE Atlas, which stay
  separate public inputs with their own limits.
- No default-on switch, and no shipped example that turns herd on.

## Data model

### Granularity

Turning herd on is one switch. Granularity is a second, separate choice
per instance:

- **`origin_asn` (default when herd is on).** Records are keyed by the
  origin ASN of the learned route, with no prefix. The routes probed
  toward one origin ASN through one provider in one round are pooled
  into one record, the same way the probe engine pools hosts
  (`combineStats`). A route whose path ends in an AS_SET or has no
  known origin is not shared at this level.
- **`route` (separate opt-in).** Records are keyed by the **exact learned
  route**: the prefix exactly as it is in the local RIB view when the
  probe ran (a /24, a /20, a /48, whatever a neighbor advertised). Not a
  fixed /24 or /48 aggregate.

Rules for both:

- Only prefixes present in the RIB view at measurement time are
  recorded. A flow target that fell back to `aggregate_v4` /
  `aggregate_v6` because the RIB was not ready, or that maps to a
  default route, is never recorded.
- The prefix and the origin ASN are routing data that is already
  public. What is sensitive is the fact that this member probes them,
  which can show what its users talk to. Origin-ASN level shows which
  networks; route level shows which parts of them. Privacy below deals
  with that.
- Different members can learn different routes for the same addresses
  (one sees 198.51.100.0/22, another the /24 inside it). Route queries
  therefore take a match mode (exact, covering, covered), and each
  record stays under its own prefix; see Showing many vantages.

### Record (schema `herd/v1`)

One record is one probe round through one provider toward one origin
ASN (default) or one learned route (opt-in). Per-round records with raw
samples are the evidence a reader can inspect behind each number (see
Trust). Window rollups are an open question.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `herd/v1`. A puller ignores records with a schema it does not know. |
| `id` | string | Unique per member, stable across restarts, so a puller can deduplicate pages. |
| `granularity` | string | `origin_asn` or `route`. |
| `prefix` | prefix | Route level only: the exact learned route, as above. Absent at origin-ASN level. |
| `routes` | int | Origin-ASN level only: how many learned routes were pooled into the record. |
| `origin_asn` | uint32 | Last ASN of the AS path learned through that provider. Always present at origin-ASN level; at route level omitted when the path ends in an AS_SET or is unknown. |
| `provider_asn` | uint32 | First ASN of the AS path learned through that provider (the provider's own ASN). Never the provider's configured name, cost, or commit. Omitted when unknown. |
| `as_path` | []uint32 | The AS path learned through that provider for that prefix, as the RIB view holds it (add-path or BMP when the provider is not the best path), with private-use and reserved ASNs removed. At origin-ASN level, `as_paths` instead: the distinct paths seen toward that origin in the round. Only in the `paths` data class. |
| `vantage` | string | ISO 3166-1 alpha-2 country the member declares for this instance. Declared, not geolocated. Finer location is an open question. |
| `method` | string | `icmp`, `tcp`, or `udp`: the prober that produced the replies, since results from different probers are not comparable. |
| `time` | RFC 3339 UTC | Start of the round. |
| `sent` | int | Probe packets sent in the round, over all probed hosts (and, at origin-ASN level, all pooled routes). |
| `samples` | []object | Evidence: one entry per reply, `{"t_ms": offset from time, "rtt_ms": value}`, in send order. Host addresses are not included. |
| `loss_pct` | float | `100 × (sent − replies) / sent`. |
| `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms` | float | From the samples, the way `internal/probe` computes them; `rtt_avg_ms` is reply-weighted across hosts. Omitted when there were no replies. |
| `jitter_ms` | float | Mean absolute difference between consecutive RTTs to the same host (RFC 3550 style, without the smoothing), pooled across hosts weighted by reply gaps, the same as `probe.Compute` and `combineStats`. |
| `failed` | bool | The round produced no measurement (prober error, source down). A failed round carries no samples and no statistics. |

Summary fields are carried for convenience and must match the samples.
A puller recomputes them and drops a record that does not match.

Each member's records are stored in its own storage plugin (`sqlite`
today), in a table of their own. The existing daily `ProbeBucket`
rollups (with `JitterSum`) are not enough: they are keyed by provider
name, are daily, and have no RTT min/max or samples.

### Response envelope

Every response from the pull API is one signed document:

```json
{
  "schema": "herd/v1",
  "member": "<key id: hash of the member public key>",
  "asn": 64500,
  "generated_at": "2026-10-07T21:00:00Z",
  "retention_days": 90,
  "granularity": "route",
  "query": {"prefix": "198.51.100.0/24", "match": "exact", "from": "...", "to": "...", "cursor": ""},
  "records": [ ... ],
  "next_cursor": "...",
  "signature": "<Ed25519 over the canonical form (RFC 8785) of everything else>"
}
```

Echoing the query inside the signed body stops a reply to one query
from being replayed as the answer to another. A signed response is
provenance: a puller can show later exactly which member said what, and
when.

## What is never shared

None of these leave the box, whatever the operator selects:

- Flow and mirror data: records, byte and packet counts of user traffic,
  per-prefix volume and rates, `weight`, `top_n` rank, problem scores,
  transit/local classification.
- Which source produced a target (flow, span, static, vip, outage).
- Exact probe hosts, including the busiest flow destination, the
  problem address, and the in-prefix candidates. Samples carry no
  addresses.
- Provider names, source IPs, next hops, commits, costs, 95th
  percentiles, and any telemetry.
- Decisions, improvements, steers, announced routes, local preference,
  communities, mitigation rules, anomalies, inbound steering, and HA or
  federation state.
- Configs, secrets, tokens, SNMP communities, private keys, users,
  audit logs, and report history.
- The operator's own and customer prefixes: inbound prefixes, flow
  `transit.customers`, span `local`, and any prefix that covers or is
  inside them.
- Default routes, private, loopback, link-local, multicast, and
  unspecified space.
- Results from the `fixed` prober (labs). A member with `fixed` in its
  prober chain serves nothing outside a lab build.
- Anything on the operator's exclude list (below).

## Privacy

### What a member exposes

Without a central publisher there is no one place to apply a
k-anonymity rule before data is published. Each member exposes data
directly to every active member, so the protections have to sit at
each member and are chosen by its operator.

What any active member can learn about another:

- Its identity: the ASN it proved (see Identity) and its serving
  address, which also maps to a network. Herd members are not
  anonymous to each other. What is protected is what their users do,
  not who the operator is.
- Its providers' ASNs, the country it declares, and its retention.
- The origin ASNs (default) or learned routes (opt-in) it chose to share
  records for, and the measurements in them.

The sensitive part is the list of destinations, because a member probes what
its users talk to. That leak also runs the other way: a puller that
asks a member for specific prefixes tells that member what it cares
about.

### Controls (all at the member)

1. **Off by default.** Nothing is stored for herd, served, or pulled
   unless the operator turns herd on. No shipped example turns it on.
2. **Granularity.** Origin ASN by default; exact learned routes only
   when the operator opts in separately (see Granularity).
3. **Exclude list.** Prefixes and ASNs that are never shared. A prefix
   entry excludes every route equal to, inside, or covering it (at
   origin-ASN level, a pooled record leaves those routes out). An ASN
   entry excludes every route whose origin is that ASN or whose AS path
   contains it. Excluded routes are filtered before anything is written
   to the herd store, and again when serving, so a config change takes
   effect for data already stored.
4. **Opt in per data class.** Each class is separate and off until
   chosen:
   - `measurements`: the record without `as_path`.
   - `paths`: adds `as_path`.
   - `visibility`: route-visibility data for phase 3 (not specified
     yet).
5. **Opt in per target origin.** The operator chooses which target
   sources may produce shared records. Proposed default when herd is on:
   operator-listed targets (`static`, `vip`) and RIB-derived ones
   (`outage`, `vip` ASN expansion) only; `flow` and `span` targets,
   which come from users' traffic, need a separate opt-in.
6. **Crowd threshold for user-derived targets.** At route level, a
   route that only flow or span put on the probe list is served only
   once at least k other independent identities (distinct verified
   ASNs, see Identity) already serve records for that exact route, as
   this member sees from its own pulls or DHT lookups. Routes from
   operator-listed and RIB-derived sources are not held back by k when
   their origin is opted in. This cannot be enforced against a member
   that ignores it; it protects the member that applies it. Many nodes
   under one operator would fake the count, which is why only
   RPKI-verified identities count toward k, once per ASN. The value of
   k, and whether a threshold is also wanted at origin-ASN level, are
   open questions.
7. **Listing versus query-only.** The operator chooses how shared
   destinations can be found:
   - *listing*: a puller may page through everything by time range.
     The puller reveals nothing; the server reveals its whole list of
     origin ASNs or routes to every active member.
   - *query-only*: the server answers only for an origin ASN or prefix
     the puller names, rate-limited. Enumerating a full table becomes
     slow, not impossible. The puller reveals what it asks for.
   Queries by origin ASN are a middle ground for both sides. Which mode
   is the default is an open question.
8. **Coarse location.** Country only, declared by the operator.
9. **Preview.** The ops API (behind the existing auth) shows exactly
   what peers would see: the status document and the signed response a
   puller would receive for any query, produced by the same code that
   serves real pulls, after granularity, exclude list, data classes,
   target origins, and crowd threshold are applied. The preview is the
   bytes that would be sent. `preview_only` stores and previews records
   but serves nothing. Every served response is logged (puller
   identity, query, record count) to the audit store.
10. **Retention.** The member decides how long it keeps and serves
    records (below). Deleting records stops serving them; copies other
    members already pulled stay with them for their own retention.

## Identity and Sybil resistance

### One identity per ASN

A herd identity is an ASN. An operator counts once however many nodes
it runs. The main reason is load: spinning up many nodes must not
multiply an operator's peer-table slots, request budget, or storage on
other members (see Resource protection). It also keeps vantage counts
honest ("5 of 7 vantages"), where one operator with seven nodes is one
vantage per location and provider, not seven independent ones. Only
verified identities count toward k and toward independent-vantage
counts.

Proposed proof: an **RPKI Signed Checklist (RSC, RFC 9323)**.

1. Each node generates its own Ed25519 key on first enable and keeps it
   on the data volume (not in config, not in git). The key never leaves
   the node.
2. The operator writes a small identity statement: schema version, the
   ASN, the public keys of every node it runs, the serving endpoints,
   and a validity period.
3. The operator has its RPKI CA sign an RSC whose resources include
   that ASN and whose checklist holds the digest of the statement.
4. A node presents the statement and the RSC in its status document and
   in peer exchange. Peers validate the RSC to an RPKI trust anchor,
   check the digest, check the ASN is in the EE certificate's resources,
   and pin the listed keys.

Several nodes listed in one statement are one identity. Several ASNs
under one RPKI resource certificate are grouped as one identity too, so
an organization with many ASNs does not count many times.

Limits:

- Getting an ASN costs RIR fees and paperwork. That raises the price of
  a Sybil identity; it does not make it impossible. An operator with
  ten ASNs under different resource holders still counts ten times.
- Not every RPKI CA (hosted or delegated) can issue RSCs today; support
  has to be checked per RIR before relying on it.
- Packeteer would need to validate RPKI objects inside the one
  container. Today it does not. How (a Go relying-party library, or a
  mounted cache from rpki-client or similar) is an open question.
- A compromised RPKI account can mint an identity for that ASN.
- Operators without their own ASN (enterprise on provider space) cannot
  prove an identity. They could join unverified: shown, labeled
  unverified, not counted toward k or independent-vantage counts, and
  given the smallest slot and rate share.

### Alternatives considered

| Proof | Why not the default |
|---|---|
| ROA for a beacon prefix and a herd ASN | Abuses route origin authorizations for something that is not routing; ROAs bind prefixes to origins, not keys. |
| IRR object (aut-num remark with the key) | Most IRRs do not authenticate the maintainer against the resource holder; RIPE-style authoritative databases do, others do not. Usable as a weaker tier. |
| PeeringDB affiliation | Central service, not verifiable by peers cryptographically, and not every operator has an entry. |
| DNS TXT in the reverse zone of the operator's space | Proves control of reverse DNS, which is often delegated or held by a provider; ties identity to prefixes, not ASNs. |
| Announcing a beacon route | Packeteer never announces for herd, and it would cost a routing change to join. Out. |
| Proof of work or stake | Proves spending, not that you are a separate operator. |
| One identity per IP address or prefix | Cheap to multiply with a few addresses; does not map to operators. |

### Keys

- Each node signs its own responses and peer entries. Mutual TLS uses
  a self-signed certificate over the node key; the peer pins the key
  from the verified statement, so an unknown client is refused during
  the TLS handshake, before any request is parsed.
- Rotation: publish a new statement (new RSC) listing the new key; old
  keys stop counting once the old statement is gone or expired.
- Revocation: the RSC expires or is revoked in RPKI, or the statement
  is replaced without the key.

## Discovery and membership

Membership is discovered, not hand-maintained, and no node holds the
measurements of others.

1. **Seeds.** A short list of DNS names (as Bitcoin DNS seeds work)
   that resolve to addresses of nodes believed to be up. Seeds return
   addresses only; a node still verifies each identity itself. A static
   peer list in config works the same way and needs no seed. Who runs
   seed names is an open question.
2. **Peer exchange.** `GET /herd/v1/peers` returns the peer entries a
   node has successfully contacted recently. An entry is signed by its
   own node (not by the relayer): key, identity statement and RSC
   reference, endpoints, retention, data classes, a sequence number,
   and an expiry. The relayer adds only how long ago it last reached the
   entry, as an age. A node verifies every entry itself before using
   it, so a relayer can withhold entries but cannot forge them.
3. **Liveness.** A peer is *active* while its signed status document
   was fetched successfully within a recent window and its identity
   verifies. A peer that stays silent is aged out of the active set,
   then out of the table. An entry past its own expiry is dropped. A
   member that leaves stops serving, and may publish a signed entry
   marked `leaving` so others drop it at once.
4. **Reciprocity.** Only an active member can pull: a node that serves
   nothing (herd off, `preview_only`, or no data classes) cannot pull
   either.
5. **Bounded and diverse.** The peer table has a hard cap and an
   eviction policy (see Resource protection). Seeds and static peers are
   anchors that are not evicted; entries accepted per relayer are
   capped; peers heard from several relayers are preferred; slots are
   spread across distinct ASNs, at most one identity's worth per ASN.
6. **Optional DHT (later).** With many members, pulling everyone for a
   route gets expensive. A Kademlia-style DHT, with node IDs derived
   from verified keys, can answer "which members hold records for this
   route or origin ASN". Entries in it are pointers to holders, never
   the measurements, so data stays with its owner. Kademlia matches
   exact keys only, so a holder would publish a pointer per exact route
   and per origin ASN, and covering or covered lookups need several
   keys. A pointer reveals what the holder measures to anyone who looks
   the key up, so only routes the operator shares in listing mode get
   pointers. DHT routing needs its own Sybil and eclipse defenses
   (identity-bound IDs, lookups over disjoint paths).

## Pull API

Served on its own listener, separate from the ops HTTP API (which stays
on loopback by default). Mutual TLS with pinned keys, read-only, no
writes.

| Endpoint | Purpose |
|---|---|
| `GET /herd/v1/status` | Signed: identity statement and RSC, endpoints, `retention_days`, data classes and modes, schema versions, `generated_at`. Liveness checks fetch this. |
| `GET /herd/v1/peers` | Signed peer entries, as above. |
| `GET /herd/v1/records` | Records, filtered by `origin_asn`, or (route level only) by `prefix` with `match=exact|covering|covered`, plus `from`, `to` (inside the member's retention), `provider_asn`, `limit` (capped by the server), and an opaque `cursor`. Ordered by prefix, provider ASN, time, so pages are stable. In listing mode the prefix and ASN filters are optional. A member sharing at origin-ASN level matches no prefix query; its status document says which granularity it serves. |

Every endpoint is bounded by the limits in Resource protection: rate
limits per identity and per source address (`429` with `Retry-After`),
page size and response byte caps, and covering or covered queries
costing more than exact ones.

Freshness: a puller trusts record times only as ages relative to the
envelope's `generated_at` and the time it fetched it, as `ShiftSnapshot`
does, and drops records dated after `generated_at`.

## Retention

- Each member sets its own retention, at least 1 month and at most 1
  year (proposed as 30 to 365 days; the exact definition of a month is
  an open question). Values outside the range are a config error.
- It advertises the value in its status document and peer entry, and
  serves only records inside it. A query asking for older data gets
  what is retained, with the effective `from` in the envelope.
- Records older than retention are deleted from the store, not just
  hidden.
- What a puller keeps of pulled data is bounded by its own retention,
  and pulled data is used locally only, never re-served.

Storage cost of per-round records with samples over a year is not
known. It has to be measured before a default is chosen.

## Config shape (proposal)

Illustrative only. Nothing here is implemented, no key exists, and none
of it goes into `config.example.yaml` or CONFIG.md until a phase is
approved. Names and values are placeholders for review.

```yaml
herd:
  enabled: false              # the one opt-in switch; absent is the same
  preview_only: false         # store and preview, serve and pull nothing
  share:
    granularity: origin_asn   # default when enabled; "route" shares exact
                              # learned routes and must be set explicitly
    paths: false              # add AS paths (the `paths` data class)
    sources: [static, vip, outage]   # target origins that may be shared;
                                     # flow and span only if listed here
    discovery: query_only     # or listing
    crowd_k: 0                # route level, flow/span targets; value open
    exclude:
      prefixes: [203.0.113.0/24]     # equal, inside, or covering: never shared
      asns: [64501]                  # as origin or anywhere in the path
  retention: 90d              # 30d to 365d; advertised to peers
  vantage:
    country: US               # declared, ISO 3166-1 alpha-2
  listen: 0.0.0.0:9444        # herd listener, separate from http
  key_file: /var/lib/packeteer/herd/node.key   # generated on first enable
  identity:                   # phase 2
    statement_file: /etc/packeteer/herd/identity.json
    rsc_file: /etc/packeteer/herd/identity.rsc
  peers:                      # phase 1: static peers, pinned keys
    - url: https://192.0.2.30:9444
      key: ed25519:<public key>
  seeds: [seed.herd.example.invalid]   # phase 2
  block: {asns: [], keys: []}          # local view only
  limits: {}                  # peer, rate, size, memory, disk caps;
                              # defaults from a lab load test
```

Validation follows the plugin rules: unknown keys are errors, a
retention outside 30 to 365 days is an error, `granularity` accepts only
`origin_asn` or `route`, exclude entries must be valid prefixes and
non-zero ASNs, and `enabled: true` with no data class chosen is an
error. Rollback is `enabled: false` and a restart: the listener closes,
pulling stops, and the herd store can be deleted.

## Showing many vantages

A puller never merges records into one value. It keeps and shows them
per vantage.

1. **Validate, then keep.** Drop anything that fails checks: bad
   signature, unknown schema, summary fields that do not match the
   samples, impossible values (`loss_pct` outside 0 to 100, more replies
   than `sent`, `rtt_min`, `rtt_avg`, `rtt_max` not in ascending order,
   jitter larger than the spread between `rtt_min` and `rtt_max`,
   samples out of order or outside the round), records outside the
   advertised retention, records from members this operator blocked.
   Deduplicate by member key and record `id`. These checks reject
   malformed data; they do not judge whose numbers are right.
2. **A vantage is (member ASN, country, provider ASN, method).** Every
   view lists vantages separately with their own loss, RTT, and jitter
   over time, next to the local measurements. Several nodes of one
   identity in the same country through the same provider ASN are one
   vantage.
3. **Summaries count agreement, not truth.** A summary for a route over
   a time range says how many independent vantages saw a condition, for
   example "5 of 7 vantages see loss above 5% to 198.51.100.0/24 in the
   last 15 minutes; 2 through provider AS64501 see none". Each vantage
   contributes one count however many records it sent. A headline count
   of independent vantages counts each verified identity at most once;
   splitting the summary by country or provider ASN shows the rest.
   Unverified members appear in rows, not in counts. No vantage
   outranks another, and the summary links to the per-vantage rows.
4. **Prefixes and granularities stay apart.** A record for
   198.51.100.0/22 and one for 198.51.100.0/24 are different routes;
   the view for a local route shows exact matches first and covering or
   covered routes labeled as such. Origin-ASN records from members that
   share at that level appear under the route's origin ASN, labeled as
   pooled, never mixed into route-level rows.
5. **Provenance on every row.** Member identity (ASN, verified or not),
   node key, record age as of the fetch, and the signed envelope it came
   in, so an operator can see why a summary says what it says.
6. **Local weights only.** An operator may down-weight (hide from
   summaries, keep visible in rows) or block (neither pulled nor shown)
   a member. That changes only this operator's own view. There is no
   global reputation and nothing that suppresses a member's data for
   everyone.

## Local use

Everything here is advisory.

- **Probe-priority hints.** A herd target source adds prefixes where at
  least a minimum number of independent vantages see degradation (a
  count, not a verdict; the minimum is an operator setting), only for
  prefixes that are in the local RIB view, never a default route,
  capped like the `outage` source's `max_targets`, under the global
  probe rate limit.
  Like every source, it spends probe budget and nothing else.
- **"My upstream or the destination."** For a local route that measures
  badly through provider A, compare with members reaching the same
  route: bad from every vantage and provider points at the destination;
  bad through provider ASN A from many vantages points at A; bad only
  here points at this edge or circuit. Shown on the API and dashboard
  and added to events as a field. Not used by Decide.
- **Outage second opinion.** When the `outage` source opens an AS or
  circuit incident, annotate it with how many independent vantages
  see the same ASN degraded out of how many reported, or that none do.
  The annotation never opens, closes, or changes an incident or its
  thresholds.

## Hard rules

1. Herd never moves traffic, announces, or withdraws by itself.
2. Herd data never enters Decide, a scorer, a planner, a policy, or
   `PathStats`, and never makes a provider usable or unusable. (This is
   the line federation does cross and herd does not.)
3. A local probe must confirm. A hint can only add a probe target; any
   improvement still comes from local measurements passing the normal
   thresholds, hold time, allowlist, cap, and withdraw rules.
4. Herd never overrides the local RIB. A prefix only other members see
   is never announced. Announcing a prefix no neighbor advertised stays
   a hard stop (the opt-in `synthesize` rails in
   [more-specific.md](more-specific.md) are unchanged and do not take
   herd input).
5. Another member's word is never ground truth, and no member's data
   overrides another's. A missing record, like a missing route at
   RouteViews or RIS, is not proof of anything.
6. Herd plugins run in-process only, like the federation plugin; they
   never announce.
7. CI and labs never talk to a real herd: labs run their own members
   with documentation prefixes and ASNs, and no seed is configured.
8. Herd failure or overload never affects routing, probing, or the
   announcer. If herd is stuck, out of budget, or crashed, the instance
   behaves exactly as if herd were off.

## Resource protection

No member can harm another member's instance. Every limit below is
enforced locally, by the instance being protected, and none depends on
peers behaving. The numbers are not decided; the design fixes that each
limit exists, is hard, and has a safe default.

**Isolation from the core.**

- Herd runs on its own goroutines with its own bounded queues, the way
  `internal/notify` isolates notifiers. The probe loop, Decide, the RIB
  view, and the announcers never wait on herd, never share a lock with
  it, and never read herd state on their critical paths.
- Writing local records is a non-blocking hand-off from the probe loop
  into a bounded queue. When the queue is full, herd records are
  dropped and counted; probing does not slow down.
- Herd has its own memory budget (peer table, caches, in-flight
  responses) and its own disk budget for local and pulled records,
  separate from report history. When a budget is hit, herd drops the
  oldest pulled data first, then refuses new pulled data, and never
  touches report history or core state.
- Herd sends no probes of its own. Hint targets go through the normal
  source path and the global probe rate limit, with their own
  `max_targets`-style cap, so herd can never take more than its share
  of probe budget.
- A panic or error inside herd stops herd, logs it, raises an event,
  and leaves the controller running. Herd restarts with backoff.

**Peers.**

- Hard cap on known peers (table size) and a smaller hard cap on
  connected or actively pulled peers.
- Eviction when the table is full: never seeds or static peers; then
  entries past expiry, then the longest silent, then entries from an ASN
  already holding a slot. At most one identity's slots per ASN, so many
  nodes under one ASN do not get more room.
- Caps on peer entries accepted per gossip response and per relayer.

**Requests (serving side).**

- Global and per-identity rate limits for gossip and pull requests,
  plus per source address before the identity is known; `429` with
  `Retry-After` when exceeded.
- Caps on concurrent connections (global and per identity), on
  handshakes in progress, and on requests per connection.
- Read, write, idle, and handshake timeouts on every connection.
- Mutual TLS with pinned keys refuses unknown clients during the
  handshake, before any request is parsed.
- Requests have a byte cap and a strict parser: oversized, malformed,
  or unknown-field requests are refused without further work.
- Page size and response byte caps; a query that would exceed them
  returns a partial page and a cursor. Covering and covered queries cost
  more of the identity's budget than exact ones.

**Pulling (client side).**

- Hard cap on concurrent pulls, a per-interval request budget, and a
  per-peer budget, so a large herd costs a bounded amount per interval
  and peers are pulled in turn.
- Response size cap enforced while reading (the read stops at the
  cap); records per response capped; anything oversized or malformed is
  discarded and counts as a failure for that peer.
- Timeouts on connect and on the whole request, and exponential backoff
  with jitter per peer after failures or `429`. A peer that keeps
  failing is aged out (see Discovery).
- Records pulled from one peer are capped per interval and in total, so
  one peer cannot fill the pulled-data disk budget.

**Visibility.** Every limit that trips is counted in metrics and the
herd status API (which limit, which peer), so an operator can see who
is costing what.

## Trust

Trust is about identity and provenance, not about whose numbers win.

- **Identity.** One verified identity per ASN (above). Every node signs
  its responses and peer entries; mutual TLS pins its key.
- **Provenance.** Every record shown carries who sent it, from which
  node, how old it was when fetched, and the signed envelope it came in.
- **Evidence.** Records carry raw samples with offsets, the round time,
  and the AS path, so a reader can see what a number is based on, and
  malformed or inconsistent records are rejected (see Showing many
  vantages).
- **Per vantage, never merged.** Vantages legitimately differ, so a
  member's numbers are shown as that member's, and summaries count
  agreement across independent vantages.
- **Local blocklist and weights.** An operator may down-weight or block
  an identity, a key, or an endpoint. That affects only its own view.

There is no global reputation. Possible later, if real use shows a
need, and only as a local view setting: re-probing a sample of routes
from the operator's own edge to compare with a member's reports, or a
local agreement score per member.

**Why not remote attestation.** TPM or enclave attestation can prove
which binary started, not that its inputs are honest. Packeteer is open
source and the operator controls the box: a genuine binary can still be
fed a fake prober (the `fixed` prober exists for labs, and `exec`
probers run anything), a modified kernel, or a network that delays or
drops probes on purpose. Attestation would also need vendor trust roots
and hardware most container deployments do not expose, against the
one-container rule. Herd shows every member's data as that member's
claim and leaves interpretation to the operator.

## Phased plan

Each phase starts only after Andrew approves this design, gets its own
issue and parity row (BOT.md intake), and waits its turn on the train.
No phase changes Decide.

**Phase 1: local store, serve, and pull among a few members.**
Per-round records in the storage plugin with retention (30 to 365
days); data classes and target-origin opt-ins; preview mode and the
served-response audit; the pull API with signed responses, mutual TLS
pinned to per-node keys, and pagination; pulling from a static list of
peers with pinned keys; a per-vantage view on a read-only API endpoint.
Every resource limit in Resource protection that applies to serving and
pulling ships in this phase, not later. No discovery, no RPKI identity
(static peers are trusted by pinned key), no hints.

Acceptance:

- Off by default; with herd off, nothing is stored, served, or pulled.
- With herd on and no granularity set, only origin-ASN records are
  stored and served; no prefix appears in any response until
  `granularity: route` is set.
- Exclude list: no excluded prefix (equal, inside, or covering) or ASN
  (origin or in path) reaches the store or a response, including data
  stored before the entry was added.
- Preview: for every query shape, the preview bytes equal what a real
  pull receives.
- Nothing on the never-shared list can reach a response (tests per
  field and per source class); preview equals the served bytes;
  retention deletes; a tampered, replayed, or wrongly signed response is
  refused.
- Decisions are identical with herd on and off for the same local
  measurements.
- Isolation: with a peer that never answers, answers slowly, or floods,
  probe rounds finish on time, decisions and withdrawals are not
  delayed, and the announcer is unaffected (asserted in the lab, with
  the existing SIGTERM and SIGKILL withdraw checks still passing).
- A herd panic or blocked herd queue leaves probing and BGP running.
- Serving limits: requests over the per-identity and global rate get
  `429`; concurrent connections stop at the cap; oversized and
  malformed requests are refused without allocation beyond the cap;
  slow clients are cut off by timeouts; page and response byte caps
  hold.
- Pulling limits: an oversized or endless response is cut at the cap
  and discarded; concurrent pulls and per-interval budget hold; backoff
  grows after failures and `429`.
- Memory and disk: under a flood of valid records, herd memory and disk
  stay within their budgets, the oldest pulled data is dropped first,
  and report history is untouched.
- A lab with three members on documentation prefixes and ASNs.

**Phase 2: discovery, identity, and hints.** Seeds and peer exchange,
liveness and aging, RSC identity with one identity per ASN, the crowd
threshold for user-derived targets, the independent-vantage summaries,
local blocklist and weights, and the three local uses (hint source,
attribution, outage annotation).

Acceptance:

- Peer table: the known and connected caps hold under a gossip flood;
  eviction follows the stated order; seeds and static peers are never
  evicted; per-relayer and per-response entry caps hold.
- Many nodes under one ASN get one identity's slots and budget, and
  count as one vantage per location and provider.
- Gossip rate limits hold per peer and globally; malformed or
  oversized peer entries are refused.
- Silent peers age out; expired and `leaving` entries are dropped.
- A hinted prefix is probed within its cap and never announced without
  local measurements passing the normal thresholds.
- A local block or down-weight changes only the local view.

**Phase 3: route-visibility warnings.** The `visibility` class and
warnings from the issue: a route visible at some members and missing at
others while the provider's own space is present; an origin or AS path
that does not match the local RIB (leak or hijack hint); a more-specific
seen elsewhere that no local neighbor advertises. Events only, each
stating how many independent vantages saw it. Optional DHT if
membership size calls for it, with the same peer, request, and memory
limits applied to DHT traffic.

Acceptance: warnings are events only, carry vantage counts and
provenance, and the phase 1 isolation tests still pass with visibility
data flowing.

## Open questions for Andrew

1. **Seeds.** Who runs the seed DNS names, under which domain, and is
   a fallback list compiled into releases acceptable?
2. **Identity.** Is RSC (RFC 9323) the required proof, with IRR or
   PeeringDB as weaker tiers, and may operators without an ASN join
   unverified (shown, not counted)? How should the container validate
   RPKI objects?
3. **k.** What value for the crowd threshold, and should it apply to
   every target origin or only flow and span?
4. **Listing or query-only** as the default, given that one exposes the
   server and the other the puller.
5. **Location.** Country only, or an optional metro code?
6. **Evidence volume.** Keep raw samples for the whole retention, or
   roll records older than some age into window summaries (smaller, less
   checkable)? Depends on storage measurements not yet taken.
7. **Retention bounds.** Is "1 month" 30 days or a calendar month?
8. **Data terms.** Under what terms may a member use data pulled from
   others (members-only, attribution, research)? Is any read access for
   non-members wanted?
9. **AS path normalization.** Keep prepends as learned? Strip only
   private-use and reserved ASNs?
10. **HA and multi-POP.** One node per HA pair serving from the active
    instance only? Each POP its own node under the operator's one
    identity?
11. **Limit defaults.** Starting values for the peer caps, rate limits,
    response caps, and memory and disk budgets. They should come from a
    lab load test, not from guesses.
12. **Hint minimum.** Default minimum number of independent vantages
    before a hint adds a probe target.
13. **Charter.** Herd sends data off the box. Should AGENTS.md gain a
    safety line for it (off by default, never-shared list, advisory
    only) when phase 1 starts?
14. **Granularity default.** Is origin-ASN level the right default for
    everyone, and should route level require anything beyond the
    explicit setting (for example the crowd threshold always on)?
15. **Placement.** After the v0.6 parity milestone, or interleaved?
