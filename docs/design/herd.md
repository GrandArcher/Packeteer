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
serves them to other members, which pull and merge.

## Herd is not federation

Multi-POP federation ([multi-pop.md](../multi-pop.md), #30) connects one
operator's own instances. Herd connects strangers. The two share some
mechanics and nothing about trust.

| | Federation (`mtls`) | Herd |
|---|---|---|
| Members | One operator's POPs | Other operators' instances |
| Trust | Full: same config, same CA | None by default: any member can be wrong or lie |
| Membership | Static `peers` list | Seeds, then peer exchange; one identity per ASN |
| Auth | Mutual TLS, one shared CA | Mutual TLS with self-signed certs pinned to per-member keys, plus signed responses; identity bound to an ASN through RPKI |
| Data | Snapshot of providers, paths, exits, improvements, usage | Measurement records per learned route, nothing about decisions or traffic |
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
  the AS path seen, per learned route and provider ASN, with other
  members.
- Let a member pull those records from every active member and merge
  them into a wider view of a destination.
- Use that view locally in three advisory ways: raise probe priority for
  a prefix others see degrading; tell "my upstream" apart from "the
  destination"; give outage detection a second opinion.
- Later, warn about route-visibility problems (selective announcement,
  leak or hijack hints) seen across members.
- Keep every member in control of what leaves its box, with a preview
  of the exact bytes before anything is served.

## Non-goals

- No central collector, central dataset, or public bulk download run by
  the project. (Seeds hold addresses only, see Discovery.)
- No traffic movement, announcement, or withdrawal from herd data, ever.
  See Hard rules.
- No sharing of flow data, volumes, configs, decisions, or anything on
  the never-shared list.
- No re-serving: a member serves only its own measurements, never data
  it pulled from others.
- No reliance on remote attestation (TPM and similar). See Lying.
- Not a replacement for RouteViews, RIPE RIS, or RIPE Atlas, which stay
  separate public inputs with their own limits.
- No default-on switch, and no shipped example that turns herd on.

## Data model

### Granularity

A record is keyed by the **exact learned route**: the prefix exactly as
it is in the local RIB view when the probe ran (a /24, a /20, a /48,
whatever a neighbor advertised). Not a fixed /24 or /48 aggregate and
not only the origin ASN.

- Only prefixes present in the RIB view at measurement time are
  recorded. A flow target that fell back to `aggregate_v4` /
  `aggregate_v6` because the RIB was not ready, or that maps to a
  default route, is never recorded.
- The prefix is routing data that is already public. What is sensitive
  is the fact that this member probes it, which can show what its users
  talk to. Privacy below deals with that.
- Different members can learn different routes for the same addresses
  (one sees 198.51.100.0/22, another the /24 inside it). Queries
  therefore take a match mode (exact, covering, covered) and the merge
  keeps each record under its own prefix; see Merging.

### Record (schema `herd/v1`)

One record is one probe round toward one learned route through one
provider. Per-round records with raw samples are the evidence other
members use to check claims (see Lying). Window rollups are an open
question.

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `herd/v1`. A puller ignores records with a schema it does not know. |
| `id` | string | Unique per member, stable across restarts, so a puller can deduplicate pages. |
| `prefix` | prefix | The exact learned route, as above. |
| `origin_asn` | uint32 | Last ASN of the AS path learned through that provider. Omitted when the path ends in an AS_SET or is unknown. |
| `provider_asn` | uint32 | First ASN of the AS path learned through that provider (the provider's own ASN). Never the provider's configured name, cost, or commit. Omitted when unknown. |
| `as_path` | []uint32 | The AS path learned through that provider for that prefix, as the RIB view holds it (add-path or BMP when the provider is not the best path), with private-use and reserved ASNs removed. Only in the `paths` data class. |
| `vantage` | string | ISO 3166-1 alpha-2 country the member declares for this instance. Declared, not geolocated. Finer location is an open question. |
| `method` | string | `icmp`, `tcp`, or `udp`: the prober that produced the replies, since results from different probers are not comparable. |
| `time` | RFC 3339 UTC | Start of the round. |
| `sent` | int | Probe packets sent in the round, over all probed hosts. |
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
  "query": {"prefix": "198.51.100.0/24", "match": "exact", "from": "...", "to": "...", "cursor": ""},
  "records": [ ... ],
  "next_cursor": "...",
  "signature": "<Ed25519 over the canonical form (RFC 8785) of everything else>"
}
```

Echoing the query inside the signed body stops a reply to one query
from being replayed as the answer to another. Signed responses can be
kept as evidence when a member is caught lying.

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
- The learned routes it chose to share records for, and the
  measurements in them.

The sensitive part is the list of routes, because a member probes what
its users talk to. That leak also runs the other way: a puller that
asks a member for specific prefixes tells that member what it cares
about.

### Controls (all at the member)

1. **Off by default.** Nothing is stored for herd, served, or pulled
   unless the operator turns herd on. No shipped example turns it on.
2. **Opt in per data class.** Each class is separate and off until
   chosen:
   - `measurements`: the record without `as_path`.
   - `paths`: adds `as_path`.
   - `visibility`: route-visibility data for phase 3 (not specified
     yet).
3. **Opt in per target origin.** The operator chooses which target
   sources may produce shared records. Proposed default when herd is on:
   operator-listed targets (`static`, `vip`) and RIB-derived ones
   (`outage`, `vip` ASN expansion) only; `flow` and `span` targets,
   which come from users' traffic, need a separate opt-in.
4. **Crowd threshold for user-derived targets.** A route that only flow
   or span put on the probe list is served only once at least k other
   independent identities (distinct verified ASNs, see Identity) already
   serve records for that exact route, as this member sees from its own
   pulls or DHT lookups. Routes from operator-listed and RIB-derived
   sources are not held back by k when their origin is opted in. This
   cannot be enforced against a member that ignores it; it protects the
   member that applies it. Sybil identities can lower the real count,
   which is why only RPKI-verified identities count toward k. The value
   of k is an open question.
5. **Listing versus query-only.** Per data class, the operator chooses
   how routes can be found:
   - *listing*: a puller may page through everything by time range.
     The puller reveals nothing; the server reveals its whole route
     list to every active member.
   - *query-only*: the server answers only for a prefix or origin ASN
     the puller names, rate-limited. Enumerating a full table becomes
     slow, not impossible. The puller reveals what it asks for.
   Queries by origin ASN are a middle ground for both sides. Which mode
   is the default is an open question.
6. **Coarse location.** Country only, declared by the operator.
7. **Preview.** The ops API (behind the existing auth) shows exactly
   what a puller would receive for any query, produced by the same code
   that serves real pulls, so the preview is the bytes that would be
   sent. A `preview` mode stores and previews records but serves
   nothing. Every served response is logged (puller identity, query,
   record count) to the audit store.
8. **Retention.** The member decides how long it keeps and serves
   records (below). Deleting records stops serving them; copies other
   members already pulled stay with them for their own retention.

## Identity and Sybil resistance

### One identity per ASN

A herd identity is an ASN. An operator counts once however many nodes
it runs, and only verified identities count for k, for agreement
thresholds, and for reputation.

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
  prove an identity. They could join unverified: allowed to pull and
  serve, but weight zero for k, thresholds, and reputation.

### Alternatives considered

| Proof | Why not the default |
|---|---|
| ROA for a beacon prefix and a herd ASN | Abuses route origin authorizations for something that is not routing; ROAs bind prefixes to origins, not keys. |
| IRR object (aut-num remark with the key) | Most IRRs do not authenticate the maintainer against the resource holder; RIPE-style authoritative databases do, others do not. Usable as a weaker tier. |
| PeeringDB affiliation | Central service, not verifiable by peers cryptographically, and not every operator has an entry. |
| DNS TXT in the reverse zone of the operator's space | Proves control of reverse DNS, which is often delegated or held by a provider; ties identity to prefixes, not ASNs. |
| Announcing a beacon route | Packeteer never announces for herd, and it would cost a routing change to join. Out. |
| Proof of work or stake | Proves spending, not that you are a separate operator. |

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
   nothing (herd off, `preview`, or no data classes) cannot pull either.
5. **Eclipse resistance.** Bounded peer table; keep seeds and static
   peers as anchors; cap entries accepted per relayer; prefer peers
   heard from several relayers; spread pulls and peer slots across
   distinct ASNs.
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
| `GET /herd/v1/records` | Records, filtered by `prefix` with `match=exact|covering|covered`, or by `origin_asn`, plus `from`, `to` (inside the member's retention), `provider_asn`, `limit` (capped by the server), and an opaque `cursor`. Ordered by prefix, provider ASN, time, so pages are stable. In listing mode the prefix and ASN filters are optional. |

Rate limits: per pulling identity and per source address, with `429`
and `Retry-After`; caps on page size, query count, and response bytes;
covering and covered queries cost more than exact ones. On the puller
side: a bounded number of concurrent members, a per-interval request
budget, and backoff on errors. Herd I/O runs on its own goroutines and
bounded queues, so a slow member never delays probing, decisions, or
withdrawals (the same rule `internal/notify` follows).

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

## Merging

A puller merges per destination as follows.

1. Drop anything that fails checks: bad signature, unknown schema,
   summary fields that do not match the samples, impossible values
   (`loss_pct` outside 0 to 100, more replies than `sent`, `rtt_min`,
   `rtt_avg`, `rtt_max` not in ascending order, jitter larger than the spread
   between `rtt_min` and `rtt_max`, samples out of order or outside the
   round), records outside the advertised retention, records from
   blocklisted members.
2. Deduplicate by member key and record `id`.
3. Group by identity (verified ASN group), not by node or by sample:
   each identity contributes one value per destination, provider ASN,
   vantage, and time bucket (its median), so a member that probes more
   often does not count more.
4. Combine identities with robust statistics (median and spread) and
   discard outliers (proposed: median absolute deviation), weighted by
   reputation (see Lying). Unverified identities are shown but carry no
   weight.
5. Keep prefixes apart. A record for 198.51.100.0/22 and one for
   198.51.100.0/24 are different routes; the merged view for a local
   route shows exact matches first and covering or covered routes
   labeled as such.
6. Keep provenance: for every merged value, which identities and records
   it came from, so an operator can see why a hint fired and blocklist a
   source.

## Local use

Everything here is advisory.

- **Probe-priority hints.** A herd target source adds prefixes that
  several independent identities see degrading, only for prefixes that
  are in the local RIB view, never a default route, capped like the
  `outage` source's `max_targets`, under the global probe rate limit.
  Like every source, it spends probe budget and nothing else.
- **"My upstream or the destination."** For a local route that measures
  badly through provider A, compare with members reaching the same
  route: bad from every vantage and provider points at the destination;
  bad through provider ASN A from many vantages points at A; bad only
  here points at this edge or circuit. Shown on the API and dashboard
  and added to events as a field. Not used by Decide.
- **Outage second opinion.** When the `outage` source opens an AS or
  circuit incident, annotate it with how many independent identities
  see the same ASN degraded, or that none do. The annotation never
  opens, closes, or changes an incident or its thresholds.

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
5. Another member's word is never ground truth. A missing record, like
   a missing route at RouteViews or RIS, is not proof of anything.
6. Herd plugins run in-process only, like the federation plugin; they
   never announce.
7. CI and labs never talk to a real herd: labs run their own members
   with documentation prefixes and ASNs, and no seed is configured.

## Lying and poisoning

A member can be wrong (bad clock, broken prober, filtered ICMP) or can
lie on purpose: fake degradation to make others spend probes or blame a
provider, fake health to hide an outage, or invented AS paths. What the
code can do about it:

1. **Evidence in every record.** Raw samples with offsets, the round
   time, and the AS path. Lying then takes a consistent fake, not a
   single number, and mismatches are dropped at merge (above).
2. **Spot checks from the puller's own edge.** A member re-probes a
   small, random sample of routes that others report on, through its
   own providers, with its normal prober chain, under a capped budget
   inside the global probe rate limit. A different vantage sees
   different numbers, so a spot check compares only what should agree:
   - reachability: a route others report answering with low loss that
     never answers here or from any other identity, or the reverse;
   - same provider ASN and same country: members in one country
     through one provider ASN should be close;
   - a rough triangle check: the puller knows its RTT to the member's
     endpoint, so `|RTT(me, P) − RTT(member, P)|` far above
     `RTT(me, member)` is suspicious. Internet routing breaks the
     triangle inequality often, so this is a weak signal, never a
     verdict;
   - AS paths: adjacencies in a claimed path that the local RIB and
     public collectors have never shown.
   A spot check never moves traffic; it only feeds reputation.
3. **Reputation by agreement.** Each identity gets a weight from how
   often its records agree with spot checks and with the consensus of
   other identities over time. New identities start low and earn
   weight; disagreement lowers it; it decays without fresh agreement.
4. **Independent-ASN thresholds.** A hint, annotation, or warning needs
   agreement from a minimum number of distinct verified identities,
   preferably through more than one provider ASN. One identity alone
   never triggers anything.
5. **Outlier rejection.** Robust statistics per destination, provider
   ASN, and vantage, as in Merging.
6. **Blocklists.** The operator can block an identity (ASN group), a
   key, or an endpoint locally; blocked members are neither pulled nor
   counted. Whether the project publishes a shared blocklist is an open
   question, since it would be a central point of trust.

**Why not remote attestation.** TPM or enclave attestation can prove
which binary started, not that its inputs are honest. Packeteer is open
source and the operator controls the box: a genuine binary can still be
fed a fake prober (the `fixed` prober exists for labs, and `exec`
probers run anything), a modified kernel, or a network that delays or
drops probes on purpose. Attestation would also need vendor trust roots
and hardware most container deployments do not expose, against the
one-container rule. Herd therefore treats every member as able to lie
and relies on evidence, cross-checks, and independent agreement.

## Phased plan

Each phase starts only after Andrew approves this design, gets its own
issue and parity row (BOT.md intake), and waits its turn on the train.
No phase changes Decide.

**Phase 1: local store, serve, and pull among a few members.**
Per-round records in the storage plugin with retention (30 to 365
days); data classes and target-origin opt-ins; preview mode and the
served-response audit; the pull API with signed responses, mutual TLS
pinned to per-node keys, pagination, and rate limits; pulling from a
static list of peers with pinned keys; merged view on a read-only API
endpoint. No discovery, no RPKI identity (static peers are trusted by
pinned key), no hints. Proof: unit tests that nothing on the
never-shared list can reach a response, that preview equals the served
bytes, that retention deletes, that a tampered or replayed response is
refused; a test that decisions are identical with herd on and off for
the same local measurements; a lab with three members on documentation
prefixes and ASNs.

**Phase 2: discovery, identity, and hints.** Seeds and peer exchange,
liveness and aging, RSC identity and per-ASN grouping, the crowd
threshold for user-derived targets, reputation and spot checks, and the
three local uses (hint source, attribution, outage annotation). Proof:
lab with Sybil nodes under one ASN counting once, an eclipse attempt
held off by anchors, a hinted prefix probed and never announced without
local thresholds, and a lying member losing weight.

**Phase 3: route-visibility warnings.** The `visibility` class and
warnings from the issue: a route visible at some members and missing at
others while the provider's own space is present; an origin or AS path
that does not match the local RIB (leak or hijack hint); a more-specific
seen elsewhere that no local neighbor advertises. Events only. Optional
DHT if membership size calls for it.

## Open questions for Andrew

1. **Seeds.** Who runs the seed DNS names, under which domain, and is
   a fallback list compiled into releases acceptable?
2. **Identity.** Is RSC (RFC 9323) the required proof, with IRR or
   PeeringDB as weaker tiers, and may operators without an ASN join
   unverified with zero weight? How should the container validate RPKI?
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
11. **Shared blocklist.** Should the project publish one, knowing it
    becomes a central point of trust?
12. **Charter.** Herd sends data off the box. Should AGENTS.md gain a
    safety line for it (off by default, never-shared list, advisory
    only) when phase 1 starts?
13. **Placement.** After the v0.6 parity milestone, or interleaved?
