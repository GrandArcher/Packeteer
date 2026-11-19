# Herd

Herd (#260, [design](design/herd.md)) lets a few operators share what their probes measure. Each member stores its own per-round records, serves them signed over mutual TLS pinned to per-node keys, and pulls the records of its peers. It is off by default. It is advisory: no herd data is read by `Decide`, a scorer, a policy, or the announcer, and herd never announces. If herd fails at startup (listen address taken, key file unreadable), the controller does not start. Once running, if herd fails, is out of budget, or panics, probing and BGP run as if it were off.

Peers come from `herd.peers`, a hub list ([herd-hub.md](herd-hub.md)), and peer exchange with the hub peers (#672).

Not built: route-visibility warnings (phase 3), a public hub repository, a DHT, local blocklists and weights, the "my upstream or the destination" attribution and the outage annotation, and the IXP vantage kind (proposals in the [design](design/herd.md), #87).

## What leaves the box

One record is one probe round through one provider toward one origin ASN (default) or one learned route (`granularity: route`): the time, the number of packets sent, each reply's RTT, loss, RTT min, average, max and jitter, the country you declared, the method (`icmp`, `tcp`, or `udp`), the origin ASN, and your provider's ASN. `paths` also adds AS paths. Nothing else is in a record: no provider names, probed host addresses, SNMP or usage data, config, or free text.

A route is shared only when all of these hold; the checks run before a record is stored and again each time one is served, so a new exclude entry also covers data stored earlier:

- the exact prefix is in the RIB view and a path through that provider was learned (nothing is served while no BGP session is up);
- it is not a default route or private, loopback, link-local, or multicast space;
- no `exclude.prefixes` entry is equal to, inside, or covering it, and no `exclude.asns` entry is its origin or anywhere in its AS path;
- it is not equal to, inside, or covering your own or your customers' prefixes (`inbound.prefixes`, the `flow` source's `transit.customers` and `problems.local`, the `span` source's `local`);
- a target source of a type in `share.sources` listed it (default `static`, `vip`, `outage`);
- at route level, when only `flow` or `span` listed it, at least `share.crowd_k` (default 2) other verified ASNs already serve records for exactly that route, as this node's own pulls show (the crowd threshold, #672). Their users' traffic named the route, so it stays private until a crowd measures it too. Without `herd.identity` nobody is verified, so the config refuses `flow` or `span` at route level without it.

At origin-ASN level the routes of one origin are pooled into a record that names no prefix; a pooled record is dropped whole if any route behind it now fails a check. A prefix query matches nothing at that level.

## Pull API

`GET /herd/v1/status`, `GET /herd/v1/records`, and, with a hub, `GET /herd/v1/peers` on `herd.listen`, TLS 1.3 with a client certificate. Both sides pin the other's Ed25519 key (`herd.peers[].key`); an unpinned client is refused in the handshake, before any request is read. Each response is one JSON document with a `signature` over its canonical form and a `generated_at`. A `records` response also echoes the query with the puller's `nonce`, so a reply cannot be replayed as the answer to another request; the status document carries no query and takes no parameter. A puller refuses a response with a bad signature, one signed by another member, or a `records` response that does not echo the nonce and query it sent; drops invalid records (statistics that do not match the samples, impossible values, wrong schema) and records dated after `generated_at`; and keeps the rest as ages against `generated_at` on its own clock.

`records` takes `origin_asn`, `prefix` with `match=exact|covering|covered` (route level only), `provider_asn`, `from`, `to`, `limit`, `cursor`, and `nonce`. Unknown or repeated parameters are `400`. With `discovery: query_only` a request must name an `origin_asn` or a `prefix`. Pages are ordered by prefix, provider ASN, time, member, id, and end with `next_cursor` when more remain. Pulled data is kept for this node only and is never served on.

## Peer exchange

With `herd.hub` set, a node also reads `GET /herd/v1/peers` from each peer it pulls (#672).

- The peer list is signed by the relayer and holds the hub entries ([herd-hub.md](herd-hub.md)) of the hub and exchange peers it pulled within the last three pull intervals, each exactly as its own node signed it, with how long ago the relayer reached it; a relayer can withhold an entry but not alter one. A list of more than 64 entries is refused whole.
- Each entry is checked like a hub entry: strict fields, at most 16 KiB, unexpired, signed by one of its own node keys. A tampered, expired, or oversized entry is refused and counted (`relay_refused` on the peer in `GET /api/herd`, `exchange_refused` in the limit trips, a log line with the reason); a peer list that cannot be read is `exchange_error` on the peer and the `exchange_failed` trip, and the peer is still pulled.
- One entry per ASN is kept; a newer one counts only when a key of the kept entry signed it, and an ASN the hub pinned to other keys is refused. This node's own entry and its static and hub peers are never learned again. For an ASN the hub does not pin, the first entry relayed is kept, and an entry signed by another key replaces it only when that one is verified and the kept one is not.
- At most `hub.exchange_peers` (default 16) members are learned; past that the `exchange_peers` trip counts. A learned member is pulled like a hub peer (source `exchange`), and its keys may connect to the pull API. It is dropped when its entry expires or no relayer has reached it for six pull intervals (the relayer's age counts), so a silent member ages out.

An exchanged entry is trusted like a hub entry, not more: it is a claim of its ASN, and its keys may read what you share. A relayer can introduce any signed entry; verification below decides whether it counts.

## Identity

`herd.identity.url` names the RPKI stand-in a node reads (#672): a document (schema `packeteer-herd-rsc/1`) of validated RPKI Signed Checklists (RFC 9323), each with the ASNs of its resources, the SHA-256 digests it signs, and `not_after`. A member is verified when a checklist that is still valid lists its ASN and the key id of its node key (the SHA-256 of the public key, as `key_id` in `GET /api/herd`). The node fetches it at start and every `refresh` (default 1h), keeps the last good document when a fetch fails, and verifies nobody before the first success. The document is only as trusted as its https source: this build does not validate RPKI objects itself, and no relying party publishes this document yet, so in the lab it is a stand-in (`lab/herdhub`). The `identity` references in hub entries are still carried, not checked.

Verification decides what counts, not what is shown. One identity is one ASN: counts take each verified ASN once, however many nodes or vantages it has. With `herd.identity` set, an unverified member is still pulled and listed with its rows marked; it is left out of the world view counts (`basis: rpki`, `counted: false` on its rows), the hint counts, and the crowd threshold. Without `herd.identity` nobody is verified: the world view and the hints count pinned peers, once per ASN, as before (`basis: pinned_key`), and nobody counts toward the crowd threshold. Verification is read from the identity source each time, so a member whose checklist expires stops counting at once, and within one pull interval for the crowd threshold. `GET /api/herd` shows `verified` for this node and each peer, and the identity source's state.

## Hints

A target source of type `herd_hints` ([CONFIG.md](CONFIG.md#source-herd_hints)) probes the routes other members see degraded now (#672). Every pull interval, on herd's own goroutine, the node takes the world view (loss at or above 5 % in the last 15 minutes), counts the other members that count and see loss, once per ASN, and maps each target to routes in its own RIB view: a route target to that exact prefix, an origin target to the learned routes of that origin. Default routes and never-shared space are left out. The source returns the routes seen by at least `min_vantages` members, at most `max_targets`, and the probe engine measures them under its usual rate limits. `GET /api/herd` lists the current `hints`.

A hint only adds a probe target. Records of a route probed only for a hint are not stored or shared (`herd_hints` is not a `share.sources` type), and any improvement still comes from this node's own measurements passing the normal thresholds, hold time, allowlist, and cap. No herd data enters `Decide`.

## Limits

Every limit is enforced by the node it protects (see `herd.limits` in [CONFIG.md](CONFIG.md#herd)): per-identity, per-address and global request rates (`429` with `Retry-After`; covering and covered queries cost up to 4 exact ones), connection and handshake caps, a request byte cap and strict parser, read, write, idle and handshake timeouts, page and response byte caps; when pulling, concurrent pulls, a per-interval and per-peer request budget, a response size cap enforced while reading, records per response, per pull and per peer, exponential backoff with jitter after a failure or `429`, and a disk budget for local and for pulled records. A full hand-off queue drops the round and counts it; the probe loop never waits. A trimmed disk budget deletes the oldest pulled rows first. The per-address table holds 4096 addresses; when it is full the least recently seen one is dropped, an address with a pinned handshake last, so many source addresses cannot refuse a pinned peer (#506). Each trip is counted by limit and peer in `GET /api/herd` and `packeteer_herd_limit_trips_total`.

## Looking at it

- `GET /api/herd`: this node's key, peers and their last error, trips, queue, and store against budgets.
- `GET /api/herd/preview` (admin): the exact signed bytes a puller would get, for any query, from the same code the pull API runs. `preview_only: true` keeps this and turns serving and pulling off.
- `GET /api/herd/vantages?origin_asn=64510`: your records and each peer's, one row group per member, country, provider ASN, and method. They are never merged into one number.
- Every served `records` response is written to the audit log (`GET /api/audit`) as `herd.serve` with the puller's key id, the query, and the record count.
- `herd.restarted` (see [EVENTS.md](EVENTS.md)) fires when a herd goroutine panics and restarts.

## Dashboard

`/herd.html` (#296) reads the same records and shows them in six views. It only reads: nothing on it feeds `Decide`, a scorer, a planner, or the announcer, and it announces and withdraws nothing. When herd is off the page says so. Every view keeps each vantage's own numbers; nothing is merged. A vantage is one member key, country, provider ASN, and method, so two nodes of one ASN are two vantages; the world view counts them once per ASN.

- **Members**: this node and each peer, with its source (`config`, `hub`, `snapshot`, or `exchange`), identity, sharing status, freshness, and last pull. `verified` is `yes` only for a member the identity source verified.
- **World view** (`/api/herd/events`): targets where a member sees loss at or above a threshold now. "3 of 4 members" counts members, one per ASN, however many nodes or records they have: verified members with `herd.identity` (`basis: rpki`), pinned peers without it (`basis: pinned_key`). An unverified member's row is listed as not counted. Origin-ASN targets and route targets are listed apart, and each event lists every vantage's row. It is not limited to routes in your RIB: the records come from what members shared.
- **Mesh**: vantages against targets, each cell one vantage's latest round.
- **Map**: vantages by the country each member declares, with the condition in words. No finer location exists.
- **Monitors**: per-vantage latency over time for one target, the AS paths each vantage saw (only for members that share the `paths` class), and the per-vantage records.
- **Search**: by prefix, origin ASN, provider ASN, or member, across your retention. A view reads at most 5000 rows, search lists at most 100 targets, and the page says when either was cut.

Outside intelligence is a separate panel, opt-in per source under `herd.outside` ([CONFIG.md](CONFIG.md#herd)): public RIPE Atlas results and the status of your hosted probes (`atlas`), routes of your AS that RIPE RIS Live reported outside it through `leak_watch` (`ris`), the origin validation of a route from `rpki`, and the `linkouts` sites (RIPEstat, Cloudflare Radar, and the rest) for the chosen prefix or ASN (`links`). Each item names its source and age. Outside items are never counted as vantages and are not mixed into any herd view. Atlas is read with no API key, at most 4 measurements and 4 probes per refresh (15 minutes or longer), one request at a time, and its addresses are not shown. With all of them off the page shows herd data only. Not included: Atlas credits and your own measurements, which are on the prefix page ([atlas.md](atlas.md), #213), IRR checks (#214), and RouteViews or bgp.tools data beyond their link-outs.

## Lab

`lab/e2e-herd.sh` runs three members (FRR edge plus Packeteer each, one AS each) on documentation prefixes and ASNs with generated keys (#659, #672). A local hub (`lab/herdhub`) lists only a seed node it also runs, plus a tampered and an expired entry every member refuses; the members find each other by peer exchange from the seed's peer list and refuse the tampered, expired, and oversized entries in it. The hub also serves the RPKI stand-in, which verifies two members and leaves the third shown and not counted. The run checks the hints, the crowd threshold, and the world view, mesh, map, monitors, and search on `/herd.html`. It is not a public hub repository, and labs never talk to a real herd. See [lab/README.md](../lab/README.md).
