# Herd (phase 1)

Herd (#260, [design](design/herd.md)) lets a few operators share what their probes measure. Each member stores its own per-round records, serves them signed over mutual TLS pinned to per-node keys, and pulls the records of its static peers. It is off by default. It is advisory: no herd data is read by `Decide`, a scorer, a policy, or the announcer, and herd never announces. If herd fails, is out of budget, or panics, probing and BGP run as if it were off.

Not in phase 1: peer discovery, RPKI identity, the crowd threshold, probe hints, and route-visibility warnings.

## What leaves the box

One record is one probe round through one provider toward one origin ASN (default) or one learned route (`granularity: route`): the time, the number of packets sent, each reply's RTT, loss, RTT min, average, max and jitter, the country you declared, the method (`icmp`, `tcp`, or `udp`), the origin ASN, and your provider's ASN. `paths` also adds AS paths. Nothing else is in a record: no provider names, probed host addresses, SNMP or usage data, config, or free text.

A route is shared only when all of these hold; the checks run before a record is stored and again each time one is served, so a new exclude entry also covers data stored earlier:

- the exact prefix is in the RIB view and a path through that provider was learned (nothing is served while no BGP session is up);
- it is not a default route or private, loopback, link-local, or multicast space;
- no `exclude.prefixes` entry is equal to, inside, or covering it, and no `exclude.asns` entry is its origin or anywhere in its AS path;
- it is not equal to, inside, or covering your own or your customers' prefixes (`inbound.prefixes`, the `flow` source's `transit.customers` and `problems.local`, the `span` source's `local`);
- a target source of a type in `share.sources` listed it (default `static`, `vip`, `outage`).

At origin-ASN level the routes of one origin are pooled into a record that names no prefix; a pooled record is dropped whole if any route behind it now fails a check. A prefix query matches nothing at that level.

## Pull API

`GET /herd/v1/status` and `GET /herd/v1/records` on `herd.listen`, TLS 1.3 with a client certificate. Both sides pin the other's Ed25519 key (`herd.peers[].key`); an unpinned client is refused in the handshake, before any request is read. Each response is one JSON document with a `signature` over its canonical form and a `generated_at`. A `records` response also echoes the query with the puller's `nonce`, so a reply cannot be replayed as the answer to another request; the status document carries no query and takes no parameter. A puller refuses a response with a bad signature, one signed by another member, or a `records` response that does not echo the nonce and query it sent; drops invalid records (statistics that do not match the samples, impossible values, wrong schema) and records dated after `generated_at`; and keeps the rest as ages against `generated_at` on its own clock.

`records` takes `origin_asn`, `prefix` with `match=exact|covering|covered` (route level only), `provider_asn`, `from`, `to`, `limit`, `cursor`, and `nonce`. Unknown or repeated parameters are `400`. With `discovery: query_only` a request must name an `origin_asn` or a `prefix`. Pages are ordered by prefix, provider ASN, time, member, id, and end with `next_cursor` when more remain. Pulled data is kept for this node only and is never served on.

## Limits

Every limit is enforced by the node it protects (see `herd.limits` in [CONFIG.md](CONFIG.md#herd)): per-identity, per-address and global request rates (`429` with `Retry-After`; covering and covered queries cost up to 4 exact ones), connection and handshake caps, a request byte cap and strict parser, read, write, idle and handshake timeouts, page and response byte caps; when pulling, concurrent pulls, a per-interval and per-peer request budget, a response size cap enforced while reading, records per response, per pull and per peer, exponential backoff with jitter after a failure or `429`, and a disk budget for local and for pulled records. A full hand-off queue drops the round and counts it; the probe loop never waits. A trimmed disk budget deletes the oldest pulled rows first. Each trip is counted by limit and peer in `GET /api/herd` and `packeteer_herd_limit_trips_total`.

## Looking at it

- `GET /api/herd`: this node's key, peers and their last error, trips, queue, and store against budgets.
- `GET /api/herd/preview` (admin): the exact signed bytes a puller would get, for any query, from the same code the pull API runs. `preview_only: true` keeps this and turns serving and pulling off.
- `GET /api/herd/vantages?origin_asn=64510`: your records and each peer's, one row group per member, country, provider ASN, and method. They are never merged into one number.
- Every served `records` response is written to the audit log (`GET /api/audit`) as `herd.serve` with the puller's key id, the query, and the record count.
- `herd.restarted` (see [EVENTS.md](EVENTS.md)) fires when a herd goroutine panics and restarts.

## Lab

`lab/e2e-herd.sh` runs three members (FRR edge plus Packeteer each) on documentation prefixes and ASNs with generated keys. See [lab/README.md](../lab/README.md). Labs never talk to a real herd and no seed is configured.
