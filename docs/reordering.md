# Packet reordering per provider path

Packeteer measures packet reordering on each provider path (#224) beside loss, latency, and jitter. Reordering hurts TCP (spurious retransmissions, a smaller window) and real-time traffic (late packets dropped by the jitter buffer) while loss and RTT look fine, so it is a path-quality metric of its own. It is off until `probe.reorder` is set, and it never announces anything.

## How it is measured

The reordering monitor sends short trains of sequence-numbered packets from every provider's `source_ip` toward each configured responder. One train is `packets` packets `spacing` apart (default 20 packets, 20 ms). Reordering closer than `spacing` is not visible. Every packet of a train leaves the same socket, so the whole train keeps one 5-tuple and routers that hash flows onto the members of an ECMP bundle keep it on one member. A reading therefore belongs to a real path, not to packets spread across members. A train never changes its ports.

To cover a bundle, `flows` trains (default 4) are sent to each responder per measurement, each on a new socket, so the kernel picks a source port that usually differs. Results are kept per flow, and the provider's headline reading is the worst flow: the bundle member that reorders most. A `flows` of 1 is a single sample of one member.

Metrics follow RFC 4737 and are computed per train from the arrival order of the replies:

- `ratio_pct`: the reordered ratio (section 4.1) in percent. A packet is reordered when it arrives after a packet that was sent later (section 3.3). The ratio is reordered packets over received packets, so loss does not count as reordering.
- `extent`: the largest reordering extent in the train (section 4.2): how many arrival positions a reordered packet came after the first later-sent packet. A pair swap is 1.
- `n_reordering`: the largest degree of n-reordering (section 5.3): the packet arrived after n later-sent packets in a row. A pair swap is 1; a packet that arrived last after three later ones is 3.

`reordered`, `sent`, and `received` are reported too. A train with no reply is an error for that flow; a responder that answers no train is an error for the measurement.

## Responders

A responder is a host every provider can reach. The reading is only as good as the responder, so two kinds are supported:

- `twamp` (the default): a TWAMP-Light Session-Reflector (RFC 5357, unauthenticated mode) on `port` (default 862). The reflector answers each test packet at once with the sender's sequence number inside, so the order the replies come back in is the order the round trip (forward and return path) delivered them, and the reading is a measurement. Packeteer ships `packeteer-reflector`, a small standalone binary that is also in the container image (`docker run --rm --network host --entrypoint packeteer-reflector ghcr.io/grandarcher/packeteer`). Run it on a host you control that is reachable through every provider, for example a server in another network you operate, or on a herd peer whose operator runs it for you. It reads only test packets, sends only replies, and holds no Packeteer config or credentials. `lab/twamp-interop.sh` checks it against nokia/twampy, an independent TWAMP-Light sender. The reflector answers any source with a reply of at least 41 bytes, about three times a minimal 14-byte test packet, so firewall it to the controller's probe source addresses.
- `icmp`: any host that answers echo requests. The train is ICMP echo with sequence numbers. Routers and servers rate-limit and deprioritize ICMP and may answer out of order themselves, so an icmp reading is an **estimate**: it is shown with that label on the API, the metrics (`estimate="true"`), and the Providers page, and it is never an input to a decision. ICMP has no ports, so an icmp responder gets one train per measurement.

Every train waits on `probe.rate_limit_pps` and `probe.per_asn_pps` like any other probe, and a responder inside `probe.exclude` gets no packet.

## Where the reading goes

- `GET /api/reorder`: every provider and responder with the worst flow and each flow ([API.md](API.md)).
- `GET /api/providers`: each provider's headline `reorder` reading (its controlled responders' worst flow; only with no controlled responder the worst estimate, marked `estimate: true`).
- `GET /api/decisions`: every candidate carries `reorder_pct`, the provider path's controlled reading, zero without one.
- `/metrics`: `packeteer_reorder_success` per provider and responder, and `packeteer_reorder_ratio` (0 to 1), `packeteer_reorder_extent`, and `packeteer_reorder_n` per flow, each with `provider`, `responder`, `type`, `estimate`, and `flow` labels.
- The Providers page shows the headline reading in a Reordering column, with an `est.` badge on an estimate.

## Scoring

By default reordering changes no decision: `reorder_weight` is 0 on the `weighted`, `commit`, and `cost` scorers. With `reorder_weight: W`, a provider path's controlled reordered ratio adds `W` points per percent to every candidate on that provider, the way `jitter_weight` adds points per millisecond of jitter. Only a fresh twamp reading counts, the worst flow across the provider's twamp responders; a reading older than the probe staleness window ([CONFIG.md](CONFIG.md#probe)) is dropped, and an estimate is never scored. Everything else is unchanged: the learned-RIB check, allowlist, thresholds, `confirm_rounds`, hold time, cap, community, NO_EXPORT, and withdraw rules.

## Reading the numbers

The ratio depends on the train: a tighter `spacing` sees finer reordering, a longer train averages more. Compare providers with the same settings. A ratio near 0 on every flow is a clean path. One flow far above the others is one bundle member; the per-flow rows on `/api/reorder` show which. A path that reorders on every flow is reordering before or after the bundle.

## Lab

`lab/e2e-reorder.sh` runs two provider paths to the shipped reflector in Docker, with a 2-way ECMP bundle on one of them and a `netem` qdisc that sends every fifth packet ahead of the previous one on one member ([lab/README.md](../lab/README.md)). The clean path reads 0 on every flow, the bad member reads a reordered ratio near 20% with extent 1, and another flow of the same provider finds the clean member. Lab-proven only, not on a public edge.

## Rollback

Remove the `probe.reorder` block and restart; set `reorder_weight` back to 0 (or omit it) and restart to take reordering out of the score (a reload refuses a scorer change). Nothing is announced by this feature, so there is nothing to withdraw.
