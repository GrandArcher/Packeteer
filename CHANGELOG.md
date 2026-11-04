# Changelog

All notable changes to Packeteer are documented here. Versions are Git tags on `main`. The image tags `ghcr.io/grandarcher/packeteer:<version>` (for example `:0.9.0`) and `:latest` are published from each `v<version>` tag. `:edge` tracks `main`.

## [Unreleased]

### Changed

- Prober memory evicts in one sort-based pass instead of a scan per host; sub-range jobs stop after two silent hosts of a down provider; job order uses the reloaded interval (#507).
- Audit hygiene: ENV.md and threat model gaps, release pins in quickstart, Compose and install.sh, ASCII gate on source, documentation test data, errcheck on, image and action pins (#494).
### Security

- The config editor refuses a new `*_env` name outside its plugin's prefix (`PACKETEER_SNMP_*`, ...); `influxdb` and a feed with a token need https, http only to loopback (#504).
- Flow decoder: IPFIX templates check their length before allocating, a bad template set ends the datagram, and sampling rates go with their last template; v9/IPFIX fuzz tests (#502).
- A RIS Live leak sighting withdraws or holds only an injected prefix with the local ASN next to the RIS peer, else emits `leak.unconfirmed`; large communities are read from RIS (#505).
- The config editor refuses any `upgrade.*` change and checks exec/grpc plugins against the running config after a reload, not the start-time one (#501).
- `packeteer-policy` requires https (http only to loopback) and `-community`, checks each route (NO_EXPORT, communities, `-allow`); GR off in the examples; feed token backoff, connection cap (#488).
- Webhook/`otlp` `${VAR}` expand only `PACKETEER_WEBHOOK_*`/`PACKETEER_OTLP_*`; webhook, exporter, feed, RPKI, OIDC, RIS Live, agent refuse cross-host redirects (RDAP: https, Accept only) (#489).
- First-run admin password is no longer logged, only its 0600 file; troubleshoot POSTs need auth; OIDC requires `email_verified: true` with the email claim (#489).
- SSO sessions mint tokens of at most 7 days; federation peers can pin a `domain` and implausible peer measurements are dropped; the federation listener has a read timeout (#508).
- `upgrade/apply` refuses an older version (use rollback); the probe-agent hub refuses a CRL with a lower Number; a delayed probe re-checks the agent's site (#508).
- RTR and VRP JSON: max length is range-checked, VRP JSON is stream-decoded under the `MaxVRPs` cap; IX-F peering LANs need at least /16 (v4) or /48 (v6) (#508).
- `packeteer-reflector -allow-from` limits who is answered; the SNMPv3 agent enforces the RFC 3414 150 s time window and answers with a notInTimeWindow Report (#508).

### Upgrade notes

- Use an `https` `url` for `influxdb` and for an `http` threat feed with `token_env` (http only to loopback); in the editor, name new secrets with the prefixes in docs/ENV.md (#504).
- `packeteer-policy` exits with code 2 without `-community` (your `packeteer_community`) or with a non-loopback `http` `-url`; add `-community`, and `-allow` with your allowlist (#488).
- Rename webhook/`otlp` variables to `PACKETEER_WEBHOOK_*`/`PACKETEER_OTLP_*` (others fail at start); use final URLs; OIDC without `email_verified`: `username_claim: sub` (#489).
- Remove `0.0.0.0/0` or `::/0` from `allowlist.prefixes`; a config with one no longer loads (#486).
- An IX-F export with a peering LAN wider than /16 (v4) or /48 (v6) is now refused; `upgrade/apply` to an older tag returns 400, use rollback (#508).
- On an iBGP-only RIB view a mitigation route is now off the wire briefly every `mitigation.hide_window` (5m); raise it to keep the route on the wire longer (#487).

### Changed

- `allowlist.prefixes` rejects `0.0.0.0/0` and `::/0` (a config with one no longer loads) and logs a warning for an entry shorter than /8 (#486).

### Fixed

- A performance switch off a commit or cost steer passes `interface_capacity_threshold_pct`, `flap_quarantine` and the MED tie break like any performance switch (#503).
- A mitigation route whose prefix is missing from a ready RIB for `mitigation.hide_window` (default 5m) is withdrawn; the rule waits for the prefix (#487).
- `docs/precedence.md` documents the shipped external policy feed instead of "Not built" (#487).
- A mitigation rule waits until an inbound steer on its prefix is withdrawn, so the steer's withdraw cannot remove the mitigation route (#486).
- Outbound `WithdrawAll` removes only outbound routes, by UUID; inbound steer and mitigation routes stay with their controllers (#486).
- The outbound allowlist is checked before the unchanged-route shortcut, so a reload that shrinks it withdraws an unchanged improvement (#486).
- Scorer weights, `balance_slack` and `min_mbps` reject NaN and Inf (#509).
- The traceroute source ends a trace only on a datagram from the target; the ICMP error parser and the SNMP secret check (no CR, LF or NUL, at most 255) are shared (#509).
- An RPSL attribute is joined in linear time and capped at 64 KB; a stopped flow source frees its watcher goroutine (#509).
- Report reads wait only for a flush's store write, not its provider series, rounds or volume lookup; subscription emails carry up to 10000 rows and say "N of M" when cut (#509).
- Static pins count as `static` in the summary, causes and performance reports (new `static` CSV column: before `total` in causes, before `active` in summary) (#509).
- The commit planner is not offered a synthesized sub-range; replay pages lose no round within 1 ms; the PeeringDB IX-F import keeps `operational` (#509).

## [0.9.0] - 2026-11-02

Lab-proven additions for evidence, explanations, registries, exporters, and plugins: RPKI and IRR per provider path, decision explanations, an SNMP agent, gRPC plugins, probe agents, an external policy feed, BMP alone, and a refreshed UI, none field-proven (#54).

### Added

- BMP alone as the RIB view: no `bgp.neighbors`, ready only while a BMP feed reports a peer, withdraw on feed loss; BMP peer metrics, interop cell `bmponly`, and a `bmp` load profile (#237).
- Docker lab job for probe agents: controller and two `packeteer-agent` containers at two sites; checks per-site attribution, a killed agent failing closed, and a revoked certificate (#478).
- External policy feed (`external_policy`): inject routes over TLS with a token, JSON and gRPC, with a TTL; `packeteer-policy` applies them to BIRD (lab-tested), OpenBGPD or ExaBGP (#232).
- Distributed probe agents: `packeteer-agent` probes from provider sites over mutual TLS with revocation; `providers[].site` and an `agent` prober; a lost agent fails its provider closed (#230).
- Optional eBPF data path: `span` `ebpf: true` captures through a ring buffer and a `flow` `ebpf` block counts every packet unsampled; both fall back when unsupported (#229).
- Report subscriptions: a `timeseries` email carries the before/after loss and latency charts as inline PNGs drawn in the controller, with the CSV still attached (#136).
- GeoIP country database: docs/geoip.md and an opt-in `geoip` download (URL, account in env vars, refresh); the Overview checklist flags an unreadable database or failing download (#135).
- Threat-intelligence feed ingest (`threat_feeds`, `http` feed): listed networks become mitigation rules only for explicit rules, through mitigation, capped; lab-proven (#134).
- The `flow` `problems` block now scores sampled NetFlow/IPFIX and sFlow on inbound RST, with rate-weighted `min_flows` and a 10-sample floor (#133).
- Registry hygiene: a read-only scan finds stale or missing IRR, RPKI, as-set, and PeeringDB records with the exact fix; an admin-confirmed push for RIPE and PeeringDB, off by default (#289).
- Providers, next hops, and communities read from NetBox or Peering Manager (`inventory`), with `packeteer config plan`, `diff`, and `apply -plan ID [-git]` and an audit entry; lab-checked (#208).
- Opt-in read-only SNMP agent (`snmpagent` exporter, v2c and v3) with a published MIB, SNMP informs, and a `syslog` (RFC 5424) notifier; lab-checked with snmpwalk and snmptrapd (#212).
- Opt-in `realtable3m` lab profile: a real RIS/RouteViews table on three sessions grown to 3M prefixes, probed by a new `sim` prober (seeded model, no packets, labeled simulated) (#103).
- Plugin author guide (`docs/PLUGIN_AUTHORING.md`), tested exec and Go skeletons in `examples/plugins`, and a community plugin list checked by a test (#288).
- `grpc` plugin type: long-running prober, source, and notifier programs over gRPC (go-plugin) with health checks, restart with backoff, and a clean stop; never an announcer; example plugin (#286).
- `influxdb` exporter, OTLP logs and metrics, and an opt-in `metrics` export stream of the `/metrics` series every 30 s; tested against InfluxDB 2 and an OTel collector (#287).
- Opt-in `exporters` (Kafka, NATS, OTLP spans, IPFIX) push events, decisions, and flows tagged with provider and improvement ID; Grafana dashboards; tested against sink containers (#207).
- Provider scorecard report: loss, RTT, jitter p50/p95 per provider and destination ASN, flow-weighted, ranked by loss then RTT; API, CSV, UI, works in observe (#209).
- Replay history: `packeteer whatif`, `POST /api/whatif`, and a Settings panel decide stored rounds again under new settings, read-only; needs `storage.round_retention` (#204).
- Opt-in `synthesize`, lab only: announce a measured sub-range NOT in the learned RIB inside a learned covering prefix, under rails, a marker community, the route cap, and warnings (#122).
- Blast-radius preview: `GET /api/blast`, a Settings panel, and a dry-run token gating online changes that can alter announcements; SIGHUP logs add/move/withdraw counts and warning codes (#227).
- Internet VRF and partial-table providers: FRR lab steers and withdraws inside a VRF with no full-table transit; a learned default route is never steered or announced; docs/vrf.md (#206).
- MED: an inbound `med` action steers between links to one transit; a neighbor's MED breaks ties between its exits within `thresholds.med_margin`, and overrides are shown and evented (#303).
- Opt-in `interface_capacity_threshold_pct` per provider: a performance steer that would overload a provider's interface is refused and steers already there are shed, with or without a commit (#307).
- Opt-in steer verification: counters show an announced outbound or inbound steer verified, partial, or not moved (API, UI, events); an unmoved inbound steer is reverted and backed off (#305).
- Opt-in RIPE Atlas ping/traceroute of a prefix's test address with your own key, on demand and after a move; credit and hourly caps; results, own probe and balance shown, display only (#213).
- `https` prober: GET or HEAD over TLS timed as connect, handshake, and first byte, status assertion counts as loss, per-target `insecure_skip_verify`, timings on `/api/probes` (#306).
- Packet reordering per provider path (RFC 4737) from TWAMP-Light trains to the shipped `packeteer-reflector`, or ICMP estimates: `probe.reorder`, `/api/reorder`, metrics, UI, `reorder_weight` (#224).
- `probe.exclude` (prefixes and origin ASNs no source probes), `probe.per_asn_pps` (probe and trace packet cap per destination ASN), and the `probe_asns` report (#203).
- Confidence on every probe sample and decision candidate (prober type, replies, hop, spread, passive agreement); opt-in `thresholds.require_evidence` refuses an ICMP-only performance move (#202).
- Every decision lists its checks in order with value, limit, blocking gate, and a counterfactual: `GET /api/decisions/<prefix>`, a Why? panel on the prefix page, stored with each improvement (#201).
- Opt-in IRR origin check per provider path beside RPKI: `whois` (IRRd or RIPE style) and `file` (RPSL, bgpq4) sources, cache, as-set and aut-num lookups, `prefer_registered` (#214).
- Herd page (`/herd.html`): members, world view, mesh, country map, latency and AS path monitors, search, and opt-in outside sources (Atlas, RIS Live, RPKI, link-outs), display only (#296).
- Docs: adopting.md maps common route-optimizer concepts to config with an observe-first cut-over plan; roi.md is a worksheet for cost, commit relief, and gain (#205).
- Opt-in `ring_lg` panel "Seen from NLNOG RING" on the prefix page: public looking-glass API, rate capped, cached, best-effort, off by default (#283).
- RPKI per provider path: `rtr` over TLS/SSH, `json` (Routinator, rpki-client), source and data age shown, per-path history, display-only RIPEstat fallback, `rpki.stale` events, metrics (#200).
- Onboarding: install.sh starts observe; Settings runs blocking preflight checks with a fix each and metrics; guided inject step; -snippet router config for six vendors; -pbr linux -apply (#221).
- Opt-in lab replay of a real RIPE RIS or RouteViews table (`lab/realtable.sh`, manual workflow), observe only, 1-4 sessions; the dump is never committed and logs hold counts only (#342).
- Providers show latency, loss, jitter (15 min, 24 h), a trend and Mbps; Overview leads with latency and improvement charts and drops the Mode tile (#349).
- Multi-session inject soak: 2-4 routers x 1M routes, flaps, a slow peer, outage and vip on; reports withdraw latency, lock wait (`packeteer_go_mutex_wait_seconds_total`), loop gaps (#383).
- Soak table follows a real full table's shape (lengths, AS path, communities, MED, attribute sets) from a counts-only RIS file, documentation space only (#341).
- Improvements explain each move in a plain sentence and show latency, loss, gain, Mbps, ASN, AS name and hold time (#348).
- First run with only the example providers opens the setup wizard with no config edit; a real config keeps the editor off, and settings push needs an explicit `http.config_editor: true` (#416).
- Plain language in the UI: BGP Active reads "Connecting (Active)" in amber, plain labels with the config key as tooltip, title-case report names, no API footer on Overview (#351).
- Forms no longer show grey examples as values: examples move to help text, defaults read "Default: X", Reports filters start empty, wizard starts from running config and takes ASN, type, IPv6 (#350).
- UI on phones: below 760 px the nav collapses behind a Menu button and table rows become labelled cards, health first; a 390x844 browser smoke step checks it (#352).
- Federation: admins push `thresholds` or `policies` to every peer over mTLS (`POST /api/federation/push`); peers validate, apply online, refuse other sections, and audit (#137).
- UI keyboard and screen reader access: Skip to content link on every page, 3 px focus ring, one h1 per page, labelled YAML editor; a browser smoke step checks them (#353).
- Multi-POP: lab phase and unit test for a cut federation link (stale peer pruned after `max_age`, no steer or flapping, clean re-sync); behavior documented in docs/multi-pop.md (#308).

### Changed

- The `icmp` prober sends each run as one train at `packet_interval` without waiting for each reply; a reply counts until `timeout` after the last send (#224).
- Dependencies: grpc 1.85.0, golang.org/x/net 0.62.0, gosnmp 1.47.0, modernc.org/sqlite 1.61.0, actions/setup-node 7 (#439, #440, #471, #472, #473).

### Fixed

- docs/atlas.md says which addresses Atlas refuses and when (#446).
- A history test no longer depends on the wall clock (#444).
- `ixp` with `rib_sources` and no `bgp.neighbors` is refused (#482).
- Why panel: a commit or cost steer kept while a performance switch confirms no longer says the planner decided the thresholds or that the cap was not reached for lack of a better path (#448).
- `POST /api/atlas/measure` answers the documented 404 when Atlas is off even with API writes disabled, not 403 (#447).
- install.sh waits for the first admin after /healthz so a follow-on API call is not 401 (HTTP listens before bootstrap, #328; unblocks onboarding lab #221).
- gobgp announcer: a provider move replaces the route in one UPDATE (make-before-break), so the edge sees no withdraw gap and a failed announce keeps the old route; lab `lab/e2e-move.sh` (#386).
- API server sets a write timeout (150 s) so a stalled client cannot hold a connection; Decide no longer rescans all results per prefix (45 s to 0.4 s at 100k x 4); benchmarks added (#387).
- Flow: readers decode and queue records for `workers` (default 4) counting goroutines, so a window stall no longer overflows the socket buffer; a full queue is counted (`limit="workers"`) (#385).
- SNMP: hosts are polled by a bounded pool (`workers`, default 4, max 16), so one slow or unreachable host no longer delays the rest (#384).
- Herd stats and trimming read per-member counters kept by triggers (`herd_stats`) instead of scanning the herd table on the shared sqlite connection (#393).
- RIB: full-table reads (routes, search, next-hop counts) use a sorted snapshot and work in short lock runs, so a UI or API read no longer delays BGP updates (#382).
- Probe: a down provider no longer starves the others; a timed-out round stores finished results, and no performance move is made until one round measures every provider (#381).

### Upgrade notes

- No config key was removed or renamed since 0.8.0, and the shipped default stays `mode: observe`; run `-check` on the new image first.
- Off until you add the block: `synthesize`, `verify`, `atlas`, `ring_lg`, `exporters`, `threat_feeds`, `inventory`, `registry`, `external_policy`, `irr`, `geoip`, `probe.reorder`, `agent` prober.
- `thresholds.med_tie_break` is on by default (`med_margin` 20): a neighbor's MED can break ties between its exits; set `med_tie_break: false` to keep 0.8 decisions (#303).
- A configured flow `problems` block now also scores sFlow and sampled NetFlow/IPFIX, on inbound resets only (#133).
- Unset by default: `providers[]` keys `asn`, `type`, `site`, `interface_capacity_threshold_pct`, and `thresholds.require_evidence`, `probe.exclude`, `probe.per_asn_pps`; `workers` is 4 (#384, #385).
- `http.config_editor` is now unset by default instead of `false`: the editor opens only during first-run setup (all provider `source_ip` in 192.0.2.0/24); `false` still forces it off (#416).
- The `icmp` prober sends each run as one train and waits `timeout` after the last send, so a slow reply that was loss may now count (#224).
- A provider with no reply holds only its share of probe workers, and no performance move is made until a round measures every provider (#381).
- An `rpki` source is fresh by its data time, not its last fetch, so a server serving old data falls through to the next source (#200).
- New secret variables for opt-in blocks (`PACKETEER_POLICY_TOKEN`, `PACKETEER_ATLAS_API_KEY`, `PACKETEER_GEOIP_*`, `PACKETEER_RIPE_*`) are listed in docs/ENV.md.
- Some UI labels changed and Overview has no Mode tile, so scripts that read page text should use the API (#349, #351).

## [0.8.0] - 2026-10-20

Internet exchanges and shared measurements: IXP observe-only mode, RPKI labels, probe multiplexing, settings forms, the opt-in herd, and sign-in on by default.

### Added

- Herd hub: `herd.hub` fetches a public list of signed member entries as seed peers and verifies each; `herd entry` prints yours, `herd hub-check` checks a hub repo; release snapshot fallback (#261).
- Herd phase 1: opt-in `herd:` stores per-round records, serves them signed over pinned mutual TLS, and pulls static peers; `GET /api/herd`, `/api/herd/vantages`, `/api/herd/preview` (#260).
- Settings page: forms for scorer, SNMP v2c/v3 hosts, BGP, BMP, maintenance, flow extras, inbound announcer, anomaly, mitigation, plugins, HTTP; Preview diff; raw YAML under Advanced (#330).
- CI runs `go test -race ./...` on every PR as its own `race` job; `make race` runs it locally (#380).
- Multi-site IXP health: each site publishes its fabric measurements over mTLS federation; `ixp.core` measures inter-site RTT and loss; `/ixp/sites`, `GET /api/ixp/sites` (#167).
- Events: `provider.down` and `provider.degraded` from measured loss, `bgp.session_not_established`, plain headline with What to do link, Details fold; observe restart is info (#347).
- IXP member pages `/ixp/member/{asn}` (fabric by vantage, filter history, IXP Manager link), `GET /api/ixp/members/{asn}`, `packeteer_ixp_member_{rtt_ms,loss_pct,jitter_ms}` (#166).
- Overview problems headline and "N of M healthy" tile; `probe.degraded_loss_pct` and `probe.down_loss_pct` set the dashboard health labels, no decision uses them (#343).
- Route-server signals: spikes in RPKI-invalid, IRR, and transit-free-ASN filtering, new origins, more-specific bursts, and RFC 7999 blackhole counts per member; GET only (#165).
- Probe multiplexing: providers and exchange peers may share one `source_ip` with a distinct `fwmark` or `dscp`; `packeteer -pbr <format>` prints Linux and router PBR config, never applies it (#157).
- Shared IX port: `exchanges[].port` (capacity, commit, flat `port_cost`) on one telemetry binding; the commit and cost scorers plan no move past its capacity or commit (#151).
- Fabric incident correlation: fabric probes grouped by switch, colo, and bundle; `ixp.fabric_degraded` vs `ixp.member_degraded` events; `GET /api/ixp/correlation`; nothing announced (#163).
- Settings form uses guided inputs: a number and a unit, one prefix or address per row, dropdowns that stay free text when no list is known (#329).
- Route-server observability: Birdseye polls per member session (state, received, accepted, filtered, filtered-by-reason, max_prefix), in-memory history, `ixp.rs_*` alerts, GET only (#164).
- PeeringDB / IX-F lookup: read-only cached org name, exchange membership, LAN addresses, route-server flag, policy, and prefix hints; GET /api/lookup; key from PACKETEER_PEERINGDB_API_KEY (#153).
- Fabric probes: member LAN loss, RTT, and jitter from ixp.vantages; Can Ping opt-out and busy-host tolerance; nothing announced (#162).
- IX-F member import: read-only GET of the IXP Manager member export or a named IX-F URL; key from PACKETEER_IXP_MANAGER_API_KEY header only; 14-day expiry warning (#161).
- Web UI shows the Packeteer logo next to the name and as the favicon (#327).
- IXP mode: `ixp: {}` is observe-only and refuses `mode: inject`, `announcer`, `mitigation`, `inbound`, `synthesize`, and `more_specific`; no BGP neighbors or RIB view required (#160).
- RPKI origin validation: an opt-in `rpki` block reads an RTR server, labels learned paths valid/invalid/notfound/unknown, and `avoid_invalid` refuses a new steer onto an invalid path (#158).
- Probe-path check: a TTL-1 probe from each provider's `source_ip` must leave through `next_hop`; a mismatch marks it down with reason `probe path mismatch`; `path_check: false` opts out (#150).
- BMP exchange peer session monitor: `exchange.peer_up`/`peer_down` with the decoded reason (Cease subcode 1), Adj-RIB-In count as `adj_rib_in` and a metric, and `exchange.max_prefix` warnings (#147).
- Herd design: an IXP vantage kind (proposal, not implemented) and the cost answer, in docs/design/herd.md (#87).

### Changed

- Sign-in is on by default, upgrades included, so `/metrics` without a token gets 401; opt out with `auth.enabled: false` (#328).
- Build and dependencies: Docker build image golang 1.27-alpine, go-jose 4.1.6, maxminddb 2.8.0 (#355, #357, #358).

### Fixed

- A mitigation rule added mid-round waits until outbound has released its prefix, so one prefix never carries both an outbound and a mitigation route (#379).
- Peer events read the neighbor set under the RIB lock, so a reload that adds or removes a neighbor during a session change no longer races and crashes the controller (#378).
- Steer reason text (performance and cost moves) uses ASCII `->` instead of a Unicode arrow in logs, events, and the UI (#335).
- Commit setup form reads `cc_disable: True` and `percentile: Separate` as the loader does, and keeps a new provider's Track commit across a rename (#311).
- Setup wizard collapses on a configured box and, over an existing config, shows a diff and what is lost before the editor changes; auth, http, storage, other blocks are kept (#345).
- Observe and suggest: pages show "Traffic now (router)" (learned path) and "Packeteer recommends"; events read "Recommends moving X from A to B (not announced, observe mode)", not "steered" (#346).
- Settings: Save applies pending form edits first instead of reporting Saved without them, names each changed key (old -> new), and a sticky bar flags unsaved changes (#344).
- Provider health follows measurements: no reply or loss at `probe.down_loss_pct` is down, at `probe.degraded_loss_pct` degraded; "no reply" replaces 0.0 ms (#343).
- BMP exchange peer monitor: a stats report no longer marks a peer up, state is kept per router and peer, and an unknown peer-down reason reads `unknown reason N` (#338).
- Fabric probes read Can Ping from the customers document (`use` ping templates, GET /admin/api/v4/nagios/customers/{vlan}/4|6) and skip a manager export with no successful list (#162).
- RTR Serial Notify uses the client's last serial, Error Report code 2 keeps the cache and retries, and an empty RPKI source is skipped (#158).
- RTR applies a serial delta only at End of Data and ignores Serial Notify during any response; RPKI labels a provider by all its learned paths; the System row matches cache use (#158).
- The `TestPrefixCapBatchEviction` time budget is race-aware, so the CI `race` job no longer times out (#397).

### Security

- IX-F member view drops the URL query string, and fetch errors no longer include the request URL; `key_expires` and `fetched` are omitted when unset (#337).
- Fabric probes stop using a Can Ping list older than three intervals after failed fetches, so opted-out members are not pinged (#336).
- IX-F import rejects an IPv4-mapped prefix on an IPv6 LAN, a percent-encoded API key in the manager URL, and a switch id from another IXP (#161).

### Upgrade notes

- Sign-in is now on for every install, upgrades included: tokenless scrapers and API clients (`/metrics`, `/api/*`) get 401 until given a token; `auth: {enabled: false}` turns it off (#328).
- No config key was removed or renamed since 0.7.0.
- The probe-path check is on by default; opt out per provider with `path_check: false` or for all with `probe.path_check.enabled: false` (#150).
- `provider.down`, `provider.degraded`, and `bgp.session_not_established` events reach every notifier that has no `events` filter (#347, #343).
- `herd`, `ixp`, `rpki`, and `exchanges[].port` are off unless you add the block (the default stays `mode: observe`).

## [0.7.0] - 2026-10-15

### Added

- Potential-peers report: destination origin ASNs by flow bytes, present at an exchange or not, LAN path today, route server vs bilateral; `GET /api/exchanges/potential-peers`, CSV (#154).
- IX LAN health: each exchange peer's next hop is probed from its `source_ip`; reachability, RTT, loss on `/api/exchanges` and metrics; `exchange.degraded` and `exchange.recovered` events (#149).
- Transit-to-IX offload report: prefixes that leave through a transit while an exchange peer advertises them, by bytes, with the saving at the transit's cost; `GET /api/exchanges/offload`, CSV (#152).
- Exchange peers: prefixes seen only via the route server, only bilaterally, or both, counts over time, and a partial-feed flag; `GET /api/exchanges/member` (#156).
- Exchange view on Providers & Exchanges: peers, type, improvements with Mbps moved, discovered members; `exchanges` report and `volume_mbps` on improvements (#148).
- Dashboard widgets: chart widgets (improvements by cause, provider usage vs commit), grid move and resize by drag or keyboard, per-widget refresh and window, a favorite dashboard (#182).
- Commit & Cost page and `GET /api/commit`: samples, running 95th, commit, and commit moves per provider for 1, 7, 30 days; Commit setup in Settings (#174).
- Reports page: filters, sortable columns, CSV/XLSX export, and a dashboard widget (#178).
- Reports API: an unknown parameter, a filter or `sort` the report does not take, or `limit` on an uncut report is a 400 (#178).
- AS search matches an improvement recorded without an origin by its prefix's stored origin (#178).
- Top bar search and `GET /api/search`: a prefix (exact, covering, more specific), AS number, or AS name over live data and stored history; the improvements report takes `prefix` and `asn` (#172).
- System page and `GET /api/system` show state, since, and last error per component (BGP, BMP, probes, sources, announcer, storage, notifiers, telemetry, HA); Overview tile links to it (#184).
- Policies page lists maintenance windows (current, upcoming, finished) and opens or closes on-demand ones in local time; `POST /api/maintenance` takes `start`/`end` and `GET` lists the rest (#177).
- Settings form lists discovered exchange LAN members; Accept adds a draft peer with its AS and next hop, and saves, probes, and announces nothing (#155).
- Prefix, ASN, and exchange-peer pages link out to HE BGP Toolkit, RIPEstat, PeeringDB, bgp.tools, Cloudflare Radar, IRR Explorer, opt-in NLNOG RING; `linkouts` sets sites and https URLs (#211).
- Steering precedence doc and pairwise interaction tests for mitigation, inbound, outbound, shared cap, quarantine and HA handover (#235).
- Router guides give the export deny for `packeteer_community`, standard and large, on every customer, peer, and transit session for FRR, Junos, Cisco, and MikroTik, with a check per vendor (#210).

### Changed

- `internal/config/config.go` split into schema, `defaults.go`, and `validate.go` with one validate method per section; behavior unchanged (#236, part 1 of 3).
- `cmd/controller/main.go` split into per-area wiring files (surfaces, inbound, announce, probing, sources, rib, decision, maintenance); pure moves (#236, part 2 of 3).
- `internal/policy/policy.go` split into `decide.go`, `select.go`, `cap.go`, `confirm.go`, `cost.go`, `subrange.go`, and `weights.go`; pure moves (#236, part 3 of 3).

## [0.6.0] - 2026-10-13

Sixth release: gaps found in the 2026-10-07 review of prefix selection, measurement, and the UI (#113-#132, #145-#146, #170-#183), plus hardening (#217, #223, #226, #228, #233, #234, #240) and upgrade from the UI (#196). Probe targeting and qualification, switch thresholds with confirm rounds, scale limits up to multi-million path tables, flap quarantine, live apply for core, inbound and mitigation settings, a UI shell with pages per area and full settings forms, a manual probe, and a failure-mode e2e matrix across every injection surface. Lab-proven only, against simulated routers in CI with documentation prefixes and private ASNs, not on a public edge. Safety rules are unchanged: the default stays `mode: observe`, an announcement still needs the exact prefix in the learned RIB, the allowlist, the configured community and NO_EXPORT, the improvement cap, and hold time. The opt-in synthesized more-specific block (#122) is not part of this release.

### Added

- Failure-mode e2e matrix across outbound, more-specific, inbound, mitigation, and HA: six failures per surface, one CI matrix job, a broken withdraw path fails it (#234).

### Changed

- Settings form edits `exchanges` and their peers (name, LANs, bmp, group; peer AS, next hop, probe source, cost) through `POST /api/config/form`; Save runs the loader's checks (#181).
- CI lint job runs `staticcheck` and `deadcode -test`, and CHANGELOG entries are capped at 200 characters; staticcheck findings and test-only helpers are fixed or moved to tests (#240).
- Manual probe takes a hostname, shows current vs best per provider and the covering prefix, falls back to indirect hops; Probe and optimize queues that prefix for 10 minutes (#126).
- Load budgets scale per million prefixes with a `large` 5M profile; flow and span `max_prefixes` is configurable, target caps rise, and `packeteer_truncated_total` meters the caps (#217).
- Settings forms list and edit every `flow`, `vip`, `outage` source and `rules` policy with add, remove, reorder, names, flow aggregate lengths and a policy `geoip_db` path (#226).

### Fixed

- Troubleshooting indirect traces wait on `probe.rate_limit_pps` per packet, and Probe and optimize refuses setup errors before it spends a rate-limit token (#272, #274).
- Probe and optimize refuses a prefix inside an exchange peering LAN with 422 instead of queuing a prefix the probe engine never measures (#273).
- Live apply for inbound and mitigation (#233): `inbound.mode`/`mitigation.mode`, `hold_time`, `improvement_ttl` and the allowlist apply on reload; a shrunk allowlist withdraws a steer on the wire.
- Load-test RSS plateau and leak check (#112): trimmed per-prefix heap, `GOGC=50` when unset, and a new `rss_slope_mb` budget fails the load job if RSS is still climbing at the end. No budget raised.

- UI display bugs (#171): mode chip meets WCAG AA, the improvements widget title follows the mode, widget timestamps use the dashboard format, and provider form fields have labels.

- FRR HA lab lease-release check (#190): `lab/checklease` watches the lease file in the standby instead of grepping logs once, so a delayed log line no longer fails the job.

- Exchange peering LANs are not probe targets (#145): `exchanges[].lans` prefixes and hosts are dropped from every source; an `allowlist` overlapping a LAN fails config load.

- Exchange session type (#146): `via` on learned paths and in `/api/exchanges` is `route_server`, `bilateral`, or `unknown`, from BMP neighbor versus path next hop. MED stays display-only.

- Load-test RSS growth budget (#120): the `pr` budget is 384 MiB after a run measured 258 MiB of growth against 256. Peak RSS and the weekly soak budget are unchanged.

- Improved prefixes stay probe targets (#116): while an improvement is active its prefix stays in the probe set after every source drops it; all withdraw rules are unchanged.

- Flow probe hosts are candidates, not pins (#113): the busiest destination and a problem address are probed first, then automatic in-prefix addresses; one silent address no longer reads as 100% loss.

### Added

- Flap quarantine (#228): a prefix that changes provider over `max_flips` times in `window` is withdrawn and held on its native path for a doubling cool-down. Events, audit, metric, release API.
- Upgrade from the UI (#196): opt-in `upgrade` block; Settings checks releases, and an admin can upgrade to a signed, checksummed binary after confirming (routes withdrawn first) or roll back.
- Measured-prefix list is server-paged (#183): `/api/prefixes` takes `limit`, `offset`, `prefix`, `asn`, `provider`, `differs`, `sort`; `/prefixes.html` is a filterable table.
- Troubleshooting page draws looking glass paths and per-provider traceroute hops as tables with raw JSON, rerun, and remove; read-only, roles unchanged (#180).
- Leak watch (#199): optional `leak_watch` withdraws one injected route seen outside the AS and holds it out until `POST /api/leaks/clear`; rollback `enabled: false`.
- Prefix detail page `/prefix/<prefix>` (#179): improvement rows link to the prefix card and a stored timeline, with a Probe now link; new read-only `GET /api/prefixes/history`.
- Events and audit log page (#173): filterable recent events kept in `sqlite` storage or memory, an admin Audit tab, and a top bar count of new warnings.
- Admin Users page and Tokens page over the existing /api/users and /api/tokens, with the same roles and audit (#175). Rollback: revert.
- Sign-in page and sign-out for local users (#176). Pages redirect to `/signin.html` only over https or on localhost; plain http keeps the basic-auth prompt. Rollback: revert.
- UI forms for mitigation, inbound, and anomaly rules (#131): a Protection add/remove form with `GET /api/mitigations/candidates`, and `inbound` and `anomaly.rules` settings sections.
- Settings forms for the first `flow`, `rules`, `vip`, and `outage` entries, and a wizard flow step (#130); same merge, validation, and audit path as other fields. UI and API only.

- Before/after graphs (#129): a `timeseries` report and `/graphs.html` chart loss and RTT per UTC day, native versus chosen provider, plus a `timeseries` widget. Needs `storage: sqlite`; read-only.

- Online apply of thresholds, policies, sources, probe timing, `mode`, `allowlist`, and `bgp.neighbors` on SIGHUP and `PUT /api/config` (#128); restart-only keys are refused by name.

- UI shell (#170): left navigation and top bar on every page with the mode banner first, own URLs for each section, empty states naming the issue that builds them, and role-aware Settings and Admin.

- Probe scheduler and passive prefix counts (#125): due prefixes probe in priority order, a missed deadline keeps finished results, flow cells are counted by HyperLogLog; load profiles gate on both.

- Outage detection from traceroute hop ASNs and alternate provider paths (#124): the `outage` source maps hops to origin ASNs from the learned RIB; ASN-only incidents blame a degraded provider.

- FRR lab checks per-cause `local_pref` on the edge (#132 follow-up): `local_pref_cause.performance: 260` is present while the route is, and gone after SIGTERM and SIGKILL.

- Extra outbound communities and large communities (#132, part 2): `communities_cause` and `providers[].communities` add up to 16 communities after `packeteer_community`, standard or large (RFC 8092).

- Local preference per cause and per provider (#132, part 1): `local_pref_cause` and `providers[].local_pref`; provider beats cause beats global `local_pref`, and 0 is rejected in every mode.

- Per-provider indirect probing for silent targets (#123): optional `probe.indirect` traces a prefix in the background from each provider's source and probes the highest stable hop. Off when omitted.

- Sub-range measurement inside a wide prefix (#121): optional flow `subranges` block counts bytes per sub-range and the probe engine scores each; `/api/decisions` lists them. Measurement only.

- Flow volume floor and priority tiers (#118): `min_bytes`, `min_pct`, `max_targets` and `tail_interval` split probed prefixes into a `top_n` tier at `probe.interval` and a slower tail.

- Host qualification (#119): `probe.min_replies` and `probe.dispersion_ms` decide when a host defines a prefix, a wide RTT spread triggers the retry, and flow uses the three busiest destinations.

- Prober memory (#120): the engine starts each round at the prober that last answered a host; `probe.prober_recheck_rounds` and `probe.prober_memory` bound the recheck and the host count.

- RTT percent and confirm rounds before a new performance move (#117): `thresholds.min_rtt_delta_pct` and `thresholds.confirm_rounds`, both off by default so the previous rule holds.

- MED on each learned path and an ASN map of measured prefixes (#105): paths show next hop, AS path, and MED, and prefixes group by origin ASN and provider site. MED is display-only.


- Automatic probe targets (#104): a prefix with no host is measured at up to three in-prefix addresses plus the provider next hop, at most four per provider; a configured `host` is a pin.

- Setup wizard (#106): `/settings.html` walks edge session, providers, and an optional prefix; `POST /api/config/wizard` writes nothing and always returns `mode: observe` with an empty allowlist.
- Opt-in 3 million prefix lab profile `routes3m` in `lab/soak/budgets.yaml` (#103; lab only); its budgets are empty until a large host records them. CI still runs `pr` and `soak`.
- Settings form beside the YAML editor (#102): `/settings.html` edits providers, static prefixes, allowlist, and decision knobs via `POST /api/config/form`; save is still `PUT /api/config`.

## [0.5.0] - 2026-10-01

Fifth release: hardening and polish (#49-#53). UI/UX polish so a first run is readable (mode banner, overview tiles, setup checklist, empty and error states); install and walkthrough docs that CI runs (single-container quickstart, observe -> suggest -> inject on a simulated edge, troubleshooting, MikroTik/FRR/Junos/Cisco router guides); load and soak budgets under a full-table synthetic RIB, a fix for flow ingest when that window is full, and an RSS growth check that does not treat a Go heap refill as a leak; a MikroTik CHR lab in QEMU on CI runners; and a scheduled router interop matrix (FRR, BIRD 2/3, and GoBGP edges against iBGP, add-path, and BMP, plus CHR). Lab-proven only, against simulated routers in CI with documentation prefixes and private ASNs, not on a public edge. Safety rules are unchanged: the default stays `mode: observe`, an announcement still needs the exact prefix in the learned RIB, the allowlist, the configured community and NO_EXPORT, the improvement cap, and hold time, and CI still proves announce, withdraw, and crash-withdraw. Field feedback from real observe-mode deployments (#54) is still open.

### Added

- Router interop matrix in the lab (#53; lab only): weekly `interop` workflow runs `lab/e2e-interop.sh` for FRR, BIRD 2/3, and GoBGP edges against iBGP, add-path, and BMP, plus the CHR lab.
- MikroTik CHR lab in CI (#52; lab only): `chr` job and `lab/e2e-chr.sh` boot RouterOS CHR in QEMU and prove it accepts the tagged exact prefix and drops it on flip-back, SIGTERM, freeze, and SIGKILL.
- Load and soak testing (#51; lab only): `lab/soak` and `lab/soak.sh` run the stock image on a 1.25M-prefix synthetic table against `lab/soak/budgets.yaml`; `load` CI job, weekly `soak.yml`.
- Docs and install guides (#50): quickstart, walkthrough, troubleshooting, and FRR, Junos, and Cisco router guides; `lab/doccmds` and `lab/e2e-docs.sh` run the guides' shell blocks as CI steps.
- UI/UX polish and first run (#49): mode banner, overview tiles, setup checklist, read-only `GET /api/overview`, and a headless-Chrome smoke test; `mode` defaults to `observe` when omitted.

### Fixed

- Load-test RSS growth check (#97): growth is the second-half median minus the warmup median, so a Go return-and-refill valley no longer reads as growth. The 256 MiB budget stays.
- Flow ingest under a full-table flow mix (#51): a full bucket frees its smallest sixteenth in one pass, cutting dropped flow datagrams from 78.8% to 1.8%; the busiest prefixes are still kept.

## [0.4.0] - 2026-09-30

Fourth release: the v0.4 milestone (#30-#34). Multi-POP federation with routing domains, inter-DC RTT, global commit, and a central view; active/standby HA with a lease elector plus config and history backup/restore; user accounts, RBAC, API tokens, access restriction, an audit log, and OIDC SSO for the ops API; flow-baseline anomaly (DDoS) detection that alerts by default and mitigates only through explicit rules and the existing mitigation controller; and the remaining UI features (improvement weights, a validated config editor and first-run wizard, custom dashboards, email report subscriptions). The BGP-facing parts are lab-proven against FRR/GoBGP in CI with documentation prefixes and private ASNs, not on a public edge. The default stays `mode: observe`; every new block is off unless configured, and a remote-POP steer, an HA takeover, or a detector rule still needs the exact prefix in the learned RIB, the allowlist, the community + NO_EXPORT, the cap, and hold time. CI still proves announce, withdraw, and crash-withdraw.

### Added

- Remaining UI features (#34; lab-proven only): `improvement_weights`, the `http.config_editor` config editor and wizard, custom dashboards, and `report_subscriptions` email reports. See docs/ui.md.
- Traffic anomaly (DDoS) detection (#33; lab-proven only): `detector` plugin kind with `baseline`; acts only through explicit `anomaly.rules` and the mitigation controller. See docs/anomaly.md.
- User accounts, RBAC, access restriction, audit log, and optional OIDC SSO for the ops HTTP server (#32): `auth` block, `http.allow_from`, viewer/operator/admin roles, API tokens. See docs/auth.md.
- High availability, active/standby with config and history backup (#31; lab-proven only): `ha` block and `lease` elector; only the active instance announces; `-backup` and `-restore`. See docs/ha.md.
- Multi-POP federation and routing domains (#30; lab-proven only): `federation` plugin kind with `mtls`, `domain`, `inter_dc_rtt`, `global_commit`, and `GET /api/federation`. See docs/multi-pop.md.

## [0.3.0] - 2026-09-29

Third release: the v0.3 milestone (#25-#29, #56). Inbound commit control and performance steering (prepends, provider TE communities, selective announcements), a BMP monitoring station and BGP add-path receive, multiple edge routers, route reflectors, and IX peers with per-peer next hop, threat mitigation (RTBH, BGP redirect, FlowSpec drop/rate-limit/redirect, country policies), transit traffic classification, and more-specific injection with a route cap. Everything here is lab-proven against FRR/GoBGP in CI with documentation prefixes and private ASNs, not on a public edge. The default stays `mode: observe`; inbound and mitigation have their own `mode` (default `observe`), and `more_specific` is off by default and only announces more-specifics learned exactly in the RIB. CI still proves announce, withdraw, and crash-withdraw.

### Added

- More-specific injection, route-capped (#56; lab-proven only): optional `more_specific` block announces learned more-specifics of an improved prefix, up to `max_routes` (docs/design/more-specific.md)
- Transit traffic optimization (#29): optional `transit` block on `flow` classifies prefix traffic as transit or local, and `rules` policies take `traffic: transit|local`. No new announce path.
- Threat mitigation, second half (#28; lab-proven only): FlowSpec drop, rate-limit and redirect, country rules from a mounted GeoIP database, a monitor, an event feed, and history.
- Threat mitigation, first half (#28; lab-proven only): `mitigation` block with its own mode and allowlist, an in-process announcer, RTBH and redirect rules on `/api/mitigations` (docs/mitigation.md).
- Internet exchanges, AS-path behavior, and online reconfiguration (#27, second half; lab-proven only): `exchanges`, `bgp.as_path`, and SIGHUP reload of `bgp.neighbors`.
- Multiple edge routers and route reflectors (#27, first half; lab-proven only): `bgp.neighbors[].providers` and `next_hops` give per-router export policy. See docs/route-reflector.md.
- BGP add-path (#26, second half; lab-proven only): `bgp.neighbors[].add_path` receives all paths (RFC 7911, never sends), and `providers[].add_path` applies the route check from them.
- BMP monitoring station (#26, first half; lab-proven only): `rib_sources` plugin kind with the `bmp` station (RFC 7854, RFC 9069) and a per-provider `bmp` route check; pre-policy routes are refused.
- Inbound optimization, second half (#25; lab-proven only): `inbound.performance` trigger, `inbound.damping`, `inbound.moderated`, and a `withhold` catalog action.
- Inbound commit control, first half (#25; lab-proven only): optional `inbound` block re-announces own prefixes with a provider's TE communities when its 95th exceeds commit. See docs/inbound.md.

## [0.2.0] - 2026-09-28

Second release: the v0.2 milestone (#15-#24). More probing (UDP, traceroute discovery, retry, outage detection), SNMP telemetry and 95th-percentile commit control, cost-aware routing, routing policies and maintenance windows, passive problem detection, alerts, reports and history, and read-only troubleshooting tools. The default stays `mode: observe`; every new capability is off unless configured, and injection still requires the learned RIB, the allowlist, the community, the cap, and hold time. CI still proves announce, withdraw, and crash-withdraw against FRR with documentation prefixes.

### Added

- Troubleshooting tools (#24): looking glass always on; with `troubleshoot.enabled`, on-demand probe, traceroute, and whois (`whois` plugin kind, `rdap`). Read-only and rate limited.
- Reports and history (#23): `storage` plugin kind with the `sqlite` built-in, daily rollups, `/api/reports/<name>` as JSON or CSV, and a Reports section. A storage failure never delays a withdraw.
- Alerts and notifications (#22): event catalog in docs/EVENTS.md; `smtp` and `snmptrap` notifiers, `webhook` presets and templates; per-notifier queue, `events`, `min_severity`, `rate_limit`.
- Passive problem detection (#21): the `span` target source reads a mirror port and scores remote prefixes by retransmissions and resets; `flow` gains an optional `problems` block. Neither announces.
- Routing policies: the `rules` policy matches prefix, origin ASN, or country and applies `ignore`, `allow`, `deny`, `static`, or `vip`; the `maintenance` policy excludes providers during windows.
- `snmp` telemetry plugin: polls interface octet counters over SNMP v2c or v3 and tracks 95th-percentile usage per UTC billing period, exposed on `/api/telemetry`. Does not announce.
- `commit` scorer: keeps each provider's billable 95th under its commit by moving volume prefixes to a provider with room; can balance provider groups. Commit steers share `max_improvements`.
- `cost` scorer and `providers[].cost`: moves a prefix to the cheapest provider inside a performance floor; `precedence` picks performance or cost. Reports `cost_delta` and `est_savings`.
- `fixed` telemetry plugin, for labs and tests. It reports a configured billable figure and can re-read a file. It does not poll and it does not announce.
- Static targets accept an optional `mbps` rate so commit control can run without a flow export. The FRR lab has a commit-cause announce, withdraw, and SIGKILL job.
- `outage` target source: probe results correlated by learned AS path and provider re-queue affected prefixes and emit `outage.as` or `outage.circuit`. Does not announce.
- `udp` prober: a datagram reply counts; ICMP unreachable counts only from the target, so a firewall `REJECT` is loss. Not in the default chain.
- `traceroute` target source: when the configured host does not answer, probes move to the last stable hop. Discovery runs in the background, capped by `budget` (default 10s).
- `vip` target source: listed prefixes, and prefixes whose learned AS path has a listed ASN, are probed on their own interval; `max_targets` (default 100) caps the list.
- Retry probing. `probe.retry_loss_pct` (default off) re-measures a lossy sample with `probe.retry_packets` before it is stored.

## [0.1.0] - 2026-09-25

First release. An observe-first BGP path performance controller in one container. Injection is opt-in and is tested in CI against FRR with documentation prefixes (RFC 5737) and the private ASN 64512.

### Added

- Probe engine. ICMP echo and TCP connect (port 443), sourced from each provider, with a worker pool and a global packet-rate cap. Loss, RTT min/avg/max, and jitter.
- Target sources: a static prefix list, and a flow collector for NetFlow v5/v9, IPFIX, and sFlow v5 (top prefixes by bytes).
- Learn-only iBGP RIB view on an embedded GoBGP speaker. Graceful restart is not enabled. The speaker proposes a 90s hold time.
- Decision engine with a weighted scorer, loss and latency thresholds, hold time, a cooldown after flip-back, an improvement cap (default 50), and an improvement TTL.
- Inject mode. The `gobgp` announcer publishes the exact learned prefix on that same iBGP session, with the provider next hop, `local_pref`, the configured community, and `no-export`.
- Withdraw on shutdown, dead probe source, stale measurements, every BGP session down, and when a still-advertised prefix leaves the RIB.
- Read-only HTTP surface on `127.0.0.1:8080`: dashboard, `/healthz`, `/readyz`, Prometheus `/metrics`, and a JSON API. Optional basic auth from the environment.
- Plugin host: prober, source, scorer, announcer, and notifier. Built-ins plus `exec` and `webhook`. Announcers stay in-process.
- Container image (linux/amd64, linux/arm64) and a Compose file. Config is a mounted file.
- FRR lab. The e2e job checks announce, flip-back, withdraw while the controller is alive, clean shutdown, and SIGKILL (the route is gone within the BGP hold timer).
- Operator quick start, config reference, router filters (MikroTik, FRR, Junos, IOS), and policy routing.

### Safety

- The shipped example and Compose instructions stay `mode: observe`.
- Inject requires `mode: inject`, a non-empty allowlist, a community, `local_pref`, a positive hold time, positive loss and latency thresholds, an announcer, and an iBGP neighbor.
- Packeteer does not announce a prefix that is absent from the learned RIB. `more_specific_bits` is rejected.
- Learned routes are not reflected. The export policy accepts only Packeteer's own routes that carry the community.
- No graceful restart.

### Known limitations

- On a best-path-only iBGP session the router stops advertising a prefix once Packeteer's route wins; a provider withdraw is caught at `improvement_ttl` unless the router sends the native path.
- `observe` and `suggest` share one code path. Neither announces. Recommendations are the log, the dashboard, and `/api/decisions`.
- No inbound optimization, FlowSpec, RTBH, SNMP, commit or cost control, alerts beyond the webhook notifier, reports, or high availability.
- The flow collector is unauthenticated UDP. Firewall it to the exporter.
- The HTTP server is read-only and has no accounts or audit log. It defaults to loopback.
- Communities are RFC 1997 (two 16-bit integers). `router_id` is IPv4.
- RouterOS, Junos, and IOS snippets are documentation. The automated BGP test is the FRR lab.

[Unreleased]: https://github.com/GrandArcher/Packeteer/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/GrandArcher/Packeteer/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/GrandArcher/Packeteer/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/GrandArcher/Packeteer/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/GrandArcher/Packeteer/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/GrandArcher/Packeteer/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/GrandArcher/Packeteer/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/GrandArcher/Packeteer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.2.0
[0.1.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.1.0
