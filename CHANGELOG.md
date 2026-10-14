# Changelog

All notable changes to Packeteer are documented here. Versions are Git tags on `main`. The image tags `ghcr.io/grandarcher/packeteer:<version>` (for example `:0.6.0`) and `:latest` are published from each `v<version>` tag. `:edge` tracks `main`.

## [Unreleased]

### Added

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

## [0.6.0] - 2026-10-13

Sixth release: gaps found in the 2026-10-07 review of prefix selection, measurement, and the UI (#113–#132, #145–#146, #170–#183), plus hardening (#217, #223, #226, #228, #233, #234, #240) and upgrade from the UI (#196). Probe targeting and qualification, switch thresholds with confirm rounds, scale limits up to multi-million path tables, flap quarantine, live apply for core, inbound and mitigation settings, a UI shell with pages per area and full settings forms, a manual probe, and a failure-mode e2e matrix across every injection surface. Lab-proven only, against simulated routers in CI with documentation prefixes and private ASNs, not on a public edge. Safety rules are unchanged: the default stays `mode: observe`, an announcement still needs the exact prefix in the learned RIB, the allowlist, the configured community and NO_EXPORT, the improvement cap, and hold time. The opt-in synthesized more-specific block (#122) is not part of this release.

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

Fifth release: hardening and polish (#49–#53). UI/UX polish so a first run is readable (mode banner, overview tiles, setup checklist, empty and error states); install and walkthrough docs that CI runs (single-container quickstart, observe → suggest → inject on a simulated edge, troubleshooting, MikroTik/FRR/Junos/Cisco router guides); load and soak budgets under a full-table synthetic RIB, a fix for flow ingest when that window is full, and an RSS growth check that does not treat a Go heap refill as a leak; a MikroTik CHR lab in QEMU on CI runners; and a scheduled router interop matrix (FRR, BIRD 2/3, and GoBGP edges against iBGP, add-path, and BMP, plus CHR). Lab-proven only, against simulated routers in CI with documentation prefixes and private ASNs, not on a public edge. Safety rules are unchanged: the default stays `mode: observe`, an announcement still needs the exact prefix in the learned RIB, the allowlist, the configured community and NO_EXPORT, the improvement cap, and hold time, and CI still proves announce, withdraw, and crash-withdraw. Field feedback from real observe-mode deployments (#54) is still open.

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

Fourth release: the v0.4 milestone (#30–#34). Multi-POP federation with routing domains, inter-DC RTT, global commit, and a central view; active/standby HA with a lease elector plus config and history backup/restore; user accounts, RBAC, API tokens, access restriction, an audit log, and OIDC SSO for the ops API; flow-baseline anomaly (DDoS) detection that alerts by default and mitigates only through explicit rules and the existing mitigation controller; and the remaining UI features (improvement weights, a validated config editor and first-run wizard, custom dashboards, email report subscriptions). The BGP-facing parts are lab-proven against FRR/GoBGP in CI with documentation prefixes and private ASNs, not on a public edge. The default stays `mode: observe`; every new block is off unless configured, and a remote-POP steer, an HA takeover, or a detector rule still needs the exact prefix in the learned RIB, the allowlist, the community + NO_EXPORT, the cap, and hold time. CI still proves announce, withdraw, and crash-withdraw.

### Added

- Remaining UI features (#34; lab-proven only): `improvement_weights`, the `http.config_editor` config editor and wizard, custom dashboards, and `report_subscriptions` email reports. See docs/ui.md.
- Traffic anomaly (DDoS) detection (#33; lab-proven only): `detector` plugin kind with `baseline`; acts only through explicit `anomaly.rules` and the mitigation controller. See docs/anomaly.md.
- User accounts, RBAC, access restriction, audit log, and optional OIDC SSO for the ops HTTP server (#32): `auth` block, `http.allow_from`, viewer/operator/admin roles, API tokens. See docs/auth.md.
- High availability, active/standby with config and history backup (#31; lab-proven only): `ha` block and `lease` elector; only the active instance announces; `-backup` and `-restore`. See docs/ha.md.
- Multi-POP federation and routing domains (#30; lab-proven only): `federation` plugin kind with `mtls`, `domain`, `inter_dc_rtt`, `global_commit`, and `GET /api/federation`. See docs/multi-pop.md.

## [0.3.0] - 2026-09-29

Third release: the v0.3 milestone (#25–#29, #56). Inbound commit control and performance steering (prepends, provider TE communities, selective announcements), a BMP monitoring station and BGP add-path receive, multiple edge routers, route reflectors, and IX peers with per-peer next hop, threat mitigation (RTBH, BGP redirect, FlowSpec drop/rate-limit/redirect, country policies), transit traffic classification, and more-specific injection with a route cap. Everything here is lab-proven against FRR/GoBGP in CI with documentation prefixes and private ASNs, not on a public edge. The default stays `mode: observe`; inbound and mitigation have their own `mode` (default `observe`), and `more_specific` is off by default and only announces more-specifics learned exactly in the RIB. CI still proves announce, withdraw, and crash-withdraw.

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

Second release: the v0.2 milestone (#15–#24). More probing (UDP, traceroute discovery, retry, outage detection), SNMP telemetry and 95th-percentile commit control, cost-aware routing, routing policies and maintenance windows, passive problem detection, alerts, reports and history, and read-only troubleshooting tools. The default stays `mode: observe`; every new capability is off unless configured, and injection still requires the learned RIB, the allowlist, the community, the cap, and hold time. CI still proves announce, withdraw, and crash-withdraw against FRR with documentation prefixes.

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

[0.2.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.2.0
[0.1.0]: https://github.com/GrandArcher/Packeteer/releases/tag/v0.1.0
