# HTTP API and metrics

The dashboard, JSON API, and Prometheus metrics share one listener, `http.listen` (default `127.0.0.1:8080`). With host networking it is an address on the host. Auth, roles, and tokens: [auth.md](auth.md). Dashboard pages: [ui.md](ui.md). Keys: [CONFIG.md](CONFIG.md).

## Endpoints

| Path | Body |
|---|---|
| `/` | Overview (#170): the mode banner (first on every page; observe says it announces nothing), tiles, and the setup checklist. Each area has its own URL under the left navigation: improvements, prefixes and ASNs, reports, providers, troubleshooting, settings, the events and audit log page (#173), and the pages that are still empty states. See [docs/ui.md](ui.md). When the controller cannot be reached, the page says so and keeps the last data, marked stale. |
| `/api/overview` | The dashboard's summary: mode, readiness, counts, per-provider probe results, optional features on or off, and the setup checklist (`setup`: `id`, `level` `todo`/`warn`/`info`, `title`, `detail`, `doc`). |
| `/healthz` | Liveness. JSON `status` is `ok`. |
| `/readyz` | Readiness. 503 until startup finishes, and until an iBGP session is up when neighbors are configured. |
| `/metrics` | Prometheus text. |
| `/api/providers` | Providers, probe-source health, and BGP sessions. |
| `/api/probes` | Latest probe per provider and prefix. |
| `/api/prefixes` | Probed prefixes with measurements, current exit, and recommended exit, one page at a time (`limit` up to 500, default 100; `offset`, `prefix`, `asn`, `provider`, `differs`, `sort`; [ui.md](ui.md#prefix-list)). Prefixes that are only in the RIB are not listed. |
| `/api/decisions` | Latest per-prefix decision. |
| `/api/improvements` | Active improvements. In observe and suggest these are recommendations. In inject they are the routes being announced. |
| `/api/telemetry` | Interface rates and 95th-percentile usage when a telemetry plugin is configured. Empty when it is not. This does not announce. |
| `/api/reports` | The report list, and whether history storage is on. |
| `/api/reports/<name>` | One report as JSON, or CSV with `?format=csv`. Range: `?days=7` (default), or `from` and `to` as RFC 3339 or `YYYY-MM-DD` (UTC). `limit` and, for `prefixes`, `asns`, and `countries`, `sort=problems\|volume\|loss`. Reports: `summary`, `improvements`, `causes`, `performance` (loss and latency before and after), `providers` (efficiency), `prefixes`, `asns`, `countries`, `probes` (per day), `savings`, `timeseries` (before/after loss and latency per day and bucket, drawn on `/graphs.html`). Needs `storage`. |
| `/api/troubleshoot` | Which troubleshooting tools are on ([CONFIG.md](CONFIG.md#troubleshoot)). |
| `/api/troubleshoot/lookingglass?prefix=<prefix or address>` | Learned route for exactly that prefix, the longest covering route, and learned more-specifics (up to 100). Read from the RIB view; always on. |
| `/api/troubleshoot/probe` | `POST {"target":"<address or hostname>"}`. Resolves a hostname (`host`, `addresses`, and the `target` used), probes the address from every provider with the prober chain, and adds the covering learned `route`, the `current` exit, and the `best` measured exit. A provider that gets no reply is traced and its highest stable hop is probed (`indirect`). The result is returned only; it does not feed decisions. Needs `troubleshoot.enabled`. |
| `/api/troubleshoot/optimize` | `POST {"target":"<address or hostname>"}`, operator. Queues the learned prefix covering the target as an urgent probe target for 10 minutes. The decision engine still applies every rule to the result ([docs/ui.md](ui.md#troubleshooting-results)). Needs `troubleshoot.enabled`. |
| `/api/troubleshoot/traceroute` | `POST {"target":"<address>","provider":"<optional name>"}`. UDP traceroute from each provider's source. Needs `troubleshoot.enabled`. |
| `/api/troubleshoot/whois` | `POST {"query":"<address, prefix, or ASN>"}`. RDAP lookup through `troubleshoot.whois`. Needs `troubleshoot.enabled`. |
| `/api/mitigations` | Threat mitigation rules (RTBH, BGP redirect, FlowSpec drop/rate-limit/redirect), the catalog, the mitigation allowlist, and the feed of recent changes. `POST {"prefix","action","target","ttl","reason"}` (FlowSpec adds `match`, `source_countries`, `rate_mbps`) adds a rule and `DELETE /api/mitigations/<id>` removes one, when `mitigation` is configured and basic auth is on ([docs/mitigation.md](mitigation.md)). Lab-proven only. |
| `/api/leaks` | Leak watch (#199): `state` (`watching` or `unknown`), each source's health, and the prefixes held out because a route was seen outside the AS. `POST /api/leaks/clear {"prefix"}` releases one, with auth ([docs/leak-watch.md](leak-watch.md)). |
| `/api/ha` | Active/standby role (#31): `role` (`active` or `standby`), `holder`, `eligible`, `detail`, `takeovers`. `ha_enabled: false` and `role: active` when `ha` is not configured ([docs/ha.md](ha.md)). |
| `/api/federation` | Central view of every federated instance (#30): this instance's published snapshot, each peer's freshness, last error, snapshot, and inter-DC RTT, and the global commits with each member's usage. Read-only. `enabled: false` when `federation` is not configured ([docs/multi-pop.md](multi-pop.md)). |
| `/api/me` | Who you are: `auth` (`rbac`, `basic`, or `off`), `user`, `role`, `method`. |
| `/api/tokens` | Your API tokens (an admin sees all). `POST {"name","role","ttl"}` creates one and returns its secret once; `DELETE /api/tokens/<id>` revokes one. Needs `auth` ([docs/auth.md](auth.md)). |
| `/api/users` | Admin only. Users and roles. `POST {"name","role","password"}`, `PATCH /api/users/<name>` (`role`, `password`, `disabled`), `DELETE /api/users/<name>`. Needs `auth`. |
| `/api/audit` | Admin only. The audit log, newest first: `?limit=` (1–1000, default 100), `from`, `to` (RFC 3339). Needs a `storage` plugin. |
| `/auth/login`, `/auth/callback`, `/auth/logout` | OIDC single sign-on when `auth.sso` is set. |
| `/api/config` | Admin only, with `http.config_editor: true` and auth or basic auth (#34, #102). `GET` returns the mounted config file and its `sha256`; `POST /api/config/validate {"yaml"}` runs the start checks; `PUT {"yaml","base","confirm_inject"}` writes it (needs the `sha256` it edits, and `confirm_inject` to turn inject on). Applies on restart. `POST /api/config/form` reads or merges the settings form into YAML without writing. `GET /api/config/suggestions` lists iBGP or BMP next hops that are not providers (a draft row only; it does not probe or announce). `POST /api/config/wizard` renders an observe config from the setup wizard (edge session, provider rows, optional pinned probe host, optional flow collector; inject is not a step). The settings form also edits every `flow`, `vip`, and `outage` source and every `rules` policy (#130, #226). UI: `/settings.html` ([docs/ui.md](ui.md)). |
| `/api/dashboards` | Your custom dashboards and the widget catalog (#34). `PUT /api/dashboards/<name>` saves one, `DELETE` removes it. Needs a storage plugin and auth or basic auth. UI: `/dashboards.html`. |
| `/api/upgrade` | Admin only. Running version, install type, the last release check, and the rollback target (#196). `POST /api/upgrade/check` lists GitHub releases and changes nothing; `POST /api/upgrade/apply {"tag","confirm":true}` and `POST /api/upgrade/rollback {"confirm":true}` switch versions after the SIGTERM shutdown path has withdrawn every route. Need `upgrade.enabled`, `upgrade.public_key`, and auth or basic auth ([docs/ui.md](ui.md#upgrade-from-the-ui)). |
| `/api/subscriptions` | Report subscriptions (#34): schedule, next and last send, errors. `POST /api/subscriptions/<name>/send` (operator) sends one now. |
| `/api/maintenance` | Open maintenance windows. `POST` opens an on-demand window and `DELETE /api/maintenance/<id>` closes one, when a `maintenance` policy is configured and basic auth is on ([CONFIG.md](CONFIG.md#policy-maintenance)). |

## Metrics

Prometheus metrics are `packeteer_up`, `packeteer_ready`, `packeteer_build_info`, `packeteer_provider_up`, `packeteer_probe_success`, `packeteer_probe_rtt_seconds`, `packeteer_probe_rtt_min_seconds`, `packeteer_probe_rtt_max_seconds`, `packeteer_probe_loss_ratio`, `packeteer_probe_jitter_seconds`, `packeteer_probe_prefix_commits`, `packeteer_flow_prefixes_tracked`, `packeteer_truncated_total`, `packeteer_decisions`, `packeteer_decision`, `packeteer_improvements_active`, `packeteer_improvement`, `packeteer_estimated_savings`, `packeteer_bgp_configured`, `packeteer_bgp_ready`, `packeteer_rib_prefixes`, `packeteer_bgp_session_up`, `packeteer_bgp_session`, and, when telemetry is configured, `packeteer_telemetry_up`, `packeteer_telemetry_in_bps`, `packeteer_telemetry_out_bps`, `packeteer_telemetry_in_95th_bps`, `packeteer_telemetry_out_95th_bps`, `packeteer_telemetry_usage_bps`, `packeteer_telemetry_commit_bps`, and `packeteer_telemetry_samples`.

Scrape `http://127.0.0.1:8080/metrics` on the host. With `auth` on, use an API token ([auth.md](auth.md)).
