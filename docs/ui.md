# Dashboard, config editor, wizard, dashboards, report subscriptions, and improvement weights

The remaining UI conveniences (#34). All of them work in the stock image with a mounted config file. None of them announces a route, and the default mode stays `observe`. Every key is in [CONFIG.md](CONFIG.md).

| Feature | Where | Who | Config |
|---|---|---|---|
| Before/after graphs (#129) | `/graphs.html`, `/api/reports/timeseries`, the `timeseries` dashboard widget | viewer | `storage: {type: sqlite}` |
| Troubleshooting results (#180) | `/troubleshooting.html`, `/api/troubleshoot/...` | viewer for the looking glass, operator for probe, traceroute, and whois | `troubleshoot.enabled` for the active tools |
| Prefix list (#183) | `/prefixes.html`, `/api/prefixes` | viewer | none |
| Prefix detail and history (#179) | `/prefix/<prefix>`, `/api/prefixes/history` | viewer | `storage: {type: sqlite}` for the timeline |
| Maintenance windows (#177) | `/policies.html`, `GET`/`POST /api/maintenance`, `DELETE /api/maintenance/{id}` | viewer reads, operator opens and closes | a `maintenance` policy; opening needs auth or basic auth |
| Link-outs (#211) | `/prefix/<prefix>`, `/prefixes.html`, `/providers.html`, `GET /api/linkouts` | viewer | `linkouts` (optional) |
| Global search (#172) | the top bar on every page, `/search.html`, `GET /api/search` | viewer | `storage: {type: sqlite}` for history |
| System health (#184) | `/system.html`, `/api/system`, the System tile on `/` | viewer | none |
| Events and audit log (#173) | `/events.html`, `/api/events`, `/api/audit` | viewer for events, admin for the audit tab | `storage: {type: sqlite}` keeps events across a restart |
| Users and API tokens (#175) | `/admin.html`, `/tokens.html`, `/api/users`, `/api/tokens` | admin for users, every signed-in user for tokens | `storage` + `auth.enabled` |
| Dashboard overview and setup checklist (#49) | `/`, `/api/overview` | viewer | none |
| Config editor and settings form (#102, inbound and anomaly rules #131, exchanges #181) | `/settings.html`, `/api/config`, `POST /api/config/form` | admin | `http.config_editor: true` + auth or basic auth |
| Setup wizard (#106, flow step #130) | `/settings.html`, `POST /api/config/wizard` | admin | `http.config_editor: true` + auth or basic auth |
| Custom dashboards | `/dashboards.html`, `/api/dashboards` | every signed-in user, own dashboards | `storage: {type: sqlite}` + auth or basic auth |
| Report subscriptions | `report_subscriptions`, `/api/subscriptions` | viewers see them, operators send now | `storage` + an `smtp` notifier |
| Version check, upgrade, and rollback (#196) | `/settings.html`, `GET /api/upgrade`, `POST /api/upgrade/{check,apply,rollback}` | admin | `upgrade.enabled: true` + `upgrade.public_key` + auth or basic auth |
| Improvement weights | `scorer.config.improvement_weights`, `/api/decisions` | - | `weighted`, `commit`, or `cost` scorer |

With `auth` on, roles are checked per route like every other endpoint ([auth.md](auth.md)); with basic auth, the one account may do everything; with neither, the editor, the wizard, dashboards, and send-now are refused.

## Shell

Every page has the same chrome (#170). The mode banner is the first thing on the page, above a left navigation and a top bar. A reload of a page URL opens that page. The navigation links are:

| Page | URL | What is on it |
|---|---|---|
| Overview | `/` | Tiles, setup checklist, optional features, and POPs when federation is on |
| Dashboards | `/dashboards.html` | Custom dashboards (the existing page) |
| Improvements | `/improvements.html` | Recommended or active improvements |
| Prefixes & ASNs | `/prefixes.html` | The measured-prefix table, one page at a time, and the ASN map ([below](#prefix-list)) |
| Graphs | `/graphs.html` | Before/after loss and latency charts (#129; [below](#graphs)). Empty state without history |
| Reports | `/reports.html` | History reports and CSV |
| Providers & Exchanges | `/providers.html` | Provider health. The exchange view is empty (#148) |
| Commit & Cost | `/commit.html` | Empty (#174) |
| Policies | `/policies.html` | Points to Settings, where the `rules` policy is edited (#130). It does not list rules yet. With a `maintenance` policy, it lists maintenance windows ([below](#maintenance-windows)) |
| Protection | `/protection.html` | The threat-mitigation monitor with an add and remove rule form (#131) when that feature is on. Otherwise an empty state that says how to configure it |
| Troubleshooting | `/troubleshooting.html` | Looking glass, probe, traceroute, whois ([below](#troubleshooting-results)) |
| Events | `/events.html` | Recent events and, for admins, the audit log ([below](#events-and-audit-log)) |
| System | `/system.html` | One row per component with state, since, and last error ([below](#system-health)) |
| Tokens | `/tokens.html` | The signed-in user's API tokens ([below](#users-and-api-tokens)) |
| Settings | `/settings.html` | Wizard, settings form, YAML, report subscriptions. Admin |
| Admin | `/admin.html` | Users ([below](#users-and-api-tokens)). Admin |

POPs stay on Overview and the threat-mitigation monitor stays on Protection. Both stay hidden when the feature is off, as they did on the single dashboard.

The top bar holds the mode chip, a search slot, an events slot, and the account menu. The search slot does not query (#172). The events slot opens the Events page and shows how many warnings (or worse) arrived since this browser last opened it. The account menu shows who is signed in (`GET /api/me`). Sign out appears when the request carries a session cookie, from the sign-in page or single sign-on, and calls `POST /auth/logout`. A request signed with basic auth or an API token has no session, so no sign-out item.

**Sign-in page (#176).** With `auth.enabled`, a browser without a session that asks for a page over https (or through a proxy that sends `X-Forwarded-Proto: https`) or on localhost is sent to `/signin.html`. Over plain http to any other address it gets the basic-auth prompt, because the browser would drop the `Secure` cookie. API paths and `/metrics` answer `401`. The page asks for a user name and password, posts them as JSON to `POST /auth/signin`, and on success loads the dashboard. The server keeps the session in memory and sets a `packeteer_session` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, lifetime `auth.session_ttl`). The page shows the mode banner and a single sign-on link when an `sso` plugin is configured. A wrong user name or password gets one answer (`401`); ten failures from one address in five minutes lock that address out (`429`), counted together with basic auth. Basic auth and API tokens work as before for scripts. The mode banner on the page comes from `GET /auth/signin`, which needs no sign-in. Without `auth.enabled` the sign-in POST answers `404` and the browser keeps its basic-auth prompt.

Settings and Admin are marked admin-only. With role-based auth, a viewer or an operator does not see those two links. Opening Admin directly says "Your account may not read this page." Opening Settings directly keeps the editor's existing not-allowed message; report subscriptions on that page are unchanged. With auth off, or with the one basic-auth account, both links are shown. Nothing in the shell announces, and it does not write config.

## Users and API tokens

Two pages put `/api/users` and `/api/tokens` on screen (#175). They need `auth.enabled` and a `storage` plugin ([auth.md](auth.md)); without them each page says so and has no form. They call the existing endpoints, so the role checks, the last-admin lockout, the password rules, and the audit record are the API's. Neither page can announce anything.

**Users** (`/admin.html`, admin role). A table of every user with role, source (local or SSO), status, and last change. Actions per row:

- change the role (`PATCH /api/users/{name}` with `role`);
- reset the password (`password`; the user's sessions end);
- disable or enable (`disabled`);
- delete (two clicks; the user's tokens go with it).

A form adds a local user (`POST /api/users`). An SSO user's role comes from the identity provider, so only disable, enable, and delete are offered for it. A refused change, such as demoting or deleting the last enabled admin, shows the API's message. A viewer or an operator does not get the Admin link, and opening the page says the account may not read it; `/api/users` answers `403` either way.

**Tokens** (`/tokens.html`, every signed-in user). A table of the user's tokens (an admin sees everyone's) with role, created, expires, and status, and a revoke button (two clicks). The create form takes a name, a role up to the user's own (default `viewer`), and a lifetime in hours (empty is `auth.token_ttl`). The secret appears once, in a box that stays until it is closed or the page is left; it is not in the table or the audit log, is never written to a cookie or browser storage, and closing the box removes it from the page. A request signed with an API token can list and revoke but not create, and the page says so.

A password typed into the Admin page is sent and the field is cleared. Every change is written to the audit log with its actor, as for a script.

## Troubleshooting results

The Troubleshooting page (#180) draws looking glass and traceroute answers as tables. It sends the same requests as before, so the roles, the `troubleshoot.requests_per_minute` limit, and the `troubleshoot.enabled` switch are unchanged ([CONFIG.md](CONFIG.md#troubleshoot)). Nothing on it announces anything, and the mode banner is on top in every mode.

- **Looking glass.** Learned paths for the query: state (`selected` for the path the RIB view publishes, `inactive` for add-path and BMP paths), provider, next hop, AS path, via, and MED. MED is display only and does not choose the exit. Below it, the longest covering route when it is not the query itself, and the learned more-specifics (cut off at 100).
- **Traceroute.** One block per provider: its source address, whether the target was reached or the trace's error, a diagram of the hops (silent hops are dashed, `*`), and a table of hop, address, reverse name, origin AS, RTT, loss, and error. The origin AS is the last AS on the longest learned route that covers the hop address; a default route is not a match, and a hop outside the learned RIB shows none. No external data is used. The reverse name is a PTR lookup through the container's resolver, bounded to three seconds for the whole trace, and is empty when there is none. One probe is sent per hop, so loss reads 0% (it answered) or 100% (it did not).
- **Probe.** The target is an address or a hostname; the result says which address a hostname resolved to (and the others). The covering learned prefix is shown with the current exit, and a table lists each provider's loss, RTT average, and jitter. The current provider's row is shaded and the best measured exit is bold; the Exit column names them. A provider that got no reply shows the hop it was measured at, marked indirect.
- **Probe and optimize** (operator). Under a probe result whose address is covered by a learned prefix other than the default route. It queues that prefix for measuring for 10 minutes ([CONFIG.md](CONFIG.md#troubleshoot)) and links to the prefix page. Nothing is announced by the click: the decision engine decides on the next round with the usual allowlist, cap, thresholds, and hold time, and in `observe` the outcome is a recommendation.
- **Raw JSON.** Every result keeps a collapsible raw view. Whois results show only the raw JSON, open.
- **Stack.** Results stack newest first, up to 20, in the page and are gone when it is closed or reloaded. Rerun sends the same request again and adds a new result on top. Remove drops one result. A refused or failed request, such as the rate limit, is a result with its message.

The smoke step "UI troubleshooting smoke" in the docker job (`lab/ui-smoke.sh`) loads the page through `lab/uiproxy -fixtures lab/ui-fixtures/troubleshoot`. The proxy answers the looking glass, traceroute, hostname probe, and probe-and-optimize calls from canned files on documentation prefixes and ASNs (a learned best and an inactive path, a covering route, a three-provider trace with a silent hop, an error, and a provider whose source is unavailable, a single-provider trace, and a rate-limited call) and adds a script that presses Run, Remove, and Rerun, runs a hostname probe, and presses Probe and optimize, because headless Chrome cannot click. The step checks the tables, the diagram, the resolved address, current and best, the indirect note, the queued confirmation, the raw view, the error text, a real unstubbed looking glass call against the image, and the newest-first order after a remove and a rerun. `lab/uiproxy` tests decode the canned files with the API's own types. `internal/troubleshoot` tests cover the origin AS and reverse name on each hop.

## Prefix list

`/prefixes.html` (#183) shows the measured prefixes as a table, one page at a time, so a table of 100k prefixes costs one page per request. It is read-only and announces nothing; the mode banner is on top in every mode.

- **Table.** Prefix (links to its [detail page](#prefix-detail-and-history)), current exit, recommended exit, score gain, loss, RTT, and whether it is in the RIB. Loss and RTT are those of the current exit, or of the recommended exit when the current one has no successful probe. Score gain is the scorer's gain of the recommended exit over the current one (current score minus recommended score), and is blank unless the exits differ and both were usable. Details opens the same card as the prefix page, with the measured sub-ranges and the learned paths. MED in it is labelled display only and does not choose the exit. The card is built when a row opens, and open rows stay open through the 5-second refresh while they remain on the page.
- **Filters.** Prefix (a CIDR matches that prefix; other text matches as a substring), origin AS (the last AS of a learned path, as on the ASN map; `64500` or `AS64500`), provider (a probed, current, or recommended exit), and only where the recommended exit differs. Sort is prefix order, largest score gain, highest loss, or highest RTT; for loss and RTT, rows without a measurement sort last, and for score gain a row with none counts as zero; equal values keep prefix order so pages do not overlap. Rows per page is 25, 50 (default), 100, or 200.
- **URL.** The filters, sort, `page`, and `size` are in the query string (`/prefixes.html?asn=64500&sort=gain&page=2`), so a link opens the same view. Defaults are left out. A page past the end opens the last page.
- **Refresh.** Every 5 seconds the page asks for its own page again, not the table. Other pages do not read the list at all.
- **ASN map.** Bounded in the same response: the first 100 origin ASNs, each site listing at most 8 prefixes next to its full count. The heading of an ASN filters the table to it. Filtering by origin AS shows only that ASN. An origin AS that is not a number is marked on the page and not applied.

`GET /api/prefixes` (viewer) takes:

| Query | Meaning |
|---|---|
| `limit` | Rows per page, 1 to 500. Default 100. |
| `offset` | Rows to skip, 0 or more. Default 0. |
| `prefix`, `asn`, `provider`, `differs` | The filters above. `differs` is `true` or `false`. |
| `sort` | `prefix` (default), `gain`, `loss`, or `rtt`. The last three are highest first. |

A bad value is a `400`. The body keeps `prefixes` (each row also has `gain`, `exit_loss_pct`, and `exit_rtt_ms` when known) and `asn_map`, and adds `total` (rows that matched), `measured` (before filtering), `offset`, `limit`, and `asn_total` (origin ASNs after the origin AS filter, before the cut). A client that sends no parameters gets the first 100 rows in prefix order and can read `total` to see there are more; `/api/probes` is not paged. The `prefixes` dashboard widget shows that first page. In `asn_map`, a site's `prefixes` is cut to 8 and `count` is the full number.

The smoke step "UI prefix list smoke" in the docker job (`lab/ui-smoke.sh`) loads the page through `lab/uiproxy -fixtures lab/ui-fixtures/prefixes`. The proxy answers `/api/prefixes` with canned pages of 25 rows that claim 100000 measured prefixes (documentation prefixes and ASNs) and adds a script that opens a row, presses Next, and types an origin AS, because headless Chrome cannot click. The step checks the open card and its MED label, the bounded ASN map, the page 2 URL and rows, and the filtered result. The stock-image steps check the real API (default page, `offset` past the end, filters, and the `400` cases) and the page against it. `lab/uiproxy` tests decode the canned pages with the API's own type. `internal/httpapi` tests cover the filters, orders, and the response size and ASN map bound with 100k prefixes.

## Prefix detail and history

Every improvement row opens `/prefix/<prefix>` (#179), for example `/prefix/192.0.2.0/24` or `/prefix/2001:db8::/32`. The URL is shareable and a reload opens the same page. The links are on the Improvements page, the Improvements and Prefixes reports on Reports, and the improvements widget of a custom dashboard. The page is read-only and announces nothing; the mode banner is on top in every mode.

- **Card.** The same card as the Prefixes page: per-provider loss, RTT, and jitter, the current and recommended exit, measured sub-ranges, and learned paths with AS path, via, and MED. MED is labelled display only and does not choose the exit. It refreshes every five seconds. For a prefix Packeteer is not measuring now, the page says so and still shows the stored timeline.
- **Timeline.** Newest first, for 7, 30, 90, or 365 days: the daily probe rollup of each provider toward the prefix (UTC day, probes, failures, average loss, RTT, and jitter) and each improvement's start and end with provider, native provider, cause, reason, and the loss and RTT of both paths when it started (before and after) and why it ended. A record made in `observe` or `suggest` reads "Recommended"; only a record made in `inject` reads "Announced". Days are the finest history the store keeps. Without `storage: {type: sqlite}` the page says history is off.
- **Probe now.** A link to `/troubleshooting.html?tool=probe&target=<prefix>`, which opens the Probe tool with the tool and target filled in. Nothing runs until Run is pressed, and Probe keeps its operator role and rate limit ([troubleshooting](troubleshooting.md)).

`GET /api/prefixes/history?prefix=<prefix>&days=7` (viewer; `days`, or `from` and `to`, like the reports) returns `enabled`, `prefix`, `from`, `to`, `days` (`day`, `provider`, `probes`, `failed`, and the averages `loss_pct`, `rtt_ms`, `jitter_ms` when any probe returned statistics), and `improvements` (the rows of the improvements report, including `mode`). The prefix must be a network in CIDR form; anything else is a `400`. The match is exact: a covering or covered prefix is a different prefix. With no storage plugin it returns `enabled: false`.

CI loads the page twice in the graphs step of the docker job (`lab/ui-smoke.sh`), against history seeded by `lab/mkhistory`: the timeline, the "Recommended" wording with no "Announced", the MED label, and the Probe now link; then the Probe tool with the prefix filled in. `internal/history` and `internal/httpapi` tests cover the filtering, the API, and the page wiring.

## Link-outs

Prefix, ASN, and exchange-peer views link to the same object in public tools (#211). The links are display only. Packeteer makes no request to any of these sites, scrapes nothing, stores nothing they show, and the links do not affect probing or announcements. Each opens in a new tab with `noopener noreferrer`.

| Where | Links |
|---|---|
| Prefix page (`/prefix/<prefix>`) and an open row on `/prefixes.html` | The prefix, and on the prefix page the origin AS of its first learned path |
| `/prefixes.html?asn=<asn>` and each ASN map heading | The AS |
| Providers table (`/providers.html`), exchange peers only | The peer's AS (`peer_asn` in `GET /api/providers`) |

Built-in sites (names for `linkouts.enabled`; defaults marked):

| Name | Site | Prefix | AS |
|---|---|---|---|
| `he` (default) | Hurricane Electric BGP Toolkit | `bgp.he.net/net/<prefix>` | `bgp.he.net/AS<asn>` |
| `he_lg` (default) | HE looking glass | `lg.he.net`, opened without a query | - |
| `ripestat` (default) | RIPEstat | `stat.ripe.net/app/launchpad/<prefix>` | `stat.ripe.net/app/launchpad/AS<asn>` |
| `peeringdb` (default) | PeeringDB | - | `www.peeringdb.com/asn/<asn>` |
| `bgptools` (default) | bgp.tools | `bgp.tools/prefix/<prefix>` | `bgp.tools/as/<asn>` |
| `cloudflare_radar` (default) | Cloudflare Radar | - | `radar.cloudflare.com/routing/as<asn>` |
| `irr_explorer` (default) | IRR Explorer | `irrexplorer.nlnog.net/prefix/<prefix>` | - |
| `nlnog_ring` (off) | NLNOG RING looking glass | `lg.ring.nlnog.net/prefix?q=<prefix>` | - |

The RING link is a page the operator opens by hand. Packeteer does not call RING's API, log in to RING, or run commands on any RING node. PeeringDB is linked per AS: its AS page lists the exchanges the AS is on, and the exchange name in `exchanges` is a local label, not a PeeringDB object.

The server builds every URL, so the browser never assembles one. `GET /api/linkouts?prefix=<cidr>&asn=<n>` (viewer; both repeatable, at most 300 values; a bad value is a `400`) returns `{"prefix": {<cidr>: [{"name", "url"}]}, "asn": {<n>: [...]}}`. A prefix is masked and written as CIDR with `/` and `:` left readable; an AS is decimal digits. With `linkouts.hide_internal` on (default) an RFC 1918, ULA, loopback, or link-local prefix and a private-use AS (RFC 6996: 64512-65534, 4200000000-4294967294) get an empty list, so the page shows no link for it. Documentation prefixes and ASNs are not internal. Settings and the `linkouts` keys are in [CONFIG.md](CONFIG.md#linkouts); a change needs a restart.

The `ui-smoke` steps of the docker job load `/prefix/2001:db8::%2F32` and `/prefixes.html?asn=64496` in headless Chrome and check the rendered `href`s, `target`, and `rel`, that NLNOG RING is absent, and that an RFC 1918 prefix and a private-use AS render no link. `internal/linkout`, `internal/config`, and `internal/httpapi` tests cover the URLs, the template checks, and the page wiring.

## Global search

The search box in the top bar (#172) takes a prefix, an address, an AS number, or an AS name, and Enter opens `/search.html?q=<query>`. The page and `GET /api/search?q=` are read-only: they change nothing, announce nothing, and the mode banner stays on top.

| You type | Matches |
|---|---|
| `192.0.2.0/24` | That prefix (`exact`), prefixes that contain it (`covering`), and prefixes inside it (`more-specific`). A default route is never a covering match. |
| `192.0.2.77` | Prefixes that contain the address. |
| `AS64510`, `as64510`, or `64510` | Rows whose origin AS is that AS: the last AS of a learned path, and the origin stored with an improvement or a probe rollup. |
| `carrier` | Every AS whose known name contains the text (any case), then the rows of those AS numbers (at most 10 of them). |

Packeteer has no AS-name database. A name is known from an exchange peer in the config (`exchanges`, shown as the provider name) or from an ASN lookup made with the whois tool on the Troubleshooting page since the process started (at most 1000, kept in memory). A name that Packeteer has not seen finds nothing; search its AS number instead.

Results are grouped by type, newest first, at most 25 rows per list; each heading shows the full count:

- **AS numbers**: the AS or ASes searched, with the name when known.
- **Measured prefixes**: the prefixes Packeteer probes now, with the current and recommended exit and the last probe time.
- **Learned routes (RIB)**: routes in the learned RIB view, newest first.
- **Current recommendations** (current improvements in inject): what the decision engine holds now.
- **Stored improvements** and **Probe rollups**, for the last 90 days: improvement records and the per-prefix daily probe rollups, newest first. Without `storage: {type: sqlite}` these lists are empty and the page says history is off, so only live data was searched.

Each row links to its prefix page (`/prefix/<prefix>`), to the improvements report filtered to that prefix or origin AS (`/reports.html?report=improvements&prefix=<prefix>` or `&asn=<number>`, 90 days; the same `prefix` and `asn` parameters filter `GET /api/reports/improvements` and its CSV), and to the Probe tool (`/troubleshooting.html?tool=probe&target=<prefix>`, which runs nothing until Run). An AS row links to the Prefixes page filtered by AS, the filtered report, and the whois tool.

The last five searches are kept in this browser's local storage under the signed-in user's name (`local` without auth) and offered in the search box and on the search page. Nothing is stored on the controller.

`GET /api/search?q=` needs the viewer role. Input that is not a prefix, an address, an AS number from 1 to 4294967295, or a name of 2 to 64 letters, digits, spaces, and `. , & ( ) ' -` is a `400`. Each caller (user, or client address without auth) may search 10 times at once and then twice a second; more is a `429` with `Retry-After`. At most 1024 callers are tracked; while all of them are active, a further caller gets a `429` too. The body has `query`, `kind` (`prefix`, `asn`, or `name`), `limit`, `history` (`enabled`, `days`, and a `note` when history is off or did not answer), and the lists `asns`, `measured`, `rib`, `recommendations`, `improvements`, and `rollups`, each `{total, rows}`.

CI loads the page against the stock image with storage on (`lab/ui-smoke.sh`, docker job, "history survives a container restart" step): the grouped results, the links, the `400` and `405` cases, and the rate limit. The history-off note is covered by the `internal/httpapi` tests. `internal/httpapi`, `internal/history`, `internal/rib`, and `internal/troubleshoot` tests cover matching, ordering, caps, the limiter, and the name source.

## System health

The System page (#184) answers "which part is broken" when the status tile says not ready. It is read-only, announces nothing, and shows the mode banner in every mode. The Overview has a System tile (components down or degraded, or "all ok") that links to it.

`GET /api/system` (viewer) returns `summary` (`total`, `ok`, `degraded`, `down`, `idle`) and `components`. Each component has `kind`, `name`, `type`, `state`, `since`, `error`, and `detail`. `state` is `ok`, `degraded`, `down`, or `idle` (configured but nothing to do or report yet; not a fault).

| Kind | One row per | State comes from |
|---|---|---|
| `version` | the process | always `ok`; detail has the version and mode |
| `ha` | the elector, or one `role` row without `ha` | `degraded` when ineligible, or standby with no lease holder |
| `bgp_session` | `bgp.neighbors` entry | `down` until the session is established; `since` is the last state change. One `idle` row without neighbors |
| `rib_source` | `rib_sources` entry (BMP) | `down` when every router that reported a peer has closed its session, `degraded` when some have, `degraded` before any router reported. `since` is the latest change |
| `probe_source` | provider | the provider's probe-source health; `down` with the reason (for example the source address is not on the host). A provider measured by a peer POP is `idle` |
| `prober` | `probers` entry | `ok` when it produced a measurement (a 100% loss result counts), `down` when probes failed with an error naming it, `idle` when none used it (an earlier prober in the chain answered). Results of providers whose probe source is down are ignored |
| `source` | `sources` entry | `down` when its last call failed; `since` is when it started or stopped failing |
| `scorer` | the scorer | always `ok` |
| `announcer` | the announcer | `idle` and "announces nothing in observe mode" (or suggest) whatever is configured; in inject `ok` and "may announce allowlisted prefixes that are in the learned RIB", "announces nothing while this instance is standby", `degraded` without an iBGP session, `down` if inject has no announcer |
| `storage` | the storage plugin | the history recorder's and the event log's latest writes: `down` with the error while either one's latest write failed (the later failure is shown), `idle` before the first write. `idle` without a storage plugin |
| `notifier` | `notifiers` entry | the latest delivery attempt: `down` with the error when it failed, `idle` before the first. An event a filter or rate limit turned away is not an attempt |
| `telemetry` | `telemetry` entry | `down` when the poll or a binding reports an error; detail has the last poll |
| `federation_peer` | federation peer | `down` when its snapshot is stale or never seen. One `idle` row when standalone |

`since` is set where the component records state changes (sessions, sources, storage, notifiers, RIB sources, probe sources, HA). Telemetry and federation peers show the last poll or sighting in `detail` instead.

Results of storage writes, notifier deliveries, and BMP sessions are kept in memory from the start of the process. A notifier's state therefore reads `idle` until its first delivery attempt; a restart clears it. Nothing is probed or sent to build the page.

**No secrets.** Rows carry names, types, states, and error text only. A URL in an error is cut to scheme and host, so a webhook's path and token never appear. Plugin config, credentials, and SNMP communities are not read.

The "UI system page smoke" step of the docker job (`lab/ui-smoke.sh`) mounts an observe file with a webhook notifier aimed at a closed port, a provider whose probe source address is not on the host, and a `static` source, then loads `/system.html` in headless Chrome. It checks the rows and their states, that the announcer row says "announces nothing", that the webhook path never appears in the DOM, and `GET /api/system` and the System tile on `/`. `internal/httpapi` tests cover every state, the announcer wording by mode, and the redaction. `cmd/controller` tests inject a failing notifier, a read-only store, a failing source, and a closed BMP session through the real hooks and read them back on their rows.

## Events and audit log

The Events page (#173) lists what the controller reports to notifiers ([EVENTS.md](EVENTS.md)), newest first: time (local), source, severity, event, and detail (the message and its fields). Source is the event's catalog group (`provider`, `bgp`, `commit`, and so on). It is read-only and works in every mode.

- **Filters.** Severity (all, warning and critical, critical only), a text search over the event kind, message, and field names and values, and a range (last hour, 24 hours, 7 days, 30 days, all kept, or custom from and to). The page reloads every five seconds and on Refresh.
- **Where events are kept.** With a `storage` plugin of type `sqlite` they are written to the database and pruned with `retention`, so they survive a restart. Without storage the page shows the newest 1000 events since start, from memory, and says so. Events are recorded whether or not a notifier is configured, and a notifier's filter or rate limit does not hide an event from the page. With storage, a full write queue (256 events) drops new events and logs it. `audit.recorded` events are not listed: the Audit tab shows those records.
- **Top bar indicator.** The Events link in the top bar shows a count of warning and critical events newer than the last time this browser opened the page (100 or more shows `100+`). The time is the controller's clock, kept in the browser's local storage; nothing is stored on the controller. It refreshes every 15 seconds.
- **Audit tab (admin).** Time, actor, role, method, action, target, result, and status of the newest 200 records of `GET /api/audit` ([auth.md](auth.md#audit-log)). `/events.html#audit` opens it. A viewer or operator does not see the tab, and the API refuses them. It needs a storage plugin that keeps the audit log (`sqlite`); without one the tab says so. Passwords and token secrets are never in an audit record.

`GET /api/events` (viewer) takes `severity` (`info`, `warning`, `critical`; a floor), `q`, `from` and `to` (RFC 3339), and `limit` (1 to 1000, default 200). It returns `events` (`time`, `source`, `severity`, `kind`, `message`, `fields`), `stored`, `now`, and `since` when storage is off.

## Dashboard and first run

The dashboard (`/`) is built for a first run from the stock image with nothing but a mounted config file (#49):

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

- **Mode banner.** `observe` reads "Observe mode: Packeteer measures and recommends. It announces nothing." `suggest` also says it announces nothing. `inject` says improvements for allowlisted prefixes are announced. A file without `mode` observes. The banner is the first thing on every page, in every mode.
- **Mode chip (#171).** The header chip sets its own text and background. Observe is `#0b3a5b` on `#d4e4f4`, suggest is `#6a3b06` on `#f6e4c4`, inject is white on `#9d1c2a`, and any other mode is `#12263a` on `#e7eef5`. Each pair meets WCAG AA (4.5:1) for this text size. The chip no longer inherits the header's white text.
- **Overview tiles.** Mode, status (ready, not ready, starting), providers up, prefixes measured (and which sources list them), recommended improvements (outside inject) or active improvements (inject) against `max_improvements`, and BGP sessions with the number of probed prefixes in the learned RIB.
- **Setup checklist.** Shown until there is nothing left to do, most urgent first. `todo`: no `sources` (nothing to probe). `warn`: every probe through a provider fails (with the last error), every provider is down, `bgp.neighbors` is set but no session is up, or no probed prefix is in the learned RIB. `info`: still starting, waiting for the first round, no `bgp.neighbors` (the current exit is unknown), report history off. Each line names the doc to read. The checklist only reads state; fix the mounted file and restart.
- **Providers** (`/providers.html`) show `no data yet` until something is measured through them, `no answer` when every probe through them fails, and per-provider probe counts. The exchange view on that page is an empty state (#148).
- **Prefixes** (`/prefixes.html`) are a filtered, paged table; a row opens the prefix card with each learned path, its MED (display only) and `via` (route server, bilateral, or unknown; #146). See [Prefix list](#prefix-list). The ASN map is on the same page.
- **Improvements** (`/improvements.html`) are labeled recommended outside inject and active in inject.
- **Reports** (`/reports.html`) and **troubleshooting** (`/troubleshooting.html`) are the same sections as before, on their own URLs.
- **Optional sections** (POPs on Overview, threat mitigation on Protection) are hidden when not configured; the overview lists which optional features are on and off. Protection shows its empty state while the monitor is hidden.
- **Errors.** Every section shows `Loading…` until its first answer and a plain empty state after it. When the controller cannot be reached or answers with an error, a banner says so (sign-in required, not allowed, or unreachable), the last data stays on screen marked stale, and the page keeps retrying every 5 seconds.

`GET /api/overview` (viewer) is the same summary as JSON: `mode`, `ready`, `started`, `sources`, `providers` (`name`, `up`, `ok`, `failed`, `last_error`), `counts`, `bgp`, `features` (`name`, `on`), and `setup` (`id`, `level`, `title`, `detail`, `doc`). It is read-only and announces nothing.

CI runs a UI smoke test in the docker job (`lab/ui-smoke.sh`): headless Chrome loads every shell page from the stock image. The first run mounts `config.example.yaml` unchanged. The banner says observe and that it announces nothing, the header chip is `mode-observe`, the checklist on `/` asks for sources, `/providers.html` shows `no data yet`, `/improvements.html` says Recommended, and the empty pages name their issues. The second run uses a minimal file with no `mode` key and one static target (observe, the prefix measured with an RTT on `/prefixes.html`, no improvement).

A third run turns the config editor on with basic auth and sqlite, saves a dashboard of providers and improvements, and loads `/`, `/settings.html`, and `/dashboards.html` through `lab/uiproxy` (headless Chrome does not send URL credentials on later fetches). That run checks the filled provider fields keep their labels, the improvements widget says Recommended, and the provider `since` time is the local format.

The auth step of the docker job (#175) creates a viewer and a token through the API, then loads `/admin.html` and `/tokens.html` as the admin (the user table with its row actions) and as the viewer (the denial text, and only its own token), and the stock-image run checks both pages say they need `auth` when it is off. `internal/httpapi` tests drive the calls the pages make and read the audit log.

The settings forms (#130, #181) have their own smoke step in the same job. The stock image mounts an observe file that has a `flow`, `vip`, and `outage` source, a `rules` policy, and an exchange of two peers with an add-path neighbor. The step reads the form through the API, merges an edit, and requires the editor's start checks to accept the result as observe with inject not enabled. The merge adds a third peer, keeps the peers' hidden `precedence`, and the start checks accept it. It renders a wizard config with the flow step and requires the same. Headless Chrome then loads `/settings.html` through `lab/uiproxy` and checks that each section, the exchange and its peers included, is filled from the file, that the observe banner is on top, and that the wizard has its optional flow step. `internal/configedit`, `internal/httpapi`, and `cmd/controller` tests round-trip every section through `config.Load` and the start checks.

## Maintenance windows

With a `maintenance` policy ([CONFIG.md](CONFIG.md#policy-maintenance)), the Policies page (#177) lists its windows and opens and closes on-demand ones. It calls the existing API, so the role check, the policy's limits, and the audit record are the API's, and a window only excludes providers from improvements. The page announces nothing, the mode banner stays on top, and without the policy the section is hidden.

- **List.** One row per window with its state: `current` (open now), `upcoming`, or `finished`, each also in a color, then providers, start, end, source (`configured` or `on demand`), and note. Times show in the browser's time zone. Configured one-off windows are listed in all three states. A recurring (`schedule`) window is listed only while it is open. Finished on-demand windows stay for 24 hours (the last 50).
- **Open a window** (operator). Providers, a start, an end, and a note. The browser reads start and end as local time and sends them as RFC 3339 (`start`, `end`, `reason` in `POST /api/maintenance`). The policy's limits apply: the length is 1 minute to `max_api_duration`, the start is at most 7 days ahead, and a start that is already past is fine while the end is not. An upcoming window excludes nothing until its start.
- **Close** (operator). Each `current` or `upcoming` on-demand row has a Close button. Configured windows cannot be closed here. A closed window leaves the list.
- **Viewer.** The list only. There is no form and no Close button, and the page says opening needs the operator role. It also says so when auth or basic auth is off.

On-demand windows are in memory and end at a restart; put a planned window in the policy's `windows`.

The "UI maintenance page smoke" step of the docker job (`lab/ui-smoke.sh`) mounts an observe file with a `maintenance` policy (one past and one far-future one-off window) and loads `/policies.html` through `lab/uiproxy -fixtures lab/ui-fixtures/maintenance`. A driver script presses Open window twice (from now, and tomorrow at 10:00 local) and Close once, because headless Chrome cannot click. With Chrome in `Asia/Kolkata`, the step checks the list and its states, that 10:00 is shown as 10:00 and sent as `T04:30:00.000Z`, that Close removes the current window, and, through the real API, what is left. A second run through `lab/ui-fixtures/maintenance-viewer` answers `/api/me` as a viewer and checks the form is hidden, there is no Close button, and no write call is made. `internal/httpapi` tests cover the roles, the audit record, and the list against the real policy; `internal/plugins/policy/maintenance` tests cover future, finished, and bounded windows.

## Graphs

`/graphs.html` charts the `timeseries` report (#129): two charts, loss (%) and latency (ms), one point per UTC day. A dashed line is **before**, the native provider's path, and a solid line is **after**, the chosen provider's path. Both come from the same daily probe rollups, so they are measurements of the two paths whether or not the improvement was announced; in observe the chosen path is the recommended one. The page needs `storage: {type: sqlite}` and says so when history is off. With history but nothing to compare it shows "No before/after data in this range" and draws no chart. Under the charts, a Data table lists the plotted values. A day with no point breaks the line. Days are the finest history the store keeps, so there is no intra-day resolution.

The Destinations list picks one of four buckets, each a subset of the one before it where noted:

| Bucket (`bucket`) | What is in it |
|---|---|
| All destinations (`all`) | Every prefix with an improvement active on that day, when both its native and its chosen provider were measured that day. |
| Problem prefixes (`problem`) | The `all` prefixes whose improvement was made for performance (the native path broke the loss or latency thresholds), not for commit or cost. A record with no cause counts as performance. |
| 20% or more better (`better_20`) | Prefix-days on which the chosen path's average loss or average RTT was at least 20% lower than the native path's. |
| 50% or more better (`better_50`) | The same with 50%. A subset of `better_20`. |

Each point averages the prefixes in the bucket that day, weighted by measured probes. A prefix is placed per day from that day's rollups, so a prefix can be in `better_20` on one day and not the next. The Days list sets the range (7, 30, 90, or 365) and CSV downloads the same rows.

`GET /api/reports/timeseries` (viewer; `days`, or `from` and `to`, like every report) returns `rows`, one per day and bucket that has data, oldest first: `day`, `bucket`, `prefixes`, `before_loss_pct`, `after_loss_pct`, `before_rtt_ms`, `after_rtt_ms`. `limit` does not apply. A bucket and day with no data has no row.

The **Before/after graphs** dashboard widget (`{"type": "timeseries", "days": 7, "bucket": "all"}`; `days` 0 to 3660 and `bucket` one of the four ids, both optional) draws the same charts for one bucket. The charts are inline SVG drawn by `/charts.js`: no external script, font, or style, and nothing inline, so the CSP (same-origin scripts and styles only) holds. The page and the widget only read; they announce nothing, and the mode banner is on top in every mode.

CI (docker job) loads `/graphs.html` twice in headless Chrome: against the stock example config with empty history (the empty state, no chart), and against a history seeded by `lab/mkhistory` on documentation prefixes (the charts, the data table, and a `timeseries` dashboard widget). `internal/history` tests cover every bucket with synthetic history.

## Config editor

Turn it on in the file itself, and mount the file writable:

```yaml
http:
  listen: "127.0.0.1:8080"
  config_editor: true
```

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_HTTP_USER=ops -e PACKETEER_HTTP_PASSWORD='use-a-long-secret' \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

`/settings.html` loads the file, validates it, and saves it. The API:

- `GET /api/config`: `path`, `yaml`, and `sha256` of the file on disk.
- `POST /api/config/validate {"yaml": "..."}`: runs the checks without writing. Returns `valid`, `errors` (one line each), `mode`, `changed` (keys that differ from the running config), `restart_required`, `reload_online` (every change can apply while running: thresholds, hold time, the cap, policies, sources, probe timing, mode, the allowlist, and `bgp.neighbors`), and `enables_inject`.
- `PUT /api/config {"yaml": "...", "base": "<sha256>", "confirm_inject": false}`: writes the file.

A write is accepted only when:

- `base` is the `sha256` of the file on disk now (otherwise `409`: someone else changed it; reload and edit again);
- it adds or changes no `exec` plugin and keeps `plugin_dir` (see below);
- the new text passes the same checks the controller runs when it starts: `config.Load`'s strict parser and validator (unknown keys are errors), the environment overrides, every plugin's own config, and the cross-checks (auth, telemetry, VIP and outage intervals, anomaly source, report subscriptions). Otherwise `422` with the errors, and the file is not touched;
- a file that turns `mode: inject` on (and was not inject before) carries `confirm_inject: true` (otherwise `428`). The inject rules still apply: allowlist, `local_pref`, community, announcer, thresholds, hold time, and at least one neighbor are required by the validator.

The file is written next to itself and renamed into place when the directory allows it. A single-file bind mount cannot be renamed over, so the file is then rewritten in place (restored if that write fails; if the restore fails too, the old content is kept in a temporary file whose path is in the error). It is then read back and loaded with `config.Load`; the response is sent only after that. The file mode is kept. Comments and formatting are what you typed: the editor writes your text, not a re-rendered config. Files larger than 1 MiB are refused.

When `reload_online` is true, the running controller applies the file on this write (#128). The response adds `applied` (the keys now running) or `apply_error` (the running config was left as it was, or the process is stopping because the BGP speaker changed). A mix of online and restart-only keys is not applied: restart the container. SIGHUP applies the same online keys ([CONFIG.md](CONFIG.md#online-reconfiguration)). A restart withdraws every Packeteer route first, as always. The observe banner stays on the dashboard in every mode.

Every write, accepted or refused, is in the audit log with the old and new hashes (never the content) and is logged as a warning.

## Settings form

`/settings.html` puts a form beside the YAML (#102). The form has a row per provider (name, probe source, next hop, cost, commit), a row per static probe prefix, a row per allowlist prefix, and separate fields for hold time, the improvement cap, the loss and latency thresholds, the RTT percent (`min_rtt_delta_pct`, empty or 0 is off), confirm rounds (`confirm_rounds`, empty means 1), and, when the scorer is `cost`, whether cost or performance wins plus the floor (extra loss, extra delay). Plus adds a row and minus removes one.

Each provider field has a visible label above the input, and that label is the field's accessible name, including after the placeholder disappears (#171). Apply copies the form into the YAML in the editor and does not write the file. Save is still `PUT /api/config`: the same checks as a start, the same `confirm_inject` when the text turns inject on, and the same online apply as a SIGHUP when every change can run while the process is up (#128). A cap of 0 is a whole number and retires every improvement on the next decision. MED stays display-only. A next hop seen on the wire is a draft suggestion, not a provider, until it is saved as one.

Fields the form does not show stay in the YAML, including plugin blocks. An unchanged form is not reformatted. Commit is the SNMP telemetry binding's `commit_mbps` for that provider; there is no field for a community or a passphrase. A commit with no binding is refused until the binding is in the YAML. Choosing cost-or-performance, or setting the floor, on a `weighted` scorer (or none) switches `scorer.type` to `cost` and keeps the weights. It does not replace a `commit` scorer.

### Flow, policies, VIP, and outage (#130)

Four more sections sit under the allowlist. Each edits the **first** source or policy of its type; further ones, and every key the form does not show, stay in the YAML.

| Section | Edits | Notes |
|---|---|---|
| Flow collector | the first `flow` source: `listen` (comma separated `host:port`), `window`, `top_n` (the priority tier, probed every round), `max_targets`, `tail_interval`, `min_bytes`, `min_pct`, `exclude` | `problems`, `transit`, `subranges`, `aggregate_v4`, and `aggregate_v6` are kept as they are. Unchecking the box removes the source and those blocks from the YAML. Measurement only |
| Policies (rules) | the first `rules` policy: one row per rule (`name`, `action`, `providers`, `prefixes`, `asns`, `countries`, `traffic`, `max_loss_pct`, `max_rtt`) | Rules keep their order. Removing every rule removes that policy. `geoip_db`, `maintenance`, and any other policy stay in the YAML. A country rule still needs `geoip_db` in the file; the start checks say so on Validate or Save |
| VIP | the first `vip` source: `interval`, `max_targets`, prefixes with an optional pinned host, `asns` | Unchecking removes the source |
| Outage detection | the first `outage` source: `min_prefixes`, `window`, `loss_pct`, `rtt_ms`, `interval`, `max_targets`, `ignore_asns` | Empty fields use the defaults. Unchecking removes the source |

A policy or source only restricts, orders, or measures. The learned-RIB check, the allowlist, `max_improvements`, the community and NO_EXPORT, hold time, and the withdraw rules are unchanged, and nothing here can announce. The form checks each field the way the plugin does (types, bounds, duplicates, a rule's action against its providers and `max_loss_pct`, and that a rule names configured providers) and refuses with the field named. The start checks that need the whole file still run on Validate and Save, for example a flow `tail_interval` that must be longer than `probe.interval`. A section the operator did not change is not checked or rewritten, so a file the form does not fully model still lets the other fields apply.

`vip` ASNs and the `outage` source read the learned RIB: set `bgp.neighbors` before enabling them. A controller with no BGP session currently stops with a nil-pointer panic once either one runs. This change does not alter that.

`POST /api/config/form {"yaml"}` returns `form`, now with `flow`, `policies` (`rules`), `vip`, and `outage` objects (`enabled` on each source). A request that leaves a section out of `form` leaves that part of the file alone, so a client written before #130 cannot remove one. Saving is the same `PUT /api/config` as every other edit: admin role, the same checks as a start, `confirm_inject` when the text turns inject on, and a line in the audit log with the old and new hashes.

`POST /api/config/form {"yaml"}` returns `form`. `POST /api/config/form {"yaml","apply":true,"form":{...}}` returns the merged `yaml` and the form read back. Neither writes.

`GET /api/config/suggestions` lists next hops seen on iBGP (including add-path) or BMP that are not a configured provider and not on an exchange LAN: `next_hop`, `asn` (the most common first AS), and `prefixes`. The busiest 64 are returned. Accepting one in the page adds a draft provider row with the next hop and the AS shown. The probe source, cost, and commit stay empty. Accepting does not call the API, so it does not write a provider, start probing, or announce. Exchange LAN hops are listed on `GET /api/exchanges` and offered under Discovered members in the Exchanges section. The list is cached against the RIB generation and only reads.

**Secrets.** `GET /api/config` returns the file exactly as it is on disk, to every admin API client; nothing is redacted (a redacted file could not be saved back). With the editor on, keep every secret out of the file: built-in plugins only take secrets by environment variable name (`password_env`, `community_env`, `auth_env`, `client_secret_env`, `routing_key_env`), and webhook `url`/`headers` and exec `env` values should reference `${VAR}` instead of holding a token.

**Exec plugins.** Checking or saving a candidate never runs a program. `exec` plugins in the candidate are validated without running their command (no `init` handshake), and a candidate that adds or changes an `exec` plugin (command, args, env, anything in its block) or changes `plugin_dir` is refused with `422`. Which programs the controller runs is set only by editing the mounted file; removing an `exec` plugin through the editor is allowed.

The file is read-only in many deployments (`:ro`). Then saving fails with a clear error and nothing changes. Leave `config_editor` off if you manage the file with Git or configuration management.

### Exchanges (#181)

The Exchanges section lists every `exchanges` entry: `name`, peering `lans` (comma separated), `bmp`, `group`, and a row per peer (`name`, AS, next hop, probe source, cost). Plus and minus add and remove exchanges and peers. A peer's `exclude` and `precedence` stay in the YAML. There is no field for a session or route-server credential.

Apply checks what the form can see: names (unique across providers, exchanges, and peers), LANs without host bits, a non-zero AS, and a next hop inside one of the exchange's LANs. The route check requirement (`add_path` on a `bgp.neighbors` entry, or `bmp: prefer` or `only` with `rib_sources`), a peer's probe source, and the allowlist-versus-LAN overlap are checked by Validate and Save, as for a start. A file whose only providers are exchange peers is accepted. Exchanges are not an online key: Save writes the file and the change applies on restart. Nothing is probed or announced until then, and mode and the allowlist are not touched. A form that leaves `exchanges` out of the request leaves the block alone, and an unchanged form is not reformatted.

Below the exchanges, Discovered members lists the next hops on a peering LAN that are not peers, from `GET /api/exchanges` (the running controller's view, so an exchange lists members only once it is running and the form's exchange has the same name). Accept adds a draft peer to that exchange with the AS (the most common first AS, empty when unknown) and the next hop filled in. Name, probe source, and cost stay empty, so Apply refuses the row until it has a name and a probe source is set before Save. No PeeringDB name is looked up (#153). Accepting does not call the API, so it does not save, probe, or announce; a member that is already a peer row is not offered again. Refresh re-reads the running view.

The smoke step "UI settings forms smoke" in the docker job (`lab/ui-smoke.sh`) also loads the page through `lab/uiproxy -fixtures lab/ui-fixtures/exchanges`. The proxy answers `/api/exchanges` with two discovered members of `ix-lab` and one of an exchange the form does not have (documentation prefixes and ASNs), and adds a script that presses Accept, because headless Chrome cannot click. The step checks the list, the draft peer's fields, and that no config write was made. `lab/uiproxy` tests decode the canned answer with the API's own type.

### Mitigation, inbound, and anomaly rules (#131)

Three forms put the features most likely to be misconfigured on screen. Each block shows a badge with its own mode: `observe` (nothing is announced), `suggest` (inbound only; nothing is announced), or `inject`. The page banner stays on top in every mode.

**Flap quarantine** (#228). A prefix parked on its native path shows a `quarantined` badge on its card and, on the prefix page, a note with the flip count, the offense number, and when it ends. The page stays read-only; an operator releases it with `POST /api/quarantine/release` ([CONFIG.md](CONFIG.md#flap_quarantine)).

**Mitigation rules** (`/protection.html`, operator role). The form sits above the rule table and uses the existing API: `POST /api/mitigations` to add, `DELETE /api/mitigations/{id}` to remove. It needs the same things the API does: `mitigation` configured, and auth or basic auth on (otherwise the page says so and shows no form). With role-based auth the form is hidden below operator, and the server refuses the call anyway. Fields: the prefix, the action, a target for a redirect, the TTL, a reason, and for FlowSpec actions the match (source network, protocols, destination ports, source ports), a rate for a rate limit, and source countries when `mitigation.geoip_db` is set. Only the actions the announcer's catalog offers are listed (RTBH always; redirect when targets exist; FlowSpec when it is enabled).

The prefix picker reads `GET /api/mitigations/candidates?q=` (viewer): the prefixes in the **learned RIB view** that equal or sit inside the mitigation allowlist and contain `q`, at most 100, with `ready` (false until the RIB view is ready), `truncated`, and the allowlist. A default route is never listed. The form asks the same endpoint before it sends and refuses a prefix that is not in the answer, so it never submits a prefix outside the learned RIB view or the allowlist.

That is a convenience on top of the controller, not the rail: the controller checks the allowlist, `max_rules`, the TTL bounds, the catalog, the FlowSpec conflict rule, and the mode on every call, and announces only in `inject`, only a prefix that is in the learned RIB, with the community and NO_EXPORT, and withdraws when the rule ends, the controller stops, or the RIB session drops. Removing a rule takes two clicks (Remove, then Confirm remove). Every add and remove is in the audit log with the actor and the rule id.

In `observe` a rule is listed with the pending reason `mitigation.mode is observe (dry run, never announced)` and nothing reaches the announcer.

**Inbound and anomaly rules** (`/settings.html`, admin role). Two more sections of the settings form, through the same `POST /api/config/form` merge and `PUT /api/config` save as the sections above.

| Section | Edits | Notes |
|---|---|---|
| Inbound optimization | the `inbound` block: `mode`, `prefixes`, `local_pref`, `release_pct`, `max_improvements`, `moderated`, `performance` (`loss_pct`, `latency_ms`, `min_prefixes`, `release_pct`), `damping` (`disabled`, `confirm`, `backoff`, `max_hold`) | Mode offers `observe` and `suggest`. The form never turns inject on: a block that is already `inject` keeps it until changed, and turning it on is a YAML edit. The announcer stays in the YAML (shown as present or missing). Unchecking removes the whole block, announcer included. Empty fields use the defaults. A new block needs `telemetry` or the performance trigger, which the start checks say on Validate or Save |
| Anomaly rules | `anomaly.rules`: one row per rule (`name`, `prefixes`, `protocols`, `min_mbps`, `action`, `target`, `rate_mbps`, `ttl`) | The first matching rule wins and rules keep their order. The detector, `source`, `interval`, and the caps stay in the YAML, and rules need an `anomaly` block that already has a detector. Rule prefixes must be inside `mitigation.allowlist`, which is shown beside the rows. The badge shows the mitigation mode, because a rule acts only through the mitigation controller |

A section the operator did not change is not checked or rewritten, and a request that leaves a section out leaves that part of the file alone. A save that turns `inbound.mode` or `mitigation.mode` to `inject` needs `confirm_inject`, the same as turning on the top-level mode (a file that already had the block in inject does not ask again for an unrelated edit). Inbound and anomaly rules decide nothing about announcing: inbound steers still need top-level inject, an allowlisted prefix in the learned RIB, the community, NO_EXPORT, the cap, and hold time, and an anomaly rule only asks the mitigation controller.

`POST /api/config/form` returns `form` with `inbound` (`enabled`, `has_announcer` display only) and `anomaly` (`enabled`, `mitigation_mode`, and `mitigation_allowlist` display only; `rules`) objects. Display-only fields sent back by a client are ignored.

UI e2e: `internal/httpapi` tests drive the real mitigation controller in observe behind the API with an announcer that fails the test on any call: the page ships the form, the picker offers only learned prefixes inside the allowlist, a rule is added and removed through the calls the form makes, both are in the audit log, and the announcer is never reached. `internal/configedit` tests round-trip inbound and anomaly rules through `config.Load`. The docker job adds a smoke step (`#131`) that adds and removes a rule against the stock image in observe and loads both pages.

## Setup wizard

`/settings.html` walks four steps, the last optional (#106, #130). `POST /api/config/wizard` renders a config from them and writes nothing. The result opens in the editor for review, and you save it like any other edit.

1. Edge session: ASN, an IPv4 router ID, and the edge address. The session is learn-only iBGP.
2. Providers: one row each (name, probe source, next hop), with plus and minus. Each of those three fields has a visible label, the same way as the settings form (#171). A next hop from `GET /api/config/suggestions` can be added as a row; you still name it and set the probe source. Adding a row does not probe or announce.
3. What to probe: an optional prefix and an optional pinned host inside it. Leave both empty to add targets later in the form. A prefix without a host is probed at a few addresses inside it, including the provider next hop when that address can be used. A host pins that prefix to one address. Report history (sqlite) is a checkbox on this step, not a secret.
4. Flow collector (optional): a checkbox, a listen address (empty means every address), and a UDP port (default 2055). When on, the file gets a `flow` source listening there, with the source's defaults; tune it afterwards in the settings form. The step explains exporter setup: point the router's NetFlow v5/v9, IPFIX, or sFlow export at that host and port. Packeteer does not configure the router. With `--network host` the port is a host UDP port: do not publish it, and allow it only from the router. The generated file carries the same note. `POST /api/config/wizard` takes it as `"flow": {"listen": "192.0.2.10:2055"}`; a bad address or port is refused with the other wizard errors. Leaving the step off renders exactly what the wizard rendered before.

The rendered file is always:

- `mode: observe` (it measures and recommends; it never announces). Any other mode, including inject, is refused. Inject is not a step;
- an empty allowlist and no announcer;
- one `bgp.neighbors` entry, the edge address;
- the `weighted` scorer, `max_improvements: 50`, `hold_time: 15m`, the default thresholds, and `http.listen: 127.0.0.1:8080`;
- a `static` source only when a prefix was given, and a `flow` source only when the flow step was used;
- `packeteer_community` `<asn>:666` when the ASN fits in 16 bits.

There is no field for a password, a community string, or any other secret. Those stay in environment variables. The page checks each step before continuing, and the server checks the whole body again with `config.Parse`. The wizard is part of the editor: it is off (`404`) unless `http.config_editor` is on. Turning inject on afterwards is a separate edit; follow the [inject checklist](CONFIG.md#inject-checklist).

## Custom dashboards

`/dashboards.html` builds dashboards from read-only widgets. Each user has their own (at most 20, with at most 24 widgets each), kept by the storage plugin (`sqlite`, table `dashboards`). Widgets read endpoints the viewer role can already read: readiness, providers, prefixes, improvements, decisions, provider usage, inbound steers, threat mitigation, anomalies, POPs, HA, report subscriptions, and any stored report with a range in days, and the before/after graphs (type `timeseries`, below). A widget can span the full row.

The improvements widget is titled Recommended improvements in observe and suggest, and Active improvements in inject (#171). A title the operator set on that widget is kept. Timestamps in a widget use the same local format as the main dashboard (`toLocaleString`). An unparseable value stays as returned.

API: `GET /api/dashboards` returns `widget_types`, the report list, and your dashboards; `PUT /api/dashboards/<name>` with `{"title": "...", "widgets": [{"type": "providers"}, {"type": "report", "report": "summary", "days": 7, "wide": true}, {"type": "timeseries", "days": 30, "bucket": "better_50"}]}` saves one (unknown widget types, unknown reports, an unknown `bucket`, `report`, `days`, or `bucket` on a widget type that does not take them, and unknown fields are refused); `DELETE /api/dashboards/<name>` removes it. Deleting a user deletes that user's dashboards.

## Report subscriptions

```yaml
storage:
  type: sqlite
notifiers:
  - type: smtp
    name: mail
    config:
      host: smtp.example.net
      from: packeteer@example.net
      to: [noc@example.net]
      username_env: PACKETEER_SMTP_USER
      password_env: PACKETEER_SMTP_PASSWORD
report_subscriptions:
  - name: weekly-summary
    report: summary
    schedule: weekly        # daily, weekly (weekday, default monday), monthly (the 1st)
    at: "06:00"             # UTC
    notifier: mail
  - name: monthly-savings
    report: savings
    schedule: monthly
    days: 31
    notifier: mail
    to: [finance@example.net]
```

Each send is one email from the named `smtp` notifier: a short text body (report, range, row count) and the report as a CSV attachment, the same rows `/api/reports/<report>?format=csv` returns for the range ending at the send time. The notifier's event filters do not apply to reports; a subscription's `to` replaces the notifier's recipients. Recipients come only from the file; the API cannot add one.

At start the controller refuses an unknown report name or a notifier that cannot send reports (webhook, SNMP trap, exec). A failed send is logged, counted, and shown on `/api/subscriptions`, and tried again at the next scheduled time. Sends missed while the controller was down are not replayed. `POST /api/subscriptions/<name>/send` (operator) sends one now for the range ending now, without moving the schedule.

## Improvement weights

When more prefixes want an improvement than `max_improvements` allows, Packeteer admits the biggest score gains first. With `improvement_weights` on the scorer, it admits the highest weight instead:

```yaml
scorer:
  type: weighted
  config:
    improvement_weights:
      performance: 1   # times the score gain (default 1)
      volume: 1        # times the prefix's traffic in Mbps (default 0)
```

`weight = performance × gain + volume × volume_mbps`. The gain is the native path's score minus the chosen path's; with the default `weighted` scores, 1 ms of RTT is 1 point and 1 % of loss is 100 points. The volume comes from a source that reports it: the `flow` window, or `mbps` on a `static` target. A prefix with no volume counts 0.

Weights only order moves inside their lane: static policy pins first, then VIP moves, then other performance moves. Commit and cost moves keep their relief and savings order. Each move's weight is on `/api/decisions` (`weight`).

Weights never relax a rule: a prefix must still be an exact prefix in the learned RIB and, in inject, allowlisted; the thresholds, hold time, and cooldowns apply as before; the cap is never exceeded; an active improvement is never displaced by a heavier newcomer (no churn); every route still carries `packeteer_community` and NO_EXPORT; and routes are withdrawn on shutdown, stale data, and session loss as always.

Lab proof (`lab/e2e-weights.sh`, CI job `e2e`): an FRR edge advertises 198.51.100.0/24 (5 Mbps) and 203.0.113.0/24 (500 Mbps) with the same gain, and `max_improvements: 1`. The heavier 203.0.113.0/24 takes the slot (without weights the other one would: equal gains break by prefix), with next hop, local-pref, community, and NO_EXPORT; 198.51.100.0/24 is capped with its weight on `/api/decisions`; 198.51.100.0/25, the heaviest and allowlisted but never advertised, is never announced; a real RIB leave withdraws the route and hands the slot over; the heavier prefix coming back does not displace it; SIGTERM withdraws; a restart gives the slot to the heavier prefix again; SIGKILL drops the route with the session within the hold timer. Lab-proven only, not on a public edge.

## Upgrade from the UI

Issue #196. The Settings page has a Version and upgrade section (admin). It always shows the running version, whether this is a container or a binary install, and the architecture. With `upgrade.enabled: true` and `upgrade.public_key` ([CONFIG.md](CONFIG.md#upgrade)) it also:

- **Checks** (`POST /api/upgrade/check`): reads the newest GitHub releases of `upgrade.repo` and shows each tag, publish date, and release notes (as text), marking the running one, newer ones, and any release that has no signed binary for this architecture. A check changes nothing. It is opt-in: the default is a check only when an admin presses the button; `upgrade.check_interval` adds a background check that only notifies (the page and the log say a newer release exists). Nothing ever upgrades automatically.
- **Upgrades** (`POST /api/upgrade/apply {"tag": "v0.6.0", "confirm": true}`): the page asks for confirmation and says what happens. Nothing changes until the new version has been prepared and has passed three checks, in this order: the release's `SHA256SUMS.sig` verifies against `upgrade.public_key`; the binary's SHA-256 equals its `SHA256SUMS` entry; and the new binary, run with `-version` and `-check` against this container's mounted config, reports the release's version and accepts the config. Any failure answers with an error and leaves everything as it was (no staged binary, no state, no shutdown). The failure is in the audit log.
- **Switches**: once prepared, the controller shuts down through the same path as SIGTERM. Mitigation, inbound, and outbound routes are withdrawn while the sessions are up, the HA lease is released after the withdraw, the notifiers are told, and the plugins stop. Only then does the process start the new binary in place (`exec`: the PID, so the container, does not change). The new version starts in the configured mode (observe stays observe), has no state carried over, learns the RIB again, and injects only after fresh probes and the hold time, for a prefix that is in its learned view. If the shutdown ends with a non-zero exit (a plugin that fails to stop, a failed config reload), or a SIGINT or SIGTERM arrives while the switch is prepared, the switch is undone and the process exits as it would without an upgrade. A withdraw that failed does not undo the switch: the `exec` closes the BGP sessions, and without graceful restart the routes go with them.
- **Rolls back** (`POST /api/upgrade/rollback {"confirm": true}`): the previous version stays on disk (the installed binary, or the last staged one). Rollback runs the same start check on it, then the same shutdown and start. The config file is never written by an upgrade or a rollback.

**Install types.** Both work the same way. The installed binary (the image's `/usr/local/bin/packeteer`, or the file on a host) is never overwritten. A verified release is kept under `upgrade.dir` (`versions/<version>/packeteer`) with `state.json`, and the installed binary hands over to it at start, before anything else is started. Consequences, so there are no surprises: the container is not recreated, so `docker run` with the same config and a volume on `/var/lib/packeteer` keeps the staged version across `docker restart` and recreation; without the volume, a recreated container starts the image's version again (the staged copy is lost with the old container). Pulling a newer image is the other upgrade path: when the installed binary's version differs from the one the state was made for, the state is discarded and the image's version runs. A staged version that fails to start twice in a row without staying up for 30 seconds is dropped and the previous version runs again; the page shows why. Deleting `state.json` returns to the installed version. Keep `upgrade.dir` writable only by the user Packeteer runs as: a staged binary is checked against its recorded SHA-256 at every start, but the directory is trusted like the installed binary. The pinned `public_key` is what decides whether a release is trusted, not the GitHub account.

**Release assets** (`.github/workflows/publish.yml`, on a version tag): `packeteer-linux-amd64`, `packeteer-linux-arm64` (static, `-X main.version=<version>`), `SHA256SUMS`, and `SHA256SUMS.sig` (base64 Ed25519 over the exact bytes of `SHA256SUMS`, made by `go run ./cmd/relsign sign`). The maintainer makes the key pair once with `go run ./cmd/relsign keygen`, keeps the private key in the repository secret `RELEASE_SIGNING_KEY`, and publishes the public key with the release notes. A release without all four assets is listed but cannot be installed.

**High availability.** The pair is upgraded one node at a time, standby first. A standby only upgrades while another node holds the lease (otherwise `409`: restarting it would leave no controller). The active node refuses unless the request carries `standby_upgraded: true`, which the page asks for with a checkbox: you confirm the standby already runs the target version. The active node's shutdown withdraws its routes and releases the lease, so the upgraded standby takes over; the restarted node comes back as the standby. The lease keeps the two from announcing at once ([ha.md](ha.md)).

**Audit.** Every check, upgrade, and rollback is a `POST`, so the audit log records it with the signed-in user, the target version, and the result, refusals included (`POST /api/upgrade/check`, `/apply`, `/rollback`). A background check is recorded as `system`. Needs auth or basic auth; with neither, upgrade and rollback answer `403`.

**Tests.** `internal/upgrade` (signature, checksum, bad signature, bad checksum, unsigned release, failed start check, all abort with no change; staging, rollback, HA order, the launcher's attempt limit and tamper check), `internal/httpapi` (roles, audit, errors), and `cmd/controller`: `TestDaemonUpgradeWithdrawsRelearnsAndRollsBack` runs the controller in inject against a simulated GoBGP edge with an injected route present. The edge sees the route withdrawn before the new binary is started; the new version, with the edge no longer advertising the prefix, announces nothing; when the edge advertises it again the route returns; rollback repeats the withdraw; the config file is byte-identical throughout. `lab/e2e-upgrade.sh` (CI jobs `test`, binary, and `docker`, stock image) runs the real binary against `lab/fakerelease`: bad signature and bad checksum refused, an unconfirmed upgrade refused, a confirmed upgrade in the same process (same PID, same container, not restarted), rollback, the Settings page in headless Chrome, and a clean SIGTERM exit.

## Rollback

The upgrade section (#196) is rolled back by removing the `upgrade` block (or `enabled: false`) and restarting; the installed binary then runs. To leave a staged version: use the Roll back button, or stop the controller and delete `state.json` in `upgrade.dir`. It adds no write to the config file.

The graphs (#129) are read-only and need no rollback. Delete a `timeseries` widget from a dashboard to hide it; a build from before #129 refuses to save a dashboard that still has one.

The mitigation form and the inbound and anomaly sections (#131) are UI and API only and add no config key: revert the change to drop them, or remove the rules in the YAML (a restart withdraws every Packeteer route first, and mitigation rules are in memory, so they also go with a restart). The form sections and the wizard's flow step (#130) are UI and API only and add no config key: revert the change to drop them, or delete the `flow`, `vip`, and `outage` sources and the `rules` policies from the YAML (a restart withdraws every Packeteer route first). A file the form wrote is an ordinary config file that an older build loads unchanged.

Remove `improvement_weights`, `http.config_editor`, and `report_subscriptions` and restart. The dashboard polish (#49) needs no rollback: it reads the same state, and `/api/overview` is read-only. The file config works exactly as before; the editor only ever wrote a plain YAML file. Stored dashboards stay in the database and are ignored by an older build. The display fixes (#171) are presentation only: revert that change to restore the previous chip, titles, timestamps, and unlabeled provider fields. The shell (#170) is presentation only as well: revert it to put every section back on `/`.

The System page (#184) is UI and API only and adds no config key; revert it to drop the page, the tile, and `/api/system`. The result hooks it adds (notifier delivery, storage write, BMP session) only record.

The Events page (#173) only reads; revert it to bring back the empty page. The `events` table it adds to the `sqlite` file is ignored by an older build. No config key changes.
