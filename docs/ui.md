# Dashboard, config editor, wizard, dashboards, report subscriptions, and improvement weights

The remaining UI conveniences (#34). All of them work in the stock image with a mounted config file. None of them announces a route, and the default mode stays `observe`. Every key is in [CONFIG.md](CONFIG.md).

| Feature | Where | Who | Config |
|---|---|---|---|
| Commit & Cost (#174) | `/commit.html`, `GET /api/commit`; setup in `/settings.html#commit-setup` | viewer to read, admin to set up | `telemetry` (`snmp`) + `storage: {type: sqlite}` for the graph |
| Reports page (#178) | `/reports.html`, `GET /api/reports`, `GET /api/reports/{name}` (JSON, CSV, XLSX) | viewer | `storage: {type: sqlite}` |
| Before/after graphs (#129) | `/graphs.html`, `/api/reports/timeseries`, the `timeseries` dashboard widget | viewer | `storage: {type: sqlite}` |
| Troubleshooting results (#180) | `/troubleshooting.html`, `/api/troubleshoot/...` | viewer for the looking glass, operator for probe, traceroute, and whois | `troubleshoot.enabled` for the active tools |
| Prefix list (#183) | `/prefixes.html`, `/api/prefixes` | viewer | none |
| Prefix detail and history (#179) | `/prefix/<prefix>`, `/api/prefixes/history` | viewer | `storage: {type: sqlite}` for the timeline |
| Why? panel (#201) | `/prefix/<prefix>`, `GET /api/decisions/<prefix>` | viewer | none |
| Maintenance windows (#177) | `/policies.html`, `GET`/`POST /api/maintenance`, `DELETE /api/maintenance/{id}` | viewer reads, operator opens and closes | a `maintenance` policy; opening needs auth or basic auth |
| Link-outs (#211) | `/prefix/<prefix>`, `/prefixes.html`, `/providers.html`, `GET /api/linkouts` | viewer | `linkouts` (optional) |
| NLNOG RING panel (#283) | `/prefix/<prefix>`, `GET /api/ring_lg` | viewer | `ring_lg.enabled` (off by default) |
| Global search (#172) | the top bar on every page, `/search.html`, `GET /api/search` | viewer | `storage: {type: sqlite}` for history |
| IXP site health (#167) | `/ixp/sites`, `GET /api/ixp/sites` | viewer | `ixp` and `federation` ([design/ixp.md](design/ixp.md#multi-site-fabric-health)) |
| IXP member pages (#166) | `/ixp/member/<asn>`, `/ixp/member/`, `GET /api/ixp/members/{asn}` | viewer | `ixp` ([design/ixp.md](design/ixp.md#member-pages)) |
| System health (#184) | `/system.html`, `/api/system`, the System tile on `/` | viewer | none |
| Events and audit log (#173) | `/events.html`, `/api/events`, `/api/audit` | viewer for events, admin for the audit tab | `storage: {type: sqlite}` keeps events across a restart |
| Users and API tokens (#175) | `/admin.html`, `/tokens.html`, `/api/users`, `/api/tokens` | admin for users, every signed-in user for tokens | `storage` + `auth.enabled` |
| Dashboard overview and setup checklist (#49) | `/`, `/api/overview` | viewer | none |
| Config editor and settings form (#102, inbound and anomaly rules #131, exchanges #181, guided inputs #329, every block #330) | `/settings.html`, `/api/config`, `POST /api/config/form` | admin | `http.config_editor: true` (or unset during first-run setup) + auth or basic auth |
| Setup wizard (#106, flow step #130, keeps an existing config #345) | `/settings.html`, `POST /api/config/wizard` | admin | `http.config_editor: true` (or unset during first-run setup) + auth or basic auth |
| Custom dashboards | `/dashboards.html`, `/api/dashboards` | every signed-in user, own dashboards | `storage: {type: sqlite}` + auth or basic auth |
| Report subscriptions | `report_subscriptions`, `/api/subscriptions` | viewers see them, operators send now | `storage` + an `smtp` notifier |
| Herd (#260, page #296) | `/herd.html`, `GET /api/herd`, `/api/herd/{overview,events,mesh,monitor,map,search,vantages,outside}`, `/api/herd/preview` | viewer, admin for preview | `herd` ([herd.md](herd.md#dashboard)) |
| Version check, upgrade, and rollback (#196) | `/settings.html`, `GET /api/upgrade`, `POST /api/upgrade/{check,apply,rollback}` | admin | `upgrade.enabled: true` + `upgrade.public_key` + auth or basic auth |
| Improvement weights | `scorer.config.improvement_weights`, `/api/decisions` | - | `weighted`, `commit`, or `cost` scorer |

With `auth` on, roles are checked per route like every other endpoint ([auth.md](auth.md)); with basic auth, the one account may do everything; with neither, the editor, the wizard, dashboards, and send-now are refused.

## Shell

Every page has the same chrome (#170). The mode banner is the first thing on the page, above a left navigation and a top bar. A reload of a page URL opens that page. The navigation links are:

| Page | URL | What is on it |
|---|---|---|
| Overview | `/` | Latency and improvement charts, tiles, setup checklist (with a Fix in Settings link when the config editor is on), optional features, and POPs when federation is on (an admin also gets Push settings to peers there, [multi-pop.md](multi-pop.md#pushing-settings)) |
| Dashboards | `/dashboards.html` | Custom dashboards (the existing page) |
| Improvements | `/improvements.html` | Recommended or active improvements |
| Prefixes & ASNs | `/prefixes.html` | The measured-prefix table, one page at a time, and the ASN map ([below](#prefix-list)) |
| Graphs | `/graphs.html` | Before/after loss and latency charts (#129; [below](#graphs)). Empty state without history |
| Reports | `/reports.html` | History reports by category with a range, filters, sortable columns, and CSV and XLSX export ([below](#reports)) |
| Providers & Exchanges | `/providers.html` | Provider health with latency, loss, jitter, a trend, and Mbps, and per exchange its peers, improvements with Mbps moved, and discovered members ([below](#exchanges-view)) |
| Commit & Cost | `/commit.html` | Usage against commit per provider, 1, 7, or 30 days ([below](#commit--cost)) |
| Policies | `/policies.html` | Points to Settings, where the `rules` policy is edited (#130). It does not list rules yet. With a `maintenance` policy, it lists maintenance windows ([below](#maintenance-windows)) |
| Protection | `/protection.html` | The threat-mitigation monitor with an add and remove rule form (#131) when that feature is on. Otherwise an empty state that says how to configure it |
| Troubleshooting | `/troubleshooting.html` | Looking glass, probe, traceroute, whois ([below](#troubleshooting-results)) |
| Events | `/events.html` | Recent events and, for admins, the audit log ([below](#events-and-audit-log)) |
| System | `/system.html` | One row per component with state, since, and last error ([below](#system-health)) |
| Tokens | `/tokens.html` | The signed-in user's API tokens ([below](#users-and-api-tokens)) |
| Settings | `/settings.html` | Wizard, settings form, YAML, report subscriptions. Admin |
| Admin | `/admin.html` | Users ([below](#users-and-api-tokens)). Admin |

POPs stay on Overview and the threat-mitigation monitor stays on Protection. Both stay hidden when the feature is off, as they did on the single dashboard.

**Keyboard and screen readers (#353).** The first Tab on every page, sign-in included, focuses "Skip to content"; it is hidden until focused, and activating it moves focus to `<main id="main">`. The focus ring is 3 px blue (`#2f80ed`), at least 3:1 against the dark nav, the page, and white. Each page has one `<h1>`, its title; the Settings page's title is "Settings", over the wizard and the forms. The raw YAML text box is labelled "Config file (YAML)". `internal/httpapi` tests check the markup of every page. The docker job's UI display smoke step loads `/settings.html` through `lab/uiproxy -fixtures lab/ui-fixtures/a11y`, whose script focuses the first focusable element (headless Chrome cannot press Tab), activates the skip link, measures the ring, and fetches each nav page for the same markup rules.

**Phones (#352).** Below 760 px wide the navigation links are behind a "Menu" button (a 44 px target; Escape closes the list and returns focus to the button), the top bar is one row, and the search box shows only while the menu is open. A table row becomes a card: each cell gets its column name as a label, empty cells are hidden, and on Providers the Health cell comes first and on Events the severity and the message do. Tables inside a scrolling container (Reports) keep their columns. The 760 px breakpoint replaces the old 800 px one, so from 760 px up the full side nav shows. Every page carries the Menu button and a wrapper around the nav links; the table labels are added only on a narrow screen. The docker job's "UI display smoke" step loads every nav page in a 390x844 frame through `lab/uiproxy -fixtures lab/ui-fixtures/mobile` (headless Chrome will not open a window under 500 px, so the fixture lets the proxy's pages be framed by their own origin) and checks the list is collapsed, the page's h1 starts within 150 px, Providers, Improvements, Events, and Prefixes have no sideways scroll or clipped cell, and each provider's Health text is fully visible, including one that does not answer. `lab/uiproxy` tests decode the canned answers with the API's own types.

The brand link shows the Packeteer logo next to the name (`alt="Packeteer logo"`). The same embedded file, `/logo.png` (the 128px mark, drawn at 32px), is the favicon on every page, including sign-in. It is public, with the sign-in files, so the icon loads before a session. Pages do not link `docs/`. The UI smoke test checks the markup and that `/logo.png` returns a PNG.

The top bar holds the mode chip, a search slot, an events slot, and the account menu. The search slot does not query (#172). The events slot opens the Events page and shows how many warnings (or worse) arrived since this browser last opened it. The account menu shows who is signed in (`GET /api/me`). Sign out appears when the request carries a session cookie, from the sign-in page or single sign-on, and calls `POST /auth/logout`. A request signed with basic auth or an API token has no session, so no sign-out item.

**Sign-in page (#176).** With sign-in on (the default, #328), a browser without a session that asks for a page over https (or through a proxy that sends `X-Forwarded-Proto: https`) or on localhost is sent to `/signin.html`. Over plain http to any other address it gets the basic-auth prompt, because the browser would drop the `Secure` cookie. API paths and `/metrics` answer `401`. The page asks for a user name and password, posts them as JSON to `POST /auth/signin`, and on success loads the dashboard. The server keeps the session in memory and sets a `packeteer_session` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, lifetime `auth.session_ttl`). The page shows the mode banner and a single sign-on link when an `sso` plugin is configured. A wrong user name or password gets one answer (`401`); ten failures from one address in five minutes lock that address out (`429`), counted together with basic auth. Basic auth and API tokens work as before for scripts. The mode banner on the page comes from `GET /auth/signin`, which needs no sign-in. With `auth.enabled: false` the sign-in POST answers `404` and the browser keeps its basic-auth prompt.

**First-run password change (#328).** The generated first-run admin password signs in but only buys a password change: the page then shows a change form (current password, new password twice) that posts to `POST /api/account/password`, and any other page or call from that account goes back to it (`/signin.html?change=1`). On success the dashboard loads. [auth.md](auth.md#first-run) has the API side. **Sign-in off banner.** With `auth.enabled: false` every page shows a red banner, "Sign-in is off (auth.enabled: false)", driven by `auth` in `GET /api/overview`; the start log warns too.

Settings and Admin are marked admin-only. With role-based auth, a viewer or an operator does not see those two links. Opening Admin directly says "Your account may not read this page." Opening Settings directly keeps the editor's existing not-allowed message; report subscriptions on that page are unchanged. With auth off, or with the one basic-auth account, both links are shown. Nothing in the shell announces, and it does not write config.

## Commit & Cost

`/commit.html` (#174) shows billable usage against commit for each provider that has a telemetry binding. It is read-only and announces nothing; the mode banner is on top in every mode.

- **Summary.** One row per binding: commit, the billable 95th (what commit control compares with the commit), its share of the commit (red at 100% or more), the samples in the open billing period, the period, the last sample, and the last poll error.
- **Graph.** One per provider for 1, 7, or 30 days (`?days=30` in the URL): the busiest sample in each point (thin line), the running 95th of the billing period (thick line, which starts over at a period change), the commit (dashed), and a vertical bar where commit control moved traffic off or onto the provider. A point is 5 minutes, 30 minutes, or 2 hours wide. The running 95th counts the whole billing period, so a range that starts mid-period still starts from the period's samples. Which figure a sample is follows the binding's `percentile`: the larger direction for `greater` and `greater_separate`, outbound for `separate`. A Data table lists the newest points.
- **Moves.** A bar is a commit improvement from stored history, grouped by time and peer. In observe, and in any record made outside inject, it reads "Recommended"; only a record made in inject reads "Announced". Without storage the page says moves are not recorded.
- **Empty states.** With no telemetry binding the page says so and links to Commit setup. Without `storage: {type: sqlite}` the summary still shows the open period and the graph says samples are not stored. A binding with no stored samples in the range says so on its card. The `fixed` telemetry plugin has no interface, so it has a summary row and no graph.

`GET /api/commit` is in [API.md](API.md).

### Commit setup

The Settings page has a four-step Commit setup (`#commit-setup`) over the settings form's `commit` section and `POST /api/config/form`. It needs `http.config_editor: true`, the admin role, and auth or basic auth, like the form. It writes YAML text only: Apply copies the choices into the editor and validates them with the same checks as a start, Save is the editor's (hash check, audit record), and nothing applies until a restart. It does not change `mode`, the allowlist, or `max_improvements`.

1. **Strategy.** `weighted`, `commit` (with the balance mode for a group), or `cost` (cost or performance first). Switching keeps the shared weights and drops the other scorer's keys. A scorer of another type is not replaced.
2. **Commit and telemetry.** Tick a provider, then its commit (Mbps), SNMP host, interface, billing day (1-28), and percentile. A host is picked from the file's `snmp` hosts, or added with a name, an address, and the name of the environment variable that holds the community (version 2c). No field takes a community or passphrase. The host cards in this step also edit existing hosts and switch them to version 3 (a user and the names of the environment variables for its secrets). A provider's binding is removed by clearing its host. A commit with no binding is refused as before.
3. **Groups and precedence.** Per provider: `group`, `precedence` (lower is preferred, blank is 100), and `cc_disable`.
4. **Review.** The list of what Apply will write, then Apply.

Next hops seen on iBGP or BMP stay suggestions in the provider table; they never become a provider here.

The smoke steps "UI commit smoke" in the docker job (`lab/ui-smoke.sh`) and the empty state in the stock-image step load the page. The first seeds `lab/mkhistory -commit` (samples and commit improvements on documentation names, one move recorded in inject), checks `/api/commit` for 1, 7, and 30 days, loads the page for each, and then loads `/settings.html` through `lab/uiproxy -fixtures lab/ui-fixtures/commit`. The injected driver presses the setup through (headless Chrome cannot click), including a community typed where a variable name goes, which the page refuses, a provider renamed after its commit is ticked, and a config with `cc_disable: True` and `percentile: Separate` (the form reads both as the loader does); the answers are the real API's and the editor's check says Valid. `internal/commitview`, `internal/configedit`, and `internal/httpapi` tests cover the series, the form round trip through `config.Parse`, and the API.

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

- **Table.** Prefix (links to its [detail page](#prefix-detail-and-history)), the exit now, the recommended exit, expected gain, loss, RTT, and whether the router advertises it ("On router"). Loss and RTT are those of the current exit, or of the recommended exit when the current one has no successful probe. Expected gain is the scorer's gain of the recommended exit over the current one (current score minus recommended score), and is blank unless the exits differ and both were usable. In observe and suggest the exit columns are "Traffic now (router)", the learned path, and "Packeteer recommends", so a recommendation is never shown as where traffic goes; in inject they are "Current" and "Recommended". Details opens the same card as the prefix page, with the measured sub-ranges and the learned paths. MED in it is labelled display only and does not choose the exit. The card is built when a row opens, and open rows stay open through the 5-second refresh while they remain on the page.
- **Smoke test.** The "UI observe wording smoke" step of the docker job (`lab/ui-smoke.sh`) loads `/prefixes.html`, the prefix page, and `/events.html` of an observe image through `lab/uiproxy -fixtures lab/ui-fixtures/observe-wording`, which answers `/api/prefixes` and `/api/events` with one pending recommendation on documentation prefixes. It checks the two labels and the event wording, and that "steered" does not appear. `internal/httpapi` tests cover the API values and `cmd/controller` tests the event text in each mode.
- **Filters.** Prefix (a CIDR matches that prefix; other text matches as a substring), origin AS (the last AS of a learned path, as on the ASN map; `64500` or `AS64500`), provider (a probed, current, or recommended exit), and only where the recommended exit differs. Sort is prefix order, largest expected gain, highest loss, or highest RTT; for loss and RTT, rows without a measurement sort last, and for expected gain a row with none counts as zero; equal values keep prefix order so pages do not overlap. Rows per page is 25, 50 (default), 100, or 200.
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

- **Card.** The same card as the Prefixes page: per-provider loss, RTT (with connect, TLS handshake, and first byte in its tooltip for the `https` prober, #306), jitter, prober, and confidence (#202: a `high`, `medium`, or `low` pill, amber for low, with the evidence beside it, such as `icmp, 4/4 replies` or `tcp, 1/4 replies, traceroute hop`; a failed probe shows a dash), the current and recommended exit, measured sub-ranges, and learned paths with AS path, via, RPKI validity, and MED. The RPKI cell names the source that answered and the age of its data (`valid via routinator, 2m 5s old`), which may be the display-only `ripestat` fallback (#200). With the `irr` block on, the IRR cell shows `registered`, `not registered` (amber), or `unknown`, the source and IRR database with the age of its data, the origins registered for the prefix, the provider's as-set membership when `irr.as_sets` names it, and the origin's as-name (#214). MED is labelled display only and does not choose the exit. It refreshes every five seconds. For a prefix Packeteer is not measuring now, the page says so and still shows the stored timeline.
- **Why? (#201).** The checks the latest decision for the prefix passed through, in order: learned RIB, fresh measurements, thresholds (loss, RTT, and the RTT percent when set), measurement evidence (#202: what each compared sample rests on; it holds a decision back only with `thresholds.require_evidence`), confirm rounds, hold time, the `max_improvements` cap, routing policy, allowlist, route check, RPKI, and IRR. Each row shows Passed, Held it back, or Not checked (the allowlist outside inject mode, RPKI with the `rpki` block off, and IRR with the `irr` block off are Not checked), the value compared, and the limit. The headline names the one gate that held the decision back. Under the table are a sentence on what would change it (for example the RTT gain that would clear the threshold) and the providers' measurements behind it, each with its confidence and evidence. It reads `GET /api/decisions/<prefix>` and changes nothing.
- **Timeline.** Newest first, for 7, 30, 90, or 365 days: the daily probe rollup of each provider toward the prefix (UTC day, probes, failures, average loss, RTT, and jitter) and each improvement's start and end with provider, native provider, cause, reason, and the loss and RTT of both paths when it started (before and after) and why it ended; with the `rpki` block on, each learned path's RPKI state per provider and origin AS from the round it began, with its source and when it was last seen (#200). A record made in `observe` or `suggest` reads "Recommended"; only a record made in `inject` reads "Announced". Days are the finest history the store keeps. Without `storage: {type: sqlite}` the page says history is off.
- **Probe now.** A link to `/troubleshooting.html?tool=probe&target=<prefix>`, which opens the Probe tool with the tool and target filled in. Nothing runs until Run is pressed, and Probe keeps its operator role and rate limit ([troubleshooting](troubleshooting.md)).

`GET /api/prefixes/history?prefix=<prefix>&days=7` (viewer; `days`, or `from` and `to`, like the reports) returns `enabled`, `prefix`, `from`, `to`, `days` (`day`, `provider`, `probes`, `failed`, and the averages `loss_pct`, `rtt_ms`, `jitter_ms` when any probe returned statistics), `improvements` (the rows of the improvements report, including `mode`), and `rpki` (`provider`, `origin_asn`, `state`, `source`, `first`, `last`). An improvement row also carries `explain`, the gate list of the decision that started it (#201), when it was recorded; the timeline lists the checks that passed or held it back. The prefix must be a network in CIDR form; anything else is a `400`. The match is exact: a covering or covered prefix is a different prefix. With no storage plugin it returns `enabled: false`.

CI loads the page twice in the graphs step of the docker job (`lab/ui-smoke.sh`), against history seeded by `lab/mkhistory`: the timeline, the "Recommended" wording with no "Announced", the MED label, and the Probe now link; then the Probe tool with the prefix filled in. The RPKI step loads `/prefix/203.0.113.0%2F25` through `uiproxy` with `lab/ui-fixtures/rpki`: the source and age on each path, the stored RPKI spans, and the confidence pill and evidence on each probe row. The Why step loads `/prefix/198.51.100.0%2F24` with `lab/ui-fixtures/why`: the gate table with the evidence row, the gate that held the decision back, the counterfactual, the confidence of each sample, and the stored checks on the timeline; then a prefix with no decision. `internal/history` and `internal/httpapi` tests cover the filtering, the API, and the page wiring.

## Reports

`/reports.html` (#178) lists the stored reports by category: Overview (`summary`), Improvements (`improvements`, `exchanges`, `causes`), Performance (`performance`, `timeseries`, `providers`, `probes`, `probe_asns`), Traffic (`prefixes`, `asns`, `countries`), Cost (`savings`), and Protection (`mitigations`, `anomalies`). It needs `storage: {type: sqlite}` and says so when history is off. It is read-only and announces nothing; the mode banner is on top in every mode.

- **Range.** Last 1, 7, 30, 90, or 365 days, or a custom From and To typed in the browser's local time. The page sends a custom range as UTC (`from` and `to` as RFC 3339), and the count line shows the range back in local time. A range is at most 3660 days.
- **Filters.** Only the filters the report takes are shown. A filter that matches nothing gives an empty table, not an error.
- **Columns.** Each column has a label and, for numbers, a unit (`Avg loss (%)`, `Active (h)`). Click a header to sort by it; click again to reverse. Numbers and times sort largest or latest first, text and prefixes A to Z. Prefixes sort by address, not as text. An empty cell sorts last in either direction. Prefix cells link to the [prefix page](#prefix-detail-and-history) and origin AS cells to `/prefixes.html?asn=<number>`.
- **Rows.** `improvements`, `savings`, `prefixes`, `asns`, `countries`, `probe_asns`, `mitigations`, and `anomalies` are cut to a row limit (the Rows menu; default 100 for `improvements`, `savings`, `mitigations`, and `anomalies`, 20 for the others, at most 10000). The sort happens before the cut, so sorting by Active (h) shows the longest improvements, not the longest of the newest 100. "Showing 20 of 140 rows" says when the table is cut. The other reports have one row per day, provider, or cause and are never cut.
- **Export.** CSV and XLSX download the same query as the table: same range, filters, sort, and row limit. The CSV header names are unchanged. XLSX has one sheet named after the report, a bold header row of the labels with units, numbers as numeric cells, and everything else as text, so text that starts with `=` is never evaluated.
- **Add to dashboard.** Saves the current view as a `report` widget on one of the user's [dashboards](#custom-dashboards) (or a new one) with the same filters, sort, and limit. It uses `PUT /api/dashboards/<name>`, so it needs `storage`, auth or basic auth, and the dashboard limits apply. A range from the preset menu is saved as `days` and keeps following the present; a custom range is saved as that fixed range.
- **URL.** The view is in the query string using the API's parameters (`/reports.html?report=improvements&days=30&provider=transit-a&sort=hours&order=desc`), so a link opens the same view. A link with `report=improvements` and no range opens 90 days, as the search page links always did.

Filters by report. All filters are optional and combine with AND.

| Report | Filters |
|---|---|
| `improvements`, `exchanges`, `causes`, `performance`, `savings` | `provider`, `asn`, `prefix`, `cause`, `ip_version` |
| `summary`, `providers`, `probes`, `probe_asns`, `prefixes`, `asns`, `countries` | `provider`, `asn`, `prefix`, `ip_version` |
| `timeseries` | `asn`, `prefix`, `cause`, `ip_version` |
| `mitigations`, `anomalies` | `prefix`, `ip_version` |

| Filter | Keeps |
|---|---|
| `provider` | Probe rows of that provider, and improvements where it is the chosen or the native provider. In `providers` only that provider's row remains; its counts still come from the improvements that involve it. |
| `asn` | Origin AS (`64500` or `AS64500`): the origin stored with an improvement, or the prefix's origin when the improvement has none. Probe rows use the prefix's stored origin, or the origin of its matching improvements when it has none. |
| `prefix` | That exact prefix in CIDR form (`192.0.2.0/24`). A covering or covered prefix is a different prefix. |
| `cause` | Improvements with that cause: `performance`, `commit`, `cost`, or `static`. An improvement stored with no cause is `performance`. |
| `ip_version` | `4` or `6`. |

`GET /api/reports/<name>` takes `days` or `from` and `to` (not both), `limit`, `format` (`json`, `csv`, or `xlsx`), the filters above, and `sort` with `order`. `sort` is a column `key` from the response's `columns`, or for `prefixes`, `asns`, and `countries` still `problems`, `volume`, or `loss` (which rows the top list keeps). `order` is `asc` (default) or `desc` and goes with a column `sort`. Every other parameter is a `400`, as is a filter the report does not take, `limit` on a report that is never cut, a bad value, and `order` without a column `sort`, so a misspelled filter cannot return unfiltered rows. `GET /api/reports` lists each report with `category`, `summary`, `filters`, `columns` (`key`, `label`, `unit`, `type` of `text`, `number`, `time`, or `prefix`), and `limited`. The body of a report adds `columns` and `total` (the rows that matched, before the row limit). `days=` URLs and report subscriptions work as before.

The "UI reports smoke" step of the docker job (`lab/ui-smoke.sh`) mounts history seeded by `lab/mkhistory` and checks the API (filters, sort before the limit, the `400` cases, the old URLs, and that the CSV and the XLSX hold the same rows in the same order). It loads the page from URLs, then loads it through `lab/uiproxy -fixtures lab/ui-fixtures/reports`, whose script presses the Prefix header twice, filters by cause, picks a custom range, and adds the view to a dashboard, because headless Chrome cannot click. Chrome runs in `Asia/Kolkata`, so the step checks that 08:30 typed is sent as `03:00Z`, and that the saved widget holds the page's query and shows the same rows. `internal/history` tests cover the filters, the sort, the cut, and the XLSX file; `internal/httpapi` tests cover the parameters, the downloads, and the widget check.

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

The RING link is a page the operator opens by hand and makes no request. The separate, opt-in [NLNOG RING panel](#nlnog-ring-panel) reads the public API. PeeringDB is linked per AS: its AS page lists the exchanges the AS is on, and the exchange name in `exchanges` is a local label, not a PeeringDB object.

The server builds every URL, so the browser never assembles one. `GET /api/linkouts?prefix=<cidr>&asn=<n>` (viewer; both repeatable, at most 300 values; a bad value is a `400`) returns `{"prefix": {<cidr>: [{"name", "url"}]}, "asn": {<n>: [...]}}`. A prefix is masked and written as CIDR with `/` and `:` left readable; an AS is decimal digits. With `linkouts.hide_internal` on (default) an RFC 1918, ULA, loopback, or link-local prefix and a private-use AS (RFC 6996: 64512-65534, 4200000000-4294967294) get an empty list, so the page shows no link for it. Documentation prefixes and ASNs are not internal. Settings and the `linkouts` keys are in [CONFIG.md](CONFIG.md#linkouts); a change needs a restart.

The `ui-smoke` steps of the docker job load `/prefix/2001:db8::%2F32` and `/prefixes.html?asn=64496` in headless Chrome and check the rendered `href`s, `target`, and `rel`, that NLNOG RING is absent, and that an RFC 1918 prefix and a private-use AS render no link. `internal/linkout`, `internal/config`, and `internal/httpapi` tests cover the URLs, the template checks, and the page wiring.

## NLNOG RING panel

With `ring_lg.enabled: true` the prefix page (`/prefix/<prefix>`) shows "Seen from NLNOG RING" (#283): the routes the public [NLNOG RING looking glass](https://lg.ring.nlnog.net/) shows for exactly that prefix (peer, AS path, origin AS, RING's own RPKI state, last update). It is off by default, and while it is off nothing calls RING and the panel is hidden. The answer is display only. It never reaches `Decide`, scoring, or steering, and nothing in it announces.

RING is run by volunteers, so use is small and fair:

- One `GET https://lg.ring.nlnog.net/api/prefix?q=<prefix>&match=exact` per prefix page view that misses the cache. No background polling, no batch or all-peer queries, and redirects are not followed.
- A cap on upstream calls across all prefixes and viewers: `ring_lg.requests_per_minute` in any 60 seconds (default 6). Over the cap the panel says it was not asked.
- A per-prefix cache for `ring_lg.cache_ttl` (default 10m, at least 1m), held in memory for at most 256 prefixes. A repeat view inside the TTL makes no call.
- A failure (timeout after `ring_lg.timeout`, HTTP 5xx or 429, an unreadable answer) shows "Unavailable" with the reason and is remembered for one minute, so a struggling service is not asked again on every view. A RING failure affects nothing else.
- Every request sends `User-Agent: Packeteer/<version> (+https://github.com/GrandArcher/Packeteer)`.
- Private, loopback, and link-local prefixes (the set `linkouts.hide_internal` hides) are never sent, whatever `hide_internal` says.

NLNOG RING services may be unavailable. Packeteer never uses SSH or any other interactive access to RING nodes, never logs in, never runs a command on a member's node, and keeps no credentials: the public API needs none. The keys are in [CONFIG.md](CONFIG.md#ring_lg); a change needs a restart.

`GET /api/ring_lg?prefix=<cidr>` (viewer) returns `state` (`off`, `ok`, or `unavailable`), `routes` (up to 200), `warnings`, `message`, `cached`, and `fetched_at`. `internal/ringlg` tests use an `httptest` server with synthetic documentation-prefix answers and cover the cap, the cache, the User-Agent, timeouts, 5xx and 429, and that an off panel makes no request. The `ui-smoke` steps load the prefix page with the panel off (hidden) and with it on against canned answers from `lab/ui-fixtures/ring-lg`, so CI never calls RING.

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

`GET /api/search?q=` needs the viewer role. Input that is not a prefix, an address, an AS number from 1 to 4294967295, or a name of 2 to 64 bytes made of letters, digits, spaces, and `. _ , & ( ) ' -` is a `400` (a non-ASCII letter takes two or more bytes). Each caller (user, or client address without auth) may search 10 times at once and then twice a second; more is a `429` with `Retry-After`. The limit is checked before the input, so a `400` uses a token too. At most 1024 callers are tracked; while all of them are active, a further caller gets a `429` too. The body has `query`, `kind` (`prefix`, `asn`, or `name`), `limit`, `history` (`enabled`, `days`, and a `note` when history is off or did not answer), and the lists `asns`, `measured`, `rib`, `recommendations`, `improvements`, and `rollups`, each `{total, rows}`.

CI loads the page against the stock image with storage on (`lab/ui-smoke.sh`, docker job, "history survives a container restart" step): the grouped results, the links, the `400` and `405` cases, and the rate limit. The history-off note is covered by the `internal/httpapi` tests. `internal/httpapi`, `internal/history`, `internal/rib`, and `internal/troubleshoot` tests cover matching, ordering, caps, the limiter, and the name source.

## System health

The System page (#184) answers "which part is broken" when the status tile says not ready. It is read-only, announces nothing, and shows the mode banner in every mode. The Overview has a System tile (components down or degraded, or "all ok") that links to it.

`GET /api/system` (viewer) returns `summary` (`total`, `ok`, `degraded`, `down`, `idle`) and `components`. Each component has `kind`, `name`, `type`, `state`, `since`, `error`, and `detail`. `state` is `ok`, `degraded`, `down`, or `idle` (configured but nothing to do or report yet; not a fault).

| Kind | One row per | State comes from |
|---|---|---|
| `version` | the process | always `ok`; detail has the version and mode |
| `ha` | the elector, or one `role` row without `ha` | `degraded` when ineligible, or standby with no lease holder |
| `bgp_session` | `bgp.neighbors` entry | `degraded` while the session is Connect, Active, OpenSent, or OpenConfirm (the handshake has not finished), `down` in Idle or any other state; `ok` once established; `detail` is the plain label followed by the raw state, such as `Connecting (ACTIVE)`; `since` is the last state change. One `idle` row without neighbors |
| `rib_source` | `rib_sources` entry (BMP) | `down` when every router that reported a peer has closed its session, `degraded` when some have, `degraded` before any router reported. `since` is the latest change |
| `rpki` | `rpki.sources` entry | `ok` when lookups use the cache (fresh and non-empty, even while the session is down; `error` says why), `degraded` when the cache is stale or empty and skipped (fail open), `down` before any data. `since` is the data time, as `rpki_updated` on `/api/prefixes` |
| `irr` | `irr.sources` entry | `ok` when its last lookup answered, `degraded` when it failed after earlier answers (they are used until `irr.staleness`), `down` when it never answered, `idle` before the first lookup. `since` is the newest data time it answered with |
| `probe_source` | provider | the provider's probe-source health; `down` with the reason (for example the source address is not on the host). A provider measured by a peer POP is `idle` |
| `prober` | `probers` entry | `ok` when it produced a measurement (a 100% loss result counts), `down` when probes failed with an error naming it, `idle` when none used it (an earlier prober in the chain answered). Results of providers whose probe source is down are ignored |
| `source` | `sources` entry | `down` when its last call failed; `since` is when it started or stopped failing |
| `scorer` | the scorer | always `ok` |
| `announcer` | the announcer | `idle` and "announces nothing in observe mode" (or suggest) whatever is configured; in inject `ok` and "may announce allowlisted prefixes that are in the learned RIB", "announces nothing while this instance is standby", `degraded` without an iBGP session, `down` if inject has no announcer |
| `storage` | the storage plugin | the history recorder's and the event log's latest writes: `down` with the error while either one's latest write failed (the later failure is shown), `idle` before the first write. `idle` without a storage plugin |
| `notifier` | `notifiers` entry | the latest delivery attempt: `down` with the error when it failed, `idle` before the first. An event a filter or rate limit turned away is not an attempt |
| `telemetry` | `telemetry` entry | `down` when the poll or a binding reports an error; detail has the last poll |
| `federation_peer` | federation peer | `down` when its snapshot is stale or never seen. One `idle` row when standalone |

`since` is set where the component records state changes (sessions, sources, storage, notifiers, RIB sources, RPKI sources, IRR sources, probe sources, HA). Telemetry and federation peers show the last poll or sighting in `detail` instead.

Results of storage writes, notifier deliveries, and BMP sessions are kept in memory from the start of the process. A notifier's state therefore reads `idle` until its first delivery attempt; a restart clears it. Nothing is probed or sent to build the page.

**No secrets.** Rows carry names, types, states, and error text only. A URL in an error is cut to scheme and host, so a webhook's path and token never appear. Plugin config, credentials, and SNMP communities are not read.

The "UI system page smoke" step of the docker job (`lab/ui-smoke.sh`) mounts an observe file with a webhook notifier aimed at a closed port, a provider whose probe source address is not on the host, and a `static` source, then loads `/system.html` in headless Chrome. It checks the rows and their states, that the announcer row says "announces nothing", that the webhook path never appears in the DOM, and `GET /api/system` and the System tile on `/`. `internal/httpapi` tests cover every state, the announcer wording by mode, and the redaction. `cmd/controller` tests inject a failing notifier, a read-only store, a failing source, and a closed BMP session through the real hooks and read them back on their rows.

## Events and audit log

The Events page (#173) lists what the controller reports to notifiers ([EVENTS.md](EVENTS.md)), newest first: time (local), source, severity, event, and what happened. A row leads with a plain sentence, then a What to do link (the System page for BGP, announcer, and controller events, otherwise the doc to read, which opens the project repository in a new tab), then the key=value fields folded under Details (#347). Source is the event's catalog group (`provider`, `bgp`, `commit`, and so on). It is read-only and works in every mode.

- **Filters.** Severity (all, warning and critical, critical only), a text search over the event kind, message, and field names and values, and a range (last hour, 24 hours, 7 days, 30 days, all kept, or custom from and to). The page reloads every five seconds and on Refresh.
- **Where events are kept.** With a `storage` plugin of type `sqlite` they are written to the database and pruned with `retention`, so they survive a restart. Without storage the page shows the newest 1000 events since start, from memory, and says so. Events are recorded whether or not a notifier is configured, and a notifier's filter or rate limit does not hide an event from the page. With storage, a full write queue (256 events) drops new events and logs it. `audit.recorded` events are not listed: the Audit tab shows those records.
- **Top bar indicator.** The Events link in the top bar shows a count of warning and critical events newer than the last time this browser opened the page (100 or more shows `100+`). The time is the controller's clock, kept in the browser's local storage; nothing is stored on the controller. It refreshes every 15 seconds.
- **Audit tab (admin).** Time, actor, role, method, action, target, result, and status of the newest 200 records of `GET /api/audit` ([auth.md](auth.md#audit-log)). `/events.html#audit` opens it. A viewer or operator does not see the tab, and the API refuses them. It needs a storage plugin that keeps the audit log (`sqlite`); without one the tab says so. Passwords and token secrets are never in an audit record.

`GET /api/events` (viewer) takes `severity` (`info`, `warning`, `critical`; a floor), `q`, `from` and `to` (RFC 3339), and `limit` (1 to 1000, default 200). It returns `events` (`time`, `source`, `severity`, `kind`, `message`, `fields`, `help_url`), `doc_base`, `stored`, `now`, and `since` when storage is off.

## Dashboard and first run

The dashboard (`/`) is built for a first run from the stock image with nothing but a mounted config file (#49):

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

- **Mode banner.** `observe` reads "Observe mode: Packeteer measures and recommends. It announces nothing." `suggest` also says it announces nothing. `inject` says improvements for allowlisted prefixes are announced. A file without `mode` observes. The banner is the first thing on every page, in every mode.
- **Mode chip (#171).** The header chip sets its own text and background. Observe is `#0b3a5b` on `#d4e4f4`, suggest is `#6a3b06` on `#f6e4c4`, inject is white on `#9d1c2a`, and any other mode is `#12263a` on `#e7eef5`. Each pair meets WCAG AA (4.5:1) for this text size. The chip no longer inherits the header's white text.
- **Overview tiles.** Providers first (N of M healthy, colored by the worst one), status (ready, not ready, starting), prefixes measured (at least one reply; a prefix every provider fails to answer is not measured; the sources that list them), recommended improvements (outside inject) or active improvements (inject) against `max_improvements`, and BGP sessions with the number of probed prefixes in the learned RIB. There is no Mode tile: the mode is in the banner and the header chip (#349).
- **Provider health (#343).** A provider is `down` (red) when its probe source is down, nothing came back, or its mean loss is at least `probe.down_loss_pct`. It is `degraded` (amber) at `probe.degraded_loss_pct`, otherwise `up` (green); with no result yet, still starting, or measured by a federation peer it is `unknown` (`no data yet`), not a problem and not counted healthy; the providers tile then adds "N not measured yet". A probe that errored counts as 100% loss. A path with no reply shows `no reply` instead of an RTT, never `0.0 ms`. When any provider is down or degraded, a sentence above the tiles lists each one with a link to its row on the Providers page (for example "2 problems: lab-b 100% loss, lab-c no answer"); it is absent when all are healthy. The System tile shows "N warnings" instead of "all ok" while the setup checklist has a `warn` line. These labels do not change any decision.
- **Setup checklist.** Shown until there is nothing left to do, most urgent first. `todo`: no `sources` (nothing to probe). `warn`: every probe through a provider fails (with the last error), every provider is down, `bgp.neighbors` is set but no session is up, or no probed prefix is in the learned RIB. `info`: still starting, waiting for the first round, no `bgp.neighbors` (the current exit is unknown), report history off. Each line names the doc to read, as a link to the project repository (the image carries no docs). The checklist only reads state; fix the mounted file and restart.
- **Providers** (`/providers.html`) show the health state above with its reason (`100% loss`, `no answer`, a loss percent) and per-provider probe counts (`ok` means a reply came back). The table also has latency, loss, jitter, a 24-hour trend, and Mbps ([below](#provider-figures-and-overview-charts)). The exchange view on that page is described [below](#exchanges-view).
- **Prefixes** (`/prefixes.html`) are a filtered, paged table; a row opens the prefix card with each learned path, its MED (display only) and `via` (route server, bilateral, or unknown; #146). See [Prefix list](#prefix-list). The ASN map is on the same page.
- **Improvements** (`/improvements.html`) are labeled recommended outside inject and active in inject. With no BGP session the empty state says so and links to the System page, because without a session Packeteer sees no routes and recommends nothing (#347).
  Each row explains itself (#348). The Why column is a plain sentence, for example `lab-b is 40 ms faster (60 -> 20 ms, 67%), loss equal. Threshold 15 ms.`, quoting the threshold from `thresholds` only when the latest measurements beat it (a kept move below it reads `... under the thresholds now. It cleared them when chosen.`), then `Recommended since` (`Active since` in inject) the start time, and, while `hold_time` has not elapsed, `Hold time: 2m 10s left before it can change.` Beside it: Latency and Loss as native -> recommended from the latest probe round, Gain (ms and percent, plus points of loss saved; `none now` when neither improves), Mbps (`no flow data` without a flow source), and the origin ASN and AS name. The AS name is the provider that uses that ASN, or a name an earlier whois lookup on the Troubleshooting page returned; otherwise `-`. Commit, cost, and static moves lead with their cause and stored reason. Without a usable measurement for both providers the sentence is the stored reason and the Latency, Loss, and Gain cells read `-`. A recommendation that is still collecting `confirm_rounds` is not on this page yet; `GET /api/decisions` shows it as "confirming switch". On a wide screen the page uses the full width; below 760 px each row is a card. The docker job's UI plain language step loads the page in 1440 px and 390 px frames through `lab/uiproxy -fixtures lab/ui-fixtures/explain` and checks the sentence, the columns, fit, and text size.
- **Reports** (`/reports.html`) and **troubleshooting** (`/troubleshooting.html`) are the same sections as before, on their own URLs.
- **Optional sections** (POPs on Overview, threat mitigation on Protection) are hidden when not configured; the overview lists which optional features are on and off. Protection shows its empty state while the monitor is hidden.
- **Errors.** Every section shows `Loading...` until its first answer and a plain empty state after it. When the controller cannot be reached or answers with an error, a banner says so (sign-in required, not allowed, or unreachable), the last data stays on screen marked stale, and the page keeps retrying every 5 seconds.

`GET /api/overview` (viewer) is the same summary as JSON: `mode`, `ready`, `started`, `sources`, `providers` (`name`, `up`, `state`, `loss_pct`, `detail`, `ok`, `failed`, `last_error`), `problems` (`provider`, `state`, `detail`; down first), `counts` (including `providers_healthy` and `warnings`), `bgp`, `features` (`name`, `on`), and `setup` (`id`, `level`, `title`, `detail`, `doc`, `doc_url`). It is read-only and announces nothing.

CI runs a UI smoke test in the docker job (`lab/ui-smoke.sh`): headless Chrome loads every shell page from the stock image. The first run mounts `config.example.yaml` unchanged. The banner says observe and that it announces nothing, the header chip is `mode-observe`, the checklist on `/` asks for sources, `/providers.html` shows `no data yet`, `/improvements.html` says Recommended, and the empty pages name their issues. A separate step (#343) runs a fixed-prober lab with one provider at 100% loss and one with no answer, and checks the red pills, `no reply`, the "1 of 3 healthy" tile, the headline, and that "all ok" is absent. Another step (#347) runs a lab with the same two providers and an edge session that never comes up (`bgp.not_established_after: 5s`), and checks the three events with their headline, What to do link, and Details fold on `/events.html`, the System link on `/improvements.html`, and the doc link on the checklist. The second run uses a minimal file with no `mode` key and one static target (observe, the prefix measured with an RTT on `/prefixes.html`, no improvement).

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

Each provider field has a visible label above the input, and that label is the field's accessible name, including after the box is filled (#171). Apply copies the form into the YAML in the editor and does not write the file. Save applies unapplied form changes first, so it never drops a form edit; if the YAML text also has hand edits, Save refuses and asks for Apply first. Its result names each changed key, old to new (`Saved 1 change: hold_time 1m -> 2m (applied online)`, or `No changes to save.`), from `result.changes` in the reply. A sticky bar at the bottom of the page repeats the last result, flags unsaved changes, and has Apply and Save (#344). Save is still `PUT /api/config`: the same checks as a start, the same `confirm_inject` when the text turns inject on, and the same online apply as a SIGHUP when every change can run while the process is up (#128). A cap of 0 is a whole number and retires every improvement on the next decision. MED stays display-only. A next hop seen on the wire is a draft suggestion, not a provider, until it is saved as one.

Fields the form does not show stay in the file with their values. An unchanged form is not reformatted. Commit is the SNMP telemetry binding's `commit_mbps` for that provider; there is no field for a community or a passphrase. A commit with no binding is refused until the provider has a host. Choosing cost-or-performance, or setting the floor, on a `weighted` scorer (or none) switches `scorer.type` to `cost` and keeps the weights. It does not replace a `commit` scorer.

Guided inputs (#329) are how those fields are filled in. A duration is a number and a unit (`ms`, `s`, `m`, or `h`). A cap, a percent, a port, or a price is a number. Prefixes, peering LANs, listen addresses, ASNs, and countries are added one at a time. A bad prefix, AS number, port (1 to 65535), percent, or duration is marked on the field before Apply. An AS typed by name is added only when one AS matches, or one name matches exactly; otherwise the matches are listed and nothing is added. Next hops, probe sources, provider names, peer AS numbers, and originated prefixes offer values the controller already has, and stay free text when it has none. The config key is the field tooltip. An unchanged Apply still returns the original YAML bytes. Nothing is written until Save.

### Flow, policies, VIP, and outage (#130)

Four more sections sit under the allowlist. Each edits every source or policy of its type. Keys the form does not show stay in the file.

| Section | Edits | Notes |
|---|---|---|
| Flow collector | every `flow` source: `listen` (one host and port per row), `window`, `top_n` (the priority tier, probed every round), `max_targets`, `tail_interval`, `min_bytes`, `min_pct`, `exclude` (one prefix per row), `aggregate_v4` (1 to 32), `aggregate_v6` (1 to 128) | `problems`, `transit`, and `subranges` are under the card's Show advanced fold. Removing the source removes it and those blocks. Measurement only |
| Policies (rules) | every `rules` policy: one row per rule (`name`, `action`, `providers`, `prefixes`, `asns`, `countries`, `traffic`, `max_loss_pct`, `max_rtt`) and `geoip_db` | Rules keep their order. Removing every rule removes that policy. Blur on the GeoIP path reports whether that file opens. `maintenance` has its own card and the other policy types are under Plugins (see [Settings blocks](#settings-blocks-330)). A country rule still needs `geoip_db`; Validate and Save run the start checks |
| VIP | every `vip` source: `interval`, `max_targets`, prefixes with an optional pinned host, `asns` | Removing the source removes it. `max_targets` is at least 1; empty uses 100 |
| Outage detection | every `outage` source: `min_prefixes`, `window`, `loss_pct`, `rtt_ms`, `interval`, `max_targets`, `ignore_asns` | Empty fields use the defaults. Removing the source removes it. 1 is refused for `min_prefixes`; empty or 0 keeps the default |

A policy or source only restricts, orders, or measures. The learned-RIB check, the allowlist, `max_improvements`, the community and NO_EXPORT, hold time, and the withdraw rules are unchanged, and nothing here can announce. The form checks each field the way the plugin does (types, bounds, duplicates, a rule's action against its providers and `max_loss_pct`, and that a rule names configured providers) and refuses with the field named. The start checks that need the whole file still run on Validate and Save, for example a flow `tail_interval` that must be longer than `probe.interval`. A section the operator did not change is not checked or rewritten, so a file the form does not fully model still lets the other fields apply.

`vip` ASNs and the `outage` source read the learned RIB: set `bgp.neighbors` before enabling them. A controller with no BGP session currently stops with a nil-pointer panic once either one runs. This change does not alter that.

`POST /api/config/form {"yaml"}` returns `form`, now with `flow`, `policies` (`rules`), `vip`, and `outage` objects (`enabled` on each source). A request that leaves a section out of `form` leaves that part of the file alone, so a client written before #130 cannot remove one. Saving is the same `PUT /api/config` as every other edit: admin role, the same checks as a start, `confirm_inject` when the text turns inject on, and a line in the audit log with the old and new hashes.

`POST /api/config/form {"yaml"}` returns `form`. `POST /api/config/form {"yaml","apply":true,"form":{...}}` returns the merged `yaml` and the form read back. Neither writes.

`GET /api/config/suggestions` lists next hops seen on iBGP (including add-path) or BMP that are not a configured provider and not on an exchange LAN: `next_hop`, `asn` (the most common first AS), and `prefixes`. The busiest 64 are returned. Accepting one in the page adds a draft provider row with the next hop and the AS shown. The probe source, cost, and commit stay empty. Accepting does not call the API, so it does not write a provider, start probing, or announce. Exchange LAN hops are listed on `GET /api/exchanges` and offered under Discovered members in the Exchanges section. The list is cached against the RIB generation and only reads.

**Secrets.** `GET /api/config` returns the file exactly as it is on disk, to every admin API client; nothing is redacted (a redacted file could not be saved back). With the editor on, keep every secret out of the file: built-in plugins only take secrets by environment variable name (`password_env`, `community_env`, `auth_env`, `client_secret_env`, `routing_key_env`), and webhook `url`/`headers` and exec `env` values should reference `${VAR}` instead of holding a token.

**Exec plugins.** Checking or saving a candidate never runs a program. `exec` plugins in the candidate are validated without running their command (no `init` handshake), and a candidate that adds or changes an `exec` plugin (command, args, env, anything in its block) or changes `plugin_dir` is refused with `422`. Which programs the controller runs is set only by editing the mounted file; removing an `exec` plugin through the editor is allowed.

The file is read-only in many deployments (`:ro`). Then saving fails with a clear error and nothing changes. Set `config_editor: false` if you manage the file with Git or configuration management; unset with the example providers, the editor is also on until the first-run setup is done or skipped and the controller restarts.

### Provider figures and Overview charts

Per-provider latency, loss, and jitter (#349) come from probe results grouped in five-minute slots per provider, over every prefix probed through it. They are display only, never a routing input, and announce nothing. With a `sqlite` storage plugin the last 24 hours are kept in the `provider_samples` table and reloaded on start, and pruned with `retention`; without storage they start empty at each start.

- **Providers table.** Latency, Loss, and Jitter each show two lines, `15 min` and `24 h`: the median of the five-minute slots that overlap the window. Reordering (#224) is the provider path's latest RFC 4737 reordered ratio from `probe.reorder`, the worst flow toward a responder the operator runs, or an `est.` badge on an ICMP estimate; a dash until a responder answered ([reordering.md](reordering.md)). Loss counts a probe that errored or got no reply as 100%, as provider health does. A window in which nothing answered shows loss and `no reply` for latency and jitter, never `0.0 ms`; a window with no probes shows `no data`. Trend, 24 h is a small line of the hourly mean latency. Mbps is the sum of the flow source's rates for the prefixes that leave through the provider (the learned exit; in inject, the engine's exit), or `no flow data` when no source reports volume. At 760 px and above the table scrolls inside its box when it is wider than the page, and below it each row is a card with labelled cells.
- **Overview charts.** Above the tiles, "Latency by provider, last 24 h" draws one line per configured provider that answered (hourly mean round-trip time, both axes titled, the legend names each provider with its 24-hour median, and a provider that never answered is named under the chart). "Recommended / active improvements, last 24 h" counts the improvements open at each whole hour from `GET /api/reports/improvements?days=1`, as Recommended (observe or suggest) and Active (inject); it needs `storage: {type: sqlite}` and says so without it, and says when the day holds more improvements than one report returns (10000). Lines differ by dash pattern as well as color.
- **`GET /api/providers/stats`** (viewer, read-only): `flow` (true when a flow source reports volume) and `providers`, each with `provider`, `last_15m` and `last_24h` (`slots`, `loss_pct`, `rtt_ms`, `jitter_ms`; `rtt_ms` and `jitter_ms` are absent when nothing answered, and all figures when `slots` is 0), `points` (hourly `t`, `loss_pct`, and `rtt_ms` when something answered), and `mbps` when `flow` is true. A provider with traffic and no probes is listed with empty windows.

The "UI provider figures smoke" step of the docker job (`lab/ui-smoke.sh`) mounts history seeded by `lab/mkhistory` (lab-a at 120 ms with 8% loss, lab-b at 40 ms with none, documentation names) and checks `/api/providers/stats`, then the Providers columns, both windows, the sparkline, and `no flow data` at 1440 px, and Overview with both charts, their axis titles and legend, Providers as the first tile, and no Mode tile. A second run through `lab/uiproxy -fixtures lab/ui-fixtures/provider-stats` loads both pages in a 390x844 frame and checks the charts are drawn with data inside the frame, every provider cell is whole, and there is no sideways scroll. `internal/provseries`, `internal/history`, `internal/plugins/storage/sqlite`, `internal/httpapi`, `cmd/controller`, and `lab/mkhistory` tests cover the medians, the silent path, expiry, persistence across a restart, the endpoint, the Mbps by exit, and the seed; a Node test runs the page's cells and charts. Rollback: the feature adds no config key; revert the change. The `provider_samples` table is ignored by older versions.

### Exchanges view

The Exchanges section of `/providers.html` (#148) reads `GET /api/exchanges` every 5 seconds. Per exchange it shows the peering LANs and, per configured peer: AS (with `sees AS<n>` when most paths through the next hop start with another AS, a misconfigured peer that fails the route check), next hop, type (`route server`, `bilateral`, or `unknown`, from #146), prefixes seen through the next hop, probe-source state, the last probe of the next hop (`2.5 ms, 0% loss`, `unreachable`, or `not probed`, in red when the peer is degraded, #149), active improvements, and Mbps moved. With the `rpki` block on, each peer also shows the origin-validation counts (`valid`, `invalid`, `not found`, `unknown`) of the prefixes through its next hop (#158). An exchange where enough peers fail that probe carries a red Degraded line above its peers. Below the peers are the active improvements onto them (prefix, since, Mbps) and the discovered members. A discovered member is never probed or used.

Route server vs bilateral (#156): each configured peer also shows how many prefixes through its next hop arrive only via a route server, only over a bilateral session, or over both, and an `RS partial` or `RS missing` flag. `RS partial`: paths arrive via a route server, but some prefixes arrive only bilaterally. `RS missing`: no path arrives via a route server although the exchange has one for other members. Packeteer cannot tell whether the route server, the member's export policy, or an import filter dropped them. Compare opens, once per click, the last 12 of the counts recorded every 15 minutes (3 hours; the API keeps 3 days, in memory, emptied by a restart) and up to 50 prefixes of each class, from `GET /api/exchanges/member`. Only BMP Adj-RIB-In paths are classified, so a peer without `bmp: prefer` or `only` shows zeros, and a discovered member has no columns. The next hop is the same on both sessions, so this compares availability, not latency. It only reads.

Mbps moved is the observed rate of the prefixes steered onto the peer, from a target source that reports volume (a flow source or a static `mbps`). A prefix with no reported rate adds nothing and its rate shows as a dash (an em dash); `unknown` means improvements exist but no rate is known. `moved_mbps` and `moves` (`prefix`, `since`, `volume_mbps`) are on each peer in the API, and `volume_mbps` is on each entry of `/api/improvements`. It is display only and changes no decision.

Transit to exchange offload (#152): the section below the exchanges lists prefixes that leave through a transit while a configured exchange peer advertises the exact prefix, from `GET /api/exchanges/offload` (the CSV link downloads up to 1000 rows). It shows bytes, rate, the transit, the peers, and the saving at the transit's `cost` (a dash, an em dash, without one). A prefix counts only with a rate from a target source that reports volume and a peer route that passes the route check (`bmp: prefer` or `only`, or add-path). It is a report: nothing is steered or announced.

Potential peers (#154): the section below the offload table ranks destination origin ASNs by flow bytes and splits them by how the exchanges show them, from `GET /api/exchanges/potential-peers` (the CSV link downloads up to 1000 rows). "On the route server" lists ASNs that a member with that AS reaches through a route server: where `Prefixes on the LAN` is short of the prefix count, check our route server session or filters. "Bilateral only" lists ASNs seen only on bilateral sessions: a candidate for a peering request. A line below counts ASNs on a LAN whose session type is not visible and ASNs not seen at any exchange. Presence comes from the configured peers and the discovered LAN members, and the session type needs BMP Adj-RIB-In paths (`bmp: prefer` or `only`); without them an AS is `unknown`. It does not read the PeeringDB lookup (#153). The origin AS is the last AS of the covering learned route and the volume comes from a target source that reports it. It is a report: no session is opened and nothing is announced.

"Improvements to exchanges, last 7 days" below it is the `exchanges` report: one row per configured exchange peer, with improvements started in the range, active now, prefixes, Mbps moved (each prefix counted once, at its latest improvement), and hours steered. It needs `storage` and says so without it; the Reports page opens it with the same filters as `improvements` (`/reports.html?report=exchanges`). Exchange peers come from the config at start. The view is read-only, the viewer role may open it, the mode banner stays on top, and nothing on it announces.

The smoke step "UI settings forms smoke" in the docker job (`lab/ui-smoke.sh`) also loads `/providers.html` through `lab/uiproxy -fixtures lab/ui-fixtures/exchange-page`, which answers the calls with documentation prefixes and ASNs, and checks the peer table, the improvements with their Mbps, the discovered member, the next-hop probe cells and the Degraded line, the report table, the route server vs bilateral columns and flags (#156), the offload table (#152), and the two potential-peers tables (#154). The stock-image step checks the empty state. `lab/uiproxy` tests decode the canned files with the API's own types; `internal/exchange`, `internal/policy`, and `internal/history` tests cover the moves, the volume, and the report.

### Exchanges (#181)

The Exchanges section lists every `exchanges` entry: `name`, peering `lans` (one prefix per row), `bmp`, `group`, and a row per peer (`name`, AS, next hop, probe source, cost). Plus and minus add and remove exchanges and peers. A peer's `exclude` and `precedence` are under the peer's Show advanced fold. There is no field for a session or route-server credential.

Apply checks what the form can see: names (unique across providers, exchanges, and peers), LANs without host bits, a non-zero AS, and a next hop inside one of the exchange's LANs. A peer AS typed as AS64501 is stored as the number. The route check requirement (`add_path` on a `bgp.neighbors` entry, or `bmp: prefer` or `only` with `rib_sources`), a peer's probe source, and the allowlist-versus-LAN overlap are checked by Validate and Save, as for a start. A file whose only providers are exchange peers is accepted. Exchanges are not an online key: Save writes the file and the change applies on restart. Nothing is probed or announced until then, and mode and the allowlist are not touched. A form that leaves `exchanges` out of the request leaves the block alone, and an unchanged form is not reformatted.

Below the exchanges, Discovered members lists the next hops on a peering LAN that are not peers, from `GET /api/exchanges` (the running controller's view, so an exchange lists members only once it is running and the form's exchange has the same name). Accept adds a draft peer to that exchange with the AS (the most common first AS, empty when unknown) and the next hop filled in. Name, probe source, and cost stay empty, so Apply refuses the row until it has a name and a probe source is set before Save. No PeeringDB name is filled in; `GET /api/lookup` (#153) has them. Accepting does not call the API, so it does not save, probe, or announce; a member that is already a peer row is not offered again. Refresh re-reads the running view.

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
| Inbound optimization | the `inbound` block: `mode`, `prefixes`, `local_pref`, `release_pct`, `max_improvements`, `moderated`, `performance` (`loss_pct`, `latency_ms`, `min_prefixes`, `release_pct`), `damping` (`disabled`, `confirm`, `backoff`, `max_hold`) | Mode offers `observe` and `suggest`. The form never turns inbound inject on: a block that is already `inject` keeps it until changed, and turning it on is a YAML edit. The announcer is the Inbound announcer block (see [Settings blocks](#settings-blocks-330)), shown as present or missing. Unchecking removes the whole block, announcer included. Empty fields use the defaults. A new block needs `telemetry` or the performance trigger, which the start checks say on Validate or Save |
| Anomaly rules | `anomaly.rules`: one row per rule (`name`, `prefixes`, `protocols`, `min_mbps`, `action`, `target`, `rate_mbps`, `ttl`) | The first matching rule wins and rules keep their order. The detector, `source`, `interval`, and the caps are the Anomaly detector block (see [Settings blocks](#settings-blocks-330)); rules need an `anomaly` block with a detector. Rule prefixes must be inside `mitigation.allowlist`. An exact allowlist prefix is a checkbox. A more-specific already in the file is shown with a remove control. A prefix outside the allowlist is marked and removable, and Apply refuses until it is gone. The badge shows the mitigation mode, because a rule acts only through the mitigation controller |

A section the operator did not change is not checked or rewritten, and a request that leaves a section out leaves that part of the file alone. A save that turns `inbound.mode` or `mitigation.mode` to `inject` needs `confirm_inject`, the same as turning on the top-level mode (a file that already had the block in inject does not ask again for an unrelated edit). Inbound and anomaly rules decide nothing about announcing: inbound steers still need top-level inject, an allowlisted prefix in the learned RIB, the community, NO_EXPORT, the cap, and hold time, and an anomaly rule only asks the mitigation controller.

`POST /api/config/form` returns `form` with `inbound` (`enabled`, `has_announcer` display only) and `anomaly` (`enabled`, `mitigation_mode`, and `mitigation_allowlist` display only; `rules`) objects. Display-only fields sent back by a client are ignored.

UI e2e: `internal/httpapi` tests drive the real mitigation controller in observe behind the API with an announcer that fails the test on any call: the page ships the form, the picker offers only learned prefixes inside the allowlist, a rule is added and removed through the calls the form makes, both are in the audit log, and the announcer is never reached. `internal/configedit` tests round-trip inbound and anomaly rules through `config.Load`. The docker job adds a smoke step (`#131`) that adds and removes a rule against the stock image in observe and loads both pages.

### Settings blocks (#330)

The sections that used to say "edit it in the YAML" are forms now. `GET /api/config/schema` describes each block's fields (label, help, default, limits, whether it is required, the check a value gets), and the page draws them from it, so a form field and its checks come from one description. An empty field uses the loader's default and writes nothing.

| Block | Fields |
|---|---|
| Mode | `inject` is offered. Choosing it shows the inject checklist and the confirmation; Save still sends `confirm_inject`. |
| Inject settings | `packeteer_community`, `local_pref`, `announcer.type` (gobgp). |
| Scorer | the type select (`weighted`, `cost`, `commit`) and the knobs of the type shown (`scorer.config`); a switch drops the other type's knobs. |
| BGP | `bgp.neighbors` rows (address, add-path, label, port, source address, passive, providers) and `listen_port`, `listen_addresses`, `as_path`, `not_established_after`. |
| BMP | the `bmp` entry of `rib_sources` (listen, routers, Loc-RIB, idle timeout) and, per provider and exchange, the `bmp` select (off, prefer, only). |
| Exchanges | a peer's `exclude` and `precedence`, under its Show advanced fold. |
| Maintenance | `policies[maintenance]` windows: providers, a cron schedule with a duration, or a one-off start and end set with date and time pickers (saved as UTC). |
| Flow | `problems`, `transit`, and `subranges` of each flow source, under its Show advanced fold. |
| Inbound announcer | `inbound.announcer`: type, marker community, and a row per provider (signal communities, prepend, withhold), with a present or missing status. Needs the inbound block on. |
| Anomaly detector | `detector` and its knobs, `source`, `interval`, and the caps. Turning the block off removes it with its rules. |
| Mitigation | `mode` (`observe`; `inject` is offered only when the file already has it), `allowlist`, `max_rules`, TTLs, `local_pref`, `geoip_db`. The mitigation announcer, redirect targets, and turning mitigation inject on stay with the inject checklist in the raw YAML. |
| Plugins | the probers, notifiers, other sources, other telemetry, other policies, and storage entries that have no card of their own: type, name, an on switch (off removes the entry on Save), and the scalar keys of `config`. A new entry is picked from the registered types that no other card owns. A key that holds a secret (a token, password, or community, or a URL that does not take its value from `${VAR}`) is listed by name and never shown; a nested value is kept as it is. An `exec` plugin runs a program: it is added and edited in the raw YAML, and an existing one is shown read-only. |
| HTTP | `listen`, `config_editor`, `allow_from` (one prefix per row). These need a restart, and the help warns about lock-out. |

Every optional block has an on switch; off removes the block. Left to the raw YAML: adding or editing an `exec` plugin (an existing one is shown read-only), the mitigation announcer, redirect targets, turning mitigation inject on, and turning inbound inject on (the form never does), a scorer the form does not list (its cost and commit knobs are then disabled), and any key the schema does not describe. Keys the forms do not show are never dropped. The raw YAML is the last section, under **Advanced: raw YAML** and closed by default. It is still the escape hatch for anything above that the forms leave out, and it needs the admin role and `http.config_editor` like the rest of the page.

**Save from the form.** Save merges the form into the file text, runs the start checks, and writes it, with the inject confirmation when the text turns inject on. An error that names a key (for example `policies[maintenance].config.windows[0].schedule`) is shown under that field. The flow extras (problems, transit, subranges) are the exception: their errors are listed in the status text with the other errors, not under the field. Every key the form does not know, and every key you did not edit, keeps its value, and comments are kept. When anything changes the whole file is written out again, so indentation is normalized and blank lines can go. A form you did not change writes nothing.

**Preview.** Preview changes (or the sticky bar's Preview) calls `POST /api/config/preview {"yaml"}`: the start checks, a line diff of the file on disk against the candidate (`diff`), and the keys that differ from that file (`changes`). "Needs a restart" and "Applies when you Save" (`restart` and `online` on the result, as on `/api/config/validate`) compare with the running config instead. It writes nothing. After a Save the pane reads "Nothing differs from the file."; a saved key that needs a restart stays under "Needs a restart" until Packeteer restarts.

The smoke step "UI settings sections smoke" in the docker job loads the page through `lab/uiproxy -fixtures lab/ui-fixtures/sections` against `lab/ui-fixtures/sections/config.yaml` (documentation prefixes, observe). The driver checks that each block is drawn from the file and that a secret value is not on the page, marks an empty required field, makes one edit in each block, shows a server error on its field, previews the diff, saves once from the form, and checks that the saved file keeps its comment and the plugin's URL. Rollback: the blocks are UI and API only (`GET /api/config/schema`, `POST /api/config/preview`) and add no config key. Revert the change; a file the form wrote is ordinary YAML.

## Setup wizard

After the wizard, the Preflight checks panel on the same page decides when injection can be turned on ([onboarding.md](onboarding.md)).

**First run (#416).** With `http.config_editor` unset and the example providers (every `source_ip` in 192.0.2.0/24) still in the config, a start with no saved setup state needs no config edit: the editor and wizard are on for an admin while the first-run setup is pending, and only with sign-in (never with auth off). A config with a real provider is never pending, so an upgrade or a container re-created without its volume keeps the editor off. After the generated password is changed, the Overview sends the admin to `/settings.html#wizard`. Setup ends when an admin saves a config through the editor or wizard, or presses Skip setup (`POST /api/setup/skip`); the state is the file `first-run-setup-pending` next to the storage file. The editor stays on until the next restart; from then on the old default applies: it is off unless `http.config_editor: true`. `http.config_editor: false` keeps it off from the first start; `true` keeps it on and never redirects. With storage that has no file (memory), nothing is saved, so the example providers decide on each start. A federation settings push needs an explicit `true` whatever the setup state, and an accepted push ends a pending setup ([multi-pop.md](multi-pop.md)). The wizard still writes `mode: observe` and inject is not a step.

`/settings.html` walks four steps, the last optional (#106, #130). `POST /api/config/wizard` renders a config from them and writes nothing. The result opens in the editor for review, and you save it like any other edit.

1. Edge session: ASN, an IPv4 router ID, and the edge address. The session is learn-only iBGP.
2. Providers: one row each (name, probe source, next hop, and optionally the provider AS, a type of transit, peer, or customer, and an IPv6 probe source with an IPv6 next hop), with plus and minus. Each field has a visible label, the same way as the settings form (#171). The AS and type are written as the provider's `asn` and `type` labels. A provider has one address family, so an IPv6 pair becomes a second provider named after the first with `-v6`, sharing its AS and type (#350). Commit stays in Settings. A next hop from `GET /api/config/suggestions` can be added as a row; you still name it and set the probe source. Adding a row does not probe or announce.
3. What to probe: an optional prefix and an optional pinned host inside it. Leave both empty to add targets later in the form. A prefix without a host is probed at a few addresses inside it, including the provider next hop when that address can be used. A host pins that prefix to one address. Report history (sqlite) is a checkbox on this step, not a secret.
4. Flow collector (optional): a checkbox, a listen address (empty means every address), and a UDP port (default 2055). When on, the file gets a `flow` source listening there, with the source's defaults; tune it afterwards in the settings form. The step explains exporter setup: point the router's NetFlow v5/v9, IPFIX, or sFlow export at that host and port. Packeteer does not configure the router. With `--network host` the port is a host UDP port: do not publish it, and allow it only from the router. The generated file carries the same note. `POST /api/config/wizard` takes it as `"flow": {"listen": "192.0.2.10:2055"}`; a bad address or port is refused with the other wizard errors. Leaving the step off renders exactly what the wizard rendered before.

### Over a config that already exists (#345)

`GET /api/config` returns `configured: true` when the file has providers, BGP neighbors, or an `ixp` block. The page then collapses the wizard behind "Run setup again (replaces your config)", and its button reads "Generate (replaces your config)". An empty or fresh file shows it open.

**Fields start empty or real (#350).** No form field or filter on any page shows an example or a default as grey text inside the box. On a file that has a setup, `GET /api/config` also returns `setup` (`asn`, `router_id`, `edge`, `providers`) and the wizard fields start from it. On a fresh file they are empty and the example is in the help line under the field ("for example 64512"). A built-in default is text beside the field ("Default: 50"). The Reports and Prefixes filters start empty and say so ("Empty shows all providers").

The page posts the editor text as `current`. The server replaces only the keys the wizard writes: `mode`, `asn`, `router_id`, `packeteer_community`, `max_improvements`, `hold_time`, `thresholds`, `providers`, `allowlist`, `bgp`, `sources`, and `scorer`. `auth`, `http`, `storage`, and every other block stay as they are. A new `storage` block is added only when the file has none. The reply adds `existing`, `diff` (a line diff, ASCII only: any other character in the file shows as a `\u` escape), and `removes`, for example `Removes 2 providers (transit-b, transit-c)`. It also names a mode change, a scorer change, and dropped sources, static targets, BGP neighbors, and allowlist prefixes. A provider or neighbor that keeps its name or address but loses other fields is listed too, for example `Resets provider transit-a: drops fwmark`, as is a `bgp` key the wizard does not write.

The page keeps the editor text until you press "Replace the editor text" in the confirm box that shows `removes` and the diff. Cancel leaves it alone. Nothing is written to the file until you Save.

Sign-in stays on. A tick box "Turn off sign-in" on the last step sends `"disable_auth": true`, which sets `auth.enabled: false` and lists "Turns off sign-in" in `removes`. Without it, a result that would turn sign-in off is refused. The flow-collector comment is written only to a fresh file. The reply is `422` when `current` is not a YAML mapping, or when the result does not load with the rest of the file.

A fresh file is rendered as follows. Over an existing file, `announcer`, `http.listen` (unless the page sends a listen address), and every other kept block stay as they are; with `mode: observe` a kept `announcer` does not announce.

- `mode: observe` (it measures and recommends; it never announces). Any other mode, including inject, is refused. Inject is not a step;
- an empty allowlist and no announcer (a fresh file);
- one `bgp.neighbors` entry, the edge address;
- the `weighted` scorer, `max_improvements: 50`, `hold_time: 15m`, the default thresholds, and `http.listen: 127.0.0.1:8080`;
- a `static` source only when a prefix was given, and a `flow` source only when the flow step was used. Over an existing file this list replaces `sources`, so it can be empty; `removes` counts what is lost;
- `packeteer_community` `<asn>:666` when the ASN fits in 16 bits.

There is no field for a password, a community string, or any other secret. Those stay in environment variables. The page checks each step before continuing, and the server checks the whole body again with `config.Parse`. The wizard is part of the editor: it is off (`404`) unless `http.config_editor` is on or the first-run setup is pending. Turning inject on afterwards is a separate edit; follow the [inject checklist](CONFIG.md#inject-checklist).

## Custom dashboards

`/dashboards.html` builds dashboards from read-only widgets. Each user has their own (at most 20, with at most 24 widgets each), kept by the storage plugin (`sqlite`, table `dashboards`). Widgets read endpoints the viewer role can already read: readiness, providers, prefixes, improvements, decisions, provider usage, inbound steers, threat mitigation, anomalies, POPs, HA, report subscriptions, and any stored report with a range in days or a saved Reports view (`query`, below), and the before/after graphs (type `timeseries`, below). Two more types are charts (#182): `causes` (**Improvements by cause**, stacked bars of improvements started per UTC day from the `causes` report, with a data table; needs `storage` for history, and says so without it) and `commit` (**Provider usage vs commit**, the Commit & Cost graph of every telemetry binding from `/api/commit`; it says there is no binding when none is configured). Both draw with `/charts.js`, the same code as `/commit.html` and the graphs page, and say so when the range has no data.

**Layout (#182).** The grid is 12 columns wide and the widgets flow in list order, so a widget's place is its position in the list plus its size. Each widget has a width `w` (1 to 12 columns, default 6) and a height `h` (1 to 8 rows of 144 px; unset fits the content, and a taller widget scrolls). Below 760 px every widget takes the full row. A `wide` flag saved before #182 reads as `w` 12, and the page saves `w` instead. Each card has two grips in its header, drawn as symbols with no text label (their tooltip and accessible name say what they do):

- **Move grip** (a braille-dots handle). Drag it onto another widget to take its place, or focus it and press the arrow keys (left or up earlier, right or down later) or Home and End (first or last).
- **Resize grip** (a small corner triangle). Drag it, or focus it and press left or right for the width and up or down for the height.

The list under Edit does the same with an up-arrow and a down-arrow button (move earlier or later) and a width menu and a height menu (options such as "Width 6/12"), and sets the widget's refresh (15, 30, 60, or 300 seconds; default 15) and its time window in days (commit: 1, 7, or 30; the other types with a range: the preset list). A move or a resize is announced in a polite live region, and focus stays on the control that was used. Nothing is stored until Save; a saved layout reloads in the same order and sizes. With **Open this one first** checked, the page opens that dashboard (`favorite`; saving one clears the mark on the user's others, so there is one per user). The limits are the same: 20 dashboards and 24 widgets.

**Add to dashboard** is on Reports and on Graphs (the `timeseries` widget for the shown destinations and days). Both save through `PUT /api/dashboards/<name>` with a full-row width.

The "UI graphs and dashboard widgets smoke" step of the docker job (`lab/ui-smoke.sh`) loads the page against seeded history (a stored layout with `wide` is a full row, the causes chart draws, the commit widget shows its empty state, the favorite opens first), then through `lab/uiproxy -fixtures lab/ui-fixtures/dashboards`, whose script moves and resizes widgets with the arrow keys, the list, and a drag, sets a window and a refresh, and saves, because headless Chrome cannot click or press keys. The step checks that the saved layout equals the one on screen and reloads in the same order and sizes, that 25 widgets and unknown or out-of-range fields are a `400`, and, in the commit smoke step, that the commit widget draws a stored graph. `internal/httpapi` tests cover the layout round trip, the limits, the favorite, and the page's keyboard wiring.

The improvements widget is titled Recommended improvements in observe and suggest, and Active improvements in inject (#171). A title the operator set on that widget is kept. Timestamps in a widget use the same local format as the main dashboard (`toLocaleString`). An unparseable value stays as returned.

API: `GET /api/dashboards` returns `widget_types`, the report list, and your dashboards; `PUT /api/dashboards/<name>` with `{"title": "...", "favorite": true, "widgets": [{"type": "providers", "w": 4, "h": 2, "refresh": 60}, {"type": "report", "report": "summary", "days": 7, "w": 12}, {"type": "report", "report": "improvements", "days": 30, "query": "provider=transit-a&sort=hours&order=desc"}, {"type": "timeseries", "days": 30, "bucket": "better_50"}, {"type": "causes", "days": 30}, {"type": "commit", "days": 7}]}` saves one (unknown widget types, unknown reports, an unknown `bucket`, `report`, `days`, `query`, or `bucket` on a widget type that does not take them, `days` other than 1, 7, or 30 on `commit`, a `w` outside 1 to 12, an `h` outside 1 to 8, a `refresh` that is not 15, 30, 60, or 300, `wide` together with `w`, a `query` that `/api/reports/<name>` would refuse, and unknown fields are refused; `query` holds the filters, `sort`, `order`, and `limit`, or `from` and `to` instead of `days`); `DELETE /api/dashboards/<name>` removes it. Deleting a user deletes that user's dashboards.

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

`weight = performance x gain + volume x volume_mbps`. The gain is the native path's score minus the chosen path's; with the default `weighted` scores, 1 ms of RTT is 1 point and 1 % of loss is 100 points. The volume comes from a source that reports it: the `flow` window, or `mbps` on a `static` target. A prefix with no volume counts 0.

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

The graphs (#129) are read-only and need no rollback. Delete a `timeseries` widget from a dashboard to hide it; a build from before #129 refuses to save a dashboard that still has one. The layout (#182) is presentation only. A build from before it ignores `w`, `h`, `refresh`, and `favorite` (and drops them the next time it saves the dashboard) and does not list a dashboard that has a `causes` or `commit` widget, so delete those widgets first or keep the newer build.

The mitigation form and the inbound and anomaly sections (#131) are UI and API only and add no config key: revert the change to drop them, or remove the rules in the YAML (a restart withdraws every Packeteer route first, and mitigation rules are in memory, so they also go with a restart). The form sections and the wizard's flow step (#130) are UI and API only and add no config key: revert the change to drop them, or delete the `flow`, `vip`, and `outage` sources and the `rules` policies from the YAML (a restart withdraws every Packeteer route first). A file the form wrote is an ordinary config file that an older build loads unchanged.

Remove `improvement_weights`, `http.config_editor`, and `report_subscriptions` and restart. To undo the first-run setup state (#416), set `http.config_editor: false`, or create an empty `first-run-setup-pending` next to the storage file to see the setup again. The dashboard polish (#49) needs no rollback: it reads the same state, and `/api/overview` is read-only. The file config works exactly as before; the editor only ever wrote a plain YAML file. Stored dashboards stay in the database and are ignored by an older build. The display fixes (#171) are presentation only: revert that change to restore the previous chip, titles, timestamps, and unlabeled provider fields. The shell (#170) is presentation only as well: revert it to put every section back on `/`.

The System page (#184) is UI and API only and adds no config key; revert it to drop the page, the tile, and `/api/system`. The result hooks it adds (notifier delivery, storage write, BMP session) only record.

The Events page (#173) only reads; revert it to bring back the empty page. The `events` table it adds to the `sqlite` file is ignored by an older build. No config key changes.
