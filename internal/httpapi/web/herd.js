"use strict";
// The Herd page (#296): the members, a world view of where several members
// see loss, a vantage by target mesh, a country map, latency and AS path
// monitors for one target, search, and the opt-in outside sources. It only
// reads /api/herd/*. Each vantage keeps its own numbers: nothing is merged,
// and outside items are shown apart from herd data. Cells are built with
// textContent only. Uses api, el, clear, fmtTime, ixpTable, ixpCell from
// ui.js, lineChart and seriesClass from charts.js, and isoCountries from
// countries.js. No inline script: the CSP allows scripts from this origin
// only.

var HERD_REFRESH_MS = 30000;
var HERD_CHART_SERIES = 6;

// herdTarget is the target the monitors and the outside panel show:
// {asn, prefix}, either may be empty.
var herdTarget = null;

function herdAge(sec) {
  if (typeof sec !== "number") return "-";
  if (sec < 90) return Math.round(sec) + " s";
  if (sec < 5400) return Math.round(sec / 60) + " min";
  if (sec < 129600) return Math.round(sec / 3600) + " h";
  return Math.round(sec / 86400) + " d";
}

function herdPct(v) { return typeof v === "number" ? v.toFixed(1) + " %" : "-"; }
function herdMs(v) { return typeof v === "number" ? v.toFixed(1) + " ms" : "-"; }
function herdAS(n) { return n ? "AS" + n : "unknown"; }

function herdTargetLabel(t) { return t.kind === "origin_asn" ? "AS" + t.value : t.value; }

function herdMemberLabel(v) {
  if (v.local) return "this node (AS" + v.asn + ")";
  return "AS" + v.asn + " " + String(v.member).slice(0, 8);
}

// herdVantageLabel names a vantage: member, country, provider, method.
function herdVantageLabel(v) {
  return herdMemberLabel(v) + ", " + v.country + ", via " + herdAS(v.provider_asn) + ", " + v.method;
}

function herdCountryName(code) {
  if (typeof isoCountries === "undefined") return "";
  for (var i = 0; i < isoCountries.length; i++) {
    if (isoCountries[i][0] === code) return isoCountries[i][1];
  }
  return "";
}

function herdLink(text, href) {
  var a = el("a", "", text);
  a.href = href;
  return a;
}

// herdOpenHref is the link that opens a target in the monitors and the
// outside panel. A route target also names its origin ASN when members
// agree on one.
function herdOpenHref(kind, value, origins) {
  var asn = kind === "origin_asn" ? value : (origins && origins.length === 1 ? String(origins[0]) : "");
  return "/herd.html?" + herdQuery({origin_asn: asn, prefix: kind === "prefix" ? value : ""}) + "#herd-monitor-h";
}

function herdQuery(params) {
  var parts = [];
  Object.keys(params).forEach(function (k) {
    if (params[k] !== "" && params[k] != null) parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(params[k]));
  });
  return parts.join("&");
}

// ---- Members ----

function renderHerdOverview(sharing, members, d) {
  clear(sharing);
  clear(members);
  var s = d.sharing;
  var mode = s.preview_only ? "Preview only: records are stored and previewed, nothing is served or pulled."
    : (s.serving ? "Serving and pulling." : "Not serving.");
  sharing.appendChild(el("p", "", "This node shares " + s.granularity + " records (" + (s.classes || []).join(", ") +
    ") from " + (s.sources || []).join(", ") + " targets, declared in " + s.country + ", kept " + s.retention_days + " days. " + mode));
  var p = el("p", "tag", "Key " + s.key_id + ". ");
  if (typeof shellAdmin !== "undefined" && shellAdmin) p.appendChild(herdLink("Preview what a peer receives", "/api/herd/preview"));
  sharing.appendChild(p);
  sharing.appendChild(el("p", "tag", d.vantages + " vantages in " + (d.countries || []).length + " countries in the last 24 hours" +
    (d.truncated ? " (more records than one view reads; counts are a floor)" : "") + "."));
  var rows = (d.members || []).map(function (m) {
    var state = m.stale ? "stale" : "fresh";
    return [ixpCell(m.local ? "this node" : m.member.slice(0, 12), "mono"), ixpCell("AS" + m.asn),
      ixpCell(m.local ? "this node" : "pinned key"), ixpCell(m.verified ? "yes" : "no"), ixpCell(m.source),
      ixpCell((m.countries || []).join(", ")), ixpCell(m.vantages), ixpCell(m.records),
      ixpCell(herdAge(m.newest_age_seconds)), ixpCell(m.last_ok ? fmtTime(m.last_ok) : (m.local ? "" : "never")),
      ixpCell(m.last_error ? state + ": " + m.last_error : state, m.stale ? "bad" : "")];
  });
  members.appendChild(ixpTable(["Member", "ASN", "Identity", "Verified", "Source", "Countries", "Vantages", "Records (24 h)", "Newest record", "Last pulled", "State"], rows));
  members.appendChild(el("p", "tag", "Verified is no for every member: identity is a pinned key, and RPKI identity proof is not implemented."));
}

// ---- World view ----

function renderHerdEvents(root, d) {
  clear(root);
  var win = herdAge(d.window_seconds);
  if (!(d.events || []).length) {
    root.appendChild(el("p", "empty", "No target shows loss at or above " + d.loss_pct + " % from any member in the last " + win + " (" + d.targets + " targets measured)."));
    return;
  }
  root.appendChild(el("p", "tag", "Counts are members with a pinned key, one per ASN; none is RPKI-verified. Loss at or above " + d.loss_pct + " %, last " + win + "."));
  d.events.forEach(function (e) {
    var box = el("div", "tool-result");
    var head = el("div", "tool-head");
    head.appendChild(el("h3", "mono", herdTargetLabel(e)));
    head.appendChild(el("span", "tag", e.degraded + " of " + e.reporting + " members see loss" +
      (e.kind === "prefix" ? " (route level" + (e.origins && e.origins.length ? ", origin " + e.origins.map(function (a) { return "AS" + a; }).join(", ") : "") + ")" : " (pooled by origin AS)")));
    head.appendChild(herdLink("Monitor and context", herdOpenHref(e.kind, e.value, e.origins)));
    box.appendChild(head);
    box.appendChild(el("p", "tag", (e.by_provider || []).map(function (p) {
      return "through " + herdAS(p.provider_asn) + ": " + p.degraded + " of " + p.reporting;
    }).join("; ")));
    box.appendChild(ixpTable(["Vantage", "Loss", "RTT avg", "Age", "State"], (e.vantages || []).map(function (v) {
      return [ixpCell(herdVantageLabel(v)), ixpCell(herdPct(v.loss_pct), v.degraded ? "bad" : ""), ixpCell(herdMs(v.rtt_avg_ms)),
        ixpCell(herdAge(v.age_seconds)), ixpCell(v.degraded ? "loss" : "ok", v.degraded ? "bad" : "")];
    })));
    root.appendChild(box);
  });
  if (d.truncated) root.appendChild(el("p", "tag", "Only the first targets are shown."));
}

// ---- Mesh ----

function renderHerdMesh(root, d) {
  clear(root);
  if (!(d.rows || []).length) {
    root.appendChild(el("p", "empty", "No member measured anything in the last " + herdAge(d.window_seconds) + "."));
    return;
  }
  var heads = ["Vantage"].concat(d.targets.map(herdTargetLabel));
  var rows = d.rows.map(function (r) {
    var cells = [ixpCell(herdVantageLabel(r))];
    r.cells.forEach(function (c) {
      if (!c) { cells.push(ixpCell("")); return; }
      cells.push(ixpCell(herdPct(c.loss_pct) + (typeof c.rtt_avg_ms === "number" ? ", " + herdMs(c.rtt_avg_ms) : ""), c.degraded ? "bad" : ""));
    });
    return cells;
  });
  root.appendChild(ixpTable(heads, rows));
  root.appendChild(el("p", "tag", "Loss, then average round-trip time, as of each vantage's latest round in the window; a dash is no measurement. Loss at or above " + d.loss_pct + " % is marked."));
  if (d.truncated) root.appendChild(el("p", "tag", "The grid shows the targets measured by the most members, and the first vantages."));
}

// ---- Map ----

var HERD_CONDITION_TEXT = {degraded: "loss seen", ok: "no loss", no_data: "no recent data"};
var HERD_CONDITION_TILE = {degraded: "bad", ok: "good", no_data: "muted"};

function renderHerdMap(root, d) {
  clear(root);
  if (d.truncated) root.appendChild(el("p", "tag", "More records than one view reads; the vantages per country are a floor."));
  if (!(d.countries || []).length) {
    root.appendChild(el("p", "empty", "No vantage has reported in the last 24 hours."));
    return;
  }
  var grid = el("div", "tiles");
  d.countries.forEach(function (c) {
    var tile = el("div", "tile " + (HERD_CONDITION_TILE[c.condition] || "muted"));
    tile.appendChild(el("span", "tile-v", c.country));
    var name = herdCountryName(c.country);
    if (name) tile.appendChild(el("span", "tile-note", name));
    tile.appendChild(el("span", "tile-note", HERD_CONDITION_TEXT[c.condition] || c.condition));
    tile.appendChild(el("span", "tile-note", c.members + " members, " + c.vantages + " vantages"));
    if (c.measured) tile.appendChild(el("span", "tile-note", c.degraded + " of " + c.measured + " measured targets at or above " + d.loss_pct + " %"));
    grid.appendChild(tile);
  });
  root.appendChild(grid);
}

// ---- Monitors ----

// herdSeriesByTarget groups the series of a monitor by target, in order.
function herdSeriesByTarget(list) {
  var order = [], by = {};
  list.forEach(function (s) {
    var k = s.target.kind + ":" + s.target.value;
    if (!by[k]) { by[k] = {target: s.target, series: []}; order.push(k); }
    by[k].series.push(s);
  });
  return order.map(function (k) { return by[k]; });
}

function renderHerdLatency(root, d) {
  clear(root);
  if (!(d.series || []).length) {
    root.appendChild(el("p", "empty", "No round in the last " + herdAge(d.window_seconds) + " for this target."));
    return;
  }
  herdSeriesByTarget(d.series).forEach(function (g) {
    var fig = el("figure", "ts-fig");
    fig.appendChild(el("figcaption", "", "Round-trip time to " + herdTargetLabel(g.target) + ", per vantage"));
    var drawn = [];
    g.series.forEach(function (s) {
      var pts = s.points.filter(function (p) { return typeof p.rtt_avg_ms === "number"; })
        .map(function (p) { return {t: Date.parse(p.time), v: p.rtt_avg_ms}; });
      if (pts.length && drawn.length < HERD_CHART_SERIES) drawn.push({name: herdVantageLabel(s), cls: seriesClass(drawn.length), points: pts});
    });
    if (drawn.length) {
      var to = Date.now(), from = to - d.window_seconds * 1000;
      fig.appendChild(lineChart("Round-trip time to " + herdTargetLabel(g.target) + " per vantage, in milliseconds", "Time", "Average round-trip time (ms)", "ms", drawn, from, to));
      var legend = el("p", "ts-legend tag");
      drawn.forEach(function (s) { legend.appendChild(el("span", "ts-key " + s.cls, s.name)); });
      fig.appendChild(legend);
    } else {
      fig.appendChild(el("p", "empty ts-empty", "No vantage got a reply, so there is no latency line."));
    }
    root.appendChild(fig);
    root.appendChild(ixpTable(["Vantage", "Rounds", "Latest loss", "Latest RTT avg", "Worst loss"], g.series.map(function (s) {
      var last = s.points[s.points.length - 1], worst = null;
      s.points.forEach(function (p) { if (typeof p.loss_pct === "number" && (worst === null || p.loss_pct > worst)) worst = p.loss_pct; });
      return [ixpCell(herdVantageLabel(s)), ixpCell(s.points.length), ixpCell(last.failed ? "round failed" : herdPct(last.loss_pct)), ixpCell(herdMs(last.rtt_avg_ms)), ixpCell(herdPct(worst))];
    })));
  });
  if (d.truncated) root.appendChild(el("p", "tag", "Each vantage shows its newest 200 rounds."));
}

function renderHerdPaths(root, d) {
  clear(root);
  var rows = [];
  (d.paths || []).forEach(function (t) {
    t.changes.forEach(function (c, i) {
      rows.push([ixpCell(herdVantageLabel(t)), ixpCell(herdTargetLabel(t.target), "mono"), ixpCell(fmtTime(c.time)), ixpCell(i === 0 ? "first seen" : "changed"),
        ixpCell(c.paths.map(function (p) { return p.join(" "); }).join(" | "), "mono")]);
    });
  });
  root.appendChild(el("h3", "", "AS path changes"));
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No AS path in this window. Members share paths only with the paths data class."));
    return;
  }
  root.appendChild(ixpTable(["Vantage", "Target", "Time", "Event", "AS path"], rows));
}

function renderHerdVantages(root, d) {
  clear(root);
  root.appendChild(el("h3", "", "Per-vantage records"));
  if (!(d.vantages || []).length) {
    root.appendChild(el("p", "empty", "No record for this target in the last 24 hours."));
    return;
  }
  root.appendChild(ixpTable(["Vantage", "Records", "Latest loss", "Latest RTT avg", "Age", "Fetched"], d.vantages.map(function (v) {
    var l = v.latest;
    return [ixpCell(herdVantageLabel(v)), ixpCell(v.records), ixpCell(l.failed ? "round failed" : herdPct(l.loss_pct)), ixpCell(herdMs(l.rtt_avg_ms)),
      ixpCell(herdAge(l.age_seconds)), ixpCell(l.fetched_at ? fmtTime(l.fetched_at) : "this node")];
  })));
}

// ---- Search ----

function renderHerdHits(root, d) {
  clear(root);
  if (!(d.hits || []).length) {
    root.appendChild(el("p", "empty", "Nothing matches within the last " + d.days + " days of retention."));
    return;
  }
  var rows = d.hits.map(function (h) {
    return [ixpCell(herdTargetLabel(h), "mono"), ixpCell(h.kind === "origin_asn" ? "origin AS (pooled)" : "route"), ixpCell(h.members), ixpCell(h.vantages), ixpCell(h.records),
      ixpCell((h.providers || []).map(herdAS).join(", ")), ixpCell(fmtTime(h.first_seen)), ixpCell(fmtTime(h.last_seen)),
      {text: "Open", href: herdOpenHref(h.kind, h.value, h.origins)}];
  });
  root.appendChild(ixpTable(["Target", "Level", "Members", "Vantages", "Records", "Providers", "First seen", "Last seen", "Monitors"], rows));
  if (d.truncated) root.appendChild(el("p", "tag", "Some matches may be missing: the search reads a limited number of records and lists at most 100 targets. Narrow the search."));
}

// ---- Outside intelligence ----

function renderHerdOutside(root, d) {
  clear(root);
  if (!(d.sections || []).length) {
    root.appendChild(el("p", "empty", "No outside source is enabled. The page shows herd data only."));
    return;
  }
  d.sections.forEach(function (s) {
    var box = el("div", "tool-result");
    var head = el("div", "tool-head");
    head.appendChild(el("h3", "", s.source));
    head.appendChild(el("span", "tag", s.as_of ? "as of " + fmtTime(s.as_of) + " (" + herdAge(s.age_seconds) + " old)" : "no data yet"));
    box.appendChild(head);
    if (s.error) box.appendChild(el("p", "bad", "Last read failed: " + s.error));
    if (s.note) box.appendChild(el("p", "tag", s.note));
    if ((s.rows || []).length) {
      box.appendChild(ixpTable(s.columns, s.rows.map(function (r) { return r.map(function (c) { return ixpCell(c); }); })));
    }
    if ((s.links || []).length) {
      var list = el("p", "linkouts");
      s.links.forEach(function (k) {
        var a = herdLink(k.name, k.url);
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        list.appendChild(a);
      });
      box.appendChild(list);
    }
    root.appendChild(box);
  });
}

// ---- Page ----

function herdBox(id) { return document.getElementById(id); }

function herdSetStatus(id, text, bad) {
  var n = herdBox(id);
  n.textContent = text;
  n.className = bad ? "bad" : "tag";
}

function herdFail(id) {
  return function (err) { herdSetStatus(id, err.message, true); };
}

function loadHerdOutside() {
  var t = herdTarget || {asn: "", prefix: ""};
  return api("GET", "/api/herd/outside?" + herdQuery({origin_asn: t.asn, prefix: t.prefix})).then(function (d) {
    renderHerdOutside(herdBox("herd-outside"), d);
  }, herdFail("herd-status"));
}

function loadHerdMonitor() {
  var t = herdTarget;
  if (!t || (!t.asn && !t.prefix)) {
    herdSetStatus("herd-t-status", "Name an origin ASN or a prefix, or open one from the world view or search.");
    return Promise.resolve();
  }
  // A route target is read at route level; a bare ASN at origin level.
  var q = t.prefix ? herdQuery({prefix: t.prefix}) : herdQuery({origin_asn: t.asn});
  herdSetStatus("herd-t-status", "Showing " + (t.prefix || "AS" + t.asn) + ".");
  return Promise.all([api("GET", "/api/herd/monitor?" + q), api("GET", "/api/herd/vantages?" + q)]).then(function (r) {
    renderHerdLatency(herdBox("herd-latency"), r[0]);
    renderHerdPaths(herdBox("herd-paths"), r[0]);
    renderHerdVantages(herdBox("herd-vantages"), r[1]);
  }, herdFail("herd-t-status"));
}

function loadHerdBoard() {
  var q = herdQuery({window: herdBox("herd-window").value, loss: herdBox("herd-loss").value});
  var lossOnly = herdQuery({loss: herdBox("herd-loss").value});
  return Promise.all([api("GET", "/api/herd/overview"), api("GET", "/api/herd/events?" + q),
    api("GET", "/api/herd/mesh?" + lossOnly), api("GET", "/api/herd/map?" + lossOnly)]).then(function (r) {
    var status = herdBox("herd-status"), body = herdBox("herd-body");
    if (!r[0].enabled) {
      status.textContent = "Herd is off. Turn it on with the herd block in the config file; nothing is shared or pulled until you do.";
      status.className = "tag";
      body.hidden = true;
      return;
    }
    status.textContent = "";
    body.hidden = false;
    renderHerdOverview(herdBox("herd-sharing"), herdBox("herd-members"), r[0]);
    renderHerdEvents(herdBox("herd-events"), r[1]);
    renderHerdMesh(herdBox("herd-mesh"), r[2]);
    renderHerdMap(herdBox("herd-map"), r[3]);
  }, herdFail("herd-status"));
}

function onHerdTarget(ev) {
  ev.preventDefault();
  herdTarget = {asn: herdBox("herd-t-asn").value.trim(), prefix: herdBox("herd-t-prefix").value.trim()};
  loadHerdMonitor();
  loadHerdOutside();
}

function onHerdSearch(ev) {
  ev.preventDefault();
  var prefix = herdBox("herd-s-prefix").value.trim();
  var q = herdQuery({prefix: prefix, match: prefix ? herdBox("herd-s-match").value : "", origin_asn: herdBox("herd-s-origin").value.trim(),
    provider_asn: herdBox("herd-s-provider").value.trim(), member: herdBox("herd-s-member").value.trim()});
  if (!q) {
    herdSetStatus("herd-s-status", "Fill in at least one field.", true);
    return;
  }
  herdSetStatus("herd-s-status", "Searching.");
  api("GET", "/api/herd/search?" + q).then(function (d) {
    herdSetStatus("herd-s-status", d.hits.length + " matching targets.");
    renderHerdHits(herdBox("herd-hits"), d);
  }, herdFail("herd-s-status"));
}

function startHerdPage() {
  herdBox("herd-target").addEventListener("submit", onHerdTarget);
  herdBox("herd-search").addEventListener("submit", onHerdSearch);
  herdBox("herd-window").addEventListener("change", loadHerdBoard);
  herdBox("herd-loss").addEventListener("change", loadHerdBoard);
  herdBox("refresh").addEventListener("click", loadHerdBoard);
  var params = new URLSearchParams(location.search);
  herdTarget = {asn: params.get("origin_asn") || "", prefix: params.get("prefix") || ""};
  herdBox("herd-t-asn").value = herdTarget.asn;
  herdBox("herd-t-prefix").value = herdTarget.prefix;
  loadHerdBoard().then(function () {
    if (herdTarget.asn || herdTarget.prefix) loadHerdMonitor();
    loadHerdOutside();
  });
  setInterval(loadHerdBoard, HERD_REFRESH_MS);
}

if (typeof document !== "undefined" && document.getElementById("herd-body")) startHerdPage();
