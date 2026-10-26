"use strict";

var REFRESH_MS = 5000;
var refreshing = false;
var refreshAgain = false;
var lastProviders = null;
var lastProviderStats = null;
var lastPrefixes = null;
var lastImprovements = null;
var lastReady = null;
var lastMitigation = null;
var lastOverview = null;
var lastOK = null;

function el(tag, className, text) {
  var n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null && text !== "") n.textContent = String(text);
  return n;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fmtMs(v) {
  if (v == null || Number.isNaN(Number(v))) return "—";
  return Number(v).toFixed(1) + " ms";
}

function fmtPct(v) {
  if (v == null || Number.isNaN(Number(v))) return "—";
  return Number(v).toFixed(1) + "%";
}

// NO_REPLY is what a path with no answer shows instead of an RTT. A 0.0 ms
// there would read as the fastest path (#343).
var NO_REPLY = "no reply";

// healthPill is the provider's measured state: red down, amber degraded,
// green up. A provider with no result yet is not a problem.
function healthPill(state) {
  if (state === "down") return el("span", "dot down", "down");
  if (state === "degraded") return el("span", "dot degraded", "degraded");
  if (state === "unknown") return el("span", "badge muted", "no data yet");
  return el("span", "dot up", "up");
}

function providerState(name) {
  var list = (lastOverview && lastOverview.providers) || [];
  for (var i = 0; i < list.length; i++) {
    if (list[i].name === name) return list[i].state;
  }
  return "";
}

function fmtTime(s) {
  if (!s) return "—";
  var d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function getJSON(path) {
  return fetch(path, {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) {
        try { body = JSON.parse(text); } catch (e) { body = null; }
      }
      if (!res.ok) {
        var msg = (body && body.error) || (body && body.status) || res.statusText;
        var err = new Error(path + " failed: " + msg);
        err.status = res.status;
        throw err;
      }
      return body;
    });
  });
}

// Link-outs (#211). The server builds every URL from the object's own
// prefix or ASN (/api/linkouts) and drops internal ones when
// linkouts.hide_internal is on; the page only places them. Spans made in
// one pass share one request. Packeteer fetches none of these sites.
var LINKOUT_BATCH = 200;
var linkoutCache = {};
var linkoutWaiting = {};
var linkoutTimer = null;

function linkoutSpan(kind, value) {
  var span = el("span", "linkouts");
  var key = kind + "|" + value;
  if (linkoutCache[key]) {
    fillLinkouts(span, linkoutCache[key]);
    return span;
  }
  (linkoutWaiting[key] = linkoutWaiting[key] || []).push(span);
  if (!linkoutTimer) linkoutTimer = setTimeout(flushLinkouts, 0);
  return span;
}

function fillLinkouts(span, links) {
  var shown = links.filter(function (l) { return /^https:/.test(l.url); });
  if (!shown.length) return;
  span.appendChild(el("span", "k", "Open in"));
  shown.forEach(function (l) {
    var a = el("a", "", l.name);
    a.href = l.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    span.appendChild(a);
  });
}

function flushLinkouts() {
  var waiting = linkoutWaiting;
  linkoutWaiting = {};
  linkoutTimer = null;
  var keys = Object.keys(waiting);
  if (Object.keys(linkoutCache).length > 2000) linkoutCache = {};
  for (var i = 0; i < keys.length; i += LINKOUT_BATCH) {
    var chunk = keys.slice(i, i + LINKOUT_BATCH);
    var q = new URLSearchParams();
    chunk.forEach(function (key) {
      var at = key.indexOf("|");
      q.append(key.slice(0, at), key.slice(at + 1));
    });
    getJSON("/api/linkouts?" + q.toString()).then(function (data) {
      chunk.forEach(function (key) {
        var at = key.indexOf("|");
        var links = ((data[key.slice(0, at)] || {})[key.slice(at + 1)]) || [];
        linkoutCache[key] = links;
        waiting[key].forEach(function (span) { fillLinkouts(span, links); });
      });
    }, function () {});
  }
}

// originASN is the last AS on the first learned path that has one, the
// same origin the ASN map groups by.
function originASN(row) {
  var paths = (row && row.paths) || [];
  for (var i = 0; i < paths.length; i++) {
    var p = paths[i].as_path || [];
    if (p.length) return p[p.length - 1];
  }
  return 0;
}

// statCell shows one measured figure over the last 15 minutes and the last
// 24 hours. A path that never answered has loss but no latency, so it reads
// "no reply", not 0.0 ms (#343).
function statCell(st, key, fmt) {
  var td = el("td", "stat");
  [["15 min", st && st.last_15m], ["24 h", st && st.last_24h]].forEach(function (w) {
    var line = el("div", "stat-line");
    line.appendChild(el("span", "stat-k", w[0]));
    var win = w[1];
    var text;
    if (!win || !win.slots) text = "no data";
    else if (win[key] == null) text = NO_REPLY;
    else text = fmt(win[key]);
    line.appendChild(el("span", win && win.slots && win[key] != null ? "stat-v" : "stat-v muted", text));
    td.appendChild(line);
  });
  return td;
}

// mbpsText is the provider's current rate. Without a flow source there is
// no rate to show.
function mbpsText(st, all) {
  if (!all || !all.flow) return "no flow data";
  return st && st.mbps != null ? (Math.round(st.mbps * 10) / 10).toFixed(1) : "0.0";
}

// reorderCell is the provider path's RFC 4737 reordered ratio (#224) from
// /api/providers: the worst flow toward a responder the operator runs, or,
// marked "est.", toward an echo host whose replies the far end may
// reorder. A dash until a responder answered.
function reorderCell(r) {
  var td = el("td", "reorder");
  if (!r) {
    td.textContent = "\u2014";
    return td;
  }
  td.appendChild(el("span", r.ratio_pct > 0 ? "num warn" : "num", fmtPct(r.ratio_pct)));
  if (r.estimate) {
    var est = el("span", "badge muted", "est.");
    est.title = "Estimate: measured with ICMP echo toward " + r.responder + ". The far end and ICMP rate limiting can reorder replies. Never used for a decision.";
    td.appendChild(document.createTextNode(" "));
    td.appendChild(est);
  }
  td.title = "RFC 4737 reordered ratio of the worst flow toward " + r.responder + "; extent " + r.extent + ", n-reordering " + r.n_reordering;
  return td;
}

function renderProviders(data) {
  var root = document.getElementById("providers");
  if (!root) return;
  clear(root);
  var rows = (data && data.providers) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No providers in the config."));
    return;
  }
  var table = el("table");
  var head = el("tr");
  var health = {};
  ((lastOverview && lastOverview.providers) || []).forEach(function (h) { health[h.name] = h; });
  var stats = {};
  ((lastProviderStats && lastProviderStats.providers) || []).forEach(function (st) { stats[st.provider] = st; });
  ["Provider", "Source", "Next hop", "Open in", "Health", "Latency", "Loss", "Jitter", "Reordering", "Trend, 24 h", "Mbps", "Probes", "Since", "Detail"].forEach(function (h) {
    head.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(head);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (p) {
    var tr = el("tr");
    tr.id = "provider-" + (p.name || "");
    var name = el("td");
    name.appendChild(document.createTextNode(p.name || ""));
    if (p.exclude) name.appendChild(el("span", "badge", "excluded"));
    if (p.group) name.appendChild(el("span", "badge", p.group));
    if (p.cc_disable) name.appendChild(el("span", "badge", "commit off"));
    tr.appendChild(name);
    tr.appendChild(el("td", "mono", p.source || "—"));
    tr.appendChild(el("td", "mono", p.next_hop || "—"));
    var peer = el("td");
    if (p.peer_asn) {
      peer.appendChild(el("span", "k", p.exchange + " AS" + p.peer_asn));
      peer.appendChild(linkoutSpan("asn", p.peer_asn));
    } else if (p.asn) {
      peer.appendChild(el("span", "k", (p.type ? p.type + " " : "") + "AS" + p.asn));
      peer.appendChild(linkoutSpan("asn", p.asn));
    } else if (p.type) {
      peer.appendChild(el("span", "k", p.type));
    } else {
      peer.textContent = "—";
    }
    tr.appendChild(peer);
    var h = health[p.name];
    var cell = el("td");
    cell.appendChild(h ? healthPill(h.state) : el("span", p.up ? "dot up" : "dot down", p.up ? "up" : "down"));
    if (h && h.detail) cell.appendChild(el("span", "muted", " " + h.detail));
    tr.appendChild(cell);
    var st = stats[p.name];
    tr.appendChild(statCell(st, "rtt_ms", fmtMs));
    tr.appendChild(statCell(st, "loss_pct", fmtPct));
    tr.appendChild(statCell(st, "jitter_ms", fmtMs));
    tr.appendChild(reorderCell(p.reorder));
    var trend = el("td", "trend");
    trend.appendChild(sparkline(st && st.points));
    tr.appendChild(trend);
    tr.appendChild(el("td", "mbps", mbpsText(st, lastProviderStats)));
    tr.appendChild(el("td", "", h ? probeCount(h) : "—"));
    tr.appendChild(el("td", "", fmtTime(p.since)));
    tr.appendChild(el("td", "", p.reason || ""));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);

  var bgp = data && data.bgp;
  if (!bgp || !bgp.configured) return;
  root.appendChild(el("h3", "", "BGP sessions"));
  var peers = bgp.peers || [];
  if (!peers.length) {
    root.appendChild(el("p", "empty", "No neighbors."));
    return;
  }
  var pt = el("table");
  var phr = el("tr");
  ["Peer", "Description", "State", "Since"].forEach(function (h) {
    phr.appendChild(el("th", "", h));
  });
  var pth = el("thead");
  pth.appendChild(phr);
  pt.appendChild(pth);
  var pb = el("tbody");
  peers.forEach(function (peer) {
    var tr = el("tr");
    tr.appendChild(el("td", "mono", peer.address || ""));
    tr.appendChild(el("td", "", peer.description || ""));
    var st = el("td");
    var view = bgpState(peer.state, peer.established);
    var pill = el("span", "dot " + view.level, view.label);
    pill.title = view.title;
    st.appendChild(pill);
    tr.appendChild(st);
    tr.appendChild(el("td", "", fmtTime(peer.since)));
    pb.appendChild(tr);
  });
  pt.appendChild(pb);
  root.appendChild(pt);
}

// exitLabels names the two exits of a prefix. Only inject moves traffic to
// the engine's choice; elsewhere the router keeps its learned path (#346).
function exitLabels() {
  if (lastProviders && lastProviders.mode === "inject") return {now: "Current", pick: "Recommended"};
  return {now: "Traffic now (router)", pick: "Packeteer recommends"};
}

// prefixCard is the per-prefix card: exits, per-provider probes, measured
// sub-ranges, and learned paths. Used by the expandable rows of the Prefixes
// page and by the prefix page.
function prefixCard(row) {
  var card = el("article", "card");
  var head = el("div", "card-head");
  head.appendChild(el("h3", "mono", row.prefix));
  var exits = el("p", "exits");
  var labels = exitLabels();
  exits.appendChild(el("span", "k", labels.now));
  exits.appendChild(el("span", "v", row.current || "—"));
  exits.appendChild(el("span", "k", labels.pick));
  var differs = row.recommended && row.recommended !== row.current;
  exits.appendChild(el("span", differs ? "v diff" : "v", row.recommended || "—"));
  head.appendChild(exits);
  if (row.action) head.appendChild(el("span", "badge", row.action));
  var onRouter = el("span", row.in_rib ? "badge" : "badge muted", row.in_rib ? "on router" : "not on router");
  onRouter.title = "In the RIB learned from the edge router";
  head.appendChild(onRouter);
  if (row.heterogeneous) head.appendChild(el("span", "badge warn", "heterogeneous"));
  if (row.quarantine) head.appendChild(el("span", "badge warn", "quarantined"));
  card.appendChild(head);
  if (row.reason) card.appendChild(el("p", "reason", row.reason));
  var table = el("table");
  var hr = el("tr");
  ["Provider", "Loss", "RTT", "Jitter", "Probe", "Confidence"].forEach(function (h) {
    hr.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  (row.probes || []).forEach(function (pr) {
    var tr = el("tr");
    var cls = "";
    if (row.current && pr.provider === row.current) cls = "is-current";
    if (row.recommended && pr.provider === row.recommended) cls = (cls + " is-recommended").trim();
    if (cls) tr.className = cls;
    var nameCell = el("td", "", pr.provider);
    var state = providerState(pr.provider);
    if (state === "down" || state === "degraded") {
      nameCell.appendChild(document.createTextNode(" "));
      nameCell.appendChild(healthPill(state));
    }
    tr.appendChild(nameCell);
    if (!pr.ok) {
      tr.appendChild(el("td", "", "—"));
      tr.appendChild(el("td", "bad", NO_REPLY));
      tr.appendChild(el("td", "", "—"));
      tr.appendChild(el("td", "bad", pr.error || "failed"));
      tr.appendChild(el("td", "", "\u2014"));
    } else {
      var silent = !pr.received;
      tr.appendChild(el("td", silent ? "num bad" : "num", fmtPct(pr.loss_pct)));
      var rttCell = silent ? el("td", "bad", NO_REPLY) : el("td", "num", fmtMs(pr.rtt_avg_ms));
      if (!silent && pr.ttfb_ms) {
        rttCell.title = "connect " + fmtMs(pr.connect_ms) + ", TLS handshake " + fmtMs(pr.handshake_ms) + ", first byte " + fmtMs(pr.ttfb_ms);
      }
      tr.appendChild(rttCell);
      tr.appendChild(silent ? el("td", "", "\u2014") : el("td", "num", fmtMs(pr.jitter_ms)));
      var probeCell = el("td", "", pr.prober || (silent ? "\u2014" : "ok"));
      if (pr.indirect) {
        var tag = el("span", "badge muted", "indirect");
        tag.title = "Every address inside the prefix was silent. Measured at this provider's traceroute hop " + (pr.target || "") + ".";
        probeCell.appendChild(document.createTextNode(" "));
        probeCell.appendChild(tag);
      }
      tr.appendChild(probeCell);
      tr.appendChild(confidenceCell(pr.confidence && pr.confidence.level, pr.evidence));
    }
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  card.appendChild(table);
  var subs = row.subranges || [];
  if (subs.length) {
    card.appendChild(el("p", "reason", row.heterogeneous ?
      "Measured sub-ranges disagree on the best provider. The prefix decision uses their traffic-weighted score. Sub-ranges are measured only, never announced." :
      "Measured sub-ranges. The prefix decision uses their traffic-weighted score. Sub-ranges are measured only, never announced."));
    var st = el("table");
    var shr = el("tr");
    ["Sub-range", "Share", "Best"].forEach(function (h) {
      shr.appendChild(el("th", "", h));
    });
    var shead = el("thead");
    shead.appendChild(shr);
    st.appendChild(shead);
    var total = subs.reduce(function (a, s) { return a + (s.weight || 0); }, 0);
    var sb = el("tbody");
    subs.forEach(function (s) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", s.prefix));
      tr.appendChild(el("td", "num", total > 0 ? fmtPct(100 * (s.weight || 0) / total) : "—"));
      tr.appendChild(el("td", s.best && s.best !== row.recommended ? "diff" : "", s.best || "—"));
      sb.appendChild(tr);
    });
    st.appendChild(sb);
    card.appendChild(st);
  }
  var paths = row.paths || [];
  if (paths.length) {
    card.appendChild(el("p", "reason", "Learned paths. MED is display only and does not choose the exit. Via is route server, bilateral, or unknown."));
    var pt = el("table");
    var phr = el("tr");
    ["State", "Provider", "Next hop", "AS path", "Via", "RPKI", "IRR", "MED", "Whose MED"].forEach(function (h) {
      phr.appendChild(el("th", "", h));
    });
    var phead = el("thead");
    phead.appendChild(phr);
    pt.appendChild(phead);
    var pb = el("tbody");
    paths.forEach(function (path) {
      var tr = el("tr");
      if (path.selected) tr.className = "is-current";
      tr.appendChild(el("td", "", path.selected ? "selected" : "inactive"));
      tr.appendChild(el("td", "", path.provider || "—"));
      tr.appendChild(el("td", "mono", path.next_hop || "—"));
      tr.appendChild(el("td", "mono", fmtAS(path.as_path)));
      tr.appendChild(el("td", "", fmtVia(path.via)));
      tr.appendChild(rpkiCell(path.rpki, path.rpki_source, path.rpki_updated));
      tr.appendChild(irrCell(path));
      tr.appendChild(el("td", "num", path.med === undefined || path.med === null ? "—" : String(path.med)));
      tr.appendChild(el("td", "", path.med_from || "—"));
      pb.appendChild(tr);
    });
    pt.appendChild(pb);
    card.appendChild(pt);
  }

  return card;
}

// prefixHref is the shareable detail page of a prefix (#179).
function prefixHref(prefix) {
  return "/prefix/" + encodeURI(prefix);
}

function prefixCell(prefix) {
  var td = el("td", "mono");
  var a = el("a", "", prefix);
  a.href = prefixHref(prefix);
  td.appendChild(a);
  return td;
}

function fmtAS(path) {
  if (!path || !path.length) return "—";
  return path.join(" ");
}

// confidenceCell is a level pill with the evidence behind it (#202). Low
// is amber, so an ICMP-only or one-reply sample stands out.
function confidenceCell(level, text) {
  var td = el("td");
  if (!level || level === "none") {
    td.appendChild(document.createTextNode("\u2014"));
    return td;
  }
  var pill = el("span", level === "low" ? "badge warn" : "badge", level);
  if (text) pill.title = text;
  td.appendChild(pill);
  if (text) td.appendChild(el("span", "muted", " " + text));
  return td;
}

// rpkiCell is a validity with the source that answered and the age of its
// data (#200), so a stale cache or the display fallback is visible.
function rpkiCell(state, source, updated) {
  var td = el("td", state === "invalid" ? "badge warn" : "", state || "-");
  if (source) td.appendChild(el("span", "muted", " via " + source + ageText(updated)));
  return td;
}

// ageText is ", <age> old" for a data time, empty without one.
function ageText(updated) {
  var at = updated ? new Date(updated).getTime() : NaN;
  if (Number.isNaN(at)) return "";
  return ", " + fmtDuration(Math.max(0, Math.round((Date.now() - at) / 1000))) + " old";
}

var irrSetText = {registered: "member", not_registered: "not a member", unknown: "unknown"};

// irrCell is a path's IRR registration (#214) with the source, database,
// and age of the answer, the origins registered for the prefix, the
// provider's as-set membership, and the origin's as-name.
function irrCell(path) {
  var state = path.irr;
  var td = el("td", state === "not_registered" ? "badge warn" : "", state ? state.replace("_", " ") : "-");
  var parts = [];
  if (path.irr_source) parts.push("via " + path.irr_source + (path.irr_database ? " (" + path.irr_database + ")" : "") + ageText(path.irr_updated));
  if (path.irr_origins && path.irr_origins.length) parts.push("registered: AS" + path.irr_origins.join(", AS"));
  if (path.irr_as_set) parts.push(path.irr_as_set + ": " + (irrSetText[path.irr_as_set_state] || "unknown"));
  if (path.irr_origin_as_name) parts.push("origin " + path.irr_origin_as_name);
  if (parts.length) td.appendChild(el("span", "muted", " " + parts.join("; ")));
  return td;
}

function fmtVia(v) {
  if (v === "route_server") return "route server";
  if (v === "bilateral") return "bilateral";
  if (v === "unknown") return "unknown";
  return "—";
}

function renderASNMap(data) {
  var root = document.getElementById("asn-map");
  if (!root) return;
  clear(root);
  var nodes = (data && data.asn_map) || [];
  if (!nodes.length) {
    root.appendChild(el("p", "empty", "No measured prefix has a learned path yet."));
    return;
  }
  if (data.asn_total > nodes.length) {
    root.appendChild(el("p", "tag", "Showing the first " + nodes.length + " of " + data.asn_total + " origin ASNs. Filter the table above by ASN to see one."));
  }
  nodes.forEach(function (node) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    var title = el("h3", "mono");
    if (node.asn) {
      var link = el("a", "", "AS" + node.asn);
      link.href = "/prefixes.html?asn=" + node.asn;
      link.title = "List the prefixes with this origin AS";
      title.appendChild(link);
    } else {
      title.textContent = "No origin AS";
    }
    head.appendChild(title);
    if (node.asn) head.appendChild(linkoutSpan("asn", node.asn));
    card.appendChild(head);
    var t = table(["Provider", "Site", "Prefixes", "Table"]);
    (node.sites || []).forEach(function (site) {
      var prefs = site.prefixes || [];
      var count = site.count || prefs.length;
      var shown = prefs.join(", ");
      if (count > prefs.length) shown += " +" + (count - prefs.length);
      var tr = el("tr");
      tr.appendChild(el("td", "", site.provider || "—"));
      tr.appendChild(el("td", "mono", site.next_hop || "—"));
      tr.appendChild(el("td", "", count + (shown ? " (" + shown + ")" : "")));
      tr.appendChild(el("td", "", site.partial ? "partial" : "full"));
      t.body.appendChild(tr);
    });
    card.appendChild(t.table);
    root.appendChild(card);
  });
}

function renderImprovements(data) {
  var root = document.getElementById("improvements");
  if (!root) return;
  clear(root);
  var rows = (data && data.improvements) || [];
  var mode = data && data.mode;
  var inject = mode === "inject";
  var title = document.getElementById("improvements-title");
  if (title) title.textContent = inject ? "Active improvements" : "Recommended improvements";
  var cap = lastOverview && lastOverview.counts && lastOverview.counts.max_improvements;
  var tag = document.getElementById("improvements-tag");
  if (tag) tag.textContent = (inject ?
    "Announced to the edge with the Packeteer community and NO_EXPORT. " :
    "Recommendations only: what inject mode would announce. ") +
    (cap ? "At most " + cap + " at a time." : "");
  if (tag && cap) tag.title = "max_improvements";
  if (!rows.length) {
    var p = el("p", "empty");
    var bgp = lastOverview && lastOverview.bgp;
    if (bgp && !bgp.established) {
      p.appendChild(document.createTextNode("No BGP session, so Packeteer can't see current routes and makes no recommendations. Fix the edge session on the "));
      var sys = el("a", "", "System page");
      sys.href = "/system.html";
      p.appendChild(sys);
      p.appendChild(document.createTextNode("."));
    } else {
      p.textContent = inject ? "No active improvements." :
        "None. A move is recommended only when another provider beats the current exit by the configured thresholds.";
    }
    root.appendChild(p);
    return;
  }
  var table = el("table");
  var hr = el("tr");
  var heads = [["Prefix"], ["Default route via", "The native exit: where the router sends this prefix without Packeteer"],
    [inject ? "Steered to" : "Recommended"], ["Cause"],
    ["Latency", "Native -> recommended, from the latest probe round"], ["Loss", "Native -> recommended, from the latest probe round"],
    ["Gain", "Latency saved, and loss saved when there is some"], ["Mbps", "Observed traffic of the prefix, from the flow source"],
    ["ASN", "Origin AS of the learned path"], ["AS name"], ["Why"]];
  heads.forEach(function (h) {
    var th = el("th", "", h[0]);
    if (h[1]) th.title = h[1];
    hr.appendChild(th);
  });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (im) {
    var tr = el("tr");
    tr.appendChild(prefixCell(im.prefix));
    tr.appendChild(el("td", "", im.native || "—"));
    tr.appendChild(el("td", "", im.provider || "—"));
    tr.appendChild(el("td", "", im.cause || "—"));
    tr.appendChild(el("td", "", beforeAfter(im.native_rtt_ms, im.rtt_ms, " ms")));
    tr.appendChild(el("td", "", beforeAfter(im.native_loss_pct, im.loss_pct, "%")));
    tr.appendChild(el("td", "", gainText(im)));
    tr.appendChild(el("td", "", im.volume_mbps ? fmtNum(im.volume_mbps) : "no flow data"));
    tr.appendChild(el("td", "", im.asn ? "AS" + im.asn : "-"));
    tr.appendChild(el("td", "", im.as_name || "-"));
    tr.appendChild(el("td", "why", whyText(im, inject)));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);
}

function fmtNum(v) {
  return String(Math.round(v * 10) / 10);
}

function beforeAfter(before, after, unit) {
  if (before == null || after == null) return "-";
  return fmtNum(before) + " -> " + fmtNum(after) + unit;
}

function gainText(im) {
  if (im.gain_ms == null) return "-";
  var parts = [];
  if (im.gain_ms > 0) parts.push(fmtNum(im.gain_ms) + " ms" + (im.gain_pct != null ? " (" + Math.round(im.gain_pct) + "%)" : ""));
  if (im.loss_gain_pct != null) parts.push(fmtNum(im.loss_gain_pct) + " pt less loss");
  return parts.length ? parts.join(", ") : "none now";
}

// whyText is the plain sentence, the time it started, and, while hold_time
// has not elapsed, how long until the move can change.
function whyText(im, inject) {
  var s = im.explain || im.reason || "";
  if (im.since) s += " " + (inject ? "Active" : "Recommended") + " since " + fmtTime(im.since) + ".";
  if (im.hold_left_s) s += " Hold time: " + fmtDuration(im.hold_left_s) + " left before it can change.";
  return s;
}

function fmtDuration(sec) {
  var m = Math.floor(sec / 60), r = sec % 60;
  return m ? m + "m " + r + "s" : r + "s";
}

// modeBadge is the header chip. The class carries the contrast colors;
// the header's white text must not be inherited (#171).
function modeBadge(mode) {
  var name = mode === "observe" || mode === "suggest" || mode === "inject" ? mode : "unknown";
  return el("span", "badge mode-" + name, mode || "—");
}

function renderStatus(err) {
  var node = document.getElementById("status");
  if (!node) return;
  clear(node);
  var mode = lastProviders && lastProviders.mode;
  node.appendChild(modeBadge(mode));
  var ready = lastReady && lastReady.ready;
  node.appendChild(el("span", ready ? "dot up" : "dot down", ready ? "ready" : "not ready"));
  if (lastProviders && lastProviders.version) node.appendChild(el("span", "muted", lastProviders.version));
  if (lastProviders && lastProviders.generated_at) {
    node.appendChild(el("span", "muted", "updated " + fmtTime(lastProviders.generated_at)));
  }
  if (err) node.appendChild(el("span", "bad", "stale"));
}

function probeCount(h) {
  if (!h.ok && !h.failed) return "—";
  return h.ok + " ok" + (h.failed ? ", " + h.failed + " failed" : "");
}

var MODE_TEXT = {
  observe: "Observe mode: Packeteer measures and recommends. It announces nothing.",
  suggest: "Suggest mode: Packeteer measures and publishes recommendations. It announces nothing.",
  inject: "Inject mode: improvements for allowlisted prefixes are announced to the edge routers."
};

function renderBanner(mode) {
  var node = document.getElementById("banner");
  if (!node) return;
  if (!mode || !MODE_TEXT[mode]) { node.hidden = true; return; }
  node.textContent = MODE_TEXT[mode];
  node.className = "banner " + (mode === "inject" ? "banner-inject" : "banner-observe");
  node.hidden = false;
}

function tile(label, value, note, cls) {
  var t = el("div", "tile" + (cls ? " " + cls : ""));
  t.appendChild(el("span", "k", label));
  t.appendChild(el("span", "tile-v", value));
  if (note) t.appendChild(el("span", "muted tile-note", note));
  return t;
}

function renderTiles(o) {
  var root = document.getElementById("tiles");
  if (!root) return;
  clear(root);
  var c = o.counts || {};
  var inject = o.mode === "inject";
  var problems = o.problems || [];
  var worst = problems.some(function (p) { return p.state === "down"; }) ? "bad" : (problems.length ? "warn" : "");
  var unmeasured = (o.providers || []).filter(function (p) { return p.state === "unknown"; }).length;
  root.appendChild(tile("Providers", c.providers_healthy + " of " + c.providers + " healthy",
    unmeasured ? unmeasured + " not measured yet" : "", worst));
  root.appendChild(tile("Status", o.ready ? "ready" : (o.started ? "not ready" : "starting"),
    o.bgp && o.bgp.configured && !o.bgp.ready ? "no iBGP session" : "", o.ready ? "good" : "bad"));
  root.appendChild(tile("Prefixes measured", c.measured + " of " + c.prefixes,
    (o.sources || []).length ? "sources: " + o.sources.join(", ") : "no sources", c.prefixes ? "" : "muted"));
  root.appendChild(tile(inject ? "Improvements" : "Recommended", c.improvements + (c.max_improvements ? " of " + c.max_improvements : ""),
    c.recommended ? c.recommended + " prefixes differ" : ""));
  var b = o.bgp || {};
  root.appendChild(tile("BGP sessions", b.configured ? b.established + " of " + b.peers : "off",
    b.configured ? (c.in_rib + " probed prefixes known to the router") : "no edge router", b.configured && !b.established ? "bad" : ""));
  var sys = o.system || {};
  var warns = c.warnings || 0;
  var sysText = sys.down ? sys.down + " down" : (sys.degraded ? sys.degraded + " degraded" :
    (warns ? warns + (warns === 1 ? " warning" : " warnings") : "all ok"));
  var sysTile = tile("System", sysText,
    (sys.total || 0) + " components", sys.down ? "bad" : (sys.degraded || warns ? "warn" : ""));
  var sysLink = el("a", "", "System page");
  sysLink.href = "/system.html";
  sysTile.appendChild(sysLink);
  root.appendChild(sysTile);
}

function renderSetup(o) {
  var root = document.getElementById("setup");
  if (!root) return;
  clear(root);
  var hints = o.setup || [];
  if (!hints.length) return;
  var box = el("div", "setup");
  box.appendChild(el("h3", "", "Setup checklist"));
  var editor = (o.features || []).some(function (f) { return f.name === "config_editor" && f.on; });
  if (!editor) box.appendChild(el("p", "tag", "Edit the mounted config file, then restart the container."));
  var ul = el("ul", "hints");
  hints.forEach(function (h) {
    var li = el("li", "hint hint-" + h.level);
    li.setAttribute("data-hint", h.id);
    li.appendChild(el("span", "badge hint-level", h.level === "todo" ? "to do" : h.level));
    li.appendChild(el("strong", "", h.title));
    li.appendChild(el("span", "", " " + h.detail));
    if (h.fix && editor && shellAdmin) {
      li.appendChild(document.createTextNode(" "));
      var fix = el("a", "", "Fix in Settings");
      fix.href = h.fix;
      li.appendChild(fix);
    }
    if (h.doc) {
      li.appendChild(document.createTextNode(" "));
      var code = el("code", "muted");
      code.appendChild(docLink(h.doc_url, h.doc));
      li.appendChild(code);
    }
    ul.appendChild(li);
  });
  box.appendChild(ul);
  root.appendChild(box);
}

var FEATURE_NAMES = {
  history: "report history", troubleshoot: "probe/traceroute/whois tools", config_editor: "config editor",
  dashboards: "custom dashboards", inbound: "inbound optimization", mitigation: "threat mitigation",
  anomaly: "anomaly detection", federation: "multi-POP", ha: "high availability"
};

function renderFeatures(o) {
  var on = [], off = [];
  (o.features || []).forEach(function (f) {
    (f.on ? on : off).push(FEATURE_NAMES[f.name] || f.name);
    if (f.name === "federation") {
      var fed = document.getElementById("federation-section");
      if (fed) fed.hidden = !f.on;
    }
    if (f.name === "mitigation") {
      var mit = document.getElementById("mitigation-section");
      if (mit) mit.hidden = !f.on;
      var empty = document.getElementById("protection-empty");
      if (empty) empty.hidden = !!f.on;
    }
  });
  var node = document.getElementById("features");
  if (node) node.textContent = (on.length ? "On: " + on.join(", ") + ". " : "") + (off.length ? "Off: " + off.join(", ") + "." : "");
}

// renderHeadline is the one sentence above the tiles when a provider is
// down or degraded. It is hidden when every provider is healthy (#343).
function renderHeadline(o) {
  var node = document.getElementById("headline");
  if (!node) return;
  clear(node);
  var problems = o.problems || [];
  if (!problems.length) { node.hidden = true; return; }
  var down = problems.some(function (p) { return p.state === "down"; });
  node.className = "headline " + (down ? "headline-down" : "headline-degraded");
  node.appendChild(el("strong", "", problems.length + (problems.length === 1 ? " problem: " : " problems: ")));
  problems.forEach(function (p, i) {
    if (i) node.appendChild(document.createTextNode(", "));
    var a = el("a", "", p.provider);
    a.href = "/providers.html#provider-" + encodeURIComponent(p.provider);
    node.appendChild(a);
    node.appendChild(document.createTextNode(" " + p.detail));
  });
  node.hidden = false;
}

function renderOverview(o) {
  renderBanner(o.mode);
  if (typeof shellRenderAuthBanner === "function") shellRenderAuthBanner(o.auth);
  renderHeadline(o);
  renderTiles(o);
  renderSetup(o);
  renderFeatures(o);
}

function renderConn(err) {
  var node = document.getElementById("conn");
  if (!node) return;
  document.body.classList.toggle("stale", !!err);
  if (!err) { node.hidden = true; clear(node); return; }
  clear(node);
  var msg;
  if (err.status === 401) msg = "Sign in required. Reload the page to sign in.";
  else if (err.status === 403) msg = "Your account may not read this page.";
  else if (err.status) msg = "The controller answered with an error: " + err.message;
  else msg = "Cannot reach the controller. Is the container running?";
  node.appendChild(el("strong", "", msg));
  node.appendChild(el("span", "", lastOK ? " Showing data from " + fmtTime(lastOK) + "." : " No data loaded yet."));
  node.appendChild(el("span", "muted", " Retrying every " + (REFRESH_MS / 1000) + " seconds."));
  node.hidden = false;
}

function table(headers) {
  var t = el("table");
  var hr = el("tr");
  headers.forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  t.appendChild(thead);
  var tb = el("tbody");
  t.appendChild(tb);
  return {table: t, body: tb};
}

function mitigationWhat(r) {
  var parts = [];
  if (r.target) parts.push("target " + r.target + (r.route_target ? " (" + r.route_target + ")" : ""));
  if (r.next_hop) parts.push("next hop " + r.next_hop);
  if (r.rate_mbps) parts.push(r.rate_mbps + " Mbit/s");
  var m = r.match || {};
  if (m.source) parts.push("from " + m.source);
  if (r.source_countries && r.source_countries.length) parts.push("from " + r.source_countries.join(",") + " (" + r.routes + " networks)");
  if (m.protocols && m.protocols.length) parts.push("proto " + m.protocols.join(","));
  if (m.destination_ports && m.destination_ports.length) parts.push("dport " + m.destination_ports.join(","));
  if (m.source_ports && m.source_ports.length) parts.push("sport " + m.source_ports.join(","));
  return parts.join("; ");
}

function renderMitigation(data) {
  var root = document.getElementById("mitigation");
  if (!root) return;
  clear(root);
  if (!data || !data.enabled) {
    root.appendChild(el("p", "empty", "Not configured (mitigation in the config)."));
    return;
  }
  var summary = el("p", "exits");
  [["Mode", data.mitigation_mode], ["Routes held", data.routes_held + " of " + data.max_rules],
   ["Announced", data.routes_announced], ["FlowSpec", data.flowspec && data.flowspec.enabled ? "on" : "off"],
   ["GeoIP", data.geoip ? "on" : "off"]].forEach(function (kv) {
    summary.appendChild(el("span", "k", kv[0]));
    summary.appendChild(el("span", "v", kv[1]));
  });
  root.appendChild(summary);
  // The Protection form (#131) decides whether this account may remove a
  // rule; the server checks again on every call.
  if (typeof protectionUpdate === "function") protectionUpdate(data);
  var canRemove = typeof protRemoveCell === "function" && typeof protCanWrite !== "undefined" && protCanWrite;
  var rules = data.rules || [];
  if (!rules.length) {
    root.appendChild(el("p", "empty", "No rules."));
  } else {
    var t = table(["Prefix", "Action", "Detail", "State", "Expires", "Reason"].concat(canRemove ? ["Remove"] : []));
    rules.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", r.prefix));
      tr.appendChild(el("td", "", r.action));
      tr.appendChild(el("td", "", mitigationWhat(r)));
      var st = el("td");
      st.appendChild(el("span", r.announced ? "dot up" : "dot down", r.announced ? "announced" : (r.pending || "pending")));
      tr.appendChild(st);
      tr.appendChild(el("td", "", fmtTime(r.expires)));
      tr.appendChild(el("td", "", r.reason || ""));
      if (canRemove) tr.appendChild(protRemoveCell(r));
      t.body.appendChild(tr);
    });
    root.appendChild(t.table);
  }
  var feed = (data.feed || []).slice(0, 20);
  root.appendChild(el("h3", "", "Feed"));
  if (!feed.length) {
    root.appendChild(el("p", "empty", "No changes since the controller started."));
    return;
  }
  var f = table(["Time", "Change", "Prefix", "Action", "Detail"]);
  feed.forEach(function (c) {
    var tr = el("tr");
    tr.appendChild(el("td", "", fmtTime(c.time)));
    tr.appendChild(el("td", "", c.kind + (c.mode !== "inject" ? " (" + c.mode + ")" : "")));
    tr.appendChild(el("td", "mono", c.rule && c.rule.prefix));
    tr.appendChild(el("td", "", c.rule && c.rule.action));
    tr.appendChild(el("td", "", c.detail || mitigationWhat(c.rule || {})));
    f.body.appendChild(tr);
  });
  root.appendChild(f.table);
}

function renderFederation(data) {
  var root = document.getElementById("federation");
  if (!root) return;
  clear(root);
  if (!data || !data.enabled) {
    root.appendChild(el("p", "empty", "Not configured (federation in the config). This instance runs standalone."));
    return;
  }
  var t = table(["Instance", "Domain", "Mode", "State", "Inter-DC RTT", "Providers up", "Improvements", "Last seen", "Error"]);
  function row(name, snap, fresh, rtt, seen, error) {
    var tr = el("tr");
    tr.appendChild(el("td", "", name));
    tr.appendChild(el("td", "", (snap && snap.domain) || "—"));
    tr.appendChild(el("td", "", (snap && snap.mode) || "—"));
    var st = el("td");
    st.appendChild(el("span", fresh ? "dot up" : "dot down", fresh ? "fresh" : "stale"));
    tr.appendChild(st);
    tr.appendChild(el("td", "", rtt === null ? "local" : fmtMs(rtt)));
    var provs = (snap && snap.providers) || [];
    var up = provs.filter(function (p) { return p.up; }).map(function (p) { return p.name; });
    tr.appendChild(el("td", "", snap ? up.length + " of " + provs.length + (up.length ? " (" + up.join(", ") + ")" : "") : "—"));
    tr.appendChild(el("td", "", snap ? ((snap.improvements || []).length + " of " + snap.max_improvements) : "—"));
    tr.appendChild(el("td", "", seen ? fmtTime(seen) : "—"));
    tr.appendChild(el("td", "", error || ""));
    t.body.appendChild(tr);
  }
  row(data.instance + " (this)", data.local, true, null, data.local && data.local.time, "");
  (data.peers || []).forEach(function (p) {
    row(p.name, p.snapshot, p.fresh, p.snapshot ? p.inter_dc_rtt_ms : undefined, p.last_seen, p.error);
  });
  root.appendChild(t.table);
  var gc = data.global_commit || [];
  if (!gc.length) return;
  root.appendChild(el("h3", "", "Global commits"));
  var g = table(["Commit", "Usage", "Commit (Mbit/s)", "State", "Members"]);
  gc.forEach(function (c) {
    var tr = el("tr");
    tr.appendChild(el("td", "", c.name));
    tr.appendChild(el("td", "", c.complete ? c.total_mbps.toFixed(1) : "—"));
    tr.appendChild(el("td", "", String(c.commit_mbps)));
    var st = el("td");
    var label = !c.complete ? "incomplete (standalone commits)" : (c.over ? "over" : "under");
    st.appendChild(el("span", c.complete && !c.over ? "dot up" : "dot down", label));
    tr.appendChild(st);
    tr.appendChild(el("td", "", (c.members || []).map(function (m) {
      return m.provider + "@" + m.domain + " " + (m.have ? m.usage_mbps.toFixed(1) : "?");
    }).join(", ")));
    g.body.appendChild(tr);
  });
  root.appendChild(g.table);
}

// Settings push (#137): an admin sends this instance's thresholds or
// policies to every federation peer. Each peer validates them like a local
// config write and answers; nothing is announced from here. The form is
// built once, outside #federation, so a refresh does not wipe a result.
var FED_PUSH_SECTIONS = [["thresholds", "Thresholds"], ["policies", "Policies"]];
var fedPushBoxes = [];
var fedPushOut = null;

function renderFedPush(enabled) {
  var root = document.getElementById("fed-push");
  if (!root) return;
  root.hidden = !enabled;
  if (!enabled || fedPushBoxes.length) return;
  var row = el("p");
  FED_PUSH_SECTIONS.forEach(function (sec) {
    var label = el("label", "", " " + sec[1] + "  ");
    var box = el("input");
    box.type = "checkbox";
    box.checked = sec[0] === "thresholds";
    box.value = sec[0];
    label.insertBefore(box, label.firstChild);
    fedPushBoxes.push(box);
    row.appendChild(label);
  });
  var btn = el("button", "", "Push to all peers");
  btn.type = "button";
  btn.addEventListener("click", fedPushSend);
  row.appendChild(btn);
  root.appendChild(row);
  fedPushOut = el("div");
  root.appendChild(fedPushOut);
}

function fedPushSend() {
  var sections = fedPushBoxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
  clear(fedPushOut);
  if (!sections.length) {
    fedPushOut.appendChild(el("p", "empty", "Choose at least one section."));
    return Promise.resolve();
  }
  fedPushOut.appendChild(el("p", "empty", "Pushing " + sections.join(" and ") + "..."));
  return postJSON("/api/federation/push", {sections: sections}).then(function (rep) {
    renderFedPushReport(rep);
  }, function (err) {
    clear(fedPushOut);
    fedPushOut.appendChild(el("p", "errors", "Push failed: " + err.message));
  });
}

function renderFedPushReport(rep) {
  clear(fedPushOut);
  var t = table(["Peer", "Result", "Detail"]);
  (rep.peers || []).forEach(function (p) {
    var tr = el("tr");
    tr.appendChild(el("td", "", p.peer));
    var st = el("td");
    var ok = p.status === "applied" || p.status === "unchanged";
    st.appendChild(el("span", ok ? "dot up" : "dot down", p.status));
    tr.appendChild(st);
    var detail = (p.errors || []).join("; ") || (p.applied || []).join(", ");
    tr.appendChild(el("td", "", detail || (p.status === "unchanged" ? "already had these settings" : "")));
    t.body.appendChild(tr);
  });
  fedPushOut.appendChild(el("p", "", rep.ok ? "Every peer has these settings." : "At least one peer did not take them."));
  fedPushOut.appendChild(t.table);
}

// fetchPrefixes reads the one page of the measured-prefix list that the
// page asked for (#183). Pages that show no list do not read it.
// prefixListQuery is defined by prefixes.js and prefix.js, which load
// before this file.
function fetchPrefixes() {
  if (typeof prefixListQuery !== "function") return Promise.resolve(null);
  return getJSON("/api/prefixes?" + prefixListQuery());
}

// fetchProviderStats reads the per-provider figures for the pages that draw
// them: Providers and Overview.
function fetchProviderStats() {
  var page = document.body.getAttribute("data-page");
  if (page !== "providers" && page !== "overview") return Promise.resolve(null);
  return getJSON("/api/providers/stats");
}

// fetchVerification reads the steer checks (#305) for the Improvements page.
function fetchVerification() {
  if (document.body.getAttribute("data-page") !== "improvements") return Promise.resolve(null);
  return getJSON("/api/verification");
}

var VERIFY_LABEL = {verified: "Verified", partial: "Partial", not_moved: "Not moved", pending: "Pending", unknown: "Unknown"};

function verifyBadge(status) {
  var label = VERIFY_LABEL[status] || status;
  if (status === "verified") return el("span", "dot up", label);
  if (status === "partial") return el("span", "dot degraded", label);
  if (status === "not_moved") return el("span", "dot down", label);
  return el("span", "badge muted", label);
}

// renderVerification lists each outbound and inbound steer as verified,
// partial, not moved, pending, or unknown. With verify off the section stays hidden.
function renderVerification(data) {
  var sec = document.getElementById("verification-section");
  var root = document.getElementById("verification");
  if (!sec || !root) return;
  sec.hidden = !(data && data.enabled);
  if (sec.hidden) return;
  clear(root);
  var rows = data.results || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No steer has been checked yet."));
    return;
  }
  var table = el("table");
  var hr = el("tr");
  ["Direction", "Target", "Provider", "Result", "Moved", "Expected", "Checked", "Detail"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var tr = el("tr");
    tr.appendChild(el("td", "", r.kind));
    tr.appendChild(el("td", "", r.kind === "outbound" ? r.prefix : r.provider));
    tr.appendChild(el("td", "", r.kind === "outbound" ? "to " + r.provider : "away from " + r.provider));
    var st = el("td");
    st.appendChild(verifyBadge(r.status));
    if (r.backed_out) st.appendChild(el("span", "badge muted", "backed out"));
    tr.appendChild(st);
    tr.appendChild(el("td", "", r.status === "pending" || r.status === "unknown" ? "-" : fmtNum(r.moved_mbps) + " Mbps (" + Math.round(r.moved_pct) + "%)"));
    tr.appendChild(el("td", "", r.expected_mbps ? fmtNum(r.expected_mbps) + " Mbps" : "-"));
    tr.appendChild(el("td", "", r.status === "pending" ? "due " + fmtTime(r.due) : fmtTime(r.checked)));
    tr.appendChild(el("td", "why", r.detail));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);
}

function refresh() {
  if (refreshing) {
    refreshAgain = true;
    return;
  }
  refreshing = true;
  var readyReq = fetch("/readyz", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.json();
  });
  Promise.allSettled([
    getJSON("/api/providers"),
    fetchPrefixes(),
    getJSON("/api/improvements"),
    readyReq,
    getJSON("/api/mitigations"),
    getJSON("/api/federation"),
    getJSON("/api/overview"),
    fetchProviderStats(),
    fetchVerification()
  ]).then(function (results) {
    var err = null;
    if (results[6].status === "fulfilled") {
      lastOverview = results[6].value;
      renderOverview(lastOverview);
    } else err = results[6].reason;
    if (results[0].status === "fulfilled") lastProviders = results[0].value;
    else if (!err) err = results[0].reason;
    if (results[1].status === "fulfilled") lastPrefixes = results[1].value;
    else if (!err) err = results[1].reason;
    if (results[2].status === "fulfilled") lastImprovements = results[2].value;
    else if (!err) err = results[2].reason;
    if (results[3].status === "fulfilled") lastReady = results[3].value;
    else if (!err) err = results[3].reason;
    // The figures are optional: without them the cells say there is no data.
    if (results[7].status === "fulfilled" && results[7].value) lastProviderStats = results[7].value;
    if (!err) lastOK = new Date().toISOString();
    if (lastProviders) renderProviders(lastProviders);
    if (typeof renderOverviewCharts === "function") renderOverviewCharts(lastProviderStats, lastOverview);
    if (lastPrefixes) {
      if (typeof renderPrefixes === "function") renderPrefixes(lastPrefixes);
      renderASNMap(lastPrefixes);
      if (typeof prefixPageUpdate === "function") prefixPageUpdate(lastPrefixes);
    }
    if (lastImprovements) renderImprovements(lastImprovements);
    // Verification is optional: a failed read leaves the section as it was.
    if (results[8].status === "fulfilled" && results[8].value) renderVerification(results[8].value);
    // Mitigation is optional; its failure does not mark the page stale.
    if (results[4].status === "fulfilled") lastMitigation = results[4].value;
    if (lastMitigation) renderMitigation(lastMitigation);
    // The central view is optional too.
    if (results[5].status === "fulfilled") {
      renderFederation(results[5].value);
      renderFedPush(Boolean(results[5].value && results[5].value.push_enabled));
    }
    renderStatus(err);
    renderConn(err);
  }).then(function () {
    refreshDone();
  }, function () {
    refreshDone();
  });
}

// A filter change while a refresh is running is fetched right after it.
function refreshDone() {
  refreshing = false;
  if (refreshAgain) {
    refreshAgain = false;
    refresh();
  }
}

function postJSON(path, body) {
  return fetch(path, {
    method: "POST",
    cache: "no-store",
    headers: {Accept: "application/json", "Content-Type": "application/json"},
    body: JSON.stringify(body)
  }).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      if (!res.ok) {
        throw new Error((data && data.error) || res.statusText);
      }
      return data;
    });
  });
}

function bind(id, ev, fn) {
  var n = document.getElementById(id);
  if (n) n.addEventListener(ev, fn);
}

bind("refresh", "click", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
