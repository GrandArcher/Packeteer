"use strict";

var REFRESH_MS = 5000;
var refreshing = false;
var lastProviders = null;
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

function renderProviders(data) {
  var root = document.getElementById("providers");
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
  ["Provider", "Source", "Next hop", "Health", "Probes", "Since", "Detail"].forEach(function (h) {
    head.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(head);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (p) {
    var tr = el("tr");
    var name = el("td");
    name.appendChild(document.createTextNode(p.name || ""));
    if (p.exclude) name.appendChild(el("span", "badge", "excluded"));
    if (p.group) name.appendChild(el("span", "badge", p.group));
    if (p.cc_disable) name.appendChild(el("span", "badge", "commit off"));
    tr.appendChild(name);
    tr.appendChild(el("td", "mono", p.source || "—"));
    tr.appendChild(el("td", "mono", p.next_hop || "—"));
    var h = health[p.name];
    var cell = el("td");
    if (p.up && h && !h.ok && !h.failed) cell.appendChild(el("span", "badge muted", "no data yet"));
    else if (p.up && h && !h.ok) cell.appendChild(el("span", "dot down", "no answer"));
    else cell.appendChild(el("span", p.up ? "dot up" : "dot down", p.up ? "up" : "down"));
    tr.appendChild(cell);
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
    st.appendChild(el("span", peer.established ? "dot up" : "dot down", peer.state || "down"));
    tr.appendChild(st);
    tr.appendChild(el("td", "", fmtTime(peer.since)));
    pb.appendChild(tr);
  });
  pt.appendChild(pb);
  root.appendChild(pt);
}

function renderPrefixes(data) {
  var root = document.getElementById("prefixes");
  clear(root);
  var rows = (data && data.prefixes) || [];
  if (!rows.length) {
    var o = lastOverview;
    var msg = "No probed prefixes yet.";
    if (o && !(o.sources || []).length) msg = "Nothing to probe: the config has no sources. See the setup checklist above.";
    else if (o) msg = "No probed prefixes yet. The first probe round fills this in.";
    root.appendChild(el("p", "empty", msg));
    return;
  }
  var q = document.getElementById("prefix-filter").value.trim().toLowerCase();
  var changes = document.getElementById("prefix-changes").checked;
  var shown = rows.filter(function (row) {
    if (changes && !(row.current && row.recommended && row.recommended !== row.current)) return false;
    if (!q) return true;
    if (String(row.prefix).toLowerCase().indexOf(q) >= 0) return true;
    return (row.probes || []).some(function (pr) { return String(pr.provider).toLowerCase().indexOf(q) >= 0; }) ||
      [row.current, row.recommended].some(function (v) { return v && String(v).toLowerCase().indexOf(q) >= 0; });
  });
  if (shown.length !== rows.length) root.appendChild(el("p", "tag", "Showing " + shown.length + " of " + rows.length + " prefixes."));
  if (!shown.length) {
    root.appendChild(el("p", "empty", "No prefix matches the filter."));
    return;
  }
  shown.forEach(function (row) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    head.appendChild(el("h3", "mono", row.prefix));
    var exits = el("p", "exits");
    exits.appendChild(el("span", "k", "Current"));
    exits.appendChild(el("span", "v", row.current || "—"));
    exits.appendChild(el("span", "k", "Recommended"));
    var differs = row.recommended && row.recommended !== row.current;
    exits.appendChild(el("span", differs ? "v diff" : "v", row.recommended || "—"));
    head.appendChild(exits);
    if (row.action) head.appendChild(el("span", "badge", row.action));
    head.appendChild(el("span", row.in_rib ? "badge" : "badge muted", row.in_rib ? "in RIB" : "not in RIB"));
    if (row.heterogeneous) head.appendChild(el("span", "badge warn", "heterogeneous"));
    card.appendChild(head);
    if (row.reason) card.appendChild(el("p", "reason", row.reason));
    var table = el("table");
    var hr = el("tr");
    ["Provider", "Loss", "RTT", "Jitter", "Probe"].forEach(function (h) {
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
      tr.appendChild(el("td", "", pr.provider));
      if (!pr.ok) {
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "bad", pr.error || "failed"));
      } else {
        tr.appendChild(el("td", "num", fmtPct(pr.loss_pct)));
        tr.appendChild(el("td", "num", fmtMs(pr.rtt_avg_ms)));
        tr.appendChild(el("td", "num", fmtMs(pr.jitter_ms)));
        var probeCell = el("td", "", pr.prober || "ok");
        if (pr.indirect) {
          var tag = el("span", "badge muted", "indirect");
          tag.title = "Every address inside the prefix was silent. Measured at this provider's traceroute hop " + (pr.target || "") + ".";
          probeCell.appendChild(document.createTextNode(" "));
          probeCell.appendChild(tag);
        }
        tr.appendChild(probeCell);
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
      ["State", "Provider", "Next hop", "AS path", "Via", "MED", "Whose MED"].forEach(function (h) {
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
        tr.appendChild(el("td", "num", path.med === undefined || path.med === null ? "—" : String(path.med)));
        tr.appendChild(el("td", "", path.med_from || "—"));
        pb.appendChild(tr);
      });
      pt.appendChild(pb);
      card.appendChild(pt);
    }
    root.appendChild(card);
  });
}

function fmtAS(path) {
  if (!path || !path.length) return "—";
  return path.join(" ");
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
  nodes.forEach(function (node) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    head.appendChild(el("h3", "mono", node.asn ? "AS" + node.asn : "No origin AS"));
    card.appendChild(head);
    var t = table(["Provider", "Site", "Prefixes", "Table"]);
    (node.sites || []).forEach(function (site) {
      var prefs = site.prefixes || [];
      var shown = prefs.slice(0, 8).join(", ");
      if (prefs.length > 8) shown += " +" + (prefs.length - 8);
      var tr = el("tr");
      tr.appendChild(el("td", "", site.provider || "—"));
      tr.appendChild(el("td", "mono", site.next_hop || "—"));
      tr.appendChild(el("td", "", prefs.length + (shown ? " (" + shown + ")" : "")));
      tr.appendChild(el("td", "", site.partial ? "partial" : "full"));
      t.body.appendChild(tr);
    });
    card.appendChild(t.table);
    root.appendChild(card);
  });
}

function renderImprovements(data) {
  var root = document.getElementById("improvements");
  clear(root);
  var rows = (data && data.improvements) || [];
  var mode = data && data.mode;
  var inject = mode === "inject";
  document.getElementById("improvements-title").textContent = inject ? "Active improvements" : "Recommended improvements";
  var cap = lastOverview && lastOverview.counts && lastOverview.counts.max_improvements;
  document.getElementById("improvements-tag").textContent = (inject ?
    "Announced to the edge with the Packeteer community and NO_EXPORT. " :
    "Mode " + (mode || "observe") + ": these are what inject would announce. Nothing is announced. ") +
    (cap ? "At most " + cap + " at a time (max_improvements)." : "");
  if (!rows.length) {
    root.appendChild(el("p", "empty", inject ? "No active improvements." :
      "None. A move is recommended only when another provider beats the current exit by the configured thresholds."));
    return;
  }
  var table = el("table");
  var hr = el("tr");
  ["Prefix", "Native exit", inject ? "Steered to" : "Recommended", "Cause", "Since", "Reason"].forEach(function (h) {
    hr.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (im) {
    var tr = el("tr");
    tr.appendChild(el("td", "mono", im.prefix));
    tr.appendChild(el("td", "", im.native || "—"));
    tr.appendChild(el("td", "", im.provider || "—"));
    tr.appendChild(el("td", "", im.cause || "—"));
    tr.appendChild(el("td", "", fmtTime(im.since)));
    tr.appendChild(el("td", "", im.reason || ""));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);
}

// modeBadge is the header chip. The class carries the contrast colors;
// the header's white text must not be inherited (#171).
function modeBadge(mode) {
  var name = mode === "observe" || mode === "suggest" || mode === "inject" ? mode : "unknown";
  return el("span", "badge mode-" + name, mode || "—");
}

function renderStatus(err) {
  var node = document.getElementById("status");
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
  observe: "Observe mode: Packeteer measures and recommends. Nothing is announced.",
  suggest: "Suggest mode: Packeteer measures and publishes recommendations. Nothing is announced.",
  inject: "Inject mode: improvements for allowlisted prefixes are announced to the edge routers."
};

function renderBanner(mode) {
  var node = document.getElementById("banner");
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
  clear(root);
  var c = o.counts || {};
  var inject = o.mode === "inject";
  root.appendChild(tile("Mode", o.mode || "—", inject ? "announces" : "announces nothing", inject ? "warn" : ""));
  root.appendChild(tile("Status", o.ready ? "ready" : (o.started ? "not ready" : "starting"),
    o.bgp && o.bgp.configured && !o.bgp.ready ? "no iBGP session" : "", o.ready ? "good" : "bad"));
  root.appendChild(tile("Providers up", c.providers_up + " of " + c.providers, "", c.providers && !c.providers_up ? "bad" : ""));
  root.appendChild(tile("Prefixes measured", c.measured + " of " + c.prefixes,
    (o.sources || []).length ? "sources: " + o.sources.join(", ") : "no sources", c.prefixes ? "" : "muted"));
  root.appendChild(tile(inject ? "Improvements" : "Recommended", c.improvements + (c.max_improvements ? " of " + c.max_improvements : ""),
    c.recommended ? c.recommended + " prefixes differ" : ""));
  var b = o.bgp || {};
  root.appendChild(tile("BGP sessions", b.configured ? b.established + " of " + b.peers : "off",
    b.configured ? (c.in_rib + " probed prefixes in RIB") : "no edge router", b.configured && !b.established ? "bad" : ""));
}

function renderSetup(o) {
  var root = document.getElementById("setup");
  clear(root);
  var hints = o.setup || [];
  if (!hints.length) return;
  var box = el("div", "setup");
  box.appendChild(el("h3", "", "Setup checklist"));
  box.appendChild(el("p", "tag", "Edit the mounted config file, then restart the container. Observe mode stays safe while you do."));
  var ul = el("ul", "hints");
  hints.forEach(function (h) {
    var li = el("li", "hint hint-" + h.level);
    li.setAttribute("data-hint", h.id);
    li.appendChild(el("span", "badge hint-level", h.level === "todo" ? "to do" : h.level));
    li.appendChild(el("strong", "", h.title));
    li.appendChild(el("span", "", " " + h.detail));
    if (h.doc) {
      li.appendChild(document.createTextNode(" "));
      li.appendChild(el("code", "muted", h.doc));
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
    if (f.name === "federation") document.getElementById("federation-section").hidden = !f.on;
    if (f.name === "mitigation") document.getElementById("mitigation-section").hidden = !f.on;
  });
  var node = document.getElementById("features");
  node.textContent = (on.length ? "On: " + on.join(", ") + ". " : "") + (off.length ? "Off: " + off.join(", ") + "." : "");
}

function renderOverview(o) {
  renderBanner(o.mode);
  renderTiles(o);
  renderSetup(o);
  renderFeatures(o);
}

function renderConn(err) {
  var node = document.getElementById("conn");
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
  var rules = data.rules || [];
  if (!rules.length) {
    root.appendChild(el("p", "empty", "No rules."));
  } else {
    var t = table(["Prefix", "Action", "Detail", "State", "Expires", "Reason"]);
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

function refresh() {
  if (refreshing) return;
  refreshing = true;
  var readyReq = fetch("/readyz", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.json();
  });
  Promise.allSettled([
    getJSON("/api/providers"),
    getJSON("/api/prefixes"),
    getJSON("/api/improvements"),
    readyReq,
    getJSON("/api/mitigations"),
    getJSON("/api/federation"),
    getJSON("/api/overview")
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
    if (!err) lastOK = new Date().toISOString();
    if (lastProviders) renderProviders(lastProviders);
    if (lastPrefixes) {
      renderPrefixes(lastPrefixes);
      renderASNMap(lastPrefixes);
    }
    if (lastImprovements) renderImprovements(lastImprovements);
    // Mitigation is optional; its failure does not mark the page stale.
    if (results[4].status === "fulfilled") lastMitigation = results[4].value;
    if (lastMitigation) renderMitigation(lastMitigation);
    // The central view is optional too.
    if (results[5].status === "fulfilled") renderFederation(results[5].value);
    renderStatus(err);
    renderConn(err);
  }).then(function () {
    refreshing = false;
  }, function () {
    refreshing = false;
  });
}

function reportURL(format) {
  var name = document.getElementById("report-name").value || "summary";
  var days = document.getElementById("report-days").value || "7";
  var url = "/api/reports/" + encodeURIComponent(name) + "?days=" + encodeURIComponent(days);
  if (format) url += "&format=" + format;
  return url;
}

function fmtCell(v) {
  if (v == null) return "—";
  if (typeof v === "number") return String(Math.round(v * 1000) / 1000);
  return String(v);
}

function renderReport(data) {
  var root = document.getElementById("report");
  clear(root);
  var rows = (data && data.rows) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No history in this range."));
    return;
  }
  var cols = [];
  rows.forEach(function (r) {
    Object.keys(r).forEach(function (k) {
      if (cols.indexOf(k) < 0) cols.push(k);
    });
  });
  var table = el("table");
  var hr = el("tr");
  cols.forEach(function (c) { hr.appendChild(el("th", "", c.replace(/_/g, " "))); });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var tr = el("tr");
    cols.forEach(function (c) {
      tr.appendChild(el("td", c === "prefix" ? "mono" : "", fmtCell(r[c])));
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);
}

function loadReport() {
  document.getElementById("report-csv").setAttribute("href", reportURL("csv"));
  var root = document.getElementById("report");
  getJSON(reportURL("")).then(renderReport, function (err) {
    clear(root);
    root.appendChild(el("p", "empty", err.message));
  });
}

function initReports() {
  getJSON("/api/reports").then(function (data) {
    var sel = document.getElementById("report-name");
    clear(sel);
    ((data && data.reports) || []).forEach(function (r) {
      var o = el("option", "", r.name);
      o.value = r.name;
      o.title = r.summary || "";
      sel.appendChild(o);
    });
    if (!data || !data.enabled) {
      var root = document.getElementById("report");
      clear(root);
      root.appendChild(el("p", "empty", "History is off. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer."));
      return;
    }
    loadReport();
  }, function () {});
  document.getElementById("report-load").addEventListener("click", loadReport);
  document.getElementById("report-name").addEventListener("change", loadReport);
  document.getElementById("report-days").addEventListener("change", loadReport);
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

function runTool() {
  var tool = document.getElementById("tool-name").value;
  var target = document.getElementById("tool-target").value.trim();
  var provider = document.getElementById("tool-provider").value;
  var status = document.getElementById("tool-status");
  var out = document.getElementById("tool-out");
  if (!target) {
    status.textContent = "Enter a prefix, address, or ASN.";
    return;
  }
  status.textContent = "Running " + tool + "…";
  out.textContent = "";
  var req;
  if (tool === "lookingglass") {
    req = getJSON("/api/troubleshoot/lookingglass?prefix=" + encodeURIComponent(target));
  } else if (tool === "whois") {
    req = postJSON("/api/troubleshoot/whois", {query: target});
  } else if (tool === "traceroute") {
    req = postJSON("/api/troubleshoot/traceroute", {target: target, provider: provider});
  } else {
    req = postJSON("/api/troubleshoot/probe", {target: target});
  }
  req.then(function (data) {
    status.textContent = "Done.";
    out.textContent = JSON.stringify(data, null, 2);
  }, function (err) {
    status.textContent = err.message;
  });
}

function initTools() {
  getJSON("/api/troubleshoot").then(function (data) {
    var sel = document.getElementById("tool-provider");
    ((data && data.providers) || []).forEach(function (name) {
      var o = el("option", "", name);
      o.value = name;
      sel.appendChild(o);
    });
    if (data && !data.enabled) {
      document.getElementById("tool-status").textContent = "Probe, traceroute, and whois are off (troubleshoot.enabled: false).";
    }
  }, function () {});
  document.getElementById("tool-run").addEventListener("click", runTool);
}

initReports();
initTools();
document.getElementById("refresh").addEventListener("click", refresh);
function rerenderPrefixes() { if (lastPrefixes) renderPrefixes(lastPrefixes); }
document.getElementById("prefix-filter").addEventListener("input", rerenderPrefixes);
document.getElementById("prefix-changes").addEventListener("change", rerenderPrefixes);
refresh();
setInterval(refresh, REFRESH_MS);
