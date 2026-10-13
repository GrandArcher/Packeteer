"use strict";
// Troubleshooting page (#24, #180). Looking glass and traceroute answers
// are drawn as tables; every answer keeps its raw JSON. Results stack
// newest first for this browser session only. Needs el, clear, getJSON,
// postJSON, fmtAS, fmtVia, and fmtMs from app.js. A probe answer adds "Probe and optimize" (#126) when
// /api/troubleshoot reports optimize; it asks the controller to measure
// the covering learned prefix for a while, and any move still comes from
// the decision engine.

var TOOL_STACK_MAX = 20;
var toolOptimize = false;
var TOOL_NAMES = {lookingglass: "Looking glass", probe: "Probe", traceroute: "Traceroute", whois: "Whois"};

function toolCell(text, className) {
  return el("td", className || "", text == null || text === "" ? "—" : text);
}

function toolTable(headers, rows) {
  var t = el("table");
  var head = el("thead");
  var hr = el("tr");
  headers.forEach(function (h) {
    var th = el("th", "", h.text || h);
    if (h.title) th.title = h.title;
    hr.appendChild(th);
  });
  head.appendChild(hr);
  t.appendChild(head);
  var body = el("tbody");
  rows.forEach(function (r) { body.appendChild(r); });
  t.appendChild(body);
  return t;
}

function sameRoute(a, b) {
  return !!a && !!b && a.source === b.source && a.neighbor === b.neighbor && (a.path_id || 0) === (b.path_id || 0) &&
    a.router === b.router && !!a.loc_rib === !!b.loc_rib && a.next_hop === b.next_hop;
}

function pathRow(r, state, withPrefix) {
  var tr = el("tr");
  if (state === "selected") tr.className = "is-current";
  if (state) tr.appendChild(toolCell(state));
  if (withPrefix) tr.appendChild(toolCell(r.prefix, "mono"));
  tr.appendChild(toolCell(r.provider));
  tr.appendChild(toolCell(r.next_hop, "mono"));
  tr.appendChild(toolCell(fmtAS(r.as_path), "mono"));
  tr.appendChild(toolCell(fmtVia(r.via)));
  tr.appendChild(toolCell(r.med == null ? "" : String(r.med), "num"));
  return tr;
}

var PATH_COLUMNS = ["Provider", "Next hop", "AS path", "Via", {text: "MED", title: "Display only. MED does not choose the exit."}];

function glassSection(title, note, headers, rows) {
  var sec = el("div", "tool-section");
  sec.appendChild(el("h4", "", title));
  if (note) sec.appendChild(el("p", "tag", note));
  if (rows.length) sec.appendChild(toolTable(headers, rows));
  return sec;
}

function renderGlass(g) {
  var box = el("div");
  if (!g.rib_ready) box.appendChild(el("p", "tag", "The learned RIB is still loading; the answer may be incomplete."));
  var paths = (g.paths && g.paths.length) ? g.paths : (g.exact ? [g.exact] : []);
  box.appendChild(glassSection("Learned paths for " + g.query,
    paths.length ? "The selected path is the one Packeteer sees as best. Inactive paths come from add-path or BMP." : "No route is learned for exactly " + g.query + ".",
    ["State"].concat(PATH_COLUMNS),
    paths.map(function (r) { return pathRow(r, sameRoute(r, g.exact) ? "selected" : "inactive", false); })));
  if (g.covering && (!g.exact || g.covering.prefix !== g.query)) {
    box.appendChild(glassSection("Covering route", "The longest learned route that contains " + g.query + ".",
      ["Prefix"].concat(PATH_COLUMNS), [pathRow(g.covering, "", true)]));
  }
  var more = g.more_specifics || [];
  if (more.length) {
    box.appendChild(glassSection("More-specific routes (" + more.length + (g.truncated ? ", list cut off" : "") + ")", "",
      ["Prefix"].concat(PATH_COLUMNS), more.map(function (r) { return pathRow(r, "", true); })));
  }
  return box;
}

function fmtOrigin(asn) {
  return asn ? "AS" + asn : "";
}

function traceStatus(t) {
  if (t.error) return "error: " + t.error;
  return t.reached ? "target reached" : "target not reached";
}

function hopDiagram(t, target) {
  var ol = el("ol", "hop-diagram");
  ol.setAttribute("aria-label", "Hops from " + t.provider);
  var start = el("li", "hop hop-end");
  start.appendChild(el("span", "hop-name", t.provider));
  start.appendChild(el("span", "mono", t.source || ""));
  ol.appendChild(start);
  (t.hops || []).forEach(function (h) {
    var li = el("li", "hop" + (h.address ? "" : " hop-silent") + (h.error ? " hop-error" : "") + (h.reached ? " hop-end" : ""));
    li.appendChild(el("span", "hop-name", String(h.ttl)));
    li.appendChild(el("span", "mono", h.address || "*"));
    if (h.origin_as) li.appendChild(el("span", "tag", fmtOrigin(h.origin_as)));
    ol.appendChild(li);
  });
  if (!t.reached) {
    var end = el("li", "hop hop-silent");
    end.appendChild(el("span", "hop-name", "target"));
    end.appendChild(el("span", "mono", target));
    ol.appendChild(end);
  }
  return ol;
}

function hopRow(h) {
  var tr = el("tr");
  if (h.reached) tr.className = "is-current";
  tr.appendChild(toolCell(String(h.ttl), "num"));
  tr.appendChild(toolCell(h.address || "*", "mono"));
  tr.appendChild(toolCell(h.name));
  tr.appendChild(toolCell(fmtOrigin(h.origin_as)));
  tr.appendChild(toolCell(h.address ? fmtMs(h.rtt_ms) : "", "num"));
  // One probe is sent per hop, so a hop either answered or lost it.
  tr.appendChild(toolCell(h.address ? "0%" : "100%", "num"));
  tr.appendChild(toolCell(h.error));
  return tr;
}

function renderTrace(a) {
  var box = el("div");
  (a.traces || []).forEach(function (t) {
    var sec = el("div", "tool-section");
    var h = el("h4", "", t.provider);
    h.appendChild(el("span", "tag", " source " + (t.source || "—") + ": " + traceStatus(t)));
    sec.appendChild(h);
    if (t.hops && t.hops.length) {
      sec.appendChild(hopDiagram(t, a.target));
      sec.appendChild(toolTable(["Hop", "Address", "Reverse name",
        {text: "Origin AS", title: "From the learned RIB: the last AS on the longest matching route. No external lookup."},
        "RTT", {text: "Loss", title: "One probe per hop, so 0% or 100%."}, "Error"],
      t.hops.map(hopRow)));
    }
    box.appendChild(sec);
  });
  return box;
}

function nsToMs(ns) {
  return ns == null ? null : ns / 1e6;
}

function probeRole(a, provider) {
  var roles = [];
  if (provider === a.current) roles.push("current");
  if (provider === a.best) roles.push("best");
  return roles.join(", ");
}

function probeRow(a, r) {
  var tr = el("tr");
  if (r.provider === a.current) tr.className = "is-current";
  if (r.provider === a.best) tr.className += " is-best";
  var st = r.stats || {};
  var answered = !r.error && st.received > 0;
  tr.appendChild(toolCell(r.provider));
  tr.appendChild(toolCell(probeRole(a, r.provider)));
  tr.appendChild(toolCell(r.error ? "" : fmtPct(st.loss_pct), "num"));
  tr.appendChild(toolCell(answered ? fmtMs(nsToMs(st.rtt_avg)) : "", "num"));
  tr.appendChild(toolCell(answered ? fmtMs(nsToMs(st.jitter)) : "", "num"));
  tr.appendChild(toolCell(r.target, "mono"));
  tr.appendChild(toolCell(r.indirect ? "indirect: nothing in the target answered, so the highest stable traceroute hop was probed" : (r.error || (answered ? "" : "no reply"))));
  return tr;
}

function renderProbe(a) {
  var box = el("div");
  var sec = el("div", "tool-section");
  var used = a.host ? a.host + " resolved to " + a.target : "Probed " + a.target;
  var more = (a.addresses || []).filter(function (x) { return x !== a.target; });
  if (a.host && more.length) used += " (also " + more.join(", ") + ")";
  sec.appendChild(el("p", "tag", used));
  if (a.route) {
    sec.appendChild(el("p", "tag", "Covering learned prefix " + a.route.prefix + (a.current ? ", current exit " + a.current : "") +
      (a.best && a.best !== a.current ? ". The best measured exit is " + a.best + "." : ".")));
  } else {
    sec.appendChild(el("p", "tag", "No learned prefix covers this address."));
  }
  sec.appendChild(toolTable(["Provider", "Exit",
    {text: "Loss", title: "Packets with no reply."}, "RTT", "Jitter", "Probed address", "Note"],
  (a.results || []).map(function (r) { return probeRow(a, r); })));
  box.appendChild(sec);
  if (toolOptimize && a.route && a.route.prefix.slice(-2) !== "/0") box.appendChild(optimizeControl(a));
  return box;
}

function optimizeControl(a) {
  var box = el("div", "tool-section");
  var btn = el("button", "", "Probe and optimize");
  btn.type = "button";
  btn.title = "Measure " + a.route.prefix + " on the next round. A move still needs the decision rules.";
  var out = el("p", "tag");
  out.id = "optimize-status";
  btn.addEventListener("click", function () {
    btn.disabled = true;
    out.textContent = "Queuing…";
    postJSON("/api/troubleshoot/optimize", {target: a.target}).then(function (r) {
      clear(out);
      out.appendChild(document.createTextNode("Queued " + r.prefix + " for probing until " + new Date(r.expires).toLocaleTimeString() +
        ". Any improvement comes from the decision engine: see "));
      var link = el("a", "", "the prefix page");
      link.href = prefixHref(r.prefix);
      out.appendChild(link);
      out.appendChild(document.createTextNode("."));
      btn.disabled = false;
    }, function (err) {
      out.textContent = err.message;
      btn.disabled = false;
    });
  });
  box.appendChild(btn);
  box.appendChild(out);
  return box;
}

function rawJSON(data, open) {
  var d = el("details", "tool-raw");
  if (open) d.open = true;
  d.appendChild(el("summary", "", "Raw JSON"));
  d.appendChild(el("pre", "", JSON.stringify(data, null, 2)));
  return d;
}

var toolStack = [];

function paintEntry(e) {
  clear(e.node);
  var head = el("div", "tool-head");
  head.appendChild(el("strong", "", TOOL_NAMES[e.tool] + " " + e.target + (e.provider ? " via " + e.provider : "")));
  head.appendChild(el("span", "tag", " " + e.time));
  var again = el("button", "", "Rerun");
  again.type = "button";
  again.disabled = e.running;
  again.addEventListener("click", function () { startTool(e.tool, e.target, e.provider); });
  var gone = el("button", "", "Remove");
  gone.type = "button";
  gone.addEventListener("click", function () {
    toolStack.splice(toolStack.indexOf(e), 1);
    e.node.parentNode.removeChild(e.node);
    toolEmpty();
  });
  head.appendChild(again);
  head.appendChild(gone);
  e.node.appendChild(head);
  if (e.running) {
    e.node.appendChild(el("p", "tag", "Running…"));
  } else if (e.error) {
    e.node.appendChild(el("p", "tool-error", e.error));
  } else {
    if (e.tool === "lookingglass") e.node.appendChild(renderGlass(e.data));
    else if (e.tool === "traceroute") e.node.appendChild(renderTrace(e.data));
    else if (e.tool === "probe") e.node.appendChild(renderProbe(e.data));
    e.node.appendChild(rawJSON(e.data, e.tool === "whois"));
  }
}

function toolEmpty() {
  document.getElementById("tool-empty").hidden = toolStack.length > 0;
}

function toolRequest(tool, target, provider) {
  if (tool === "lookingglass") return getJSON("/api/troubleshoot/lookingglass?prefix=" + encodeURIComponent(target));
  if (tool === "whois") return postJSON("/api/troubleshoot/whois", {query: target});
  if (tool === "traceroute") return postJSON("/api/troubleshoot/traceroute", {target: target, provider: provider});
  return postJSON("/api/troubleshoot/probe", {target: target});
}

function startTool(tool, target, provider) {
  var list = document.getElementById("tool-results");
  var e = {tool: tool, target: target, provider: tool === "traceroute" ? provider : "", time: new Date().toLocaleTimeString(), running: true, node: el("article", "tool-result")};
  toolStack.unshift(e);
  list.insertBefore(e.node, list.firstChild);
  while (toolStack.length > TOOL_STACK_MAX) {
    var old = toolStack.pop();
    old.node.parentNode.removeChild(old.node);
  }
  toolEmpty();
  paintEntry(e);
  toolRequest(tool, target, e.provider).then(function (data) {
    e.running = false;
    e.data = data;
    paintEntry(e);
  }, function (err) {
    e.running = false;
    // Only getJSON (looking glass) prefixes the request path to its errors.
    e.error = tool === "lookingglass" ? err.message.replace(/^\S+ failed: /, "") : err.message;
    paintEntry(e);
  });
}

function runTool() {
  var tool = document.getElementById("tool-name").value;
  var target = document.getElementById("tool-target").value.trim();
  var status = document.getElementById("tool-status");
  if (!target) {
    status.textContent = "Enter a prefix, address, hostname, or ASN.";
    return;
  }
  status.textContent = "";
  startTool(tool, target, document.getElementById("tool-provider").value);
}

function initTools() {
  var run = document.getElementById("tool-run");
  getJSON("/api/troubleshoot").then(function (data) {
    var sel = document.getElementById("tool-provider");
    ((data && data.providers) || []).forEach(function (name) {
      var o = el("option", "", name);
      o.value = name;
      sel.appendChild(o);
    });
    toolOptimize = !!(data && data.optimize);
    if (data && !data.enabled) {
      document.getElementById("tool-status").textContent = "Probe, traceroute, and whois are off (troubleshoot.enabled: false).";
    }
  }, function () {});
  // The prefix page (#179) links here with the tool and target filled in.
  // Nothing runs until the operator presses Run.
  var qs = new URLSearchParams(window.location.search);
  var toolSel = document.getElementById("tool-name");
  var want = qs.get("tool");
  if (want && Array.prototype.some.call(toolSel.options, function (o) { return o.value === want; })) toolSel.value = want;
  if (qs.get("target")) document.getElementById("tool-target").defaultValue = qs.get("target");
  run.addEventListener("click", runTool);
}

initTools();
