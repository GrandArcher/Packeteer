"use strict";
// Prefix page (#179): the live card for one prefix plus its stored
// timeline. Loaded before app.js, which fetches prefixListQuery() on every
// refresh and calls prefixPageUpdate; the rest waits for DOMContentLoaded
// so app.js helpers (el, clear, getJSON, prefixCard, fmt*) exist.
// Read-only. "Probe now" only links to the Probe tool.

var PREFIX_PATH = "/prefix/";

function pagePrefix() {
  var path = window.location.pathname;
  if (path.indexOf(PREFIX_PATH) !== 0) return "";
  try { return decodeURIComponent(path.slice(PREFIX_PATH.length)); } catch (e) { return ""; }
}

var thisPrefix = pagePrefix();

// prefixListQuery asks the paged list for this one prefix; a CIDR matches
// exactly.
function prefixListQuery() {
  return "prefix=" + encodeURIComponent(thisPrefix) + "&limit=1";
}

// prefixPageUpdate is called by app.js with every refresh of /api/prefixes.
function prefixPageUpdate(data) {
  var root = document.getElementById("prefix-live");
  if (!root) return;
  loadWhy();
  clear(root);
  var row = ((data && data.prefixes) || []).filter(function (r) { return r.prefix === thisPrefix; })[0];
  if (!row) {
    root.appendChild(el("p", "empty", "Packeteer is not measuring this prefix now. The timeline shows what was stored."));
    return;
  }
  root.appendChild(prefixCard(row));
  var origin = originASN(row);
  if (origin) {
    var links = document.getElementById("prefix-links");
    if (!links.querySelector("[data-origin]")) {
      var span = linkoutSpan("asn", origin);
      span.setAttribute("data-origin", String(origin));
      links.appendChild(el("span", "k", "Origin AS" + origin));
      links.appendChild(span);
    }
  }
  if (row.quarantine) root.appendChild(quarantineNote(row.quarantine));
}

// quarantineNote explains a flap quarantine (#228). The page stays
// read-only: an operator ends it early with POST /api/quarantine/release.
function quarantineNote(q) {
  return el("p", "reason", "Flap quarantine: this prefix changed its chosen provider " + q.flips +
    " times in the window (offense " + q.strikes + "). Packeteer's route is withdrawn and traffic uses the router's native path until " +
    fmtTime(q.until) + ". An operator can release it with POST /api/quarantine/release.");
}

// The "Why?" panel (#201): the gate list of the latest decision from
// /api/decisions/<prefix>, the measurements behind it, and what would have
// to change for a held move to happen.
var GATE_LABELS = {
  rib: "Learned RIB", freshness: "Fresh measurements", thresholds: "Thresholds", med: "Neighbor MED", evidence: "Measurement evidence", confirm_rounds: "Confirm rounds",
  hold_time: "Hold time", cap: "Max simultaneous moves", policy: "Routing policy", allowlist: "Allowlist",
  route_check: "Route check", rpki: "RPKI", irr: "IRR"
};
var GATE_RESULTS = {pass: "Passed", fail: "Held it back", skip: "Not checked"};
var OUTCOMES = {moved: "Moved", kept: "Kept", retired: "Retired", held: "Held"};

function gateLabel(name) { return GATE_LABELS[name] || name; }

function whyHeadline(ex) {
  var text = (OUTCOMES[ex.outcome] || ex.outcome) + ": " + (ex.reason || "no reason recorded") + ".";
  if (ex.blocked_by) text += " Held back by: " + gateLabel(ex.blocked_by) + ".";
  return text;
}

function gateRow(g) {
  var tr = el("tr");
  tr.appendChild(el("td", "", gateLabel(g.gate)));
  var result = el("td");
  result.appendChild(g.status === "pass" ? el("span", "dot up", GATE_RESULTS.pass) :
    g.status === "fail" ? el("span", "dot down", GATE_RESULTS.fail) : el("span", "badge muted", GATE_RESULTS.skip));
  tr.appendChild(result);
  tr.appendChild(el("td", "", g.value || "-"));
  tr.appendChild(el("td", "", g.limit || "-"));
  tr.appendChild(el("td", "", g.detail || ""));
  return tr;
}

function sampleRow(s) {
  var tr = el("tr");
  tr.appendChild(el("td", "", s.provider));
  tr.appendChild(el("td", "", s.role || "-"));
  tr.appendChild(el("td", "", fmtPct(s.loss_pct)));
  tr.appendChild(el("td", "", fmtMs(s.rtt_ms)));
  tr.appendChild(el("td", "", fmtMs(s.jitter_ms)));
  tr.appendChild(el("td", "", s.usable ? String(Math.round(s.score * 10) / 10) : "-"));
  tr.appendChild(confidenceCell(s.confidence, s.evidence));
  tr.appendChild(el("td", "", s.usable ? "usable" : "not usable: " + (s.why || "no reason")));
  return tr;
}

function renderWhy(data) {
  var root = document.getElementById("why-body");
  clear(root);
  var ex = data.explain;
  root.appendChild(el("p", "reason", whyHeadline(ex)));
  var gates = table(["Check", "Result", "Value", "Limit", "Detail"]);
  (ex.gates || []).forEach(function (g) { gates.body.appendChild(gateRow(g)); });
  root.appendChild(gates.table);
  if (ex.counterfactual) root.appendChild(el("p", "reason", "What would change it: " + ex.counterfactual + "."));
  root.appendChild(el("h3", "", "Measurements behind it"));
  var samples = table(["Provider", "Role", "Loss", "RTT", "Jitter", "Score", "Confidence", "State"]);
  (ex.samples || []).forEach(function (s) { samples.body.appendChild(sampleRow(s)); });
  root.appendChild(samples.table);
  root.appendChild(el("p", "tag", "Decided " + fmtTime(data.decided_at) + "."));
}

function loadWhy() {
  var root = document.getElementById("why-body");
  if (!root || !thisPrefix) return;
  getJSON("/api/decisions/" + encodeURIComponent(thisPrefix)).then(renderWhy, function (err) {
    clear(root);
    root.appendChild(el("p", "empty", err.status === 404 ?
      "Packeteer has no decision for this prefix now, so there is nothing to explain. The timeline shows what was stored." : err.message));
  });
}

// whyStored is the one-line checks of a stored decision, for the timeline.
function whyStored(ex) {
  var parts = (ex.gates || []).filter(function (g) { return g.status !== "skip"; }).map(function (g) {
    return gateLabel(g.gate) + " " + (g.status === "pass" ? "passed" : "held it back") + (g.value ? " (" + g.value + ")" : "");
  });
  return parts.join("; ");
}

// verb never says "announced" for a record made outside inject.
function timelineVerb(mode) {
  return mode === "inject" ? "Announced" : "Recommended";
}

function measure(loss, rtt) {
  return "loss " + fmtPct(loss) + ", RTT " + fmtMs(rtt);
}

function improvementEntries(im) {
  var verb = timelineVerb(im.mode);
  var what = verb + " " + (im.provider || "—") + " over " + (im.native || "—") + ", cause " + (im.cause || "—");
  if (im.reason) what += " (" + im.reason + ")";
  if (im.explain) what += ". Checks at the time: " + whyStored(im.explain);
  if (im.before_loss_pct != null || im.after_loss_pct != null) {
    what += ". Before (native): " + measure(im.before_loss_pct, im.before_rtt_ms) +
      ". After (chosen): " + measure(im.after_loss_pct, im.after_rtt_ms) + ".";
  }
  var out = [{time: new Date(im.start), when: fmtTime(im.start), kind: verb.toLowerCase(), text: what}];
  if (im.end) {
    out.push({time: new Date(im.end), when: fmtTime(im.end), kind: "ended",
      text: verb + " " + (im.provider || "—") + " ended" + (im.end_reason ? ": " + im.end_reason : "") + "."});
  }
  return out;
}

function rollupEntry(d) {
  var text = d.provider + ": " + d.probes + " probes";
  if (d.failed) text += ", " + d.failed + " failed";
  text += d.loss_pct == null ? ", no measurement" : ", " + measure(d.loss_pct, d.rtt_ms) + ", jitter " + fmtMs(d.jitter_ms);
  return {time: new Date(d.day + "T00:00:00Z"), when: d.day + " (UTC day)", kind: "probe rollup", text: text};
}

// rpkiEntry is one learned path's origin-validation state over a span
// (#200).
function rpkiEntry(r) {
  var text = r.provider + " path from AS" + r.origin_asn + ": " + r.state;
  text += r.source ? " (source " + r.source + ")" : " (no source had fresh data)";
  text += ", last seen " + fmtTime(r.last);
  return {time: new Date(r.first), when: fmtTime(r.first), kind: "rpki", text: text};
}

function renderTimeline(data) {
  var root = document.getElementById("prefix-timeline");
  clear(root);
  if (!data.enabled) {
    root.appendChild(el("p", "empty", "History is off, so there is no timeline. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer."));
    return;
  }
  var entries = [];
  (data.days || []).forEach(function (d) { entries.push(rollupEntry(d)); });
  (data.improvements || []).forEach(function (im) { entries = entries.concat(improvementEntries(im)); });
  (data.rpki || []).forEach(function (r) { entries.push(rpkiEntry(r)); });
  if (!entries.length) {
    root.appendChild(el("p", "empty", "No stored history for this prefix in this range."));
    return;
  }
  entries.sort(function (a, b) { return b.time - a.time; });
  var t = table(["When", "Event", "Detail"]);
  entries.forEach(function (e) {
    var tr = el("tr");
    tr.appendChild(el("td", "", e.when));
    tr.appendChild(el("td", "", e.kind));
    tr.appendChild(el("td", "", e.text));
    t.body.appendChild(tr);
  });
  root.appendChild(t.table);
}

function loadTimeline() {
  var root = document.getElementById("prefix-timeline");
  var days = document.getElementById("prefix-days").value || "7";
  getJSON("/api/prefixes/history?prefix=" + encodeURIComponent(thisPrefix) + "&days=" + encodeURIComponent(days)).then(renderTimeline, function (err) {
    clear(root);
    root.appendChild(el("p", "empty", err.message));
  });
}

// renderRing draws the opt-in NLNOG RING panel (#283). The server answers
// state "off" without any request while ring_lg is off, and the panel stays
// hidden. loadRing runs once per page view: the server caches the answer.
function renderRing(data) {
  var panel = document.getElementById("ring-panel");
  var root = document.getElementById("ring-body");
  clear(root);
  if (data.state === "off") return;
  panel.hidden = false;
  if (data.state !== "ok") {
    root.appendChild(el("p", "empty", "Unavailable. " + (data.message || "NLNOG RING services may be unavailable.")));
    return;
  }
  var routes = data.routes || [];
  if (!routes.length) {
    root.appendChild(el("p", "empty", "NLNOG RING shows no route for exactly this prefix."));
  } else {
    var t = table(["Peer", "Prefix", "AS path", "Origin AS", "RPKI (RING)", "Last update"]);
    routes.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", "", r.peer));
      tr.appendChild(el("td", "mono", r.prefix));
      tr.appendChild(el("td", "mono", (r.as_path || []).join(" ")));
      tr.appendChild(el("td", "", r.origin || "-"));
      tr.appendChild(el("td", "", r.rpki || "-"));
      tr.appendChild(el("td", "", r.last_update || "-"));
      t.body.appendChild(tr);
    });
    root.appendChild(t.table);
  }
  if (data.truncated) root.appendChild(el("p", "tag", "Showing the first " + routes.length + " rows."));
  (data.warnings || []).forEach(function (w) { root.appendChild(el("p", "tag", "NLNOG RING: " + w)); });
  root.appendChild(el("p", "tag", "Fetched " + fmtTime(data.fetched_at) + (data.cached ? " (cached)." : ".")));
}

function loadRing() {
  var root = document.getElementById("ring-body");
  if (!root || !thisPrefix) return;
  getJSON("/api/ring_lg?prefix=" + encodeURIComponent(thisPrefix)).then(renderRing, function (err) {
    document.getElementById("ring-panel").hidden = false;
    clear(root);
    root.appendChild(el("p", "empty", "Unavailable. " + err.message + " NLNOG RING services may be unavailable."));
  });
}

// The RPKI-invalid only path panel (#401): the case and its evidence. It
// is read-only like the rest of the page; exceptions are proposed and
// approved on the Registry page. The origin's link-outs let the operator
// check outside incident data, such as Qrator Radar when listed in
// linkouts.enabled (#402).
var ONLY_INVALID_CLASS = {
  stale_roa: "Likely a stale ROA or misconfiguration",
  hijack: "Likely a hijack",
  unclear: "Unclear"
};

function onlyInvalidView(c, slurm) {
  var box = el("div", "");
  box.appendChild(el("p", c.class === "hijack" ? "reason bad" : "reason",
    (ONLY_INVALID_CLASS[c.class] || c.class) + " (score " + c.score + ") for AS" + c.origin + ". " + c.action));
  box.appendChild(linkoutSpan("asn", c.origin));
  var t = el("table", "");
  var head = el("tr", "");
  ["Evidence", "Points", "Detail"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  t.appendChild(head);
  (c.signals || []).forEach(function (s) {
    var tr = el("tr", "");
    tr.appendChild(el("td", "mono", s.name));
    tr.appendChild(el("td", "", (s.points > 0 ? "+" : "") + s.points));
    tr.appendChild(el("td", "", s.detail));
    t.appendChild(tr);
  });
  box.appendChild(t);
  var roas = (c.vrps || []).map(function (v) { return v.prefix + " maxLength " + v.max_length + " AS" + v.asn; });
  box.appendChild(el("p", "tag", "Covering ROAs: " + (roas.length ? roas.join(", ") : "none") + ". RPKI source: " + (c.rpki_source || "-") + ". First seen " + fmtTime(c.first) + "."));
  var held = (slurm.exceptions || []).filter(function (x) { return x.prefix === c.prefix; });
  held.forEach(function (x) {
    box.appendChild(el("p", "tag", "SLURM exception " + x.id + " (" + x.kind + ") is in " + slurm.path + (x.audit_id ? ", audit " + x.audit_id : "") + (x.review_due ? ". Due for review." : ".")));
  });
  if (!slurm.enabled) {
    box.appendChild(el("p", "tag", "SLURM exceptions are off (rpki.only_invalid.slurm)."));
  } else if (c.class === "stale_roa" && !held.length) {
    var a = el("a", "", "Propose a SLURM exception on the Registry page");
    a.href = "/registry.html";
    box.appendChild(a);
  }
  return box;
}

function renderOnlyInvalid(data) {
  var c = data && data.enabled && (data.cases || [])[0];
  document.getElementById("only-invalid-panel").hidden = !c;
  if (!c) return;
  var body = document.getElementById("only-invalid-evidence");
  clear(body);
  body.appendChild(onlyInvalidView(c, data.slurm || {}));
}

function loadOnlyInvalid() {
  getJSON("/api/rpki/only-invalid?prefix=" + encodeURIComponent(thisPrefix)).then(renderOnlyInvalid, function () {
    document.getElementById("only-invalid-panel").hidden = true;
  });
}

function initPrefixPage() {
  var title = document.getElementById("prefix-title");
  if (!title) return;
  title.textContent = thisPrefix || "Prefix";
  document.title = "Packeteer prefix " + thisPrefix;
  document.getElementById("prefix-links").appendChild(linkoutSpan("prefix", thisPrefix));
  document.getElementById("prefix-probe").href = "/troubleshooting.html?tool=probe&target=" + encodeURIComponent(thisPrefix);
  document.getElementById("prefix-load").addEventListener("click", loadTimeline);
  document.getElementById("prefix-days").addEventListener("change", loadTimeline);
  loadTimeline();
  loadRing();
  loadOnlyInvalid();
}

window.addEventListener("DOMContentLoaded", initPrefixPage);
