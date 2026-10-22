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
}

window.addEventListener("DOMContentLoaded", initPrefixPage);
