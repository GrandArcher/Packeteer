"use strict";
// Prefix page (#179): the live card for one prefix plus its stored
// timeline. Loaded after app.js (el, clear, getJSON, prefixCard, fmt*).
// Read-only. "Probe now" only links to the Probe tool.

var PREFIX_PATH = "/prefix/";

function pagePrefix() {
  var path = window.location.pathname;
  if (path.indexOf(PREFIX_PATH) !== 0) return "";
  try { return decodeURIComponent(path.slice(PREFIX_PATH.length)); } catch (e) { return ""; }
}

var thisPrefix = pagePrefix();

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

function initPrefixPage() {
  var title = document.getElementById("prefix-title");
  if (!title) return;
  title.textContent = thisPrefix || "Prefix";
  document.title = "Packeteer prefix " + thisPrefix;
  document.getElementById("prefix-probe").href = "/troubleshooting.html?tool=probe&target=" + encodeURIComponent(thisPrefix);
  document.getElementById("prefix-load").addEventListener("click", loadTimeline);
  document.getElementById("prefix-days").addEventListener("change", loadTimeline);
  loadTimeline();
}

initPrefixPage();
