"use strict";
// Commit & Cost page (#174): billable usage against commit per provider,
// from /api/commit. Loaded after app.js (el, clear, getJSON) and charts.js
// (renderCommitGraphs, the drawing shared with the dashboard widget). Read-only.

function renderCommitSummary(root, data) {
  clear(root);
  if (!data.providers.length) return;
  var t = el("table");
  var hr = el("tr");
  ["Provider", "Commit (Mbps)", "Billable 95th (Mbps)", "Of commit", "Capacity (Mbps)", "Outbound of capacity", "Samples", "Period (UTC)", "Last sample", "Poll error"].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var thead = el("thead");
  thead.appendChild(hr);
  t.appendChild(thead);
  var tb = el("tbody");
  data.providers.forEach(function (p) {
    var pct = commitPercent(p);
    var tr = el("tr");
    var load = p.utilization_pct == null ? "—" : (Math.round(p.utilization_pct * 10) / 10) + "%" +
      (p.capacity_threshold_pct > 0 ? " (limit " + p.capacity_threshold_pct + "%)" : "");
    var cells = [p.provider, p.commit_mbps > 0 ? mbps(p.commit_mbps) : "none", mbps(p.billable_mbps), pct == null ? "—" : pct + "%",
      mbps(p.capacity_mbps), load, p.samples,
      p.period_start.slice(0, 10) + " to " + p.period_end.slice(0, 10), fmtTime(p.updated), p.error || ""];
    cells.forEach(function (v, i) {
      var bad = (i === 3 && pct != null && pct >= 100) || (i === 5 && p.overloaded);
      tr.appendChild(el("td", bad ? "bad" : "", v));
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  root.appendChild(t);
}

// The range is in the query string (/commit.html?days=30), so a link opens
// the same view.
function loadCommit() {
  var days = document.getElementById("commit-days").value || "7";
  window.history.replaceState(null, "", days === "7" ? window.location.pathname : "?days=" + days);
  var graphs = document.getElementById("commit-graphs");
  getJSON("/api/commit?days=" + encodeURIComponent(days)).then(function (data) {
    renderCommitSummary(document.getElementById("commit-summary"), data);
    renderCommitGraphs(graphs, data);
  }, function (err) {
    clear(document.getElementById("commit-summary"));
    clear(graphs);
    graphs.appendChild(el("p", "empty", err.message));
  });
}

var wantDays = new URLSearchParams(window.location.search).get("days");
if (["1", "7", "30"].indexOf(wantDays) >= 0) document.getElementById("commit-days").value = wantDays;
document.getElementById("commit-days").addEventListener("change", loadCommit);
document.getElementById("commit-load").addEventListener("click", loadCommit);
loadCommit();
