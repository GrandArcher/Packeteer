"use strict";
// The opt-in RIPE Atlas panel on the prefix page (#213): local measurements
// of the prefix and the Atlas measurements beside them. It uses thisPrefix
// from prefix.js and the app.js helpers, which exist by DOMContentLoaded.
// The server answers state "off" and the panel stays hidden while atlas is
// off. This is the one part of the page that writes: the measure buttons
// POST /api/atlas/measure, which spends credits and is capped by the server.
var atlasTimer = null;

function atlasWhat(r) {
  return r.type + (r.trigger === "after_move" ? ", after move to " + (r.provider || "?") : ", on demand");
}

function atlasResultCells(tr, r) {
  var s = r.summary;
  if (!s) {
    tr.appendChild(el("td", "", "waiting"));
    tr.appendChild(el("td", "", "-"));
    tr.appendChild(el("td", "", "-"));
    return;
  }
  tr.appendChild(el("td", "", s.reached + " of " + r.requested + " reached"));
  tr.appendChild(el("td", "", s.reached ? s.median_rtt_ms.toFixed(1) + " ms" : "-"));
  tr.appendChild(el("td", "", s.loss_pct == null ? "-" : s.loss_pct.toFixed(0) + " %"));
}

function renderAtlas(data) {
  var panel = document.getElementById("atlas-panel");
  var root = document.getElementById("atlas-body");
  clear(root);
  if (atlasTimer) { clearTimeout(atlasTimer); atlasTimer = null; }
  if (data.state === "off") return;
  panel.hidden = false;
  if (data.state === "no_key") {
    root.appendChild(el("p", "empty", "RIPE Atlas is enabled but PACKETEER_ATLAS_API_KEY is not set, so no measurement is made."));
    return;
  }
  var local = data.local || [];
  root.appendChild(el("h3", "", "Local measurements" + (data.target ? " (test address " + data.target + ")" : "")));
  if (!local.length) {
    root.appendChild(el("p", "empty", "Packeteer has no local measurement of this prefix."));
  } else {
    var lt = table(["Provider", "Avg RTT", "Loss", "Confidence"]);
    local.forEach(function (l) {
      var tr = el("tr");
      tr.appendChild(el("td", "", l.provider));
      tr.appendChild(el("td", "", l.ok ? l.rtt_avg_ms.toFixed(1) + " ms" : "-"));
      tr.appendChild(el("td", "", l.loss_pct.toFixed(0) + " %"));
      tr.appendChild(el("td", "", l.confidence));
      lt.body.appendChild(tr);
    });
    root.appendChild(lt.table);
  }
  root.appendChild(el("h3", "", "RIPE Atlas measurements"));
  var ms = data.measurements || [];
  var pending = false;
  if (!ms.length) {
    root.appendChild(el("p", "empty", "No Atlas measurement of this prefix yet."));
  } else {
    var t = table(["When", "What", "Result", "Median RTT", "Loss", "State"]);
    ms.forEach(function (r) {
      var tr = el("tr");
      tr.appendChild(el("td", "", fmtTime(r.created)));
      tr.appendChild(el("td", "", atlasWhat(r)));
      atlasResultCells(tr, r);
      tr.appendChild(el("td", "", r.state));
      if (r.state === "pending") pending = true;
      t.body.appendChild(tr);
    });
    root.appendChild(t.table);
  }
  var st = data.status || {};
  root.appendChild(el("p", "tag", "Credits used today: " + st.credits_today + " of " + st.max_credits_per_day +
    ". Measurements in the last hour: " + st.measurements_last_hour + " of " + st.max_measurements_per_hour + "." +
    (st.balance != null ? " Balance: " + st.balance + " credits." : "")));
  if (data.can_measure) {
    var row = el("p");
    var note = el("span", "tag", "");
    [["ping", "Measure with ping"], ["traceroute", "Measure with traceroute"]].forEach(function (b) {
      var btn = el("button", "small", b[1]);
      btn.addEventListener("click", function () {
        btn.disabled = true;
        postJSON("/api/atlas/measure", {prefix: thisPrefix, type: b[0]}).then(loadAtlas, function (err) {
          btn.disabled = false;
          note.textContent = " " + err.message;
        });
      });
      row.appendChild(btn);
    });
    row.appendChild(note);
    root.appendChild(row);
  }
  if (pending) atlasTimer = setTimeout(loadAtlas, 20000);
}

function loadAtlas() {
  var root = document.getElementById("atlas-body");
  if (!root || !thisPrefix) return;
  getJSON("/api/atlas?prefix=" + encodeURIComponent(thisPrefix)).then(renderAtlas, function (err) {
    document.getElementById("atlas-panel").hidden = false;
    clear(root);
    root.appendChild(el("p", "empty", "Unavailable. " + err.message));
  });
}

window.addEventListener("DOMContentLoaded", function () {
  if (document.getElementById("atlas-body")) loadAtlas();
});
