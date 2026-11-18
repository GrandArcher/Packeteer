"use strict";
// Settings push (#137): an admin sends this instance's saved thresholds or
// policies to every federation peer. Each peer validates them like a local
// config write and answers; nothing is announced from here. The control is
// built once into #fed-push, on the Overview and on Settings (#658), so a
// refresh does not wipe a result. Needs el and clear, which both pages have.

// The Overview has postJSON (app.js) and Settings has api (ui.js).
function fedPushPost(body) {
  if (typeof postJSON === "function") return postJSON("/api/federation/push", body);
  return api("POST", "/api/federation/push", body);
}

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
    var label = el("label", "check");
    var box = el("input");
    box.type = "checkbox";
    box.checked = sec[0] === "thresholds";
    box.value = sec[0];
    label.appendChild(box);
    label.appendChild(el("span", "", " " + sec[1]));
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
  return fedPushPost({sections: sections}).then(function (rep) {
    renderFedPushReport(rep);
  }, function (err) {
    clear(fedPushOut);
    fedPushOut.appendChild(el("p", "errors", "Push failed: " + err.message));
  });
}

function renderFedPushReport(rep) {
  clear(fedPushOut);
  var t = el("table");
  var head = el("tr");
  ["Peer", "Result", "Detail"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  t.appendChild(head);
  (rep.peers || []).forEach(function (p) {
    var tr = el("tr");
    tr.appendChild(el("td", "", p.peer));
    var st = el("td");
    var ok = p.status === "applied" || p.status === "unchanged";
    st.appendChild(el("span", ok ? "dot up" : "dot down", p.status));
    tr.appendChild(st);
    var detail = (p.errors || []).join("; ") || (p.applied || []).join(", ");
    tr.appendChild(el("td", "", detail || (p.status === "unchanged" ? "already had these settings" : "")));
    t.appendChild(tr);
  });
  fedPushOut.appendChild(el("p", "", rep.ok ? "Every peer has these settings." : "At least one peer did not take them."));
  fedPushOut.appendChild(t);
}
