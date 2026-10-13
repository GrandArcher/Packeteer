"use strict";
// The maintenance windows section of the Policies page (#177). It lists
// GET /api/maintenance and opens or closes a window over POST and
// DELETE /api/maintenance. The server checks the role, the policy's limits,
// and the audit record on every call; the effect on improvements is the
// maintenance policy's, and nothing here announces a route. Uses el, clear,
// fmtTime, table, getJSON, and postJSON from app.js. No inline script: the
// CSP allows scripts from this origin only.

var maintMe = null;
var maintData = null;
var maintProviders = [];
var maintFormKey = "";

function maintSetStatus(text, bad) {
  var n = document.getElementById("mw-status");
  n.textContent = text || "";
  n.className = bad ? "bad" : "tag";
}

// maintCanWrite: the form and the Close buttons are offered only when the
// server says on-demand windows are on and the account is an operator.
function maintCanWrite() {
  if (!maintData || !maintData.on_demand) return false;
  if (maintMe && maintMe.auth === "rbac") return maintMe.role === "operator" || maintMe.role === "admin";
  return true;
}

// maintLocal formats a Date for a datetime-local input, in local time.
function maintLocal(d) {
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
}

function maintRow(w, state, canClose) {
  var tr = el("tr");
  var st = el("td");
  st.appendChild(el("span", "badge win-" + state, state));
  tr.appendChild(st);
  tr.appendChild(el("td", "", (w.providers || []).join(", ")));
  var start = el("td", "", fmtTime(w.start));
  start.title = w.start;
  tr.appendChild(start);
  var end = el("td", "", fmtTime(w.end));
  end.title = w.end;
  tr.appendChild(end);
  tr.appendChild(el("td", "", w.source === "api" ? "on demand" : "configured"));
  tr.appendChild(el("td", "", w.reason || ""));
  var act = el("td");
  if (canClose && w.source === "api" && state !== "finished") {
    var btn = el("button", "", "Close");
    btn.type = "button";
    btn.setAttribute("aria-label", "Close window " + w.id);
    btn.addEventListener("click", function () {
      btn.disabled = true;
      fetch("/api/maintenance/" + encodeURIComponent(w.id), {method: "DELETE", cache: "no-store"}).then(function (res) {
        if (res.ok) return null;
        return res.json().catch(function () { return {}; }).then(function (b) { throw new Error(b.error || res.statusText); });
      }).then(function () {
        maintSetStatus("Closed " + w.id + ".", false);
        maintRefresh();
      }, function (err) {
        btn.disabled = false;
        maintSetStatus(err.message, true);
      });
    });
    act.appendChild(btn);
  }
  tr.appendChild(act);
  return tr;
}

function maintRender(data) {
  var root = document.getElementById("maint-list");
  clear(root);
  var rows = [];
  (data.windows || []).forEach(function (w) { rows.push([w, "current"]); });
  (data.upcoming || []).forEach(function (w) { rows.push([w, "upcoming"]); });
  (data.finished || []).forEach(function (w) { rows.push([w, "finished"]); });
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No maintenance windows."));
    return;
  }
  var canClose = maintCanWrite();
  var t = table(["State", "Providers", "Start", "End", "Source", "Note", ""]);
  rows.forEach(function (r) { t.body.appendChild(maintRow(r[0], r[1], canClose)); });
  root.appendChild(t.table);
}

function maintBuildForm() {
  var key = maintProviders.join(",");
  if (key === maintFormKey) return;
  maintFormKey = key;
  var box = document.getElementById("mw-providers");
  var legend = box.firstChild;
  clear(box);
  box.appendChild(legend);
  maintProviders.forEach(function (name) {
    var label = el("label", "check");
    var cb = el("input");
    cb.type = "checkbox";
    cb.value = name;
    label.appendChild(cb);
    label.appendChild(document.createTextNode(name));
    box.appendChild(label);
  });
  var start = document.getElementById("mw-start");
  if (!start.value) {
    var now = new Date();
    start.value = maintLocal(now);
    document.getElementById("mw-end").value = maintLocal(new Date(now.getTime() + 3600000));
  }
}

function maintApply() {
  if (!maintData) return;
  var section = document.getElementById("maint-section");
  section.hidden = !maintData.configured;
  if (!maintData.configured) return;
  var canWrite = maintCanWrite();
  document.getElementById("maint-form").hidden = !canWrite;
  var ro = document.getElementById("maint-readonly");
  ro.hidden = canWrite;
  if (!canWrite) {
    ro.textContent = !maintData.on_demand
      ? "Windows can be opened once auth or basic auth is on and a maintenance policy takes on-demand windows."
      : "Opening and closing a window needs the operator role.";
  } else {
    maintBuildForm();
  }
  maintRender(maintData);
}

function maintRefresh() {
  return getJSON("/api/maintenance").then(function (data) {
    maintData = data;
    maintApply();
  }, function () {});
}

function maintSubmit(ev) {
  ev.preventDefault();
  var names = [];
  document.querySelectorAll("#mw-providers input:checked").forEach(function (cb) { names.push(cb.value); });
  var start = new Date(document.getElementById("mw-start").value);
  var end = new Date(document.getElementById("mw-end").value);
  if (!names.length) { maintSetStatus("Choose at least one provider.", true); return; }
  if (isNaN(start.getTime()) || isNaN(end.getTime())) { maintSetStatus("Enter a start and an end time.", true); return; }
  if (end <= start) { maintSetStatus("The end must be after the start.", true); return; }
  var body = {providers: names, start: start.toISOString(), end: end.toISOString()};
  var note = document.getElementById("mw-note").value.trim();
  if (note) body.reason = note;
  var btn = document.getElementById("mw-open");
  btn.disabled = true;
  postJSON("/api/maintenance", body).then(function (w) {
    maintSetStatus("Opened " + w.id + " for " + w.providers.join(", ") + ".", false);
    document.getElementById("mw-note").value = "";
    return maintRefresh();
  }).catch(function (err) {
    maintSetStatus(err.message, true);
  }).then(function () { btn.disabled = false; });
}

function maintInit() {
  var form = document.getElementById("maint-form");
  if (!form) return;
  document.getElementById("maint-zone").textContent = Intl.DateTimeFormat().resolvedOptions().timeZone || "local time";
  form.addEventListener("submit", maintSubmit);
  getJSON("/api/me").then(function (me) { maintMe = me; maintApply(); }, function () {});
  getJSON("/api/providers").then(function (p) {
    maintProviders = (p.providers || []).map(function (x) { return x.name; });
    maintApply();
  }, function () {});
  maintRefresh();
  setInterval(maintRefresh, 5000);
}

maintInit();
