"use strict";
// "Add to dashboard" for the Reports (#178) and Graphs (#182) pages. A page
// has a button, a form with a dashboard menu and a name for a new one, and
// a status line, with ids <prefix>-add, <prefix>-add-form, <prefix>-dash,
// <prefix>-dash-new, and <prefix>-status. It saves through PUT
// /api/dashboards/<name>, so storage, auth, and the dashboard limits apply.
// Loaded after app.js (el, clear, getJSON).

function dashSend(method, path, body) {
  return fetch(path, {method: method, cache: "no-store", headers: {Accept: "application/json", "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body)}).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      if (!res.ok) throw new Error((data && data.error) || res.statusText);
      return data;
    });
  });
}

// dashAddInit wires the page. current() returns {widget, what}: the widget
// to add for the view on screen and a name for the status line.
function dashAddInit(prefix, current) {
  function byId(suffix) { return document.getElementById(prefix + "-" + suffix); }
  function say(text) { byId("status").textContent = text; }

  byId("add").addEventListener("click", function () {
    var form = byId("add-form");
    if (!form.hidden) { form.hidden = true; return; }
    say("");
    getJSON("/api/dashboards").then(function (data) {
      if (!data || !data.enabled) {
        say("Custom dashboards need a storage plugin that keeps them (sqlite) and auth or basic auth.");
        return;
      }
      var sel = byId("dash");
      clear(sel);
      var fresh = el("option", "", "(new dashboard)");
      fresh.value = "";
      sel.appendChild(fresh);
      (data.dashboards || []).forEach(function (d) {
        var o = el("option", "", d.name);
        o.value = d.name;
        sel.appendChild(o);
      });
      if (data.dashboards && data.dashboards.length) sel.value = data.dashboards[0].name;
      form.hidden = false;
    }, function (err) { say(err.message); });
  });

  byId("add-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var name = byId("dash").value || byId("dash-new").value.trim();
    if (!name) { say("Pick a dashboard or name a new one."); return; }
    var add = current();
    getJSON("/api/dashboards").then(function (data) {
      var spec = {title: "", widgets: []};
      (data.dashboards || []).forEach(function (d) { if (d.name === name) spec = d.spec; });
      spec.widgets = (spec.widgets || []).concat([add.widget]);
      return dashSend("PUT", "/api/dashboards/" + encodeURIComponent(name), spec);
    }).then(function () {
      byId("add-form").hidden = true;
      say("Added " + add.what + " to dashboard " + name + ".");
    }, function (err) { say(err.message.replace(/^\S+ failed: /, "")); });
  });
}
