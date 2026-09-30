"use strict";

var base = "";

function edStatus(text, errors) {
  document.getElementById("ed-status").textContent = text || "";
  var ul = document.getElementById("ed-errors");
  clear(ul);
  (errors || []).forEach(function (e) { ul.appendChild(el("li", "", e)); });
}

function describe(res) {
  if (!res) return "";
  var parts = [res.valid ? "Valid" : "Invalid"];
  if (res.mode) parts.push("mode " + res.mode);
  if (res.changed && res.changed.length) parts.push("changed: " + res.changed.join(", "));
  if (res.restart_required) parts.push("restart required");
  else if (res.reload_online) parts.push("SIGHUP applies it");
  if (res.enables_inject) parts.push("turns inject on");
  return parts.join(" · ");
}

function loadConfig() {
  api("GET", "/api/config").then(function (f) {
    base = f.sha256;
    document.getElementById("ed-yaml").value = f.yaml;
    document.getElementById("ed-path").textContent = f.path;
    document.getElementById("ed-sha").textContent = f.sha256.slice(0, 12);
    edStatus("Loaded.");
  }, function (err) { edStatus(err.message); });
}

function checkConfig() {
  api("POST", "/api/config/validate", {yaml: document.getElementById("ed-yaml").value}).then(function (res) {
    edStatus(describe(res), res.errors);
  }, function (err) { edStatus(err.message); });
}

function saveConfig() {
  var body = {yaml: document.getElementById("ed-yaml").value, base: base,
    confirm_inject: document.getElementById("ed-inject").checked};
  api("PUT", "/api/config", body).then(function (out) {
    base = out.file.sha256;
    document.getElementById("ed-sha").textContent = base.slice(0, 12);
    document.getElementById("ed-inject").checked = false;
    edStatus("Saved. " + describe(out.result));
  }, function (err) {
    var res = err.data && err.data.result;
    edStatus(err.message + (res ? " — " + describe(res) : ""), res && res.errors);
  });
}

function lines(id) {
  return document.getElementById(id).value.split("\n").map(function (l) { return l.trim(); }).filter(Boolean);
}

function runWizard() {
  var providers = lines("wz-providers").map(function (l) {
    var f = l.split(/\s+/);
    return {name: f[0] || "", source_ip: f[1] || "", next_hop: f[2] || ""};
  });
  var targets = lines("wz-targets").map(function (l) {
    var f = l.split(/\s+/);
    return {prefix: f[0] || "", host: f[1] || ""};
  });
  var neighbors = document.getElementById("wz-neighbors").value.split(/[\s,]+/).filter(Boolean);
  var body = {asn: Number(document.getElementById("wz-asn").value) || 0, router_id: document.getElementById("wz-router").value.trim(),
    providers: providers, neighbors: neighbors, targets: targets, storage: document.getElementById("wz-storage").checked};
  var status = document.getElementById("wz-status");
  api("POST", "/api/config/wizard", body).then(function (out) {
    document.getElementById("ed-yaml").value = out.yaml;
    status.textContent = "Generated (observe). Review it in the editor, then Save.";
    if (!base) api("GET", "/api/config").then(function (f) { base = f.sha256; }, function () {});
  }, function (err) {
    status.textContent = err.message + ((err.data && err.data.errors) ? ": " + err.data.errors.join("; ") : "");
  });
}

function renderSubs() {
  var root = document.getElementById("subs");
  api("GET", "/api/subscriptions").then(function (data) {
    clear(root);
    var subs = (data && data.subscriptions) || [];
    if (!subs.length) {
      root.appendChild(el("p", "empty", "No report subscriptions configured."));
      return;
    }
    var t = el("table");
    var hr = el("tr");
    ["Name", "Report", "Schedule", "Next (UTC)", "Last sent", "Sent", "Failed", "Last error", ""].forEach(function (h) { hr.appendChild(el("th", "", h)); });
    var th = el("thead");
    th.appendChild(hr);
    t.appendChild(th);
    var tb = el("tbody");
    subs.forEach(function (s) {
      var tr = el("tr");
      [s.name, s.report + " (" + s.days + "d)", s.schedule + (s.weekday ? " " + s.weekday : "") + " " + s.at,
        s.next, s.last_sent || "—", s.sent, s.failed, s.last_error || ""].forEach(function (v) { tr.appendChild(el("td", "", v)); });
      var td = el("td");
      var b = el("button", "small", "Send now");
      b.type = "button";
      b.addEventListener("click", function () {
        document.getElementById("subs-status").textContent = "Sending " + s.name + "…";
        api("POST", "/api/subscriptions/" + encodeURIComponent(s.name) + "/send").then(function () {
          document.getElementById("subs-status").textContent = "Sent " + s.name + ".";
          renderSubs();
        }, function (err) { document.getElementById("subs-status").textContent = err.message; renderSubs(); });
      });
      td.appendChild(b);
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    root.appendChild(t);
  }, function (err) { clear(root); root.appendChild(el("p", "empty", err.message)); });
}

document.getElementById("ed-load").addEventListener("click", loadConfig);
document.getElementById("ed-check").addEventListener("click", checkConfig);
document.getElementById("ed-save").addEventListener("click", saveConfig);
document.getElementById("wz-run").addEventListener("click", runWizard);
loadConfig();
renderSubs();
