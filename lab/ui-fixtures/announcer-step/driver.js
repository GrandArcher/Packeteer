"use strict";
// Page driver for the UI smoke test (#568). The running file is a fresh
// observe config with no announcer. uiproxy adds this script to
// /settings.html and answers the preflight report from report.json: every
// check passes except the missing announcer. The driver reads the announcer
// form the inject step draws from the config schema, asks for a plan with
// it, and writes what happens into the page for lab/ui-smoke.sh to match.
// POST /api/config/inject is not stubbed: the container's own checks fail
// (no router answers), so the real server refuses the plan. It counts every
// call that could write the config, and checks that the file did not change.

var writes = 0;
var planBody = null;
var planAnswer = "";
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  var u = String(url);
  var body = String((opts && opts.body) || "");
  // POST /api/config/form without apply only previews the form, and
  // POST /api/config/inject only returns a plan; neither writes.
  var preview = u.indexOf("/api/config/form") >= 0 && !/"apply"\s*:\s*true/.test(body);
  var plan = u.indexOf("/api/config/inject") >= 0;
  if (method !== "GET" && u.indexOf("/api/preflight/run") < 0 && !preview && !plan) writes++;
  var p = realFetch.apply(window, arguments);
  if (!plan) return p;
  planBody = JSON.parse(body);
  return p.then(function (r) {
    r.clone().json().then(function (d) { planAnswer = r.status + " " + (d.code || ""); });
    return r;
  });
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function byId(id) { return document.getElementById(id); }

var savedYaml = "";
var steps = [
  function () { return !!document.querySelector("#pf-announcer select") && byId("ed-yaml").value.indexOf("asn: 64512") >= 0; },
  function () {
    savedYaml = byId("ed-yaml").value;
    var types = Array.prototype.map.call(document.querySelectorAll("#pf-announcer select option"), function (o) { return o.value; });
    note("fixture-step", "inject step hidden: " + byId("pf-inject").hidden);
    note("fixture-types", "announcer types: " + types.join(","));
    byId("pf-allow").value = "198.51.100.0/24";
    byId("pf-inject-plan").click();
  },
  function () { return planAnswer !== "" && byId("pf-inject-status").textContent !== ""; },
  function () {
    note("fixture-plan", "plan announcer: " + (planBody.announcer && planBody.announcer.type));
    note("fixture-answer", "plan answer: " + planAnswer.trim());
    note("fixture-after", "inject step hidden after refusal: " + byId("pf-inject").hidden);
    return realFetch("/api/config", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (r) { return r.json(); }).then(function (f) {
      note("fixture-file", "file unchanged: " + (f.yaml === savedYaml) + ", announcer in file: " + /^announcer:/m.test(f.yaml));
      note("fixture-writes", "writes: " + writes);
    });
  }
];

var tries = 0;
var busy = false;
function next() {
  if (!steps.length || tries++ > 200) return;
  if (busy) { setTimeout(next, 300); return; }
  var r = steps[0]();
  if (r && typeof r.then === "function") {
    busy = true;
    r.then(function () { steps.shift(); busy = false; });
  } else if (r !== false) {
    steps.shift();
  }
  setTimeout(next, 300);
}

next();
