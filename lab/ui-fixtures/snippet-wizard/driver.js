"use strict";
// Page driver for the UI smoke test (#569). The running file has an AS
// number, a router ID, and a provider, but no router (bgp.neighbors) yet.
// uiproxy adds this script to /settings.html. It asks for the FRR router
// config, which names the missing answer; reopens the wizard, types the edge
// address and a flow collector without saving; and writes what the panel
// shows into the page for lab/ui-smoke.sh to match. It counts every call that
// could write the config, and checks that the file did not change.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  var u = String(url);
  // POST /api/snippets only renders text from the page; it writes nothing.
  if (method !== "GET" && u.indexOf("/api/snippets") < 0) writes++;
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function byId(id) { return document.getElementById(id); }

function type(id, value) {
  var e = byId(id);
  e.value = value;
  e.dispatchEvent(new Event("change", {bubbles: true}));
}

function missing() {
  return Array.prototype.map.call(document.querySelectorAll("#pf-snippet-missing li"), function (li) { return li.textContent; });
}

var savedYaml = "";
var steps = [
  function () { return !!byId("pf-snippet-show") && byId("pf-vendor").options.length > 0 && byId("ed-yaml").value.indexOf("asn: 64512") >= 0; },
  function () {
    savedYaml = byId("ed-yaml").value;
    byId("pf-vendor").value = "frr";
    byId("pf-snippet-show").click();
  },
  function () { return missing().length > 0; },
  function () {
    note("fixture-missing", "missing: " + missing().join(" | "));
    note("fixture-missing-raw", "raw key error shown: " + (/no bgp\.neighbors|is not set/.test(byId("pf-snippet-status").textContent + missing().join(" "))));
    byId("wz-reopen").click();
    type("wz-edge", "192.0.2.254");
  },
  function () { return !byId("pf-snippet").hidden; },
  function () {
    note("fixture-edge", "after edge: " + byId("pf-snippet").textContent.split("\n").filter(function (l) { return l.indexOf("remote-as") >= 0; })[0].trim());
    byId("wz-flow").checked = true;
    type("wz-flow-addr", "192.0.2.10");
    type("wz-flow-port", "2055");
  },
  function () { return byId("pf-snippet").textContent.indexOf("UDP 2055") >= 0; },
  function () {
    note("fixture-flow-frr", "frr flow: " + byId("pf-snippet").textContent.split("\n").filter(function (l) { return l.indexOf("UDP 2055") >= 0; })[0].trim());
    type("pf-vendor", "mikrotik");
  },
  function () { return byId("pf-snippet").textContent.indexOf("/ip traffic-flow target add") >= 0; },
  function () {
    note("fixture-flow-mikrotik", "mikrotik flow: " + byId("pf-snippet").textContent.split("\n").filter(function (l) { return l.indexOf("traffic-flow target add") >= 0; })[0].trim());
    note("fixture-source", "status: " + byId("pf-snippet-status").textContent);
    return realFetch("/api/config", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (r) { return r.json(); }).then(function (f) {
      note("fixture-file", "file unchanged: " + (f.yaml === savedYaml));
      note("fixture-writes", "writes: " + writes);
    });
  }
];

var tries = 0;
var busy = false;
function next() {
  if (!steps.length || tries++ > 80) return;
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
