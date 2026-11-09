"use strict";
// Page driver for the settings guided-input smoke test (#329). Headless
// Chrome cannot click, so uiproxy adds this script to /settings.html. It
// waits until the form has been filled from the file, presses Apply, and
// checks the YAML in the editor is unchanged. A bad prefix is then marked
// on the row. Only PUT /api/config counts as a config write; Apply and
// validate do not write the file.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  if (method === "PUT") writes++;
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function seen(sel) {
  return document.querySelector(sel) ? "yes" : "no";
}

function inputValue(root, value) {
  if (!root) return false;
  var inputs = root.querySelectorAll("input");
  for (var i = 0; i < inputs.length; i++) if (inputs[i].value === value) return true;
  return false;
}

var before = "";
var steps = [
  function () {
    var y = byId("ed-yaml");
    var prov = document.querySelector("#form-providers input");
    return !!(y && y.value.indexOf("mode: observe") >= 0 && prov && prov.value === "lab-a" && byId("form-status").textContent === "");
  },
  function () {
    before = byId("ed-yaml").value;
    byId("form-apply").click();
  },
  function () {
    return byId("form-status").textContent.indexOf("Applied to the YAML") >= 0;
  },
  function () {
    var same = byId("ed-yaml").value === before;
    byId("form-add-allow").click();
    var inputs = document.querySelectorAll("#form-allow .g-cidr-input");
    var input = inputs[inputs.length - 1];
    var err = "missing row";
    if (input) {
      input.value = "999.1.1.1/24";
      input.dispatchEvent(new Event("input", {bubbles: true}));
      input.dispatchEvent(new Event("blur", {bubbles: true}));
      err = "";
      var nodes = document.querySelectorAll("#form-allow .field-error");
      for (var i = 0; i < nodes.length; i++) {
        if (!nodes[i].hidden && nodes[i].textContent) err = nodes[i].textContent;
      }
    }
    var inbound = document.getElementById("in-prefix-box");
    var anomaly = document.getElementById("form-anomaly-rules");
    note("guided-report", "guided: yaml-same: " + same + " writes: " + writes +
      " decision: " + seen("#fm-hold.g-num") +
      " providers: " + (document.querySelectorAll("#form-providers .g-combo").length >= 2 ? "yes" : "no") +
      " flow: " + (document.querySelector("#form-flows .g-listen") && document.querySelector("#form-flows .g-dur") && document.querySelector("#form-flows .g-agg") ? "yes" : "no") +
      " policy: " + (document.querySelector("#form-policies .g-country") && document.querySelector("#form-policies .g-multi") ? "yes" : "no") +
      " vip: " + (document.querySelector("#form-vips .g-cidr-input") && document.querySelector("#form-vips .g-chips") ? "yes" : "no") +
      " outage: " + (document.querySelector("#form-outages .g-pct") && document.querySelector("#form-outages .g-chips") ? "yes" : "no") +
      " exchange: " + (document.querySelector("#form-exchanges .g-cidr") && document.querySelector("#form-exchanges .g-select") ? "yes" : "no") +
      " inbound: " + seen("#in-perf-loss-on") +
      " anomaly: " + (document.querySelector("#form-anomaly-rules .g-select, #form-anomaly-rules .empty") ? "yes" : "no") +
      " inbound-prefix: " + (inputValue(inbound, "198.51.100.0/24") ? "198.51.100.0/24" : "none") +
      " anomaly-name: " + (inputValue(anomaly, "udp-flood") ? "udp-flood" : "none") +
      " cidr-error: " + err);
  }
];

var tries = 0;
function next() {
  if (!steps.length || tries++ > 40) return;
  if (steps[0]() !== false) steps.shift();
  setTimeout(next, 200);
}

next();
