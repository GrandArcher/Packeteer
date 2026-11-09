"use strict";
// Page driver for the UI smoke test (#221). Headless Chrome cannot click, so
// uiproxy adds this script to /settings.html. It presses Run checks, waits
// for the five results, presses Show router config for FRR, and writes what
// the page then shows into the page for lab/ui-smoke.sh to match. It also
// counts the calls that could write the config, which none of this makes.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  var u = String(url);
  // POST /api/config/form without apply only previews the form; it writes nothing.
  var preview = u.indexOf("/api/config/form") >= 0 && !/"apply"\s*:\s*true/.test(String((opts && opts.body) || ""));
  if (method !== "GET" && u.indexOf("/api/preflight/run") < 0 && !preview) writes++;
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function items() {
  return document.querySelectorAll("#pf-list .pf-item");
}

var steps = [
  function () { return !!document.getElementById("pf-run") && !document.getElementById("pf-run").disabled && document.querySelectorAll("#pf-vendor option").length > 0; },
  function () { document.getElementById("pf-run").click(); },
  function () { return items().length === 5; },
  function () {
    var seen = Array.prototype.map.call(items(), function (li) {
      return li.dataset.check + "=" + li.querySelector(".badge").textContent;
    });
    note("fixture-checks", "checks: " + seen.join(" "));
    note("fixture-inject-step", "inject step hidden: " + document.getElementById("pf-inject").hidden);
    var confirm = document.querySelector('#pf-list [data-check="import_filter"] button');
    note("fixture-confirm", "confirm button: " + (confirm ? confirm.textContent : "none"));
    document.getElementById("pf-vendor").value = "frr";
    document.getElementById("pf-snippet-show").click();
  },
  function () { return !document.getElementById("pf-snippet").hidden; },
  function () {
    note("fixture-snippet", "snippet: " + document.getElementById("pf-snippet").textContent.split("\n")[0]);
    note("fixture-writes", "writes: " + writes);
  }
];

var tries = 0;
function next() {
  if (!steps.length || tries++ > 60) return;
  if (steps[0]() !== false) steps.shift();
  setTimeout(next, 300);
}

next();
