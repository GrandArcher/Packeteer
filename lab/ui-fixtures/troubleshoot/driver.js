"use strict";
// Page driver for the UI smoke test (#180). Headless Chrome cannot click,
// so uiproxy adds this script to /troubleshooting.html. It fills the form,
// presses Run, Remove, and Rerun, and writes the stack order it sees into
// the page for lab/ui-smoke.sh to match.

function press(label, scope) {
  var b = Array.prototype.find.call((scope || document).querySelectorAll("button"), function (x) { return x.textContent === label; });
  b.click();
}

function run(tool, target) {
  document.getElementById("tool-name").value = tool;
  document.getElementById("tool-target").value = target;
  press("Run");
}

function titles() {
  return Array.prototype.map.call(document.querySelectorAll("#tool-results .tool-head strong"), function (n) { return n.textContent; }).join(" | ");
}

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

var steps = [
  function () { run("lookingglass", "198.51.100.0/24"); },
  function () { run("lookingglass", "198.51.100.64/26"); },
  function () { run("lookingglass", "192.0.2.0/24"); },
  function () { run("traceroute", "203.0.113.7"); },
  function () { run("traceroute", "198.51.100.9"); },
  function () { run("traceroute", "203.0.113.99"); },
  function () {
    note("fixture-order", "order: " + titles());
    var all = document.querySelectorAll("#tool-results .tool-result");
    press("Remove", all[0]);
    press("Rerun", all[1]);
  },
  function () { note("fixture-after", "after: " + titles()); }
];

function next() {
  if (!steps.length) return;
  steps.shift()();
  setTimeout(next, 300);
}

next();
