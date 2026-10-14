"use strict";
// Page driver for the UI smoke test (#178). Headless Chrome cannot click, so
// uiproxy adds this script to /reports.html. It sorts a column twice, applies
// a filter, picks a custom range in local time (the smoke test runs Chrome in
// Asia/Kolkata, so 08:30 typed is 03:00Z sent), and adds the view to a
// dashboard, and writes what it sees into the page for lab/ui-smoke.sh to
// match. Nothing is stubbed: the answers are the real API's.

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function press(label) {
  var b = Array.prototype.find.call(document.querySelectorAll("button"), function (x) { return x.textContent.indexOf(label) === 0; });
  b.click();
}

function set(id, value, type) {
  var n = document.getElementById(id);
  n.value = value;
  if (type) n.dispatchEvent(new Event(type, {bubbles: true}));
}

function prefixes() {
  return Array.prototype.map.call(document.querySelectorAll("#report tbody tr td:first-child"), function (td) { return td.textContent; }).join(" ");
}

function state(id) {
  var th = document.querySelector("#report th[aria-sort='ascending'], #report th[aria-sort='descending']");
  note(id, id + ": " + window.location.search + " | " + (th ? th.getAttribute("aria-sort") : "unsorted") + " | " + prefixes() +
    " | " + document.getElementById("report-count").textContent.split(",")[0]);
}

var steps = [
  function () { state("fixture-default"); },
  function () { press("Prefix"); },
  function () { state("fixture-asc"); },
  function () { press("Prefix"); },
  function () { state("fixture-desc"); },
  function () { set("rf-cause", "cost"); document.getElementById("report-form").requestSubmit(); },
  function () {
    state("fixture-cause");
    note("fixture-links", "links: " + document.getElementById("report-csv").getAttribute("href") + " " + document.getElementById("report-xlsx").getAttribute("href"));
  },
  function () {
    set("rf-cause", "");
    set("report-range", "custom", "change");
    set("report-from", "2020-01-01T08:30");
    set("report-to", "2020-01-02T08:30");
    document.getElementById("report-form").requestSubmit();
  },
  function () {
    var q = new URLSearchParams(window.location.search);
    note("fixture-range", "range: from=" + q.get("from") + " to=" + q.get("to") + " | " + document.getElementById("report").textContent);
  },
  function () { set("report-range", "30", "change"); set("rf-cause", "cost"); document.getElementById("report-form").requestSubmit(); },
  function () { press("Add to dashboard"); },
  function () { set("report-dash", ""); set("report-dash-new", "a-reports"); document.getElementById("report-add-form").requestSubmit(); },
  function () { note("fixture-add", "add: " + document.getElementById("report-status").textContent); }
];

function next() {
  if (!steps.length) return;
  steps.shift()();
  setTimeout(next, 400);
}

window.addEventListener("load", function () { setTimeout(next, 1200); });
