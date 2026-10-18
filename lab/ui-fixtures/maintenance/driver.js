"use strict";
// Page driver for the UI smoke test (#177). Headless Chrome cannot click,
// so uiproxy adds this script to /policies.html. It fills the maintenance
// form like an operator would, presses Open window twice (a window from now
// and one tomorrow at 10:00 local time) and Close once, and writes what the
// page then shows for lab/ui-smoke.sh to match. It records the body of each
// POST so the check can see the RFC 3339 times that were sent.

var sent = [];
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  if (opts && opts.method === "POST" && String(url) === "/api/maintenance") sent.push(JSON.parse(opts.body));
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function rows() {
  return Array.prototype.map.call(document.querySelectorAll("#maint-list tbody tr"), function (tr) {
    return Array.prototype.map.call(tr.children, function (td) { return td.textContent; }).join("|");
  });
}

function formReady() {
  var form = document.getElementById("maint-form");
  return !form.hidden && document.querySelectorAll("#mw-providers input").length === 2 && rows().length >= 2;
}

function fill(provider, start, end, text) {
  document.querySelectorAll("#mw-providers input").forEach(function (cb) { cb.checked = cb.value === provider; });
  document.getElementById("mw-start").value = start;
  document.getElementById("mw-end").value = end;
  document.getElementById("mw-note").value = text;
  document.getElementById("mw-open").click();
}

function local(d) {
  return maintLocal(d);
}

var tomorrow = new Date();
tomorrow.setDate(tomorrow.getDate() + 1);
tomorrow.setHours(10, 0, 0, 0);
var tomorrowEnd = new Date(tomorrow.getTime() + 7200000);

var steps = [
  function () { return formReady(); },
  function () {
    note("fixture-before", "before: " + rows().join(" ; "));
    fill("lab-b", local(tomorrow), local(tomorrowEnd), "fiber work");
  },
  function () { return rows().length === 3; },
  function () {
    // local() truncates to the minute and Chrome's clock can run slightly
    // ahead of the container's, so start a minute back to be current.
    var now = new Date();
    fill("lab-a", local(new Date(now.getTime() - 60000)), local(new Date(now.getTime() + 7200000)), "");
  },
  function () { return rows().some(function (r) { return r.indexOf("current") === 0; }); },
  function () {
    note("fixture-open", "open: " + rows().join(" ; ") + " sent " + JSON.stringify(sent));
    var close = document.querySelector("#maint-list button[aria-label^='Close window']");
    // The current window is first; the upcoming one has a button too.
    close.click();
  },
  function () { return rows().length === 3 && !rows().some(function (r) { return r.indexOf("current") === 0; }); },
  function () {
    note("fixture-closed", "closed: " + rows().join(" ; ") + " status [" + document.getElementById("mw-status").textContent + "]");
  }
];

var tries = 0;
function next() {
  if (!steps.length || tries++ > 80) return;
  if (steps[0]() !== false) steps.shift();
  setTimeout(next, 300);
}

next();
