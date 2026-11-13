"use strict";
// Page driver for the hold-time review smoke test (#576). Headless Chrome
// cannot click, so uiproxy adds this script to /settings.html. Nothing is
// stubbed: the form, the gate, the preview, and the save are the real API's,
// against lab/ui-fixtures/holdtime/config.yaml mounted writable. The driver
// changes Hold time from 1m to 2m and presses the sticky bar's Save. It
// checks that the review dialog opens with the change named and its confirm
// button in view, that Cancel writes nothing, and that confirming writes the
// file. A write is a PUT that was answered 200 and was not a dry run.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var put = ((opts && opts.method) || "GET") === "PUT";
  var dry = put && String(opts.body).indexOf('"dry_run":true') >= 0;
  var res = realFetch.apply(window, arguments);
  if (!put || dry) return res;
  return res.then(function (r) {
    if (r.ok) writes++;
    return r;
  });
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("ht-jserr", "script error: " + e.message); });

function text(id) { return byId(id).textContent; }
function yes(v) { return v ? "yes" : "no"; }
function inView(node) {
  var r = node.getBoundingClientRect();
  return r.width > 0 && r.top >= 0 && r.bottom <= window.innerHeight;
}

var roundReady = false;
var step = 0;
var steps = [
  // The review needs a decision round, so wait for the first one.
  function () {
    realFetch("/api/blast").then(function (r) { roundReady = r.status === 200; });
    var y = byId("ed-yaml");
    return roundReady && !!(y && y.value.indexOf("hold_time: 1m") >= 0 && byId("fm-hold") && byId("fm-hold").value === "1");
  },
  function () {
    var hold = byId("fm-hold");
    hold.value = "2";
    hold.dispatchEvent(new Event("input", {bubbles: true}));
  },
  function () { byId("bar-save").click(); },
  function () { return !byId("review").hidden; },
  function () {
    note("ht-dialog",
      "dialog: " + text("rv-title") +
      " | confirm in view " + yes(inView(byId("rv-confirm"))) +
      " | confirm focused " + yes(document.activeElement === byId("rv-confirm")) +
      " | blast radius apply gone " + yes(!document.getElementById("bl-apply")) +
      " | observe " + yes(text("rv-body").indexOf("This config does not announce") >= 0) +
      " | not saved yet " + yes(text("bar-msg").indexOf("Nothing is saved yet") >= 0) +
      " | writes " + writes);
    byId("rv-cancel").click();
  },
  function () {
    note("ht-cancel",
      "cancelled: " + text("bar-msg") + " | dialog closed " + yes(byId("review").hidden) + " | writes " + writes);
    byId("bar-save").click();
  },
  function () { return !byId("review").hidden; },
  function () { byId("rv-confirm").click(); },
  function () { return /^(Saved |Nothing was saved)/.test(text("ed-status")) || text("ed-status").indexOf("refused") >= 0; },
  function () {
    note("ht-saved",
      "saved: " + text("ed-status") + " | dialog closed " + yes(byId("review").hidden) + " | writes " + writes);
  }
];

var tries = 0;
function next() {
  if (step >= steps.length) return;
  if (tries++ > 800) {
    note("ht-timeout", "timeout at step " + step + " | " + text("ed-status") + " | " + text("form-status"));
    return;
  }
  var ok;
  document.body.setAttribute("data-step", String(step));
  try {
    ok = steps[step]();
  } catch (e) {
    note("ht-error", "error: " + e.message + " (step " + step + ")");
    return;
  }
  if (ok !== false) step++;
  setTimeout(next, 150);
}

next();
