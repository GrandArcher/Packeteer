"use strict";
// Runs the blast-radius section of the settings page script (#227) against
// a small DOM stand-in: the panel lists what would be announced, move, and
// be withdrawn with the warnings; a save the server wants previewed opens a
// review dialog (#576) that names the change, shows the preview, and saves
// only with the token it returned. The functions are
// cut out of the real settings.js. Run by TestBlastPage.

var fs = require("fs");
var path = require("path");
var vm = require("vm");

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
}

function fn(src, name) {
  var start = src.indexOf("function " + name + "(");
  assert(start >= 0, "function " + name + " not found");
  var depth = 0;
  for (var i = src.indexOf("{", start); i < src.length; i++) {
    if (src[i] === "{") depth++;
    if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  assert(false, "unbalanced " + name);
}

function node(tag) {
  var n = {tag: tag, className: "", textContent: "", children: [], dataset: {}, attrs: {}, hidden: false, disabled: false, value: "", checked: false};
  n.appendChild = function (c) { n.children.push(c); return c; };
  n.scrollIntoView = function () { n.scrolled = true; };
  Object.defineProperty(n, "firstChild", {get: function () { return n.children[0] || null; }});
  n.removeChild = function (c) { n.children.splice(n.children.indexOf(c), 1); };
  return n;
}
function text(n) {
  return n.textContent + n.children.map(text).join(" ");
}

var els = {};
["bl-body", "bl-status", "blast", "ed-yaml", "ed-inject", "ed-sha", "review", "rv-title", "rv-body", "rv-confirm"].forEach(function (id) { els[id] = node("x"); });
els["review"].hidden = true;
els["rv-confirm"].focus = function () { els["rv-confirm"].focused = true; };
// The panel sits in a closed fold on the real page (#580).
var fold = {tagName: "DETAILS", open: false, parentNode: null};
els["blast"].parentNode = fold;
els["ed-yaml"].value = "mode: inject\n";
var calls = [];
var replies = [];
var status = [];
var context = {
  document: {createElement: node, createTextNode: function (t) { var n = node("#text"); n.textContent = t; return n; }, getElementById: function (id) { return els[id]; }},
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + err.message; },
  describe: function () { return ""; },
  edStatus: function (m) { status.push(m); },
  savedMessage: function () { return "saved"; },
  refreshUnsaved: function () {},
  previewConfig: function () {},
  base: "base1",
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    return replies.shift();
  }
};
vm.createContext(context);

var ui = fs.readFileSync(path.join(__dirname, "web", "ui.js"), "utf8");
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
["el", "clear"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext("var blastToken = ''; var maxListedChanges = 8;", context);
["showTarget", "blastRoute", "blastShift", "renderBlast", "loadBlast", "previewCandidate", "putConfig", "changeValue", "changeList", "closeReview", "reviewCandidate"].forEach(function (n) {
  vm.runInContext(fn(settings, n), context);
});

var report = {
  at: "2026-01-02T03:04:05Z", announces: true, keep: 2, changes: true,
  add: [{prefix: "198.51.100.0/24", from: "transit-a", to: "transit-b", volume_mbps: 12.5}],
  move: [{prefix: "203.0.113.0/24", from: "transit-b", to: "transit-c"}],
  withdraw: [],
  providers: [{provider: "transit-b", in_mbps: 12.5, out_mbps: 0, unknown: 1, current_mbps: 80, projected_mbps: 92.5, capacity_mbps: 100}],
  warnings: [{code: "capacity", message: "transit-b would carry about 92.5 Mbps out, over its limit of 90.0 Mbps"},
    {code: "stale", message: "3 allowlisted prefixes lack a recent successful measurement", prefixes: ["192.0.2.0/24"], count: 3}]
};

context.renderBlast(report);
var body = text(els["bl-body"]);
assert(body.indexOf("Would be announced (1)") >= 0 && body.indexOf("198.51.100.0/24: transit-a -> transit-b (12.5 Mbps)") >= 0, "added route: " + body);
assert(body.indexOf("Would move (1)") >= 0 && body.indexOf("203.0.113.0/24: transit-b -> transit-c (volume unknown)") >= 0, "an unknown volume is said so: " + body);
assert(body.indexOf("Would be withdrawn (0)") >= 0, "empty withdraw list: " + body);
assert(body.indexOf("2 announced routes stay") >= 0, "kept routes counted: " + body);
assert(body.indexOf("transit-b: +12.5 Mbps in, -0.0 Mbps out (at least; 1 without a volume). Now 80.0, after 92.5 of 100.0 Mbps capacity") >= 0, "provider shift: " + body);
assert(body.indexOf("Warnings (2)") >= 0 && body.indexOf("over its limit of 90.0 Mbps") >= 0 && body.indexOf("192.0.2.0/24 and more") >= 0, "warnings: " + body);

// A synthesized sub-range (#122) says it is not in the learned RIB.
var synth = JSON.parse(JSON.stringify(report));
synth.add = [{prefix: "198.51.100.0/25", from: "transit-a", to: "transit-b", covering: "198.51.100.0/24"}];
context.renderBlast(synth);
body = text(els["bl-body"]);
assert(body.indexOf("198.51.100.0/25: transit-a -> transit-b (volume unknown) SYNTHESIZED inside 198.51.100.0/24, not in the learned RIB") >= 0, "synthesized route: " + body);

// An idle backup taking traffic and a provider that all traffic leaves:
// a zero rate must render, and a missing rate renders as 0.
var idle = JSON.parse(JSON.stringify(report));
idle.providers = [
  {provider: "transit-c", in_mbps: 25, out_mbps: 0, unknown: 0, current_mbps: 0, projected_mbps: 25, capacity_mbps: 1000},
  {provider: "transit-a", in_mbps: 0, out_mbps: 40, unknown: 0, current_mbps: 40, capacity_mbps: 1000}
];
context.renderBlast(idle);
body = text(els["bl-body"]);
assert(body.indexOf("transit-c: +25.0 Mbps in, -0.0 Mbps out. Now 0.0, after 25.0 of 1000.0 Mbps capacity") >= 0, "idle provider: " + body);
assert(body.indexOf("transit-a: +0.0 Mbps in, -40.0 Mbps out. Now 40.0, after 0.0 of 1000.0 Mbps capacity") >= 0, "drained provider: " + body);

var observe = JSON.parse(JSON.stringify(report));
observe.announces = false;
context.renderBlast(observe);
assert(text(els["bl-body"]).indexOf("every route announced now would be withdrawn") >= 0, "a config that does not announce says so");
var calm = JSON.parse(JSON.stringify(report));
calm.warnings = [];
calm.providers = [];
context.renderBlast(calm);
assert(text(els["bl-body"]).indexOf("Warnings (0)") >= 0 && els["bl-body"].children.length > 0, "no warnings is said");

replies.push(Promise.resolve({available: true, report: report}));
context.loadBlast().then(function () {
  assert(calls[0].method === "GET" && calls[0].url === "/api/blast", "load call: " + JSON.stringify(calls[0]));
  assert(els["bl-status"].textContent === "As of 2026-01-02T03:04:05Z.", "status: " + els["bl-status"].textContent);
  replies.push(Promise.resolve({available: false}));
  return context.loadBlast();
}).then(function () {
  assert(els["bl-status"].textContent.indexOf("not available") >= 0, "unavailable: " + els["bl-status"].textContent);
  var err = new Error("no decision round has run yet");
  err.data = {code: "no_round"};
  replies.push(Promise.reject(err));
  return context.loadBlast();
}).then(function () {
  assert(els["bl-status"].textContent === "explained: no decision round has run yet", "no round: " + els["bl-status"].textContent);

  // A save the server wants previewed: the first PUT is refused with
  // preview_required, the page asks for the dry run and opens the review
  // dialog, and the dialog's confirm sends the token with dry_run false.
  calls.length = 0;
  var need = new Error("this change can alter what is announced");
  need.data = {code: "preview_required"};
  replies.push(Promise.reject(need));
  replies.push(Promise.resolve({dry_run: true, required: true, preview_token: "tok1", blast: report,
    result: {changes: [{key: "hold_time", old: "1m", new: "2m"}]}}));
  context.putConfig();
  return new Promise(function (r) { setTimeout(r, 20); });
}).then(function () {
  assert(calls.length === 2, "save then dry run: " + JSON.stringify(calls));
  assert(calls[0].method === "PUT" && calls[0].body.dry_run === undefined && calls[0].body.preview_token === undefined, "the first save has no token: " + JSON.stringify(calls[0].body));
  assert(calls[1].method === "PUT" && calls[1].body.dry_run === true && calls[1].body.base === "base1" && calls[1].body.yaml === "mode: inject\n", "dry run body: " + JSON.stringify(calls[1].body));
  assert(els["review"].hidden === false && els["rv-confirm"].focused === true, "the review dialog is open on its confirm button");
  assert(els["rv-title"].textContent === "Review and save hold_time 1m -> 2m", "title names the change: " + els["rv-title"].textContent);
  assert(text(els["rv-body"]).indexOf("Would be announced (1)") >= 0, "the preview is in the dialog: " + text(els["rv-body"]));
  var many = [];
  for (var k = 0; k < 10; k++) many.push({key: "k" + k, old: null, new: "v"});
  var listed = context.changeList(many);
  assert(listed.length === 9 && listed[0] === "k0 (unset) -> v" && listed[8] === "and 2 more", "long change lists are cut: " + listed);
  assert(status[status.length - 1].indexOf("Nothing is saved yet") >= 0, "the bar says nothing is saved: " + status[status.length - 1]);

  calls.length = 0;
  status.length = 0;
  replies.push(Promise.resolve({file: {sha256: "base2"}, result: {}}));
  context.putConfig();
  return new Promise(function (r) { setTimeout(r, 20); });
}).then(function () {
  var b = calls[0].body;
  assert(b.dry_run === false && b.preview_token === "tok1", "confirm sends the token with dry_run false: " + JSON.stringify(b));
  assert(els["review"].hidden === true && context.blastToken === "", "the token is spent and the dialog closes");
  assert(status.length === 1 && status[0] === "saved", "success is reported once the file is written: " + status);

  // A refused save does not claim success and closes the dialog.
  els["review"].hidden = false;
  calls.length = 0;
  status.length = 0;
  var stale = new Error("the file changed since it was loaded");
  replies.push(Promise.reject(stale));
  context.putConfig();
  return new Promise(function (r) { setTimeout(r, 20); });
}).then(function () {
  assert(els["review"].hidden === true, "a refused save closes the dialog");
  assert(status.length === 1 && status[0] === "the file changed since it was loaded" && status[0].indexOf("Saved") < 0, "refusal is shown, not a Saved: " + status);

  // A dry run that fails (no round yet) saves nothing and opens no dialog.
  status.length = 0;
  var noRound = new Error("no decision round has run yet");
  noRound.data = {code: "no_round"};
  replies.push(Promise.reject(noRound));
  return context.reviewCandidate();
}).then(function () {
  assert(els["review"].hidden === true && context.blastToken === "", "no dialog and no token after a failed preview");
  assert(status[0] === "Nothing was saved: explained: no decision round has run yet", "failed preview says nothing was saved: " + status);

  // A dry run that returns no token cannot be confirmed.
  status.length = 0;
  replies.push(Promise.resolve({dry_run: true, required: false, blast: report}));
  return context.reviewCandidate();
}).then(function () {
  assert(els["review"].hidden === true && status[0].indexOf("Nothing was saved") === 0, "no token, no dialog: " + status);

  // The guided inject step previews in the panel and keeps the token for Save.
  replies.push(Promise.resolve({dry_run: true, required: true, preview_token: "tok2", blast: report}));
  return context.previewCandidate();
}).then(function () {
  assert(els["review"].hidden === true && context.blastToken === "tok2", "the panel keeps the token and opens no dialog");
  assert(fold.open === true, "a preview opens the closed Blast radius section");
  var bad = new Error("the preview failed");
  fold.open = false;
  replies.push(Promise.reject(bad));
  return context.previewCandidate();
}).then(function () {
  assert(context.blastToken === "" && els["bl-status"].textContent === "explained: the preview failed", "a failed preview: " + els["bl-status"].textContent);
  assert(fold.open === true, "a failed preview opens the closed section too, so its message is seen");
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + (e && e.stack || e));
  process.exit(1);
});
