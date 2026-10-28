"use strict";
// Runs the replay section of the settings page script (#204) against a
// small DOM stand-in: the form posts the editor YAML and the chosen window,
// the summary of each side and the prefixes steered differently are listed,
// and an error is explained. The functions are cut out of the real
// settings.js. Run by TestWhatIfPage.

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
  var n = {tag: tag, className: "", textContent: "", children: [], dataset: {}, attrs: {}, hidden: false, value: ""};
  n.appendChild = function (c) { n.children.push(c); return c; };
  Object.defineProperty(n, "firstChild", {get: function () { return n.children[0] || null; }});
  n.removeChild = function (c) { n.children.splice(n.children.indexOf(c), 1); };
  return n;
}
function text(n) {
  return n.textContent + n.children.map(text).join(" ");
}

var els = {};
["wi-body", "wi-status", "wi-window", "wi-run", "ed-yaml"].forEach(function (id) { els[id] = node("x"); });
els["ed-yaml"].value = "thresholds: {min_rtt_delta_ms: 30}\n";
els["wi-window"].value = "6h";
var calls = [];
var replies = [];
var context = {
  document: {createElement: node, createTextNode: function (t) { var n = node("#text"); n.textContent = t; return n; }, getElementById: function (id) { return els[id]; }},
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + (err.data && err.data.code ? err.data.code + ": " : "") + err.message; },
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    return replies.shift();
  }
};
vm.createContext(context);

var ui = fs.readFileSync(path.join(__dirname, "web", "ui.js"), "utf8");
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
["el", "clear"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
["signed", "whatIfSummary", "whatIfSteps", "renderWhatIf", "runWhatIf"].forEach(function (n) {
  vm.runInContext(fn(settings, n), context);
});

function summary(over) {
  var s = {improves: 2, switches: 1, retires: 1, prefixes: 2, active: 1, peak_active: 2, max_improvements: 50,
    capped_rounds: 3, capped_prefixes: 1, flaps: 1, quarantines: 0, loss_delta_pct: 16.666, rtt_delta_ms: -0.83,
    weighted: true, unknown_volume: 0, moved_mbps: 120, commit_moves: 1, commit_relief_mbps: 20};
  Object.keys(over || {}).forEach(function (k) { s[k] = over[k]; });
  return s;
}
var result = {
  rounds: 24, from: "2026-10-01T12:00:00Z", to: "2026-10-01T12:11:30Z",
  sides: [{name: "running config", summary: summary()}, {name: "candidate config", summary: summary({improves: 1, weighted: false, unknown_volume: 0})}],
  diff: [{prefix: "203.0.113.0/24", base: ["transit-b", "native"], new: null}],
  diff_omitted: 2
};

context.renderWhatIf(result);
var body = text(els["wi-body"]);
assert(body.indexOf("running config") >= 0 && body.indexOf("candidate config") >= 0, "both sides are named: " + body);
assert(body.indexOf("2 new, 1 switched, 1 retired; 2 prefixes steered, 1 active at the end (peak 2, cap 50)") >= 0, "move counts: " + body);
assert(body.indexOf("Expected change (weighted by traffic, positive is better): loss +16.67 points, RTT -0.8 ms") >= 0, "weighted change: " + body);
assert(body.indexOf("Expected change (mean per move, positive is better)") >= 0, "an unweighted side says so: " + body);
assert(body.indexOf("commit relief 20.0 Mbps in 1 moves") >= 0 && body.indexOf("held back by the cap: 1 prefixes in 3 rounds") >= 0, "commit relief and cap pressure: " + body);
assert(body.indexOf("Prefixes steered differently (3)") >= 0, "diff count includes the omitted: " + body);
assert(body.indexOf("203.0.113.0/24: running transit-b > native; editor no move") >= 0 && body.indexOf("and 2 more") >= 0, "diff entry: " + body);

var one = JSON.parse(JSON.stringify(result));
one.sides = one.sides.slice(0, 1);
one.diff = [];
context.renderWhatIf(one);
body = text(els["wi-body"]);
assert(body.indexOf("steered differently") < 0, "one side has no diff section: " + body);

var same = JSON.parse(JSON.stringify(result));
same.diff = [];
same.diff_omitted = 0;
context.renderWhatIf(same);
assert(text(els["wi-body"]).indexOf("makes the same moves as the running config") >= 0, "an empty diff is said");

replies.push(Promise.resolve(result));
context.runWhatIf().then(function () {
  assert(calls[0].method === "POST" && calls[0].url === "/api/whatif", "call: " + JSON.stringify(calls[0]));
  assert(calls[0].body.yaml === "thresholds: {min_rtt_delta_ms: 30}\n" && calls[0].body.from === "6h", "body: " + JSON.stringify(calls[0].body));
  assert(els["wi-status"].textContent === "Replayed 24 rounds from 2026-10-01T12:00:00Z to 2026-10-01T12:11:30Z. Nothing was announced.", "status: " + els["wi-status"].textContent);
  assert(text(els["wi-body"]).indexOf("candidate config") >= 0, "result shown");
  var err = new Error("no decision rounds are stored for that window");
  err.data = {code: "no_rounds"};
  replies.push(Promise.reject(err));
  return context.runWhatIf();
}).then(function () {
  assert(els["wi-status"].textContent === "explained: no_rounds: no decision rounds are stored for that window", "error: " + els["wi-status"].textContent);
  assert(els["wi-body"].children.length === 0, "a failed replay clears the old result");
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + (e && e.stack || e));
  process.exit(1);
});
