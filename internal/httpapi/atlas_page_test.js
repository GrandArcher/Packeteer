"use strict";
// Runs the prefix page RIPE Atlas panel (#213) against a small DOM
// stand-in: hidden while off, the no-key note, the local and Atlas tables,
// the measure buttons and their request, and the refresh while a
// measurement is pending. The functions are cut out of the real page
// sources, so the test runs what ships. Run by TestAtlasPage.

var fs = require("fs");
var path = require("path");
var vm = require("vm");

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
}

function Node(tag) {
  this.tag = tag;
  this.className = "";
  this.children = [];
  this.text = "";
  this.hidden = true;
  this.disabled = false;
  this.handlers = {};
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Node.prototype.addEventListener = function (ev, fn) { this.handlers[ev] = fn; };
Object.defineProperty(Node.prototype, "firstChild", { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this.text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this.text = String(v); this.children = []; }
});

function walk(n, out) {
  out = out || [];
  out.push(n);
  n.children.forEach(function (c) { walk(c, out); });
  return out;
}
function buttons(root) { return walk(root).filter(function (n) { return n.tag === "button"; }); }

var panel = new Node("section");
var body = new Node("div");
var timers = [];
var posts = [];
var postResult = null;
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createTextNode: function (t) { var n = new Node("#text"); n.text = String(t); return n; },
    getElementById: function (id) { return id === "atlas-panel" ? panel : id === "atlas-body" ? body : null; }
  },
  window: { addEventListener: function () {} },
  setTimeout: function (fn, ms) { timers.push({fn: fn, ms: ms}); return timers.length; },
  clearTimeout: function (id) { timers[id - 1] = null; },
  postJSON: function (url, req) {
    posts.push({url: url, req: req});
    return postResult;
  },
  getJSON: function () { return new Promise(function () {}); },
  Date: Date, Math: Math, Number: Number, String: String, Promise: Promise, encodeURIComponent: encodeURIComponent
};
vm.createContext(context);

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

var web = path.join(__dirname, "web");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var page = fs.readFileSync(path.join(web, "atlas.js"), "utf8");
[[app, "el"], [app, "clear"], [app, "fmtTime"], [app, "table"],
  [page, "atlasWhat"], [page, "atlasResultCells"], [page, "renderAtlas"], [page, "loadAtlas"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });
vm.runInContext('var thisPrefix = "198.51.100.0/24"; var atlasTimer = null;', context);

function render(data) {
  panel.hidden = true;
  context.renderAtlas(data);
}

// Off: nothing shown.
render({state: "off", measurements: []});
assert(panel.hidden === true && body.children.length === 0, "an off panel is shown or has content");

// Enabled without a key: the note, no tables, no buttons.
render({state: "no_key", measurements: []});
assert(panel.hidden === false, "the no-key panel is hidden");
assert(body.textContent.indexOf("PACKETEER_ATLAS_API_KEY is not set") >= 0, "no-key note missing: " + body.textContent);
assert(buttons(body).length === 0, "no-key panel has buttons");

var data = {
  state: "ok", target: "198.51.100.7", can_measure: true,
  local: [
    {provider: "transit-a", ok: true, loss_pct: 0, rtt_avg_ms: 12.5, confidence: "high"},
    {provider: "transit-b", ok: false, loss_pct: 100, rtt_avg_ms: 0, confidence: "low"}
  ],
  measurements: [
    {id: 2, type: "ping", trigger: "after_move", provider: "transit-b", created: "2026-01-02T11:30:00Z", requested: 4, state: "done",
     summary: {answered: 4, reached: 4, median_rtt_ms: 11.25, loss_pct: 0}},
    {id: 1, type: "traceroute", trigger: "manual", created: "2026-01-02T11:00:00Z", requested: 3, state: "pending"}
  ],
  status: {credits_today: 42, max_credits_per_day: 500, measurements_last_hour: 2, max_measurements_per_hour: 4, balance: 777}
};
render(data);
var text = body.textContent;
[
  "Local measurements (test address 198.51.100.7)", "transit-a", "12.5 ms", "high", "transit-b", "low",
  "ping, after move to transit-b", "4 of 4 reached", "11.3 ms", "0 %", "traceroute, on demand", "waiting", "pending",
  "Credits used today: 42 of 500", "Measurements in the last hour: 2 of 4", "Balance: 777 credits."
].forEach(function (want) { assert(text.indexOf(want) >= 0, "missing " + want + " in: " + text); });
assert(panel.hidden === false, "the panel stays hidden");
assert(timers.filter(Boolean).length === 1 && timers[0].ms === 20000, "a pending measurement does not schedule a refresh");

// Buttons post the prefix and type; a refusal shows its text and re-enables.
var btns = buttons(body);
assert(btns.length === 2 && btns[0].textContent === "Measure with ping" && btns[1].textContent === "Measure with traceroute", "measure buttons: " + btns.length);
postResult = Promise.reject(new Error("the daily credit cap is reached"));
btns[1].handlers.click();
assert(posts.length === 1 && posts[0].url === "/api/atlas/measure" && posts[0].req.prefix === "198.51.100.0/24" && posts[0].req.type === "traceroute", "post: " + JSON.stringify(posts));
assert(btns[1].disabled === true, "the button is not disabled while the request runs");
setImmediate(function () {
  assert(btns[1].disabled === false, "the button stays disabled after a refusal");
  assert(body.textContent.indexOf("the daily credit cap is reached") >= 0, "the refusal text is not shown");

  // Without can_measure there are no buttons, and nothing pending means no refresh.
  timers.length = 0;
  data.can_measure = false;
  data.measurements = data.measurements.slice(0, 1);
  render(data);
  assert(buttons(body).length === 0, "buttons without can_measure");
  assert(timers.filter(Boolean).length === 0, "a refresh is scheduled with nothing pending");
  console.log("ok");
});
