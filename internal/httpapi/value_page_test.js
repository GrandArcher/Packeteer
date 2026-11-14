"use strict";
// Runs the value page (#588) against a small DOM stand-in. The functions are
// cut out of web/value.js, web/charts.js, and web/app.js, so the test runs
// what ships. Run by TestValuePage, which passes the JSON that
// /api/reports/value returned for a seeded history as argv[2].

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
  this.attrs = {};
  this.text = "";
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Object.defineProperty(Node.prototype, "firstChild", { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this.text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this.text = String(v); this.children = []; }
});
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = v; };

function walk(n, out) {
  out = out || [];
  out.push(n);
  n.children.forEach(function (c) { walk(c, out); });
  return out;
}
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }
function classOf(n) { return n.className || n.attrs["class"] || ""; }
function withClass(root, cls) { return walk(root).filter(function (n) { return (" " + classOf(n) + " ").indexOf(" " + cls + " ") >= 0; }); }

var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createElementNS: function (ns, t) { return new Node(t); },
    createTextNode: function (s) { var n = new Node("#text"); n.text = s; return n; }
  },
  Date: Date, Math: Math, Number: Number, String: String, Object: Object, Infinity: Infinity
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
function varLine(src, name) {
  var m = new RegExp("^var " + name + " = [^;]*;$", "m").exec(src);
  assert(m, "var " + name + " not found");
  return m[0];
}

var web = path.join(__dirname, "web");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var charts = fs.readFileSync(path.join(web, "charts.js"), "utf8");
var value = fs.readFileSync(path.join(web, "value.js"), "utf8");
["SVG_NS", "DAY_MS"].forEach(function (n) { vm.runInContext(varLine(charts, n), context); });
["VALUE_BASES", "VALUE_TITLES"].forEach(function (n) { vm.runInContext(varLine(value, n), context); });
[[app, "el"], [app, "clear"], [charts, "svgEl"], [charts, "tsDay"], [charts, "tsLabel"], [charts, "tsTicks"], [charts, "tsChart"], [charts, "plural"],
  [value, "valueRows"], [value, "valueNum"], [value, "valueChange"], [value, "valueLatency"], [value, "valueBeforeAfter"], [value, "valueLead"], [value, "valueTile"],
  [value, "valueTotals"], [value, "valueProviders"], [value, "valueDays"], [value, "valueSavings"], [value, "renderValue"],
  [value, "valueDownText"], [value, "valueDownMap"]
].forEach(function (p) { vm.runInContext(fn(p[0], p[1]), context); });

function render(data, ctx) {
  var root = new Node("div");
  context.renderValue(root, data, ctx);
  return root;
}
function headings(root) { return find(root, "h2").map(function (n) { return n.textContent; }); }
function providerRow(root, basis, name) {
  var sec = withClass(root, "value-" + basis)[0];
  assert(sec, "no " + basis + " section");
  var rows = find(sec, "tr").filter(function (tr) { return find(tr, "td")[0] && find(tr, "td")[0].textContent.indexOf(name) === 0; });
  assert(rows.length === 1, basis + " row for " + name + ": " + rows.length);
  return rows[0];
}
function cells(tr) { return find(tr, "td").map(function (n) { return n.textContent; }); }

var tot = function (basis, o) {
  return Object.assign({scope: "total", basis: basis, improvements: 1, measured: 1, steered_hours: 2, weighting: "equal", volume_mbps: 0}, o);
};
var prov = function (basis, name, o) { return Object.assign(tot(basis, o), {scope: "provider", provider: name}); };
var day = function (basis, d, o) { return Object.assign(tot(basis, o), {scope: "day", day: d}); };
var gain = {before_loss_pct: 8, after_loss_pct: 0, loss_avoided_pct: 8, before_rtt_ms: 120, after_rtt_ms: 40, rtt_avoided_ms: 80};
var span = {from: "2026-11-01T00:00:00Z", to: "2026-11-08T00:00:00Z"};

// ---- observe: recommended, never announced ----
var observe = render(Object.assign({rows: [tot("estimate", gain), prov("estimate", "lab-b", gain), day("estimate", "2026-11-05", gain)]}, span));
var text = observe.textContent;
assert(headings(observe).join("|") === "Recommended (estimate)", "observe headings: " + headings(observe));
assert(text.indexOf("Packeteer recommended 1 move and announced none of them") >= 0, "observe lead: " + text);
assert(text.indexOf("Traffic did not change path") >= 0 && text.indexOf("estimate of what the moves would have avoided") >= 0, "observe says nothing moved");
assert(text.indexOf("Packeteer announced") < 0 && text.indexOf("Announced") < 0, "observe never says announced");
assert(text.indexOf("loss 8 points lower and latency 80 ms lower") >= 0, "observe figures: " + text);
assert(find(observe, "svg").length === 2, "observe draws the loss and latency charts");
assert(text.indexOf("Dashed: the native path") >= 0 && text.indexOf("Solid: the recommended path") >= 0, "observe legend");
assert(text.indexOf("Recommended (h)") >= 0 && text.indexOf("Steered (h)") < 0, "observe hours column");

// ---- inject: announced, no estimate wording ----
var inject = render(Object.assign({rows: [tot("announced", gain), prov("announced", "lab-b", gain), day("announced", "2026-11-05", gain)]}, span));
text = inject.textContent;
assert(headings(inject).join("|") === "Announced", "inject headings: " + headings(inject));
assert(text.indexOf("Packeteer announced 1 move in this range.") >= 0, "inject lead: " + text);
assert(text.indexOf("estimate") < 0 && text.indexOf("recommended") < 0 && text.indexOf("Recommended") < 0, "inject has no estimate wording: " + text);
assert(text.indexOf("Steered (h)") >= 0 && text.indexOf("Solid: the chosen path") >= 0, "inject hours and legend");

// ---- both bases stay apart, announced first ----
var both = render(Object.assign({rows: [tot("estimate", gain), tot("announced", gain), prov("estimate", "lab-b", gain), prov("announced", "lab-c", gain)]}, span));
assert(headings(both).join("|") === "Announced|Recommended (estimate)", "both headings: " + headings(both));
assert(find(withClass(both, "value-announced")[0], "td").map(function (n) { return n.textContent; }).join("|").indexOf("lab-b") < 0, "lab-b is only in the estimate section");

// ---- the unmeasured and the worse ----
var bare = render({rows: [tot("estimate", {measured: 0}), prov("estimate", "lab-b", {measured: 0})]});
text = bare.textContent;
assert(text.indexOf("None of them has a measurement of both paths, so no gain is shown.") >= 0, "unmeasured lead: " + text);
assert(text.indexOf("not measured") >= 0 && text.indexOf("no change") < 0 && text.indexOf(" 0 points") < 0, "unmeasured is not shown as zero: " + text);
assert(find(bare, "svg").length === 0 && text.indexOf("nothing to chart") >= 0, "no chart without a measured day");
var worse = render({rows: [tot("estimate", {before_loss_pct: 1, after_loss_pct: 3, loss_avoided_pct: -2, before_rtt_ms: 40, after_rtt_ms: 50, rtt_avoided_ms: -10}),
  prov("estimate", "lab-b", {before_loss_pct: 1, after_loss_pct: 3, loss_avoided_pct: -2, before_rtt_ms: 40, after_rtt_ms: 50, rtt_avoided_ms: -10})]});
assert(worse.textContent.indexOf("loss 2 points higher and latency 10 ms higher") >= 0, "worse path says higher: " + worse.textContent);
var noRTT = render({rows: [tot("estimate", {before_loss_pct: 4, after_loss_pct: 100, loss_avoided_pct: -96}), prov("estimate", "lab-b", {before_loss_pct: 4, after_loss_pct: 100, loss_avoided_pct: -96})]});
assert(noRTT.textContent.indexOf("Latency is not compared because a path gave no reply.") >= 0, "no reply is not latency avoided: " + noRTT.textContent);
assert(withClass(noRTT, "tile-v").map(function (n) { return n.textContent; }).indexOf("not compared") >= 0, "latency tile agrees with the lead: " + noRTT.textContent);
assert(cells(providerRow(noRTT, "estimate", "lab-b"))[6] === "not compared", "latency cell agrees with the lead: " + cells(providerRow(noRTT, "estimate", "lab-b")));

// ---- a provider that is down now ----
var downRows = [tot("estimate", gain), prov("estimate", "lab-a", gain), prov("estimate", "lab-b", gain)];
var down = context.valueDownMap({providers: [{name: "lab-a", state: "up"}, {name: "lab-b", state: "down", detail: "100% loss"}, {name: "lab-c", state: "degraded"}]});
assert(JSON.stringify(Object.keys(down)) === '["lab-b"]' && down["lab-b"] === "100% loss", "only a down provider is listed");
var dr = render({rows: downRows}, {down: down});
var rowB = providerRow(dr, "estimate", "lab-b"), rowA = providerRow(dr, "estimate", "lab-a");
assert(classOf(rowB).indexOf("value-provider-down") >= 0 && cells(rowB)[0] === "lab-bdown now", "down row is marked: " + cells(rowB));
assert(cells(rowB)[4] === "8 points lower (earlier moves)" && cells(rowB)[6] === "80 ms lower (earlier moves)", "down row figures are earlier moves: " + cells(rowB));
assert(classOf(rowA).indexOf("value-provider-down") < 0 && cells(rowA)[0] === "lab-a" && cells(rowA)[4] === "8 points lower", "an up provider is plain: " + cells(rowA));
assert(context.valueDownText(down) === "Down now: lab-b (100% loss). The figures for it come from earlier moves; it is not helping now.", "down text: " + context.valueDownText(down));
assert(context.valueDownText({}) === "", "no banner without a down provider");

// ---- estimated cost, as the summary reports it ----
var saved = render({rows: [tot("estimate", gain)]}, {savings: {est_savings_accrued: 12.5, est_savings_rate: 30}});
assert(saved.textContent.indexOf("Estimated cost: savings of 12.5 for the moves active in this range, announced and recommended alike, and 30 per month") >= 0 && saved.textContent.indexOf("accrued") < 0 && saved.textContent.indexOf("not billing") >= 0, "savings: " + saved.textContent);
assert(render({rows: [tot("estimate", gain)]}, {savings: {est_savings_accrued: -4, est_savings_rate: 0}}).textContent.indexOf("extra spend of 4 for the moves active") >= 0, "negative savings is extra spend");
var acc = render({rows: [tot("announced", gain)]}, {savings: {est_savings_accrued: 12.5, est_savings_rate: 30}});
assert(acc.textContent.indexOf("savings of 12.5 for the moves active in this range") >= 0 && acc.textContent.indexOf("accrued") < 0, "announced rows do not make the summary figure accrued: " + acc.textContent);
assert(render({rows: [tot("estimate", gain)]}, {savings: {est_savings_accrued: 0, est_savings_rate: 0}}).textContent.indexOf("Estimated cost") < 0, "no savings figure, no cost line");

// ---- nothing in the range ----
var empty = render({rows: []});
assert(empty.textContent.indexOf("No improvements started in this range") >= 0 && find(empty, "table").length === 0 && find(empty, "svg").length === 0, "empty range: " + empty.textContent);

// ---- the real report: the page shows the report's own per-provider figures ----
if (process.argv[2]) {
  var report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  var page = render(report, {});
  var seen = 0;
  report.rows.filter(function (r) { return r.scope === "provider"; }).forEach(function (r) {
    var c = cells(providerRow(page, r.basis, r.provider));
    seen++;
    assert(c[1] === String(r.improvements) && c[2] === String(r.measured), r.provider + " counts: " + c);
    assert(c[4] === context.valueChange(r.loss_avoided_pct, "points"), r.basis + " " + r.provider + " loss avoided: " + c[4]);
    assert(c[6] === context.valueLatency(r), r.basis + " " + r.provider + " latency avoided: " + c[6]);
  });
  assert(seen === 3, "provider rows in the report: " + seen);
  var lab = cells(providerRow(page, "announced", "lab-b"));
  assert(lab[3] === "4 \u2192 0.75 %" && lab[4] === "3.25 points lower" && lab[5] === "72.5 \u2192 52.5 ms" && lab[6] === "20 ms lower", "announced lab-b by hand: " + lab);
  var est = cells(providerRow(page, "estimate", "lab-b"));
  assert(est[4] === "18 points lower" && est[6] === "30 ms lower", "estimate lab-b by hand: " + est);
  assert(headings(page).join("|") === "Announced|Recommended (estimate)", "report headings: " + headings(page));
}
console.log("ok");
