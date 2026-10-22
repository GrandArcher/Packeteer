"use strict";
// Runs the preflight section of the settings page script (#221) against a
// small DOM stand-in: each check shows its status, what was found, and the
// fix; an unverified check offers Confirm; the inject step appears only
// when every check passed and posts the editor text and the prefixes. The
// functions are cut out of the real settings.js. Run by TestPreflightPage.

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
  var n = {tag: tag, className: "", textContent: "", children: [], dataset: {}, attrs: {}, listeners: {}, hidden: false, disabled: false, value: ""};
  n.appendChild = function (c) { n.children.push(c); return c; };
  n.setAttribute = function (k, v) { n.attrs[k] = v; };
  n.addEventListener = function (ev, f) { n.listeners[ev] = f; };
  n.scrollIntoView = function () { n.scrolled = true; };
  Object.defineProperty(n, "firstChild", {get: function () { return n.children[0] || null; }});
  n.removeChild = function (c) { n.children.splice(n.children.indexOf(c), 1); };
  return n;
}
function text(n) {
  return n.textContent + n.children.map(text).join("");
}

var els = {};
["pf-list", "pf-when", "pf-inject", "pf-run", "pf-vendor", "pf-allow", "pf-allow-err", "pf-cap", "pf-inject-status", "pf-explain", "ed-yaml", "editor-section", "pf-snippet", "pf-snippet-status"].forEach(function (id) { els[id] = node("x"); });
els["pf-inject"].hidden = true;
var calls = [];
var reply = null;
var loaded = [];
var checked = 0;
var context = {
  document: {createElement: node, createTextNode: function (t) { var n = node("#text"); n.textContent = t; return n; }},
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + err.message; },
  splitList: function (t) { return t.split(/[\s,]+/).filter(Boolean); },
  loadForm: function (y) { loaded.push(y); },
  checkConfig: function () { checked++; },
  Number: Number,
  encodeURIComponent: encodeURIComponent,
  Promise: Promise,
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    return reply.then ? reply : reply();
  }
};
vm.createContext(context);

var ui = fs.readFileSync(path.join(__dirname, "web", "ui.js"), "utf8");
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
["el", "clear"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext(settings.slice(settings.indexOf("var pfLabels"), settings.indexOf("var pfBadge")), context);
vm.runInContext(settings.slice(settings.indexOf("var pfBadge"), settings.indexOf("function pfSummary")), context);
["pfSummary", "pfItem", "renderPreflight", "loadPreflight", "runPreflight", "confirmCheck", "showSnippet", "planInject"].forEach(function (n) {
  vm.runInContext(fn(settings, n), context);
});

var blocked = {ran_at: "2026-01-02T03:04:05Z", ready: false, results: [
  {id: "bgp_session", title: "BGP session and learned routes", status: "fail", detail: "Not established: 192.0.2.254.", fix: "Add a neighbor on the router."},
  {id: "import_filter", title: "Router filters keep Packeteer routes inside your AS", status: "unverified", confirmable: true, detail: "Cannot test the filters.", fix: "Check both filters, then press Confirm."},
  {id: "probe_egress", title: "Probes leave through the intended provider", status: "pass", detail: "transit-a: ok."},
  {id: "timers", title: "Hold time and graceful restart", status: "warn", detail: "hold time 4m0s.", fix: "Lower it."}
]};

context.renderPreflight(blocked);
var items = els["pf-list"].children;
assert(items.length === 4, "one item per check: " + items.length);
assert(items[0].className === "pf-item pf-fail" && items[0].dataset.check === "bgp_session", "fail item class: " + items[0].className);
assert(text(items[0]).indexOf("Failed") >= 0 && text(items[0]).indexOf("Not established: 192.0.2.254.") >= 0, "fail item text: " + text(items[0]));
assert(text(items[0]).indexOf("What to do: Add a neighbor on the router.") >= 0, "the fix is shown: " + text(items[0]));
assert(text(items[2]).indexOf("What to do") < 0, "a passed check has no fix");
assert(items[0].children[0].children[0].className === "badge sys-down", "badge class: " + items[0].children[0].children[0].className);
assert(els["pf-when"].textContent === "Injection stays off: 2 checks need attention. Last run 2026-01-02T03:04:05Z.", "summary: " + els["pf-when"].textContent);
assert(els["pf-inject"].hidden === true, "the inject step is hidden while a check blocks");
var buttons = items[1].children.filter(function (c) { return c.tag === "button"; });
assert(buttons.length === 1 && buttons[0].textContent === "Confirm" && buttons[0].attrs["aria-label"].indexOf("Router filters") >= 0, "an unverified check offers Confirm");
assert(items.filter(function (i) { return i.children.some(function (c) { return c.tag === "button"; }); }).length === 1, "only the confirmable check has a button");

// Confirm posts the check id and shows the new report.
var ready = JSON.parse(JSON.stringify(blocked));
ready.ready = true;
ready.results[0].status = "pass"; ready.results[1].status = "pass"; ready.results[1].confirmable = false;
reply = Promise.resolve(ready);
buttons[0].listeners.click();
assert(calls.length === 1 && calls[0].method === "POST" && calls[0].url === "/api/preflight/confirm" && calls[0].body.id === "import_filter", "confirm call: " + JSON.stringify(calls));
assert(buttons[0].disabled === true, "the button is disabled while the call runs");

reply.then(function () {
  assert(els["pf-inject"].hidden === false, "the inject step shows when every check passed");
  assert(els["pf-when"].textContent.indexOf("Every check passed. Injection can be turned on below.") === 0, "ready summary: " + els["pf-when"].textContent);

  // An empty allowlist posts nothing.
  calls.length = 0;
  els["pf-allow"].value = "  ";
  return context.planInject();
}).then(function () {
  assert(calls.length === 0 && els["pf-allow-err"].hidden === false, "an empty allowlist is refused on the page");

  els["pf-allow"].value = "198.51.100.0/24\n203.0.113.0/24";
  els["pf-cap"].value = "3";
  els["ed-yaml"].value = "mode: observe\n";
  reply = Promise.resolve({yaml: "mode: inject\n", explain: ["mode changes from observe to inject.", "At most 3 routes."], not_learned: ["203.0.113.0/24"]});
  return context.planInject();
}).then(function () {
  var c = calls[0];
  assert(c.method === "POST" && c.url === "/api/config/inject", "plan call: " + JSON.stringify(c));
  assert(c.body.current === "mode: observe\n" && c.body.allowlist.join() === "198.51.100.0/24,203.0.113.0/24" && c.body.max_improvements === 3, "plan body: " + JSON.stringify(c.body));
  assert(els["ed-yaml"].value === "mode: inject\n" && loaded[0] === "mode: inject\n" && checked === 1, "the editor holds the plan");
  assert(els["pf-explain"].children.length === 2, "the explanation is listed");
  assert(els["pf-inject-status"].textContent.indexOf("203.0.113.0/24") >= 0 && els["pf-inject-status"].textContent.indexOf("would not be announced") >= 0, "unlearned prefix warning: " + els["pf-inject-status"].textContent);

  // A check that stopped passing in the meantime is shown again.
  var err = new Error("the preflight checks have not passed");
  err.data = {code: "preflight_required", preflight: blocked};
  reply = Promise.reject(err);
  return context.planInject();
}).then(function () {
  assert(els["pf-inject-status"].textContent.indexOf("A check no longer passes. Injection stays off: 2 checks need attention.") === 0, "refusal text: " + els["pf-inject-status"].textContent);
  assert(els["pf-list"].children.length === 4 && els["pf-inject"].hidden === true, "the blocked report replaces the list");

  // Not available: the Run button is off.
  reply = Promise.resolve({available: false});
  return context.loadPreflight();
}).then(function () {
  assert(els["pf-run"].disabled === true && els["pf-when"].textContent.indexOf("not available") >= 0, "unavailable page");

  // Never run: the page says so and fills the router list.
  reply = Promise.resolve({available: true, vendors: ["frr", "bird"]});
  return context.loadPreflight();
}).then(function () {
  assert(els["pf-when"].textContent === "The checks have not run yet." && els["pf-vendor"].children.length === 2, "never run: " + els["pf-when"].textContent);

  // The router config is requested for the chosen vendor.
  els["pf-vendor"].value = "bird";
  reply = Promise.resolve({vendor: "bird", text: "filter packeteer_in {}\n"});
  calls.length = 0;
  return context.showSnippet();
}).then(function () {
  assert(calls[0].url === "/api/snippets?vendor=bird" && els["pf-snippet"].textContent === "filter packeteer_in {}\n" && els["pf-snippet"].hidden === false, "snippet call: " + JSON.stringify(calls));
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + (e && e.stack || e));
  process.exit(1);
});
