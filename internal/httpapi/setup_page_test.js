"use strict";
// Runs the Overview checklist's complete and incomplete states (app.js
// renderSetup) and the Settings host policy routing panel (settings.js,
// #582) against a small DOM stand-in. The functions are cut out of the real
// page scripts. Run by TestSetupPage.

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
  this.dataset = {};
  this.text = "";
  this.hidden = false;
  this.disabled = false;
  this.checked = false;
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Object.defineProperty(Node.prototype, "firstChild", { get: function () { return this.children[0] || null; } });
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this.text + this.children.map(function (c) { return c.textContent; }).join(""); },
  set: function (v) { this.text = String(v); this.children = []; }
});
Node.prototype.setAttribute = function (k, v) { this.attrs[k] = v; };
function walk(n, out) { out = out || []; out.push(n); n.children.forEach(function (c) { walk(c, out); }); return out; }
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }

var ids = {};
var calls = [];
var replies = [];
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    createTextNode: function (s) { var n = new Node("#text"); n.text = s; return n; },
    getElementById: function (id) { return ids[id] || (ids[id] = new Node("div")); }
  },
  byId: function (id) { return ids[id] || (ids[id] = new Node("div")); },
  explain: function (err) { return "explained: " + err.message; },
  runPreflight: function () { calls.push({method: "RUN", url: "preflight"}); return Promise.resolve(); },
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    var r = replies.shift();
    return r.err ? Promise.reject(r.err) : Promise.resolve(r.ok);
  },
  shellAdmin: true,
  Promise: Promise
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
var settings = fs.readFileSync(path.join(web, "settings.js"), "utf8");
["el", "clear", "renderSetup"].forEach(function (n) { vm.runInContext(fn(app, n), context); });
vm.runInContext('var pbrToken = "";', context);
["renderPbrPaths", "renderPbrPlan", "showPbr", "applyPbr", "pbrConfirmChanged"].forEach(function (n) { vm.runInContext(fn(settings, n), context); });

function checklist(o) {
  ids["setup"] = new Node("div");
  context.renderSetup(o);
  return ids["setup"];
}
function state(box) {
  var s = walk(box).filter(function (n) { return n.attrs["data-setup"]; });
  return s.length ? s[0] : null;
}

// Complete in observe: the checklist says so, and that nothing is announced.
var up = {mode: "observe", setup_complete: true, bgp: {configured: true, established: 1, peers: 1, learned: 3}, setup: []};
var box = checklist(up);
var st = state(box);
assert(st && st.attrs["data-setup"] === "complete", "complete state shown with no hints left");
assert(st.textContent.indexOf("Setup complete, still observe.") === 0 && st.textContent.indexOf("Nothing is announced.") > 0, "observe wording: " + st.textContent);
assert(find(box, "a").length === 0, "no policy routing link once complete");

// With another mode the wording does not claim observe.
var inj = checklist({mode: "inject", setup_complete: true, bgp: {configured: true}, setup: []});
assert(state(inj).textContent.indexOf("still observe") < 0 && state(inj).textContent.indexOf("Nothing is announced") < 0, "inject wording: " + state(inj).textContent);

// Incomplete (a session is down): the state says so and links to the panel for an admin.
var down = checklist({mode: "observe", setup_complete: false, bgp: {configured: true, established: 0, peers: 1}, setup: [{id: "bgp-down", level: "warn", title: "t", detail: "d"}]});
st = state(down);
assert(st && st.attrs["data-setup"] === "incomplete" && st.textContent.indexOf("Setup complete") < 0, "incomplete state: " + (st && st.textContent));
var link = find(st, "a")[0];
assert(link && link.href === "/settings.html#pbr", "admin gets the policy routing link");
context.shellAdmin = false;
assert(find(state(checklist({mode: "observe", setup_complete: false, bgp: {configured: true}, setup: [{id: "x", level: "info", title: "t", detail: "d"}]})), "a").length === 0, "a lower role gets no link");
context.shellAdmin = true;

// No BGP, no hints, not complete: nothing to show.
assert(checklist({mode: "observe", setup_complete: false, bgp: {configured: false}, setup: []}).children.length === 0, "an empty checklist stays empty");

// The panel: show plan changes nothing and gates Apply behind the checkbox.
var plan = {token: "t1", lines: [{command: "ip route replace default via 192.0.2.1 table 1001"}, {command: "ip rule del from 192.0.2.12 lookup 1002 priority 2002", remove: true}],
  paths: [{provider: "transit-a", source_ip: "192.0.2.11", next_hop: "192.0.2.1", ok: false, detail: "leaves as \"x\""}]};
replies.push({ok: plan});
context.showPbr().then(function () {
  assert(calls.length === 1 && calls[0].method === "GET" && calls[0].url === "/api/pbr", "show plan is a GET: " + JSON.stringify(calls));
  assert(ids["pbr-lines"].hidden === false && ids["pbr-lines"].textContent === "+ ip route replace default via 192.0.2.1 table 1001\n- ip rule del from 192.0.2.12 lookup 1002 priority 2002", "lines: " + ids["pbr-lines"].textContent);
  assert(ids["pbr-confirm-row"].hidden === false && ids["pbr-apply"].disabled === true, "apply waits for the checkbox");
  assert(ids["pbr-status"].textContent.indexOf("Nothing was changed. 2 commands would run.") === 0, "status: " + ids["pbr-status"].textContent);
  var rows = ids["pbr-paths"].children;
  assert(rows.length === 1 && rows[0].className === "pf-item pf-fail" && rows[0].textContent.indexOf("should leave through 192.0.2.1") > 0, "wrong path row: " + rows[0].textContent);
  // Apply without the checkbox sends nothing.
  return context.applyPbr();
}).then(function () {
  assert(calls.length === 1, "apply without a confirm posted: " + JSON.stringify(calls));
  ids["pbr-confirm"].checked = true;
  context.pbrConfirmChanged();
  assert(ids["pbr-apply"].disabled === false, "the checkbox enables apply");
  replies.push({ok: {applied: 2, verified: true, paths: [{provider: "transit-a", source_ip: "192.0.2.11", next_hop: "192.0.2.1", ok: true}]}});
  return context.applyPbr();
}).then(function () {
  var post = calls[1];
  assert(post.method === "POST" && post.url === "/api/pbr/apply" && post.body.confirm === true && post.body.token === "t1", "apply body: " + JSON.stringify(post));
  assert(ids["pbr-status"].textContent === "Applied 2 commands. Every provider's probes leave through its next hop.", "applied status: " + ids["pbr-status"].textContent);
  assert(ids["pbr-paths"].children[0].className === "pf-item pf-pass" && ids["pbr-confirm-row"].hidden === true, "result row and hidden confirm");
  assert(calls[2].method === "RUN", "the preflight reruns so the Overview sees the egress");

  // The plan changed under the page: nothing ran, the new plan is shown.
  replies.push({ok: plan});
  return context.showPbr();
}).then(function () {
  ids["pbr-confirm"].checked = true;
  context.pbrConfirmChanged();
  var err = new Error("changed");
  err.data = {code: "plan_changed"};
  replies.push({err: err});
  replies.push({ok: {token: "t2", lines: [], paths: []}});
  return context.applyPbr();
}).then(function () {
  assert(ids["pbr-status"].textContent === "The host or the config changed. Nothing was run; review the new plan.", "plan changed status: " + ids["pbr-status"].textContent);
  assert(calls[calls.length - 1].method === "GET" && calls.filter(function (c) { return c.method === "POST"; }).length === 2, "the changed plan was reloaded, not applied: " + JSON.stringify(calls));
  console.log("ok");
});
