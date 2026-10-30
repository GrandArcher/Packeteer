"use strict";
// Renders the Registry page (#289) from the JSON the API returned for a
// fixture scan, against a small DOM stand-in, and drives the push control:
// a push needs the confirm click and quotes the digest that was shown, a
// non-admin and a suggest-only finding get no button, and a refused push
// is shown. The page functions are cut out of the real sources. Run by
// TestRegistryPageRendering with the fixture file as argument.

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
  this.listeners = {};
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Node.prototype.addEventListener = function (n, f) { this.listeners[n] = f; };
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
function find(root, tag) { return walk(root).filter(function (n) { return n.tag === tag; }); }
function buttons(root, label) { return find(root, "button").filter(function (b) { return b.textContent === label; }); }
function rowsOf(root) {
  return find(root, "tr").slice(1).map(function (tr) { return tr.children.map(function (td) { return td.textContent; }); });
}

var ids = {"registry-status": new Node("p"), "registry-sections": new Node("div"), "registry-findings": new Node("div")};
var calls = [];
var pushError = null;
var report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) { return ids[id]; }
  },
  Promise: Promise,
  shellAdmin: true,
  fmtTime: function (s) { return "T(" + s + ")"; },
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    if (method === "POST") return pushError ? Promise.reject(new Error(pushError)) : Promise.resolve({pushed: true});
    return Promise.resolve(report);
  }
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
var ui = fs.readFileSync(path.join(web, "ui.js"), "utf8");
var page = fs.readFileSync(path.join(web, "registry.js"), "utf8");
["el", "clear", "ixpTable", "ixpCell"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext("var registryOpen = \"\"; var registryReport = null; var REGISTRY_SEVERITY = {error: \"Error\", warning: \"Warning\", info: \"Info\"};", context);
page.match(/^function (\w+)\(/gm).map(function (m) { return m.slice(9, -1); }).forEach(function (n) {
  if (n !== "startRegistryPage") vm.runInContext(fn(page, n), context);
});

function settle() { return new Promise(function (r) { setTimeout(r, 0); }); }
function status() { return ids["registry-status"].textContent; }
function table() { return ids["registry-findings"]; }

(async function () {
  // The report is sorted error, warning, info, then by kind.
  await context.loadRegistry();
  var rows = rowsOf(table());
  assert(rows.length === report.findings.length && rows.length >= 3, "rows: " + JSON.stringify(rows));
  assert(rows[0][0] === "Error" && rows[rows.length - 1][0] === "Info", "severity order and words: " + JSON.stringify(rows.map(function (r) { return r[0]; })));
  assert(status().indexOf("Pushing is on: each push needs an admin to confirm its diff.") >= 0, "status: " + status());
  assert(ids["registry-sections"].textContent.indexOf("peeringdb") >= 0 && ids["registry-sections"].textContent.indexOf("unreachable") >= 0, "an unreachable part is listed, not read as clean: " + ids["registry-sections"].textContent);
  var diffs = find(table(), "pre");
  assert(diffs.length >= 2 && diffs.some(function (d) { return d.textContent.indexOf("+ info_prefixes4: 4") >= 0; }), "the diff is shown");
  assert(rows.some(function (r) { return r[5].indexOf("Submit this change to the rpki registry yourself.") === 0; }), "suggest-only finding says to submit by hand: " + JSON.stringify(rows));
  assert(buttons(table(), "Review and push").length === 1, "one pushable finding has a button");
  assert(calls.length === 1 && calls[0].method === "GET", "only a read so far");

  // Opening the box posts nothing; the confirm click posts the shown digest.
  buttons(table(), "Review and push")[0].listeners.click();
  assert(calls.length === 1, "opening the box must not push");
  assert(table().textContent.indexOf("Send exactly this change to peeringdb (update_field net 42)?") >= 0, "confirm text: " + table().textContent);
  buttons(table(), "Cancel")[0].listeners.click();
  assert(buttons(table(), "Confirm push").length === 0 && calls.length === 1, "cancel closes the box and posts nothing");
  buttons(table(), "Review and push")[0].listeners.click();
  buttons(table(), "Confirm push")[0].listeners.click();
  await settle();
  var post = calls.filter(function (c) { return c.method === "POST"; });
  var f = report.findings.filter(function (x) { return x.pushable; })[0];
  assert(post.length === 1 && post[0].url === "/api/registry/push" && post[0].body.id === f.id && post[0].body.digest === f.digest && Object.keys(post[0].body).length === 2, "push body: " + JSON.stringify(post));

  // A refused push is shown and the box closes.
  pushError = "the change differs from the one shown; reload the diff";
  buttons(table(), "Review and push")[0].listeners.click();
  buttons(table(), "Confirm push")[0].listeners.click();
  await settle();
  assert(status() === "Push refused or failed: " + pushError, "refusal: " + status());
  assert(buttons(table(), "Confirm push").length === 0, "the box closed after a refusal");

  // A non-admin sees the finding and the diff, no button.
  context.shellAdmin = false;
  context.renderRegistry(report, context.onRegistryPush);
  assert(buttons(table(), "Review and push").length === 0 && table().textContent.indexOf("An admin can push this change.") >= 0, "non-admin: " + table().textContent);

  // Push off: no button, and the status says each change is for the operator.
  context.shellAdmin = true;
  var off = JSON.parse(JSON.stringify(report));
  off.writable = false;
  off.push_enabled = false;
  off.findings.forEach(function (x) { x.pushable = false; delete x.digest; delete x.change; });
  context.renderRegistry(off, context.onRegistryPush);
  assert(buttons(table(), "Review and push").length === 0 && status().indexOf("Read only: pushing is off") >= 0, "push off: " + status());

  // Off and empty states.
  context.renderRegistry({enabled: false, writable: false, sections: [], findings: []}, context.onRegistryPush);
  assert(status() === "Registry hygiene is off. Set registry.enabled in the config." && table().children.length === 0, "off: " + status());
  context.renderRegistry({enabled: true, writable: false, scanned: "2026-10-30T10:00:00Z", sections: [], findings: []}, context.onRegistryPush);
  assert(table().textContent.indexOf("No difference found in the parts that answered.") >= 0, "clean: " + table().textContent);
  console.log("ok");
})();
