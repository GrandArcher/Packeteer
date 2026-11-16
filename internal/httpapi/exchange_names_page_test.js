"use strict";
// Runs the potential-peers tables of /providers.html and the discovered
// member list of /settings.html (#629) against a small DOM stand-in. The
// functions are cut out of the real page sources, so the test runs what
// ships. Run by TestExchangeNamesPage.

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
Node.prototype.addEventListener = function (k, f) { this.listeners[k] = f; };
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

var byIdNodes = {potential: new Node("div"), "potential-note": new Node("p"), "form-ix-discovered": new Node("div")};
var context = {
  Node: Node, String: String, Number: Number,
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) { return byIdNodes[id]; }
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
function varBlock(src, name) {
  var m = new RegExp("^var " + name + " = [\\s\\S]*?;$", "m").exec(src);
  assert(m, "var " + name + " not found");
  return m[0];
}

var web = path.join(__dirname, "web");
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var ex = fs.readFileSync(path.join(web, "exchanges.js"), "utf8");
var settings = fs.readFileSync(path.join(web, "settings.js"), "utf8");
["el", "clear"].forEach(function (n) { vm.runInContext(fn(app, n), context); });
["VIA_LABELS", "POTENTIAL_GROUPS"].forEach(function (n) { vm.runInContext(varBlock(ex, n), context); });
["exMbps", "exTable", "exCell", "potentialMembers", "renderPotential"].forEach(function (n) { vm.runInContext(fn(ex, n), context); });
vm.runInContext(fn(settings, "byId"), context);
vm.runInContext(fn(settings, "renderDiscovered"), context);

// ---- providers page: potential-peers tables ----
function row(asn, name, via) {
  var r = {asn: asn, class: via, bytes: 1000, mbps: 8, prefixes: 2, lan_prefixes: 1,
    members: [{exchange: "ix-lab", next_hop: "203.0.113.13", via: via}]};
  if (name) r.name = name;
  return r;
}
context.renderPotential([
  {title: "On the route server", rep: {asns: 1, rows: [row(64510, "Lab Network Ten", "route_server")], classes: {}}},
  {title: "Bilateral only", rep: {asns: 1, rows: [row(64511, "", "bilateral")], classes: {}}}
]);
var tables = find(byIdNodes.potential, "table");
assert(tables.length === 2, "two tables, got " + tables.length);
tables.forEach(function (t) {
  var heads = find(t, "th").map(function (h) { return h.textContent; });
  assert(heads.slice(0, 2).join("|") === "AS|Network", "headers: " + heads);
});
var named = find(tables[0], "tbody")[0].children[0].children.map(function (c) { return c.textContent; });
assert(named[0] === "AS64510" && named[1] === "Lab Network Ten", "named row: " + named);
var unnamed = find(tables[1], "tbody")[0].children[0].children.map(function (c) { return c.textContent; });
assert(unnamed[0] === "AS64511" && unnamed[1] === "", "an uncached name leaves the ASN alone: " + unnamed);
assert(unnamed.length === named.length, "same columns with and without a name");

// A name is page text, never markup.
context.renderPotential([{title: "t", rep: {asns: 1, rows: [row(64510, "<b>x</b>", "route_server")], classes: {}}}]);
var cell = find(byIdNodes.potential, "tbody")[0].children[0].children[1];
assert(cell.tag === "td" && cell.textContent === "<b>x</b>" && cell.children.length === 0, "name is text only");

// ---- settings page: discovered members ----
context.runningExchanges = [{name: "ix-lab", discovered: [
  {next_hop: "203.0.113.13", asn: 64510, name: "Lab Network Ten", prefixes: 3},
  {next_hop: "203.0.113.14", asn: 64511, prefixes: 1},
  {next_hop: "203.0.113.15", prefixes: 1}
]}];
context.form = {exchanges: [{name: "ix-lab", peers: []}]};
context.acceptDiscovered = function () {};
context.renderDiscovered();
var rows = byIdNodes["form-ix-discovered"].children.map(function (r) { return r.textContent; });
assert(rows.length === 3, "three members: " + rows);
assert(rows[0] === "ix-lab203.0.113.13AS 64510Lab Network Ten3 prefixesAccept", "named member: " + rows[0]);
assert(rows[1] === "ix-lab203.0.113.14AS 645111 prefixesAccept", "unnamed member shows the AS alone: " + rows[1]);
assert(rows[2] === "ix-lab203.0.113.15AS unknown1 prefixesAccept", "member without an AS: " + rows[2]);

console.log("ok");
