"use strict";
// Runs the "Open in" menu of the Providers table and the table stacking
// rule of shell.js (#580) against a small DOM stand-in. A menu puts every
// link behind one details control; a plain span lists them, as on the prefix
// pages; a table inside #improvements or #providers stacks at medium widths
// while others wait for the phone width. The functions are cut out of the
// real app.js and shell.js. Run by TestLinkoutMenuPage.

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
  var n = {tag: tag, className: "", textContent: "", children: [], attrs: {}};
  n.appendChild = function (c) { n.children.push(c); return c; };
  return n;
}
function find(n, tag) {
  var out = [];
  (function walk(x) {
    if (x.tag === tag) out.push(x);
    x.children.forEach(walk);
  })(n);
  return out;
}

var links = [
  {name: "Tool A", url: "https://tools.example.net/a"},
  {name: "Tool B", url: "https://tools.example.net/b"},
  {name: "Tool C", url: "http://tools.example.net/plain"}
];
var context = {
  document: {createElement: node},
  linkoutCache: {"asn|64496": links},
  linkoutWaiting: {},
  linkoutTimer: null,
  flushLinkouts: function () {},
  setTimeout: function () { return 1; }
};
vm.createContext(context);
var ui = fs.readFileSync(path.join(__dirname, "web", "ui.js"), "utf8");
var app = fs.readFileSync(path.join(__dirname, "web", "app.js"), "utf8");
vm.runInContext(fn(ui, "el"), context);
["linkoutSpan", "fillLinkouts"].forEach(function (n) { vm.runInContext(fn(app, n), context); });

var menu = context.linkoutSpan("asn", 64496, true);
var details = find(menu, "details");
assert(details.length === 1 && details[0].className === "linkout-menu", "one details menu: " + details.length);
assert(find(menu, "summary").length === 1 && find(menu, "summary")[0].textContent === "Open in", "the one control says Open in");
var list = details[0].children.filter(function (c) { return c.className === "linkout-list"; })[0];
assert(list, "a list inside the menu");
var anchors = find(list, "a");
assert(anchors.length === 2 && anchors[0].href === "https://tools.example.net/a" && anchors[1].textContent === "Tool B", "https links only, inside the list: " + anchors.length);
assert(anchors[0].target === "_blank" && anchors[0].rel === "noopener noreferrer", "links open safely");
assert(find(menu, "a").length === anchors.length, "no link outside the menu list");

var plain = context.linkoutSpan("asn", 64496);
assert(find(plain, "details").length === 0, "no menu without the flag");
assert(plain.children.length === 3 && plain.children[0].textContent === "Open in" && plain.children[1].tag === "a", "plain span: label then links");

var empty = context.linkoutSpan("asn", 64497, true);
context.linkoutCache["asn|64497"] = [{name: "Tool A", url: "http://tools.example.net/x"}];
var none = node("span");
none.menu = true;
context.fillLinkouts(none, context.linkoutCache["asn|64497"]);
assert(none.children.length === 0, "a menu with no https link is not drawn");
assert(empty.children.length === 0, "nothing is drawn before the links arrive");

// Stacking: Improvements and Providers use the medium query, others the phone one.
var shell = fs.readFileSync(path.join(__dirname, "web", "shell.js"), "utf8");
var sctx = {shellNarrow: {matches: false}, shellMedium: {matches: true}};
vm.createContext(sctx);
vm.runInContext(fn(shell, "shellStackTable"), sctx);
function table(wide) {
  var cells = [node("td"), node("td")];
  cells.forEach(function (c) {
    c.setAttribute = function (k, v) { c.attrs[k] = v; };
    c.removeAttribute = function (k) { delete c.attrs[k]; };
  });
  var heads = [{textContent: " Cause "}, {textContent: "ASN"}];
  var t = {
    className: "", cls: {},
    classList: {toggle: function (name, on) { t.cls[name] = on; }},
    closest: function (sel) { return sel === ".table-wrap" ? null : (wide && sel.indexOf("#improvements") >= 0 ? {} : null); },
    querySelectorAll: function () { return heads; },
    tBodies: [{rows: [{cells: cells}]}],
    removeAttribute: function () {}
  };
  return {t: t, cells: cells};
}
var imp = table(true);
sctx.shellStackTable(imp.t);
assert(imp.t.cls.stacked === true && imp.cells[0].attrs["data-label"] === "Cause" && imp.cells[1].attrs["data-label"] === "ASN", "a table in #improvements stacks at medium width");
var other = table(false);
sctx.shellStackTable(other.t);
assert(other.t.cls.stacked === false && !other.cells[0].attrs["data-label"], "another table waits for the phone width");
sctx.shellMedium.matches = false;
var wide = table(true);
sctx.shellStackTable(wide.t);
assert(wide.t.cls.stacked === false && !wide.cells[0].attrs["data-label"], "a wide screen shows the plain table");
console.log("ok");
