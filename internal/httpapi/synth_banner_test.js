"use strict";
// Runs the synthesize banner (#122) from the real shell.js against a small
// DOM stand-in: the server's warning shows under the mode banner as an
// alert, and it hides again when synthesize is off. Run by
// TestSynthesizeBanner.

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

var byID = {};
var inserted = [];
var mode = {id: "banner", parentNode: {insertBefore: function (n) { inserted.push(n); byID[n.id] = n; }}};
byID.banner = mode;
var context = {
  document: {getElementById: function (id) { return byID[id] || null; }},
  shellEl: function (tag, cls, text) {
    return {tag: tag, className: cls, textContent: text, hidden: false, attrs: {}, setAttribute: function (k, v) { this.attrs[k] = v; }};
  }
};
vm.createContext(context);
var shell = fs.readFileSync(path.join(__dirname, "web", "shell.js"), "utf8");
vm.runInContext(fn(shell, "shellRenderSynthBanner"), context);
assert(shell.indexOf("shellRenderSynthBanner(ov && ov.synthesize_warning)") >= 0, "shellRefresh does not render the banner");
var app = fs.readFileSync(path.join(__dirname, "web", "app.js"), "utf8");
assert(app.indexOf("shellRenderSynthBanner(o.synthesize_warning)") >= 0, "the dashboard does not render the banner");

context.shellRenderSynthBanner("");
assert(inserted.length === 0, "banner added with synthesize off");
var warning = "WARNING: synthesize is on. Synthesized more-specifics are NOT in the learned RIB.";
context.shellRenderSynthBanner(warning);
var node = byID["synth-banner"];
assert(node && !node.hidden && node.textContent === warning, "banner text: " + JSON.stringify(node));
assert(node.className === "banner banner-warn" && node.attrs.role === "alert", "banner is not a warning alert: " + node.className);
context.shellRenderSynthBanner(warning);
assert(inserted.length === 1, "banner added twice");
context.shellRenderSynthBanner(undefined);
assert(node.hidden, "banner stays after synthesize is off");
console.log("ok");
