"use strict";
// Runs the page warning banners (the synthesize warning, #122, and the
// simulated probes notice, #103) from the real shell.js against a small DOM
// stand-in: the server's text shows under the mode banner as an alert, and
// it hides again when the server stops sending it. Run by
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
vm.runInContext(fn(shell, "shellRenderNotice"), context);
assert(shell.indexOf('shellRenderNotice("synth-banner", ov && ov.synthesize_warning)') >= 0 && shell.indexOf('shellRenderNotice("sim-banner", ov && ov.simulated_probes)') >= 0, "shellRefresh does not render the banners");
var app = fs.readFileSync(path.join(__dirname, "web", "app.js"), "utf8");
assert(app.indexOf('shellRenderNotice("synth-banner", o.synthesize_warning)') >= 0 && app.indexOf('shellRenderNotice("sim-banner", o.simulated_probes)') >= 0, "the dashboard does not render the banners");

context.shellRenderNotice("synth-banner", "");
assert(inserted.length === 0, "banner added with synthesize off");
var warning = "WARNING: synthesize is on. Synthesized more-specifics are NOT in the learned RIB.";
context.shellRenderNotice("synth-banner", warning);
var node = byID["synth-banner"];
assert(node && !node.hidden && node.textContent === warning, "banner text: " + JSON.stringify(node));
assert(node.className === "banner banner-warn" && node.attrs.role === "alert", "banner is not a warning alert: " + node.className);
context.shellRenderNotice("synth-banner", warning);
assert(inserted.length === 1, "banner added twice");
context.shellRenderNotice("synth-banner", undefined);
assert(node.hidden, "banner stays after synthesize is off");

var simText = "SIMULATED PROBES: every probe number here is simulated, not measured.";
context.shellRenderNotice("sim-banner", simText);
var sim = byID["sim-banner"];
assert(sim && sim !== node && !sim.hidden && sim.textContent === simText, "sim banner text: " + JSON.stringify(sim));
assert(sim.className === "banner banner-warn" && sim.attrs.role === "alert", "sim banner is not a warning alert");
assert(node.hidden, "the synthesize banner came back with the sim banner");
context.shellRenderNotice("sim-banner", "");
assert(sim.hidden, "sim banner stays after the notice is gone");
console.log("ok");
