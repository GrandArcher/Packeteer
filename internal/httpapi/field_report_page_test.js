"use strict";
// Runs the field report section of the settings page script (#625) against
// a small DOM stand-in: the preview shows the text from the API before the
// download button exists, the download saves the text that is on the page,
// and a failed read hides both again. Run by TestFieldReportPage.

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

var html = fs.readFileSync(path.join(__dirname, "web", "settings.html"), "utf8");
assert(/id="fr-download"[^>]*hidden/.test(html), "the download button starts hidden");
assert(/id="fr-text"[^>]*hidden/.test(html), "the preview starts hidden");

var els = {};
["fr-text", "fr-download", "fr-status"].forEach(function (id) { els[id] = {textContent: "", hidden: true}; });
var calls = [];
var replies = [];
var saved = [];
var anchor = {click: function () { saved.push({name: anchor.download, blob: anchor.blob}); }};
var context = {
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + err.message; },
  api: function (method, url) {
    calls.push(method + " " + url);
    return replies.shift();
  },
  Blob: function (parts, opts) { this.parts = parts; this.type = opts.type; },
  URL: {createObjectURL: function (b) { anchor.blob = b; return "blob:x"; }, revokeObjectURL: function () {}},
  document: {
    createElement: function () { return anchor; },
    body: {appendChild: function () {}, removeChild: function () {}}
  }
};
vm.createContext(context);
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
vm.runInContext('var fieldReportName = "packeteer-field-report.txt";', context);
["previewFieldReport", "downloadFieldReport"].forEach(function (n) { vm.runInContext(fn(settings, n), context); });

var report = "Packeteer field report\nmode: observe\n";
replies.push(Promise.resolve({filename: "packeteer-field-report.txt", report: report}));
context.previewFieldReport().then(function () {
  assert(calls[0] === "GET /api/report/share", "call: " + calls[0]);
  assert(els["fr-text"].textContent === report && !els["fr-text"].hidden, "the preview shows the text");
  assert(!els["fr-download"].hidden, "download appears after the preview");
  assert(saved.length === 0, "nothing is saved by the preview");
  // The download saves what is on the page, even if the server would answer differently now.
  els["fr-text"].textContent = report + "edited\n";
  context.downloadFieldReport();
  assert(saved.length === 1 && saved[0].name === "packeteer-field-report.txt", "one file is saved: " + JSON.stringify(saved));
  assert(saved[0].blob.parts[0] === report + "edited\n", "the saved text is the one shown");
  replies.push(Promise.reject(new Error("history failed")));
  return context.previewFieldReport();
}).then(function () {
  assert(els["fr-text"].hidden && els["fr-download"].hidden, "a failed read hides the preview and the download");
  assert(els["fr-status"].textContent === "explained: history failed", "error: " + els["fr-status"].textContent);
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + (e && e.stack || e));
  process.exit(1);
});
