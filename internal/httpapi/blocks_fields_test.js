"use strict";
// Runs two helpers of blocks.js (#670) in Node: a block that is switched on
// starts with its enabled switch ticked and every list empty, and a list of
// whole numbers refuses text, a negative number, and a value out of range.
// Run by TestBlocksFieldHelpers.

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

var blocks = fs.readFileSync(path.join(__dirname, "web", "blocks.js"), "utf8");
var context = {Number: Number};
vm.createContext(context);
["blankValues", "intCheck"].forEach(function (n) { vm.runInContext(fn(blocks, n), context); });

var fields = [
  {key: "enabled", kind: "bool", start_on: true},
  {key: "write_tools", kind: "bool"},
  {key: "keep", kind: "bool", default_true: true},
  {key: "asns", kind: "ints"},
  {key: "classes", kind: "list"},
  {key: "sources", kind: "rows"},
  {key: "hub", kind: "group"},
  {key: "retention_days", kind: "int"}
];
var v = context.blankValues(fields);
assert(v.enabled === true, "enabled does not start on");
assert(v.write_tools === false, "write_tools starts on");
assert(v.keep === true, "a default-true switch lost its default");
assert(Array.isArray(v.asns) && v.asns.length === 0, "an ints list does not start empty");
assert(Array.isArray(v.classes) && Array.isArray(v.sources) && v.hub === null && v.retention_days === "", "other kinds changed: " + JSON.stringify(v));

var check = context.intCheck({min: 1, max: 4294967295});
assert(check("64496") === "", "64496 refused");
assert(check("AS64496") !== "", "text accepted");
assert(check("-1") !== "", "negative accepted");
assert(check("0") !== "", "below the minimum accepted");
assert(check("4294967296") !== "", "above the maximum accepted");
assert(/from 1 to 4294967295/.test(check("x")), "the message lacks the bounds: " + check("x"));
assert(context.intCheck({})("7") === "", "a field without bounds refused 7");

console.log("ok");
