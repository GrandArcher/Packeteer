"use strict";
// Runs the first-run pieces of the page scripts (#416) against a small
// stand-in: the overview sends an admin to the wizard only while setup is
// pending, other pages and other users stay put, and Skip setup posts to
// /api/setup/skip and hides itself. The functions are cut out of the real
// shell.js and settings.js. Run by TestFirstRunPage.

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

var page = "overview";
var replaced = [];
var els = {};
["setup-skip", "setup-skip-btn", "wz-status"].forEach(function (id) { els[id] = {hidden: false, disabled: false, textContent: ""}; });
var posts = [];
var fail = null;
var context = {
  window: {location: {replace: function (u) { replaced.push(u); }}},
  document: {body: {getAttribute: function () { return page; }}},
  byId: function (id) { return els[id]; },
  explain: function (err) { return "explained: " + err.message; },
  api: function (method, url) {
    posts.push(method + " " + url);
    return fail ? Promise.reject(new Error(fail)) : Promise.resolve({pending: false});
  }
};
vm.createContext(context);

var shell = fs.readFileSync(path.join(__dirname, "web", "shell.js"), "utf8");
var settings = fs.readFileSync(path.join(__dirname, "web", "settings.js"), "utf8");
vm.runInContext(fn(shell, "shellSetupRedirect"), context);
vm.runInContext(fn(settings, "skipSetup"), context);
// shellApplyMe must call the redirect, or the page never uses it.
assert(fn(shell, "shellApplyMe").indexOf("shellSetupRedirect(me)") >= 0, "shellApplyMe does not redirect");

var redirect = context.shellSetupRedirect;
redirect({user: "admin", setup_pending: true});
assert(replaced.length === 1 && replaced[0] === "/settings.html#wizard", "pending admin on the overview goes to the wizard: " + replaced);
redirect({user: "admin"});
redirect(null);
assert(replaced.length === 1, "no redirect without setup_pending");
page = "settings";
redirect({user: "admin", setup_pending: true});
assert(replaced.length === 1, "no redirect away from other pages");

context.skipSetup().then(function () {
  assert(posts.join() === "POST /api/setup/skip", "skip request: " + posts);
  assert(els["setup-skip"].hidden === true, "skip box hidden after skip");
  assert(/skipped/i.test(els["wz-status"].textContent), "status says skipped: " + els["wz-status"].textContent);
  els["setup-skip"].hidden = false;
  fail = "boom";
  return context.skipSetup();
}).then(function () {
  assert(els["setup-skip"].hidden === false, "skip box stays after a failed skip");
  assert(els["setup-skip-btn"].disabled === false, "button usable again after a failed skip");
  assert(els["wz-status"].textContent === "explained: boom", "failure explained");
  console.log("ok");
});
