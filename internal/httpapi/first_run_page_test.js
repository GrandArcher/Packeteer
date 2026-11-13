"use strict";
// Runs the first-run pieces of the page scripts (#416, #575) against a small
// stand-in: the overview shows its setup notice and stays open while setup is
// pending, the sign-in landing goes to the wizard only then, the wizard is
// collapsed behind "Run setup again" only for a configured box whose setup is
// done, and Skip setup posts to /api/setup/skip and hides itself. The
// functions are cut out of the real shell.js, signin.js, and settings.js. Run
// by TestFirstRunPage.

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

var els = {};
["setup-skip", "setup-skip-btn", "wz-status", "setup-pending", "wz-again", "wz-body", "wz-auth-row", "wz-run", "wz-confirm"].forEach(function (id) { els[id] = {hidden: false, disabled: false, textContent: ""}; });
var landed = [];
var meBody = {};
var meOK = true;
var posts = [];
var fail = null;
var context = {
  window: {location: {set href(u) { landed.push(u); }}},
  document: {getElementById: function (id) { return els[id]; }},
  fetch: function () { return meOK ? Promise.resolve({ok: true, json: function () { return Promise.resolve(meBody); }}) : Promise.reject(new Error("down")); },
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
var signin = fs.readFileSync(path.join(__dirname, "web", "signin.js"), "utf8");
vm.runInContext(fn(shell, "shellSetupNotice"), context);
vm.runInContext(fn(signin, "signinLand"), context);
vm.runInContext(fn(settings, "skipSetup"), context);
vm.runInContext(fn(settings, "setWizardConfigured"), context);
vm.runInContext(fn(settings, "applyWizardCollapse"), context);
vm.runInContext("var wzConfigured = false; var wzSetupPending = false;", context);
// The shell must call the notice, and both sign-in paths must use the landing.
assert(fn(shell, "shellApplyMe").indexOf("shellSetupNotice(me)") >= 0, "shellApplyMe does not show the notice");
assert(!/location\.replace|settings\.html#wizard/.test(shell), "the overview must not redirect to the wizard");
assert((signin.match(/signinLand\(\)/g) || []).length >= 3, "sign-in and password change must both land through signinLand");

// The overview shows the notice and nothing else changes while setup is pending.
var notice = context.shellSetupNotice;
notice({user: "admin", setup_pending: true});
assert(els["setup-pending"].hidden === false, "notice shown while pending");
notice({user: "admin"});
assert(els["setup-pending"].hidden === true, "notice hidden once setup is done");
notice(null);
assert(els["setup-pending"].hidden === true, "notice hidden without a session");

// The landing: the wizard (no #wizard hash) while pending, the dashboard otherwise.
var chain = Promise.resolve();
function lands(me, ok, want, msg) {
  chain = chain.then(function () {
    meBody = me;
    meOK = ok;
    landed = [];
    return context.signinLand().then(function () {
      assert(landed.join() === want, msg + ": " + landed);
    });
  });
}
lands({setup_pending: true}, true, "/settings.html", "pending admin lands on the wizard");
lands({user: "admin"}, true, "/", "done setup lands on the dashboard");
lands({}, false, "/", "an unreadable session still lands on the dashboard");

// The wizard body is open for a pending example and collapsed for a finished setup.
function collapse(configured, pending) {
  context.wzSetupPending = pending;
  context.setWizardConfigured(configured);
  return {again: !els["wz-again"].hidden, body: !els["wz-body"].hidden, run: els["wz-run"].textContent};
}
var r = collapse(true, true);
assert(!r.again && r.body && r.run === "Generate observe config", "pending example: wizard open, no Run setup again: " + JSON.stringify(r));
r = collapse(true, false);
assert(r.again && !r.body && r.run === "Generate (replaces your config)", "finished setup: wizard collapsed: " + JSON.stringify(r));
r = collapse(false, false);
assert(!r.again && r.body, "fresh file: wizard open: " + JSON.stringify(r));
// The pending answer can arrive after the file; applying it reopens the wizard.
collapse(true, false);
context.wzSetupPending = true;
context.applyWizardCollapse();
assert(els["wz-again"].hidden && !els["wz-body"].hidden, "pending answer after the file reopens the wizard");

chain.then(function () {
  collapse(true, true);
  return context.skipSetup();
}).then(function () {
  assert(posts.join() === "POST /api/setup/skip", "skip request: " + posts);
  assert(els["setup-skip"].hidden === true, "skip box hidden after skip");
  assert(!els["wz-again"].hidden && els["wz-body"].hidden, "skipping ends the pending state: the wizard collapses on a configured file");
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
