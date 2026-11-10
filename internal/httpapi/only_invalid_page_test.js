"use strict";
// Runs the RPKI-invalid only path UI (#401) against a small DOM stand-in,
// on the JSON the API returned for a fixture case. The prefix page panel
// is read-only: class, score, evidence, ROAs, and a link to the Registry
// page. On the Registry page an operator proposes, the box shows the exact
// entries and digest, only an admin gets the approve and remove buttons,
// and a hijack never gets a propose button. The functions are cut out of
// the real prefix.js, onlyinvalid.js, ui.js, and app.js, so the test runs
// what ships. Run by TestOnlyInvalidPages with the fixture file.

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
function buttons(n, label) { return walk(n).filter(function (x) { return x.tag === "button" && x.text === label; }); }

var data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
var ids = {"only-invalid-body": new Node("section"), "only-invalid-status": new Node("p"),
  "only-invalid-cases": new Node("div"), "only-invalid-exceptions": new Node("div")};
var calls = [];
var proposal = {id: "a01", digest: "d1", kind: "prefix_assertion", prefix: "198.51.100.0/24", origin: 64500,
  state_before: "invalid", state_after: "valid", path: "/var/lib/packeteer/slurm/slurm.json", expires: "2026-11-09T13:00:00Z",
  entries: {slurmVersion: 1, locallyAddedAssertions: {prefixAssertions: [{asn: 64500, prefix: "198.51.100.0/24", maxPrefixLength: 24}]}},
  evidence: {signals: [{name: "irr_route", points: 2}, {name: "origin_stable", points: 2}]}};
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) { return ids[id]; }
  },
  Promise: Promise, JSON: JSON, Date: Date,
  encodeURIComponent: encodeURIComponent,
  shellAdmin: true,
  api: function (method, url, body) {
    calls.push({method: method, url: url, body: body});
    if (url === "/api/rpki/only-invalid/propose") return Promise.resolve(proposal);
    if (method !== "GET") return Promise.resolve({});
    return Promise.resolve(data);
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
var app = fs.readFileSync(path.join(web, "app.js"), "utf8");
var prefix = fs.readFileSync(path.join(web, "prefix.js"), "utf8");
var page = fs.readFileSync(path.join(web, "onlyinvalid.js"), "utf8");
["el", "clear", "ixpTable", "ixpCell"].forEach(function (n) { vm.runInContext(fn(ui, n), context); });
vm.runInContext(fn(app, "fmtTime"), context);
var classes = prefix.slice(prefix.indexOf("var ONLY_INVALID_CLASS"), prefix.indexOf("};", prefix.indexOf("var ONLY_INVALID_CLASS")) + 2);
vm.runInContext(classes, context);
vm.runInContext(fn(prefix, "onlyInvalidView"), context);
vm.runInContext("var oiProposal = null; var oiData = null;", context);
page.match(/^function (\w+)\(/gm).map(function (m) { return m.slice(9, -1); }).forEach(function (n) {
  if (n !== "startOnlyInvalid") vm.runInContext(fn(page, n), context);
});

function settle() { return new Promise(function (r) { setTimeout(r, 0); }); }

(async function () {
  var c = data.cases[0];
  assert(data.enabled && c.prefix === "198.51.100.0/24" && c.class === "stale_roa", "fixture: " + JSON.stringify(data));

  // Prefix page: read-only evidence and a link, never a button.
  var view = context.onlyInvalidView(c, data.slurm);
  var text = view.textContent;
  assert(text.indexOf("Likely a stale ROA or misconfiguration (score " + c.score + ") for AS64500. Contact the holder of 198.51.100.0/24") === 0, "headline: " + text);
  assert(text.indexOf("irr_route+2AS64500 has a route object for 198.51.100.0/24") >= 0, "evidence row: " + text);
  assert(text.indexOf("Covering ROAs: 198.51.100.0/22 maxLength 22 AS64500. RPKI source: routinator.") >= 0, "roas: " + text);
  assert(walk(view).filter(function (n) { return n.tag === "button"; }).length === 0, "the prefix page has a button");
  var links = walk(view).filter(function (n) { return n.tag === "a"; });
  assert(links.length === 1 && links[0].href === "/registry.html", "link to the Registry page");
  var hijack = Object.assign({}, c, {class: "hijack", score: -7, action: "Keep dropping it."});
  var hv = context.onlyInvalidView(hijack, data.slurm);
  assert(hv.children[0].className === "reason bad" && walk(hv).filter(function (n) { return n.tag === "a"; }).length === 0, "hijack on the prefix page");

  // Registry page: proposing posts the prefix and shows the exact entries.
  await context.oiLoad();
  var cases = ids["only-invalid-cases"];
  assert(!ids["only-invalid-body"].hidden && cases.textContent.indexOf("198.51.100.0/24AS64500stale_roa") >= 0, "case row: " + cases.textContent);
  assert(buttons(cases, "Propose exception").length === 1 && calls.length === 1, "one propose button, only a read so far");
  buttons(cases, "Propose exception")[0].listeners.click();
  await settle();
  assert(calls[1].method === "POST" && calls[1].url === "/api/rpki/only-invalid/propose" && calls[1].body.prefix === "198.51.100.0/24", "propose: " + JSON.stringify(calls));
  text = cases.textContent;
  assert(text.indexOf("the route goes from invalid to valid. Approving adds exactly this to /var/lib/packeteer/slurm/slurm.json. Nothing is written until an admin approves.") >= 0, "review text: " + text);
  assert(text.indexOf('"maxPrefixLength": 24') >= 0 && text.indexOf("Digest d1, audit a01. Evidence: irr_route +2, origin_stable +2.") >= 0, "entries and digest: " + text);

  // Approval posts the id and the digest shown.
  buttons(cases, "Approve and write")[0].listeners.click();
  await settle();
  var post = calls.filter(function (x) { return x.url === "/api/rpki/exceptions"; });
  assert(post.length === 1 && post[0].body.id === "a01" && post[0].body.digest === "d1" && Object.keys(post[0].body).length === 2, "approve body: " + JSON.stringify(post));
  assert(ids["only-invalid-status"].textContent === "Written to /var/lib/packeteer/slurm/slurm.json.", "status: " + ids["only-invalid-status"].textContent);

  // A non-admin can propose and sees who approves; no approve or remove.
  context.shellAdmin = false;
  var withEx = JSON.parse(JSON.stringify(data));
  withEx.slurm.exceptions = [{id: "ab12", kind: "prefix_assertion", prefix: "198.51.100.0/24", asn: 64500, comment: "packeteer audit=a01", review_due: true}];
  withEx.slurm.held = ["198.51.100.0/24"];
  context.renderOnlyInvalidPage(withEx, context.onOnlyInvalid);
  assert(buttons(ids["only-invalid-exceptions"], "Remove").length === 0, "non-admin remove");
  assert(ids["only-invalid-exceptions"].textContent.indexOf("ab12prefix_assertion198.51.100.0/24AS64500packeteer audit=a01due") >= 0, "exception row: " + ids["only-invalid-exceptions"].textContent);
  assert(cases.textContent.indexOf("An exception is in the file.") >= 0 && buttons(cases, "Propose exception").length === 0, "held case");
  // An AS0 filter sits on the wider ROA prefix, so the case is held by the server's list, not by prefix equality.
  var wide = JSON.parse(JSON.stringify(data));
  wide.slurm.exceptions = [{id: "cd34", kind: "prefix_filter", prefix: "198.51.100.0/22", asn: 0, comment: "packeteer audit=a02"}];
  wide.slurm.held = ["198.51.100.0/24"];
  context.renderOnlyInvalidPage(wide, context.onOnlyInvalid);
  assert(cases.textContent.indexOf("An exception is in the file.") >= 0 && buttons(cases, "Propose exception").length === 0, "held by wider filter");
  context.oiProposal = proposal;
  vm.runInContext("oiProposal = " + JSON.stringify(proposal) + ";", context);
  context.renderOnlyInvalidPage(data, context.onOnlyInvalid);
  assert(buttons(cases, "Approve and write").length === 0 && cases.textContent.indexOf("An admin must approve this exception.") >= 0, "non-admin approve");
  buttons(cases, "Cancel")[0].listeners.click();
  assert(buttons(cases, "Cancel").length === 0, "cancel closes the box");

  // An admin removes an exception by id.
  context.shellAdmin = true;
  context.renderOnlyInvalidPage(withEx, context.onOnlyInvalid);
  buttons(ids["only-invalid-exceptions"], "Remove")[0].listeners.click();
  await settle();
  assert(calls.some(function (x) { return x.method === "DELETE" && x.url === "/api/rpki/exceptions/ab12"; }), "remove: " + JSON.stringify(calls));

  // A hijack gets no propose button; off hides the section.
  var hj = JSON.parse(JSON.stringify(data));
  hj.cases[0].class = "hijack";
  context.renderOnlyInvalidPage(hj, context.onOnlyInvalid);
  assert(buttons(cases, "Propose exception").length === 0 && cases.textContent.indexOf("No exception: not a likely stale ROA.") >= 0, "hijack row");
  // With auth off nothing can be proposed, and the row says why.
  var ro = JSON.parse(JSON.stringify(data));
  ro.slurm.writable = false;
  context.renderOnlyInvalidPage(ro, context.onOnlyInvalid);
  assert(buttons(cases, "Propose exception").length === 0 && cases.textContent.indexOf("Exceptions can be proposed once auth or basic auth is on") >= 0, "read-only row: " + cases.textContent);
  context.renderOnlyInvalidPage({enabled: false, cases: [], slurm: {}}, context.onOnlyInvalid);
  assert(ids["only-invalid-body"].hidden === true, "off hides the section");
  console.log("ok");
})();
