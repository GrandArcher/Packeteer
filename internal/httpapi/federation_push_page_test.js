"use strict";
// Runs the dashboard's settings push control (#137) against a small DOM
// stand-in: the form appears only when the API says a push is possible, it
// is built once, it posts the chosen sections, and the per-peer answer is
// shown. The page functions are cut out of the real app.js. Run by
// TestFederationPushPage.

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
  this.listeners = {};
  this.hidden = false;
  this.text = "";
}
Node.prototype.appendChild = function (c) { this.children.push(c); return c; };
Node.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); return c; };
Node.prototype.insertBefore = function (c, ref) { this.children.splice(this.children.indexOf(ref), 0, c); return c; };
Node.prototype.addEventListener = function (ev, fn) { this.listeners[ev] = fn; };
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

var ids = { "fed-push": new Node("div") };
var posts = [];
var reply = null;
var context = {
  document: {
    createElement: function (t) { return new Node(t); },
    getElementById: function (id) { return ids[id] || null; }
  },
  Boolean: Boolean,
  Promise: Promise,
  postJSON: function (url, body) {
    posts.push({ url: url, body: body });
    return reply();
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

var app = fs.readFileSync(path.join(__dirname, "web", "app.js"), "utf8");
var decl = app.slice(app.indexOf("var FED_PUSH_SECTIONS"), app.indexOf("function renderFedPush("));
vm.runInContext(decl, context);
["el", "clear", "table", "renderFedPush", "fedPushSend", "renderFedPushReport"].forEach(function (name) {
  vm.runInContext(fn(app, name), context);
});

var root = ids["fed-push"];

// Not possible (no editor, no federation, or no auth): the control stays hidden and empty.
context.renderFedPush(false);
assert(root.hidden === true, "hidden when push is not enabled");
assert(root.children.length === 0, "nothing built when push is not enabled");

// Possible: built once, however many refreshes follow.
context.renderFedPush(true);
context.renderFedPush(true);
assert(root.hidden === false, "shown when push is enabled");
var boxes = find(root, "input");
assert(boxes.length === 2, "one checkbox per pushable section, got " + boxes.length);
assert(boxes[0].value === "thresholds" && boxes[0].checked === true, "thresholds is checked by default");
assert(boxes[1].value === "policies" && boxes[1].checked === false, "policies is not checked by default");
var buttons = find(root, "button");
assert(buttons.length === 1 && buttons[0].textContent === "Push to all peers", "one push button");

var done = null;
function click() { done = buttons[0].listeners.click(); return done; }

// Nothing chosen: no request.
boxes[0].checked = false;
click();
assert(posts.length === 0, "no request without a section");
assert(root.textContent.indexOf("Choose at least one section.") >= 0, "asks for a section");

// Thresholds and policies: one request naming both, then the per-peer answer.
boxes[0].checked = true;
boxes[1].checked = true;
reply = function () {
  return Promise.resolve({
    sections: ["thresholds", "policies"], ok: false,
    peers: [
      { peer: "pop-b", status: "applied", applied: ["policies", "thresholds"] },
      { peer: "pop-c", status: "refused", errors: ["min_loss_delta_pct must not be negative"] },
      { peer: "pop-d", status: "unreachable", errors: ["connection refused"] },
      { peer: "pop-e", status: "unchanged" }
    ]
  });
};
click();
done.then(function () {
  assert(posts.length === 1 && posts[0].url === "/api/federation/push", "posted to the push endpoint");
  assert(JSON.stringify(posts[0].body) === JSON.stringify({ sections: ["thresholds", "policies"] }), "body = " + JSON.stringify(posts[0].body));
  var rows = find(root, "tr").slice(1).map(function (tr) {
    return find(tr, "td").map(function (td) { return td.textContent; });
  });
  assert(rows.length === 4, "a row per peer, got " + rows.length);
  assert(rows[0][0] === "pop-b" && rows[0][1] === "applied" && rows[0][2] === "policies, thresholds", "applied row: " + rows[0]);
  assert(rows[1][1] === "refused" && rows[1][2] === "min_loss_delta_pct must not be negative", "refused row shows why: " + rows[1]);
  assert(rows[2][1] === "unreachable" && rows[2][2] === "connection refused", "unreachable row: " + rows[2]);
  assert(rows[3][1] === "unchanged" && rows[3][2] === "already had these settings", "unchanged row: " + rows[3]);
  var dots = find(root, "span").map(function (s) { return s.className; });
  assert(dots.join(",") === "dot up,dot down,dot down,dot up", "dots = " + dots);
  assert(root.textContent.indexOf("At least one peer did not take them.") >= 0, "summary says a peer refused");

  // A failed request shows its message and leaves the form.
  reply = function () { return Promise.reject(new Error("forbidden")); };
  return click();
}).then(function () {
  assert(root.textContent.indexOf("Push failed: forbidden") >= 0, "failure shown");
  assert(find(root, "input").length === 2, "the form is still there after a failure");
  console.log("ok");
}).catch(function (e) {
  console.error("FAIL: " + e.stack);
  process.exit(1);
});
