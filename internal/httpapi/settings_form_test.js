"use strict";
// Drives the settings form functions against the real settings.html.
// The script stays outside web/ so go:embed does not serve it.

var fs = require("fs");
var path = require("path");
var vm = require("vm");

var calls = [];
var searchRows = [];
// disk stands in for the config file once a test sets it.
var disk = null;

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
}

function Event(type) {
  this.type = type;
  this.defaultPrevented = false;
}
Event.prototype.preventDefault = function () { this.defaultPrevented = true; };

var idMap = {};
var document = {
  nodeType: 9,
  childNodes: [],
  parentNode: null,
  documentElement: null,
  body: null
};

function connected(n) {
  while (n) {
    if (n === document) return true;
    n = n.parentNode;
  }
  return false;
}
function register(n) {
  if (!n || n.nodeType !== 1) return;
  var id = n.getAttribute("id");
  if (id) idMap[id] = n;
  for (var i = 0; i < n.childNodes.length; i++) register(n.childNodes[i]);
}
function unregister(n) {
  if (!n || n.nodeType !== 1) return;
  var id = n.getAttribute("id");
  if (id && idMap[id] === n) delete idMap[id];
  for (var i = 0; i < n.childNodes.length; i++) unregister(n.childNodes[i]);
}

function appendChild(child) {
  if (child.parentNode) child.parentNode.removeChild(child);
  child.parentNode = this;
  this.childNodes.push(child);
  if (this === document || connected(this)) register(child);
  if (this === document && child.tagName === "HTML") document.documentElement = child;
  if (child.tagName === "BODY") document.body = child;
  return child;
}
function removeChild(child) {
  var i = this.childNodes.indexOf(child);
  if (i < 0) throw new Error("not a child");
  unregister(child);
  this.childNodes.splice(i, 1);
  child.parentNode = null;
  return child;
}

function classNames(el) {
  return (el.getAttribute("class") || "").split(/\s+/).filter(Boolean);
}
function datasetOf(el) {
  if (el._ds) return el._ds;
  el._ds = new Proxy({}, {
    get: function (_, key) {
      if (typeof key !== "string") return undefined;
      return el.getAttribute("data-" + key.replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }));
    },
    set: function (_, key, value) {
      el.setAttribute("data-" + String(key).replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }), value == null ? "" : String(value));
      return true;
    },
    deleteProperty: function (_, key) {
      el.removeAttribute("data-" + String(key).replace(/[A-Z]/g, function (c) { return "-" + c.toLowerCase(); }));
      return true;
    }
  });
  return el._ds;
}

function matchSimple(el, sel) {
  sel = sel.trim();
  if (!sel || el.nodeType !== 1) return false;
  var tag = "";
  if (sel.charAt(0) !== "." && sel.charAt(0) !== "#" && sel.charAt(0) !== "[") {
    var tm = /^[A-Za-z0-9-]+/.exec(sel);
    if (!tm) return false;
    tag = tm[0].toUpperCase();
    sel = sel.slice(tm[0].length);
  }
  if (tag && el.tagName !== tag) return false;
  while (sel.length) {
    if (sel.charAt(0) === ".") {
      var cm = /^\.([A-Za-z0-9_-]+)/.exec(sel);
      if (!cm || !el.classList.contains(cm[1])) return false;
      sel = sel.slice(cm[0].length);
    } else if (sel.charAt(0) === "#") {
      var im = /^#([A-Za-z0-9_-]+)/.exec(sel);
      if (!im || el.getAttribute("id") !== im[1]) return false;
      sel = sel.slice(im[0].length);
    } else if (sel.charAt(0) === "[") {
      var am = /^\[([^\]]+)\]/.exec(sel);
      if (!am) return false;
      var inside = am[1];
      var eq = inside.indexOf("=");
      if (eq < 0) {
        if (!el.hasAttribute(inside.trim())) return false;
      } else {
        var an = inside.slice(0, eq).trim().toLowerCase();
        var av = inside.slice(eq + 1).trim();
        if ((av.charAt(0) === "'" && av.charAt(av.length - 1) === "'") || (av.charAt(0) === '"' && av.charAt(av.length - 1) === '"')) av = av.slice(1, -1);
        if (el.getAttribute(an) !== av) return false;
      }
      sel = sel.slice(am[0].length);
    } else return false;
  }
  return true;
}
function walkElements(n, fn) {
  var kids = n.childNodes || [];
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].nodeType === 1) {
      fn(kids[i]);
      walkElements(kids[i], fn);
    }
  }
}
function queryAll(root, selector) {
  var found = [];
  selector.split(",").forEach(function (group) {
    var steps = group.trim().split(/\s+/).filter(Boolean);
    var current = [root];
    steps.forEach(function (step) {
      var next = [];
      current.forEach(function (n) {
        walkElements(n, function (el) {
          if (matchSimple(el, step) && next.indexOf(el) < 0) next.push(el);
        });
      });
      current = next;
    });
    current.forEach(function (el) { if (found.indexOf(el) < 0) found.push(el); });
  });
  return found;
}

// These events bubble in a browser; blur does not.
var bubbles = {input: true, change: true, click: true};

var proto = {
  nodeType: 1,
  appendChild: appendChild,
  removeChild: removeChild,
  scrollIntoView: function () {},
  click: function () { this.dispatchEvent(new Event("click")); },
  addEventListener: function (type, fn) {
    (this._listeners[type] || (this._listeners[type] = [])).push(fn);
  },
  dispatchEvent: function (ev) {
    var list = (this._listeners[ev.type] || []).slice();
    for (var i = 0; i < list.length; i++) list[i].call(this, ev);
    if (bubbles[ev.type] && this.parentNode && this.parentNode.nodeType === 1) this.parentNode.dispatchEvent(ev);
    return true;
  },
  getAttribute: function (name) {
    name = String(name).toLowerCase();
    return Object.prototype.hasOwnProperty.call(this._attrs, name) ? this._attrs[name] : null;
  },
  hasAttribute: function (name) {
    return Object.prototype.hasOwnProperty.call(this._attrs, String(name).toLowerCase());
  },
  setAttribute: function (name, value) {
    name = String(name).toLowerCase();
    var old = this._attrs[name];
    this._attrs[name] = String(value);
    if (name === "id") {
      if (old && idMap[old] === this) delete idMap[old];
      if (connected(this)) idMap[String(value)] = this;
    }
    if (name === "value") this._value = String(value);
  },
  removeAttribute: function (name) {
    name = String(name).toLowerCase();
    var old = this._attrs[name];
    delete this._attrs[name];
    if (name === "id" && old && idMap[old] === this) delete idMap[old];
    if (name === "value") this._value = "";
  },
  querySelector: function (sel) {
    var all = queryAll(this, sel);
    return all[0] || null;
  },
  querySelectorAll: function (sel) { return queryAll(this, sel); }
};
Object.defineProperty(proto, "firstChild", { get: function () { return this.childNodes[0] || null; } });
Object.defineProperty(proto, "children", { get: function () { return this.childNodes.filter(function (n) { return n.nodeType === 1; }); } });
Object.defineProperty(proto, "textContent", {
  get: function () {
    var s = "";
    for (var i = 0; i < this.childNodes.length; i++) s += this.childNodes[i].textContent;
    return s;
  },
  set: function (v) {
    var old = this.childNodes.slice();
    for (var i = 0; i < old.length; i++) unregister(old[i]);
    this.childNodes = [];
    if (v != null && String(v) !== "") {
      this.childNodes.push({nodeType: 3, parentNode: this, childNodes: [], textContent: String(v)});
    }
  }
});
Object.defineProperty(proto, "className", {
  get: function () { return this.getAttribute("class") || ""; },
  set: function (v) { this.setAttribute("class", v == null ? "" : String(v)); }
});
Object.defineProperty(proto, "id", {
  get: function () { return this.getAttribute("id") || ""; },
  set: function (v) { this.setAttribute("id", v == null ? "" : String(v)); }
});
Object.defineProperty(proto, "classList", {
  get: function () {
    var el = this;
    return {
      contains: function (c) { return classNames(el).indexOf(c) >= 0; }
    };
  }
});
Object.defineProperty(proto, "dataset", { get: function () { return datasetOf(this); } });
["hidden", "checked", "selected", "disabled"].forEach(function (name) {
  Object.defineProperty(proto, name, {
    get: function () { return this.hasAttribute(name); },
    set: function (v) { if (v) this.setAttribute(name, ""); else this.removeAttribute(name); }
  });
});
["type", "min", "max", "step", "placeholder", "title", "name"].forEach(function (name) {
  Object.defineProperty(proto, name, {
    get: function () { return this.getAttribute(name) || ""; },
    set: function (v) { this.setAttribute(name, v == null ? "" : String(v)); }
  });
});
Object.defineProperty(proto, "value", {
  get: function () {
    if (this.tagName === "SELECT") {
      var opts = this.options;
      for (var i = 0; i < opts.length; i++) if (opts[i].selected) return opts[i].value;
      return opts.length ? opts[0].value : "";
    }
    if (this._value != null) return this._value;
    if (this.hasAttribute("value")) return this.getAttribute("value");
    return "";
  },
  set: function (v) {
    var s = v == null ? "" : String(v);
    if (this.tagName === "SELECT") {
      var opts = this.options;
      for (var i = 0; i < opts.length; i++) opts[i].selected = opts[i].value === s;
      this._value = s;
      return;
    }
    this._value = s;
    if (s) this.setAttribute("value", s); else this.removeAttribute("value");
  }
});
Object.defineProperty(proto, "options", {
  get: function () { return this.children.filter(function (c) { return c.tagName === "OPTION"; }); }
});
Object.defineProperty(proto, "selectedOptions", {
  get: function () { return this.options.filter(function (o) { return o.selected; }); }
});

function createElement(tag) {
  var el = Object.create(proto);
  el.tagName = String(tag).toUpperCase();
  el.childNodes = [];
  el.parentNode = null;
  el._attrs = {};
  el._listeners = {};
  el._value = null;
  el.multiple = false;
  el.size = 0;
  el.spellcheck = true;
  return el;
}
document.createElement = createElement;
document.appendChild = appendChild;
document.removeChild = removeChild;
document.getElementById = function (id) { return idMap[id] || null; };
document.querySelector = function (sel) { var all = queryAll(document, sel); return all[0] || null; };
document.querySelectorAll = function (sel) { return queryAll(document, sel); };

var voidTags = {area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1, link: 1, meta: 1, source: 1, track: 1, wbr: 1};
function decode(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, function (all, ent) {
    var map = {amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: "\u00a0"};
    if (ent.charAt(0) === "#") {
      var n = ent.charAt(1) === "x" || ent.charAt(1) === "X" ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      return String.fromCharCode(n);
    }
    return Object.prototype.hasOwnProperty.call(map, ent) ? map[ent] : all;
  });
}
function parseAttrs(raw, el) {
  var re = /([^\s=\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  var m;
  while ((m = re.exec(raw))) {
    var val = m[2] != null ? m[2] : (m[3] != null ? m[3] : (m[4] != null ? m[4] : ""));
    el.setAttribute(m[1], decode(val));
  }
}
function parseHTML(html) {
  var i = 0;
  var stack = [document];
  while (i < html.length) {
    var lt = html.indexOf("<", i);
    if (lt < 0) {
      if (i < html.length) stack[stack.length - 1].appendChild(textNode(decode(html.slice(i))));
      break;
    }
    if (lt > i) stack[stack.length - 1].appendChild(textNode(decode(html.slice(i, lt))));
    if (html.slice(lt, lt + 4) === "<!--") {
      var ce = html.indexOf("-->", lt);
      i = ce < 0 ? html.length : ce + 3;
      continue;
    }
    if (html.slice(lt, lt + 2) === "<!") {
      var de = html.indexOf(">", lt);
      i = de < 0 ? html.length : de + 1;
      continue;
    }
    var gt = html.indexOf(">", lt);
    if (gt < 0) break;
    var raw = html.slice(lt + 1, gt).trim();
    i = gt + 1;
    if (raw.charAt(0) === "/") {
      var cname = raw.slice(1).trim().split(/\s/)[0].toUpperCase();
      while (stack.length > 1 && stack[stack.length - 1].tagName !== cname) stack.pop();
      if (stack.length > 1) stack.pop();
      continue;
    }
    var selfClose = /\/$/.test(raw);
    if (selfClose) raw = raw.slice(0, -1).trim();
    var nm = /^([A-Za-z0-9:-]+)/.exec(raw);
    if (!nm) continue;
    var el = createElement(nm[1]);
    parseAttrs(raw.slice(nm[1].length), el);
    stack[stack.length - 1].appendChild(el);
    if (!voidTags[nm[1].toLowerCase()] && !selfClose) stack.push(el);
  }
}
function textNode(data) {
  return {nodeType: 3, parentNode: null, childNodes: [], textContent: data};
}

var dir = __dirname;
parseHTML(fs.readFileSync(path.join(dir, "web/settings.html"), "utf8"));
assert(document.getElementById("editor-section"), "editor section missing");
assert(document.getElementById("form-anomaly-rules"), "anomaly list missing");

// With PACKETEER_URL set, the page talks to a real server (the Go test
// starts one) instead of the canned replies below.
var live = process.env.PACKETEER_URL;
var realFetch = global.fetch;

global.document = document;
global.Event = Event;
global.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  if (live) {
    var headers = Object.assign({}, opts && opts.headers, {Authorization: "Bearer " + process.env.PACKETEER_TOKEN});
    return realFetch(live + url, Object.assign({}, opts, {headers: headers}));
  }
  calls.push({method: method, url: String(url), body: opts && opts.body});
  if (disk) {
    var served = serveConfig(method, String(url), opts && opts.body);
    if (served) return served;
  }
  if (method === "PUT") return Promise.reject(new Error("config write"));
  if (method === "GET" && String(url).indexOf("/api/search?") === 0) return reply({asns: {rows: searchRows}});
  if (method === "POST" && String(url) === "/api/config/validate") {
    return reply({valid: false, errors: ["policies[0]: geoip_db: open /mnt/missing.mmdb: no such file or directory"]});
  }
  if (method === "POST" && String(url) === "/api/config/form") {
    var req = JSON.parse(opts.body);
    return Promise.resolve({
      ok: true,
      status: 200,
      statusText: "OK",
      text: function () { return Promise.resolve(JSON.stringify({yaml: req.yaml, form: req.form})); }
    });
  }
  return Promise.reject(new Error("offline"));
};

// serveConfig plays the config API against disk: a file whose only setting
// is hold_time, and a form that carries it.
function serveConfig(method, url, raw) {
  var req = raw ? JSON.parse(raw) : {};
  var hold = function (yaml) { return /hold_time: (\S+)/.exec(yaml)[1]; };
  if (method === "GET" && url === "/api/config") {
    return reply({yaml: disk.yaml, path: "/etc/packeteer/config.yaml", sha256: disk.sha});
  }
  if (method === "POST" && url === "/api/config/form") {
    if (!req.apply) return reply({yaml: req.yaml, form: Object.assign(emptyForm(), {mode: "observe", hold_time: hold(req.yaml)})});
    return reply({yaml: req.yaml.replace(/hold_time: \S+/, "hold_time: " + req.form.hold_time), form: req.form});
  }
  if (method === "PUT" && url === "/api/config") {
    var changes = [];
    if (hold(req.yaml) !== hold(disk.yaml)) changes.push({key: "hold_time", old: hold(disk.yaml), new: hold(req.yaml)});
    disk = {yaml: req.yaml, sha: "sha" + disk.writes, writes: disk.writes + 1};
    return reply({result: {valid: true, mode: "observe", changes: changes, restart_required: false, reload_online: true},
      applied: changes.length ? ["hold_time"] : [], file: {path: "/etc/packeteer/config.yaml", yaml: disk.yaml, sha256: disk.sha}});
  }
  return null;
}

function reply(body) {
  return Promise.resolve({
    ok: true,
    status: 200,
    statusText: "OK",
    text: function () { return Promise.resolve(JSON.stringify(body)); }
  });
}

vm.runInThisContext(fs.readFileSync(path.join(dir, "web/ui.js"), "utf8"), {filename: "ui.js"});
vm.runInThisContext(fs.readFileSync(path.join(dir, "web/countries.js"), "utf8"), {filename: "countries.js"});
vm.runInThisContext(fs.readFileSync(path.join(dir, "web/settings.js"), "utf8"), {filename: "settings.js"});

function flush() {
  return new Promise(function (resolve) { setTimeout(resolve, 0); });
}
function fieldError(node) {
  var n = node;
  while (n && n !== document.documentElement) {
    var p = n.parentNode;
    if (!p || !p.children) return null;
    for (var i = 0; i < p.children.length; i++) {
      if (p.children[i].classList && p.children[i].classList.contains("field-error")) return p.children[i];
    }
    n = p;
  }
  return null;
}
function visibleErrors(root) {
  var out = [];
  root.querySelectorAll(".field-error").forEach(function (e) {
    if (!e.hidden && e.textContent) out.push(e);
  });
  return out;
}
function inputByLabel(root, text) {
  var labels = root.querySelectorAll("label");
  for (var i = 0; i < labels.length; i++) {
    var spans = labels[i].querySelectorAll("span");
    for (var j = 0; j < spans.length; j++) {
      if (spans[j].classList.contains("field-label") && spans[j].textContent === text) {
        var inputs = labels[i].querySelectorAll("input");
        if (inputs[0]) return inputs[0];
      }
    }
  }
  return null;
}
function anomalyBox() { return document.getElementById("form-anomaly-rules"); }
function prefixRow(prefix) {
  var rows = anomalyBox().querySelectorAll(".g-prefixes .row");
  for (var i = 0; i < rows.length; i++) {
    var spans = rows[i].querySelectorAll("span");
    for (var j = 0; j < spans.length; j++) {
      if (!spans[j].classList.contains("field-error") && spans[j].textContent === prefix) return rows[i];
    }
  }
  return null;
}
function removePrefix(row) {
  var buttons = row.querySelectorAll("button");
  for (var i = 0; i < buttons.length; i++) if (buttons[i].title === "Remove prefix") return buttons[i];
  return null;
}
function checkbox(prefix) {
  var boxes = anomalyBox().querySelectorAll("input[type=checkbox]");
  for (var i = 0; i < boxes.length; i++) if (boxes[i].value === prefix) return boxes[i];
  return null;
}
function shownError(node) {
  var e = fieldError(node);
  return e && !e.hidden ? e.textContent : "";
}
function helpFor(node) {
  var n = node;
  while (n && n.tagName !== "LABEL") n = n.parentNode;
  var help = n && n.querySelector(".field-help");
  return help ? help.textContent : "";
}
function typed(node, value) {
  node.value = value;
  node.dispatchEvent(new Event("input"));
  node.dispatchEvent(new Event("blur"));
}
function posts() {
  return calls.filter(function (c) { return c.method === "POST" && c.url === "/api/config/form"; });
}

async function main() {
  if (live) {
    if (process.env.PACKETEER_CASE === "fresh") await liveFresh();
    else await liveWizard();
    return;
  }
  await flush();
  await flush();
  assert(typeof form === "object", "settings form did not load");
  assert(!calls.some(function (c) { return c.method === "PUT"; }), "startup wrote config");

  form.anomaly.enabled = true;
  form.anomaly.mitigation_mode = "observe";
  form.anomaly.mitigation_allowlist = ["203.0.113.0/24"];
  form.anomaly.rules = [{
    key: "0", name: "udp-flood",
    prefixes: ["203.0.113.0/24", "203.0.113.128/25", "198.51.100.0/24"],
    protocols: [], min_mbps: "", action: "blackhole", target: "", rate_mbps: "", ttl: ""
  }];
  renderAnomalyRules();

  var exact = checkbox("203.0.113.0/24");
  assert(exact && exact.checked, "allowlist prefix is not a checked box");
  var more = prefixRow("203.0.113.128/25");
  assert(more, "more-specific prefix is not listed");
  assert(removePrefix(more), "more-specific prefix has no remove control");
  assert(visibleErrors(more).length === 0, "more-specific prefix is marked invalid");
  var outside = prefixRow("198.51.100.0/24");
  assert(outside, "prefix outside the allowlist is not listed");
  assert(removePrefix(outside), "rejected prefix has no remove control");
  var outsideErr = visibleErrors(outside);
  assert(outsideErr.length === 1 && outsideErr[0].textContent.indexOf("not inside the mitigation allowlist") >= 0, "rejected prefix has no error");
  var help = anomalyBox().querySelectorAll(".field-help");
  var helpOk = false;
  for (var h = 0; h < help.length; h++) if (help[h].textContent.indexOf("more-specific") >= 0) helpOk = true;
  assert(helpOk, "prefix help does not mention a more-specific");

  var before = posts().length;
  applyForm();
  assert(document.getElementById("form-status").textContent === "Fix the highlighted fields before applying. Nothing was written.", "apply was not refused");
  assert(posts().length === before, "refused apply posted the form");

  removePrefix(outside).click();
  assert(form.anomaly.rules[0].prefixes.indexOf("198.51.100.0/24") < 0, "removed prefix stayed in the model");
  assert(form.anomaly.rules[0].prefixes.indexOf("203.0.113.128/25") >= 0, "remove dropped the more-specific");
  assert(visibleErrors(anomalyBox()).length === 0, "error stayed after the prefix was removed");

  applyForm();
  await flush();
  await flush();
  await flush();
  var sent = posts();
  assert(sent.length === before + 1, "apply did not post the form");
  var body = JSON.parse(sent[sent.length - 1].body);
  var prefs = body.form.anomaly.rules[0].prefixes;
  assert(prefs.indexOf("203.0.113.0/24") >= 0 && prefs.indexOf("203.0.113.128/25") >= 0, "posted prefixes lost a listed prefix: " + prefs.join(","));
  assert(prefs.indexOf("198.51.100.0/24") < 0, "posted prefixes still include the rejected prefix");
  assert(!calls.some(function (c) { return c.method === "PUT"; }), "apply wrote the config file");

  exact = checkbox("203.0.113.0/24");
  exact.checked = false;
  exact.dispatchEvent(new Event("change"));
  assert(form.anomaly.rules[0].prefixes.indexOf("203.0.113.128/25") >= 0, "unchecking the allowlist prefix dropped the more-specific");
  assert(form.anomaly.rules[0].prefixes.indexOf("203.0.113.0/24") < 0, "unchecked prefix stayed selected");
  exact.checked = true;
  exact.dispatchEvent(new Event("change"));
  more = prefixRow("203.0.113.128/25");
  removePrefix(more).click();
  assert(form.anomaly.rules[0].prefixes.length === 1 && form.anomaly.rules[0].prefixes[0] === "203.0.113.0/24", "removing the more-specific left " + form.anomaly.rules[0].prefixes.join(","));

  form.exchanges = [{
    key: "", name: "ix-lab", lans: ["203.0.113.0/24"], bmp: "", group: "",
    peers: [{key: "", name: "ix-peer-a", asn: "", next_hop: "203.0.113.11", source_ip: "192.0.2.31", cost: ""}]
  }];
  renderExchanges();
  var asn = inputByLabel(document.getElementById("form-exchanges"), "Peer AS");
  assert(asn, "peer AS field missing");
  asn.value = "AS64501";
  asn.dispatchEvent(new Event("input"));
  assert(asn.value === "AS64501", "peer AS field was rewritten while typing");
  assert(form.exchanges[0].peers[0].asn === "64501", "AS64501 was stored as " + form.exchanges[0].peers[0].asn);
  asn.dispatchEvent(new Event("blur"));
  var asnErr = fieldError(asn);
  assert(!asnErr || asnErr.hidden || !asnErr.textContent, "AS64501 was marked invalid");

  asn.value = "AS64502";
  asn.dispatchEvent(new Event("blur"));
  assert(form.exchanges[0].peers[0].asn === "64502", "blur stored " + form.exchanges[0].peers[0].asn);
  asn.value = "AS0";
  asn.dispatchEvent(new Event("blur"));
  assert(form.exchanges[0].peers[0].asn === "AS0", "AS0 became " + form.exchanges[0].peers[0].asn);
  asnErr = fieldError(asn);
  assert(asnErr && !asnErr.hidden && asnErr.textContent, "AS0 has no error");
  asn.value = "nope";
  asn.dispatchEvent(new Event("input"));
  asn.dispatchEvent(new Event("blur"));
  assert(form.exchanges[0].peers[0].asn === "nope", "nope became " + form.exchanges[0].peers[0].asn);
  asnErr = fieldError(asn);
  assert(asnErr && !asnErr.hidden && asnErr.textContent.indexOf("AS number") >= 0, "nope has no AS error");

  runningExchanges = [
    {name: "ix-lab", discovered: [{next_hop: "203.0.113.13", asn: 64503, prefixes: 3}]},
    {name: "ix-not-in-the-form", discovered: [{next_hop: "198.51.100.77", asn: 64511, prefixes: 9}]}
  ];
  foldDiscovered();
  assert(guide.hops.indexOf("203.0.113.13") >= 0 && guide.asns.indexOf("64503") >= 0, "a member of a form exchange was not suggested");
  assert(guide.hops.indexOf("198.51.100.77") < 0 && guide.asns.indexOf("64511") < 0, "a member of an exchange not in the form was suggested");
  runningExchanges = [];

  form.vips = [{key: "", name: "vip", interval: "10s", max_targets: "", prefixes: [], asns: ["64496"]}];
  renderVIPs();
  var max = inputByLabel(document.getElementById("form-vips"), "Max targets");
  assert(max && max.min === "1", "VIP max_targets min is " + (max && max.min));
  var vipHelp = false;
  document.getElementById("form-vips").querySelectorAll(".field-help").forEach(function (n) {
    if (n.textContent.indexOf("At least 1; empty uses 100.") >= 0) vipHelp = true;
  });
  assert(vipHelp, "VIP max_targets help missing");
  max.value = "0";
  max.dispatchEvent(new Event("input"));
  max.dispatchEvent(new Event("blur"));
  var maxErr = fieldError(max);
  assert(maxErr && !maxErr.hidden && maxErr.textContent.indexOf("1") >= 0, "VIP max_targets 0 was accepted");
  assert(form.vips[0].max_targets === "0", "VIP max_targets 0 was not stored for the check");
  max.value = "";
  max.dispatchEvent(new Event("input"));
  max.dispatchEvent(new Event("blur"));
  maxErr = fieldError(max);
  assert(!maxErr || maxErr.hidden || !maxErr.textContent, "empty VIP max_targets was refused");
  assert(form.vips[0].max_targets === "", "empty VIP max_targets stored " + form.vips[0].max_targets);

  // Hold time and the thresholds have no Go default, so the page must not claim one.
  ["fm-hold", "fm-loss", "fm-rtt"].forEach(function (id) {
    var help = helpFor(document.getElementById(id));
    assert(help.indexOf("Default") < 0 && help.indexOf("Inject needs more than 0.") >= 0, id + " help: " + help);
    assert(document.getElementById(id).placeholder === "", id + " shows a placeholder default");
  });
  writeDur("fm-hold", "30s", "m");
  assert(readDur("fm-hold") === "30s", "untouched hold time read " + readDur("fm-hold"));
  var hold = document.getElementById("fm-hold");
  assert(hold.value === "30" && document.getElementById("fm-hold-unit").value === "s", "hold time shown as " + hold.value);
  typed(hold, "2");
  var unit = document.getElementById("fm-hold-unit");
  unit.value = "m";
  unit.dispatchEvent(new Event("change"));
  assert(readDur("fm-hold") === "2m" && form.hold_time === "2m", "hold time composed " + readDur("fm-hold"));
  writeDur("fm-hold", "1h30m", "m");
  assert(hold.type === "text" && hold.value === "1h30m" && unit.hidden, "a compound duration is not kept as text");
  writeNum("fm-loss", "1e2");
  assert(document.getElementById("fm-loss").type === "text", "a non-decimal number is not kept as text");
  writeNum("fm-loss", "2.5");
  assert(document.getElementById("fm-loss").type === "number", "a decimal number did not get a number box");

  var vipAdd = document.getElementById("form-vips").querySelectorAll("input").filter(function (n) { return n.getAttribute("aria-label") === "Add VIP ASNs (AS number or name)"; })[0];
  assert(vipAdd, "VIP AS picker missing");
  searchRows = [{asn: 64501, name: "Lab Transit"}, {asn: 64502, name: "Lab Transit East"}];
  vipAdd.value = "lab";
  vipAdd.dispatchEvent(new Event("change"));
  await flush();
  await flush();
  assert(form.vips[0].asns.length === 1, "an ambiguous name added " + form.vips[0].asns.join(","));
  var several = shownError(vipAdd);
  assert(several.indexOf("AS64501 Lab Transit, AS64502 Lab Transit East") >= 0, "ambiguous name error: " + several);
  vipAdd.value = "lab transit";
  vipAdd.dispatchEvent(new Event("change"));
  await flush();
  await flush();
  assert(form.vips[0].asns.join(",") === "64496,64501", "the exact name match was not added: " + form.vips[0].asns.join(","));

  form.flows = [{key: "", name: "flow", listen: ["127.0.0.1:2055"], window: "", top_n: "", max_targets: "", tail_interval: "", min_bytes: "", min_pct: "",
    aggregate_v4: "", aggregate_v6: "", exclude: []}];
  renderFlows();
  var port = document.getElementById("form-flows").querySelector("input.g-port");
  assert(port && port.min === "1", "flow port min is " + (port && port.min));
  typed(port, "0");
  assert(shownError(port) === "Enter a whole number from 1 to 65535.", "flow port 0: " + shownError(port));
  typed(port, "2056");
  assert(shownError(port) === "" && form.flows[0].listen[0] === "127.0.0.1:2056", "flow listen is " + form.flows[0].listen[0]);

  var policy = emptyPolicy();
  var rule = emptyRule();
  rule.countries = ["ZZ"];
  policy.rules.push(rule);
  form.policies = [policy];
  renderPolicies();
  var countries = document.getElementById("form-policies").querySelector("select.g-countries");
  assert(countries && countries.options.length > 240, "country picker missing");
  var picked = countries.options.filter(function (o) { return o.selected; }).map(function (o) { return o.value; });
  assert(picked.join(",") === "ZZ", "a code outside the list was not kept selected: " + picked.join(","));
  countries.options.forEach(function (o) { o.selected = o.value === "DE" || o.value === "ZZ"; });
  countries.dispatchEvent(new Event("change"));
  assert(form.policies[0].rules[0].countries.join(",") === "DE,ZZ", "countries stored " + form.policies[0].rules[0].countries.join(","));

  var geo = inputByLabel(document.getElementById("form-policies"), "GeoIP database");
  typed(geo, "country.mmdb");
  assert(shownError(geo) === "Enter an absolute path.", "relative GeoIP path: " + shownError(geo));
  var validates = calls.filter(function (c) { return c.url === "/api/config/validate"; }).length;
  assert(validates === 0, "a relative GeoIP path was sent to validate");
  typed(geo, "/mnt/missing.mmdb");
  await flush();
  await flush();
  var checks = calls.filter(function (c) { return c.url === "/api/config/validate"; });
  assert(checks.length === 1, "GeoIP path was checked " + checks.length + " times");
  assert(JSON.parse(checks[0].body).yaml.indexOf("geoip_db: '/mnt/missing.mmdb'") >= 0, "GeoIP check did not send the path");
  var note = geo.parentNode.querySelector(".field-note");
  assert(note && note.textContent.indexOf("geoip_db: open /mnt/missing.mmdb") >= 0, "GeoIP note: " + (note && note.textContent));
  assert(form.policies[0].geoip_db === "/mnt/missing.mmdb", "GeoIP path stored " + form.policies[0].geoip_db);

  assert(!calls.some(function (c) { return c.method === "PUT"; }), "the form wrote the config file");

  await saveFlow();
}

function puts() {
  return calls.filter(function (c) { return c.method === "PUT"; });
}
function bar() { return document.getElementById("save-bar"); }
function unsaved() { return !document.getElementById("unsaved").hidden; }
async function settle() {
  for (var i = 0; i < 6; i++) await flush();
}

// Save must write what the form shows (#344), name each change, and the page
// must show unsaved edits and keep Apply and Save in reach.
async function saveFlow() {
  disk = {yaml: "mode: observe\nhold_time: 1m\n", sha: "sha0", writes: 1};
  loadConfig();
  await settle();
  assert(document.getElementById("ed-yaml").value === disk.yaml, "the file was not loaded");
  assert(!unsaved() && bar().dataset.state === "clean", "a fresh load shows unsaved changes");
  assert(document.getElementById("fm-hold").value === "1", "hold time shown as " + document.getElementById("fm-hold").value);

  var bareSave = puts().length;
  document.getElementById("ed-save").click();
  await settle();
  assert(puts().length === bareSave + 1, "Save with no edits did not reach the file");
  assert(document.getElementById("ed-status").textContent === "No changes to save.", "unchanged Save said: " + document.getElementById("ed-status").textContent);

  var hold = document.getElementById("fm-hold");
  typed(hold, "2");
  assert(unsaved() && bar().dataset.state === "form", "a form edit did not show as unsaved");
  assert(document.getElementById("ed-yaml").value === disk.yaml, "the edit reached the YAML before Apply");
  typed(hold, "1");
  assert(!unsaved(), "undoing the edit left the unsaved flag");
  typed(hold, "2");

  var before = puts().length;
  document.getElementById("ed-save").click();
  await settle();
  assert(puts().length === before + 1, "Save did not write the file");
  assert(/hold_time: 2m/.test(disk.yaml), "the file still says " + disk.yaml);
  var said = document.getElementById("ed-status").textContent;
  assert(said.indexOf("Saved 1 change: hold_time 1m -> 2m (applied online)") === 0, "Save said: " + said);
  assert(document.getElementById("bar-msg").textContent === said, "the bar does not repeat the result");
  assert(!unsaved() && bar().dataset.state === "clean", "Save left the unsaved flag");

  typed(hold, "3");
  assert(unsaved() && bar().dataset.state === "form", "a second edit did not show as unsaved");
  assert(document.getElementById("bar-save") && document.getElementById("bar-apply"), "the bar has no Apply and Save");
  var css = fs.readFileSync(path.join(dir, "web/app.css"), "utf8");
  assert(/\.savebar \{[^}]*position: sticky;[^}]*bottom: 0;/.test(css), "the bar is not sticky at the bottom");
  var html = fs.readFileSync(path.join(dir, "web/settings.html"), "utf8");
  assert(html.indexOf('<div id="save-bar"') > html.indexOf("</main>"), "the bar sits inside main, where it would end with the content");

  // Apply from the bar copies the form into the YAML and does not write.
  before = puts().length;
  document.getElementById("bar-apply").click();
  await settle();
  assert(/hold_time: 3m/.test(document.getElementById("ed-yaml").value), "Apply did not reach the YAML");
  assert(puts().length === before && /hold_time: 2m/.test(disk.yaml), "Apply wrote the file");
  assert(unsaved() && bar().dataset.state === "yaml", "an applied edit is not shown as unsaved");
  document.getElementById("bar-save").click();
  await settle();
  assert(/hold_time: 3m/.test(disk.yaml), "Save from the bar did not write");
  assert(!unsaved(), "Save from the bar left the unsaved flag");

  // A form edit beside a hand edit of the YAML is refused, not merged.
  typed(hold, "4");
  var text = document.getElementById("ed-yaml");
  text.value = disk.yaml + "# by hand\n";
  text.dispatchEvent(new Event("input"));
  before = puts().length;
  document.getElementById("ed-save").click();
  await settle();
  assert(puts().length === before, "Save wrote with form and YAML edits both pending");
  said = document.getElementById("ed-status").textContent;
  assert(said.indexOf("You have unapplied form changes") === 0 && said.indexOf("Nothing was saved") > 0, "refusal said: " + said);
  assert(unsaved(), "the refused Save cleared the unsaved flag");
  assert(/hold_time: 3m/.test(disk.yaml), "the refused Save changed the file");

  // An invalid field stops the apply, so Save writes nothing.
  text.value = disk.yaml;
  typed(hold, "x");
  before = puts().length;
  document.getElementById("ed-save").click();
  await settle();
  assert(puts().length === before, "Save wrote with an invalid field");
  assert(document.getElementById("ed-status").textContent.indexOf("Nothing was saved: the form changes were not applied.") === 0, "invalid field: " + document.getElementById("ed-status").textContent);
}

function isAscii(text) {
  for (var i = 0; i < text.length; i++) if (text.charCodeAt(i) > 0x7e || (text.charCodeAt(i) < 0x20 && text.charCodeAt(i) !== 10)) return false;
  return true;
}
function yamlBox() { return document.getElementById("ed-yaml"); }
function shown(id) { return !document.getElementById(id).hidden; }

// noExampleValues fails on any input in the page whose placeholder is not a
// short search hint: a grey example reads as a value that is set (#350).
function noExampleValues() {
  var hints = ["Prefix, AS, or name", "Search countries"];
  document.querySelectorAll("input").forEach(function (n) {
    var ph = n.getAttribute("placeholder");
    assert(!ph || hints.indexOf(ph) >= 0, "input " + (n.getAttribute("id") || n.getAttribute("aria-label") || n.className) + " shows the placeholder " + ph);
  });
}

// helpText is the help line of the field that holds input.
function helpText(input) {
  var help = input.parentNode.querySelector(".field-help");
  return help ? help.textContent : "";
}

// liveFresh (#350): the server holds a config with no setup. Every wizard
// field is empty with no placeholder, and the examples are in the help line.
async function liveFresh() {
  var wait = async function (cond, what) {
    for (var i = 0; i < 200 && !cond(); i++) await new Promise(function (r) { setTimeout(r, 10); });
    assert(cond(), "timed out waiting for " + what);
  };
  await wait(function () { return yamlBox().value !== "" && typeof form === "object" && form.providers; }, "the config to load");
  assert(!shown("wz-again") && shown("wz-body"), "the wizard is not open on a fresh box");
  ["wz-asn", "wz-router", "wz-edge", "wz-prefix", "wz-host", "wz-flow-addr", "wz-flow-port"].forEach(function (id) {
    var n = document.getElementById(id);
    assert(n.value === "" && n.placeholder === "", id + " is not empty: value " + n.value + " placeholder " + n.placeholder);
  });
  assert(helpText(document.getElementById("wz-asn")).indexOf("64512") >= 0, "ASN help: " + helpText(document.getElementById("wz-asn")));
  assert(helpText(document.getElementById("wz-router")).indexOf("192.0.2.10") >= 0, "router help: " + helpText(document.getElementById("wz-router")));
  assert(helpText(document.getElementById("wz-edge")).indexOf("192.0.2.254") >= 0, "edge help: " + helpText(document.getElementById("wz-edge")));
  var row = document.getElementById("wz-providers").querySelectorAll("input,select");
  assert(row.length >= 6, "provider row has " + row.length + " controls");
  row.forEach(function (n) { assert(n.value === "" && n.placeholder === "", "provider control " + (n.getAttribute("aria-label") || n.className) + " is not empty"); });
  var labels = document.getElementById("wz-providers").querySelectorAll(".field-label").map(function (n) { return n.textContent; });
  ["Provider AS", "Type", "IPv6 probe address", "IPv6 next hop"].forEach(function (l) {
    assert(labels.indexOf(l) >= 0, "provider row has no " + l + " field: " + labels.join(", "));
  });
  document.getElementById("wz-next").click();
  assert(document.getElementById("wz-status").textContent !== "" && !shown("wz-2"), "Next went on with empty fields");
  assert(document.getElementById("wz-asn").value === "", "Next filled the ASN");
  noExampleValues();
  assert(document.getElementById("fm-cap").placeholder === "" && helpText(document.getElementById("fm-cap")).indexOf("Default: 50") >= 0, "the cap default is not shown as text: " + helpText(document.getElementById("fm-cap")));
}

// liveWizard (#345): the server holds a working config with three providers
// and sign-in on. The wizard starts collapsed, a one-provider run shows a diff
// and what is lost without touching the editor, and after the operator
// confirms the editor text still has sign-in on.
async function liveWizard() {
  var wait = async function (cond, what) {
    for (var i = 0; i < 200 && !cond(); i++) await new Promise(function (r) { setTimeout(r, 10); });
    assert(cond(), "timed out waiting for " + what);
  };
  await wait(function () { return yamlBox().value !== "" && typeof form === "object" && form.providers; }, "the config to load");
  var original = yamlBox().value;
  assert(/auth:\n\s+enabled: true/.test(original), "the fixture has no sign-in");

  assert(shown("wz-again") && !shown("wz-body"), "the wizard is open on a configured box");
  assert(document.getElementById("wz-reopen").textContent === "Run setup again (replaces your config)", "reopen button says " + document.getElementById("wz-reopen").textContent);
  assert(document.getElementById("wz-run").textContent.indexOf("replaces your config") >= 0, "generate button says " + document.getElementById("wz-run").textContent);
  document.getElementById("wz-reopen").click();
  assert(shown("wz-body") && !shown("wz-again"), "Run setup again did not open the wizard");
  assert(document.getElementById("wz-asn").value === "64512" && document.getElementById("wz-router").value === "192.0.2.10" && document.getElementById("wz-edge").value === "192.0.2.254",
    "the wizard did not start from the running config: " + document.getElementById("wz-asn").value + " " + document.getElementById("wz-router").value + " " + document.getElementById("wz-edge").value);
  assert(wzProviders.length === 3 && wzProviders[2].name === "transit-c" && wzProviders[2].next_hop === "192.0.2.3", "providers were not prefilled: " + JSON.stringify(wzProviders));
  noExampleValues();
  assert(shown("wz-auth-row") && !document.getElementById("wz-auth-off").checked, "the sign-in checkbox is missing or ticked");

  document.getElementById("wz-asn").value = "64512";
  document.getElementById("wz-router").value = "192.0.2.10";
  document.getElementById("wz-edge").value = "192.0.2.254";
  wzProviders = [{name: "transit-a", source_ip: "192.0.2.11", next_hop: "192.0.2.1", asn: "64496", type: "transit", source_ip6: "2001:db8::11", next_hop6: "2001:db8::1"}];
  renderWzProviders();

  document.getElementById("wz-run").click();
  await wait(function () { return shown("wz-confirm"); }, "the confirm step");
  var removes = document.getElementById("wz-removes").querySelectorAll("li").map(function (li) { return li.textContent; });
  assert(removes.indexOf("Removes 2 providers (transit-b, transit-c)") >= 0, "removes = " + removes.join(" | "));
  var diff = document.getElementById("wz-diff").textContent;
  assert(diff.indexOf("-   - name: transit-b") >= 0 && diff.indexOf("+ hold_time: 15m") >= 0, "diff:\n" + diff);
  assert(isAscii(diff + removes.join("")), "the diff has non-ASCII text");
  assert(yamlBox().value === original, "the editor changed before the operator confirmed");

  document.getElementById("wz-confirm-no").click();
  assert(!shown("wz-confirm") && yamlBox().value === original, "Cancel changed the editor");

  document.getElementById("wz-run").click();
  await wait(function () { return shown("wz-confirm"); }, "the confirm step again");
  document.getElementById("wz-confirm-yes").click();
  var out = yamlBox().value;
  assert(out !== original, "confirm did not replace the editor text");
  assert(/auth:\n\s+enabled: true/.test(out), "sign-in is gone after the wizard:\n" + out);
  assert(/config_editor: true/.test(out) && /path: \/data\/history\.db/.test(out), "http or storage lost:\n" + out);
  assert(out.indexOf("transit-b") < 0 && out.indexOf("name: transit-a") >= 0, "providers after the wizard:\n" + out);
  assert(/name: transit-a-v6\n\s+source_ip: 2001:db8::11\n\s+next_hop: 2001:db8::1\n\s+asn: 64496\n\s+type: transit/.test(out), "the IPv6 twin, ASN, or type is missing:\n" + out);
  fs.writeFileSync(process.env.PACKETEER_OUT, out);
}

process.on("unhandledRejection", function (err) {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
main();
