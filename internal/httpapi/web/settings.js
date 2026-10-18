"use strict";

var base = "";
var form = emptyForm();

function emptyForm() {
  return {mode: "", hold_time: "", max_improvements: "", min_loss_delta_pct: "", min_rtt_delta_ms: "",
    min_rtt_delta_pct: "", confirm_rounds: "",
    precedence: "", scorer_type: "", floor_max_loss_pct: "", floor_max_rtt: "",
    providers: [], targets: [], allowlist: [],
    flows: [], policies: [], vips: [], outages: [], exchanges: [],
    inbound: emptyInbound(), anomaly: emptyAnomaly(), commit: emptyCommit()};
}

function emptyCommit() {
  return {scorer: "", balance: "", hosts: [], providers: []};
}

function emptyInbound() {
  return {enabled: false, mode: "observe", prefixes: [], local_pref: "", release_pct: "", max_improvements: "", moderated: [],
    has_announcer: false,
    performance: {enabled: false, loss_pct: "", latency_ms: "", min_prefixes: "", release_pct: ""},
    damping: {disabled: false, confirm: "", backoff: "", max_hold: ""}};
}

function emptyAnomaly() {
  return {enabled: false, mitigation_mode: "", mitigation_allowlist: [], rules: []};
}

// A new entry has no key: Apply adds it to the file. An existing entry
// keeps the key the server gave it, so unseen config keys survive.
function emptyFlow() {
  return {key: "", name: "", listen: [], window: "", top_n: "", max_targets: "", tail_interval: "", min_bytes: "", min_pct: "",
    aggregate_v4: "", aggregate_v6: "", exclude: []};
}

function emptyPolicy() {
  return {key: "", name: "", geoip_db: "", rules: []};
}

function emptyRule() {
  return {key: "", name: "", action: "ignore", providers: [], prefixes: [], asns: [], countries: [], traffic: "", max_loss_pct: "", max_rtt: ""};
}

function emptyVIP() {
  return {key: "", name: "", interval: "", max_targets: "", prefixes: [], asns: []};
}

function emptyExchange() {
  return {key: "", name: "", lans: [], bmp: "", group: "", peers: [emptyPeer()]};
}

function emptyPeer() {
  return {key: "", name: "", asn: "", next_hop: "", source_ip: "", cost: ""};
}

function emptyOutage() {
  return {key: "", name: "", min_prefixes: "", window: "", loss_pct: "", rtt_ms: "", interval: "", max_targets: "", ignore_asns: []};
}

// The hidden inbound prefix field still round-trips as a comma list.
function listText(list) { return (list || []).join(", "); }
function splitList(text) { return text.split(/[\s,]+/).filter(Boolean); }
function byId(id) { return document.getElementById(id); }

// guide is filled from reads the page already makes. Empty lists leave the
// field as free text (#329). Nothing here is announced.
var guide = {hops: [], sources: [], asns: [], asnNames: {}, originated: [], targets: []};
var dlSeq = 0;
var protoNames = ["icmp", "tcp", "udp", "gre", "esp", "ah", "icmpv6", "sctp"];

function pushUnique(list, value) {
  if (value && list.indexOf(value) < 0) list.push(value);
}
function rememberHop(value) { pushUnique(guide.hops, value); }
function rememberSource(value) { if (value && (checkIPv4(value) || parseV6(value) != null)) pushUnique(guide.sources, value); }
function rememberASN(n, name) {
  var s = String(n || "");
  if (!s || s === "0") return;
  pushUnique(guide.asns, s);
  if (name) guide.asnNames[s] = name;
}
function asnName(n) { return guide.asnNames[String(n)] || ""; }
function hopOptions() { return guide.hops.slice(); }
function knownGroups() {
  var out = [];
  (form.exchanges || []).forEach(function (x) { pushUnique(out, x.group); });
  (form.providers || []).forEach(function (p) { pushUnique(out, p.group); });
  return out;
}
// foldDiscovered folds members of running exchanges that the form has,
// matched by name, like the discovered list (#155).
function foldDiscovered() {
  (form.exchanges || []).forEach(function (x) {
    exchangeMembers(x.name).forEach(function (d) {
      rememberHop(d.next_hop);
      if (d.asn) rememberASN(d.asn);
    });
  });
}
function exchangeMembers(name) {
  var running = runningExchanges.filter(function (r) { return r.name === name; })[0];
  return (running && running.discovered) || [];
}

function errFor(node) {
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
function showErr(node, msg) {
  var e = errFor(node);
  if (!e) return;
  e.textContent = msg || "";
  e.hidden = !msg;
}
function attachCheck(input, fn) {
  input.dataset.check = "1";
  input.addEventListener("blur", function () { showErr(input, fn() || ""); });
}

function ipv4Parts(s) {
  var p = String(s || "").split(".");
  if (p.length !== 4) return null;
  var n = 0n;
  for (var i = 0; i < 4; i++) {
    if (!/^\d+$/.test(p[i]) || (p[i].length > 1 && p[i].charAt(0) === "0") || Number(p[i]) > 255) return null;
    n = (n << 8n) + BigInt(p[i]);
  }
  return n;
}
function parseV6(s) {
  if (!s || s.indexOf("%") >= 0) return null;
  var head = s;
  if (s.indexOf(".") >= 0) {
    var last = s.lastIndexOf(":");
    if (last < 0) return null;
    var v4 = ipv4Parts(s.slice(last + 1));
    if (v4 == null) return null;
    head = s.slice(0, last + 1) + ((v4 >> 16n) & 0xffffn).toString(16) + ":" + (v4 & 0xffffn).toString(16);
  }
  var halves = head.split("::");
  if (halves.length > 2) return null;
  function groups(side) {
    if (side === "") return [];
    var g = side.split(":");
    for (var i = 0; i < g.length; i++) if (!/^[0-9a-fA-F]{1,4}$/.test(g[i])) return null;
    return g;
  }
  var left = groups(halves[0]);
  if (!left) return null;
  if (halves.length === 2) {
    var right = groups(halves[1]);
    if (!right) return null;
    var fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    var zeros = [];
    for (var z = 0; z < fill; z++) zeros.push("0");
    left = left.concat(zeros, right);
  } else if (left.length !== 8) return null;
  if (left.length !== 8) return null;
  var addr = 0n;
  for (var j = 0; j < 8; j++) addr = (addr << 16n) + BigInt(parseInt(left[j], 16));
  return addr;
}
function checkIPv4(s) { return ipv4Parts(s) != null; }
function checkIP(s) { return !s || checkIPv4(s) || parseV6(s) != null; }
function parsePrefix(s) {
  var slash = String(s || "").lastIndexOf("/");
  if (slash <= 0) return null;
  var ip = s.slice(0, slash);
  var bitsText = s.slice(slash + 1);
  if (!/^\d+$/.test(bitsText)) return null;
  var bits = Number(bitsText);
  var v4 = ipv4Parts(ip);
  if (v4 != null) {
    if (bits > 32) return null;
    return {addr: v4, bits: bits, v: 4, host: hostBits(v4, bits, 32)};
  }
  if (ip.indexOf(":") < 0) return null;
  var v6 = parseV6(ip);
  if (v6 == null || bits > 128) return null;
  return {addr: v6, bits: bits, v: 6, host: hostBits(v6, bits, 128)};
}
function hostBits(addr, bits, width) {
  if (bits === width) return false;
  if (bits === 0) return addr !== 0n;
  var mask = (1n << BigInt(width - bits)) - 1n;
  return (addr & mask) !== 0n;
}
function samePrefix(a, b) { return !!a && !!b && a.v === b.v && a.bits === b.bits && a.addr === b.addr; }
function prefixInside(p, a) {
  if (!p || !a || p.v !== a.v || a.bits > p.bits) return false;
  var width = p.v === 4 ? 32 : 128;
  if (a.bits === 0) return true;
  var shift = BigInt(width - a.bits);
  return (p.addr >> shift) === (a.addr >> shift);
}
function checkCIDR(v, allowEmpty, list, index) {
  if (!v) return allowEmpty ? "" : "Enter a prefix or remove the row.";
  var p = parsePrefix(v);
  if (!p) return "Enter a prefix, for example 192.0.2.0/24.";
  if (p.host) return "That prefix has host bits. Use the network address.";
  if (list) {
    for (var i = 0; i < list.length; i++) {
      if (i === index) continue;
      if (samePrefix(p, parsePrefix(list[i]))) return "That prefix is already listed.";
    }
  }
  return "";
}
function checkASN(s, list) {
  if (!/^\d+$/.test(s || "")) return "Enter an AS number.";
  var n = Number(s);
  if (!isFinite(n) || n < 1 || n > 4294967295 || Math.floor(n) !== n) return "Enter an AS number from 1 to 4294967295.";
  if (list) {
    for (var i = 0; i < list.length; i++) if (Number(list[i]) === n) return "That AS is already listed.";
  }
  return "";
}
// readPeerASN stores the number when the field has an optional "AS" prefix.
// The check accepts that prefix; Apply must not send the letters.
function readPeerASN(raw) {
  var q = String(raw || "").trim();
  var bare = q.replace(/^AS/i, "");
  if (checkASN(bare, null) === "") return String(Number(bare));
  return q;
}
function checkInt(v, min, max) {
  if (!v) return "";
  if (!/^\d+$/.test(v)) return "Enter a whole number from " + min + " to " + max + ".";
  var n = Number(v);
  if (n < min || n > max) return "Enter a whole number from " + min + " to " + max + ".";
  return "";
}
function checkNum(v, min, max) {
  if (!v) return "";
  if (!/^(\d+(\.\d+)?|\.\d+)$/.test(v)) return "Enter a number from " + min + " to " + max + ".";
  var n = Number(v);
  if (n < min || n > max) return "Enter a number from " + min + " to " + max + ".";
  return "";
}
function checkPctOpen(v) {
  if (!v) return "";
  var err = checkNum(v, 0, 100);
  if (err) return "Enter a percent greater than 0 and at most 100.";
  if (Number(v) <= 0) return "Enter a percent greater than 0 and at most 100.";
  return "";
}
function durationMs(v) {
  var re = /^(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)/;
  var rest = v;
  if (!rest) return null;
  var total = 0;
  while (rest) {
    var m = re.exec(rest);
    if (!m) return null;
    var mul = {ns: 1e-6, us: 0.001, ms: 1, s: 1000, m: 60000, h: 3600000}[m[2]];
    total += Number(m[1]) * mul;
    rest = rest.slice(m[0].length);
  }
  return total;
}
function checkDuration(v, minMs, maxMs) {
  if (!v) return "";
  var ms = durationMs(v);
  if (ms == null) return "Enter a duration such as 15m or 10ms.";
  if (minMs != null && ms < minMs) return "That duration is too short.";
  if (maxMs != null && ms > maxMs) return "That duration is too long.";
  return "";
}
function checkPort(v, min, max) {
  if (!v) return "Enter a port from " + min + " to " + max + ".";
  return checkInt(v, min, max);
}

var durRe = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/;
function splitDur(raw) {
  var m = String(raw || "").match(durRe);
  return m ? {n: m[1], u: m[2]} : null;
}
function readDur(id) {
  var num = byId(id);
  var unit = byId(id + "-unit");
  if (!num) return "";
  if (num.dataset.dirty !== "1" && (!unit || unit.dataset.dirty !== "1")) return num.dataset.raw || "";
  if (num.type === "text") return num.value.trim();
  var n = num.value.trim();
  if (!n) return "";
  return n + (unit ? unit.value : "");
}
function writeDur(id, raw, defUnit) {
  var num = byId(id);
  var unit = byId(id + "-unit");
  var hidden = byId(id + "-raw");
  if (!num) return;
  raw = raw || "";
  num.dataset.raw = raw;
  delete num.dataset.dirty;
  if (unit) delete unit.dataset.dirty;
  if (hidden) {
    hidden.value = raw;
    if (raw) hidden.setAttribute("value", raw); else hidden.removeAttribute("value");
  }
  var parsed = splitDur(raw);
  if (raw && !parsed) {
    num.type = "text";
    num.value = raw;
    num.setAttribute("value", raw);
    if (unit) unit.hidden = true;
    return;
  }
  num.type = "number";
  if (unit) unit.hidden = false;
  if (parsed) {
    num.value = parsed.n;
    num.setAttribute("value", parsed.n);
    if (unit) unit.value = parsed.u;
  } else {
    num.value = "";
    num.removeAttribute("value");
    if (unit && defUnit) unit.value = defUnit;
  }
}
function readNum(id) {
  var n = byId(id);
  if (!n) return "";
  if (n.dataset.dirty !== "1") return n.dataset.raw || "";
  return n.value.trim();
}
function writeNum(id, raw) {
  var n = byId(id);
  if (!n) return;
  raw = raw || "";
  n.dataset.raw = raw;
  delete n.dataset.dirty;
  if (raw && !/^[-+]?\d+(\.\d+)?$/.test(raw)) n.type = "text";
  else n.type = "number";
  n.value = raw;
  if (raw) n.setAttribute("value", raw); else n.removeAttribute("value");
}
function readSigned(id) {
  var n = byId(id);
  var on = byId(id + "-on");
  if (!n) return "";
  if (n.dataset.dirty !== "1" && (!on || on.dataset.dirty !== "1")) return n.dataset.raw || "";
  if (on && !on.checked) {
    var mag = n.value.trim();
    return mag ? "-" + mag.replace(/^-/, "") : "-1";
  }
  return n.value.trim();
}
function writeSigned(id, raw) {
  var n = byId(id);
  var on = byId(id + "-on");
  if (!n) return;
  raw = raw || "";
  n.dataset.raw = raw;
  delete n.dataset.dirty;
  if (on) delete on.dataset.dirty;
  var v = parseFloat(raw);
  var neg = raw !== "" && !isNaN(v) && v < 0;
  if (on) {
    on.checked = !neg;
    if (neg) on.removeAttribute("checked"); else on.setAttribute("checked", "checked");
  }
  var shown = neg ? raw.replace(/^\s*-/, "") : raw;
  n.value = shown;
  if (shown) n.setAttribute("value", shown); else n.removeAttribute("value");
}

function markDirty(node) { node.dataset.dirty = "1"; }

function validateGuided() {
  var root = document.getElementById("editor-section") || document;
  Array.prototype.forEach.call(root.querySelectorAll("[data-check]"), function (n) {
    n.dispatchEvent(new Event("blur"));
  });
  Array.prototype.forEach.call(root.querySelectorAll(".g-cidr-input"), function (input) {
    if (!input.value.trim()) showErr(input, "Enter a prefix or remove the row.");
  });
  Array.prototype.forEach.call(root.querySelectorAll(".g-port"), function (input) {
    var row = input.parentNode;
    var host = row.querySelector(".g-host");
    if (host && !host.value.trim() && !input.value.trim()) showErr(input, "Enter a port or remove the row.");
  });
}

function block(parent, label, node, help, key) {
  var box = el("div", "field");
  var span = el("span", "field-label", label);
  if (key) span.title = key;
  box.appendChild(span);
  box.appendChild(node);
  if (node && node._dl) box.appendChild(node._dl);
  if (help) box.appendChild(el("span", "field-help", help));
  var err = el("span", "field-error", "");
  err.hidden = true;
  box.appendChild(err);
  parent.appendChild(box);
  return box;
}

function comboInput(value, options, placeholder, wide) {
  var input = rowInput(value, placeholder || "", wide);
  input.className = (input.className ? input.className + " " : "") + "g-combo";
  var opts = options || [];
  if (!opts.length) return input;
  dlSeq++;
  var dl = el("datalist");
  dl.id = "dl-" + dlSeq;
  opts.forEach(function (o) {
    var opt = el("option");
    opt.value = o[0];
    if (o[1] && o[1] !== o[0]) opt.label = o[1];
    dl.appendChild(opt);
  });
  input.setAttribute("list", dl.id);
  input._dl = dl;
  return input;
}

function numberInput(raw, spec) {
  var input = el("input");
  spec = spec || {};
  input.type = "number";
  input.className = "g-num" + (spec.cls ? " " + spec.cls : "");
  if (spec.min != null) input.min = String(spec.min);
  if (spec.max != null) input.max = String(spec.max);
  input.step = spec.integer ? "1" : "any";
  if (spec.def != null) input.placeholder = String(spec.def);
  input.spellcheck = false;
  writeNumOn(input, raw || "");
  return input;
}
function writeNumOn(input, raw) {
  raw = raw || "";
  input.dataset.raw = raw;
  delete input.dataset.dirty;
  if (raw && !/^[-+]?\d+(\.\d+)?$/.test(raw)) input.type = "text";
  input.value = raw;
  if (raw) input.setAttribute("value", raw); else input.removeAttribute("value");
}
function readNumOn(input) {
  if (input.dataset.dirty !== "1") return input.dataset.raw || "";
  return input.value.trim();
}

function numberControl(obj, key, spec) {
  spec = spec || {};
  var wrap = el("span", "unit-row");
  var input = numberInput(obj[key], spec);
  input.addEventListener("input", function () { markDirty(input); obj[key] = readNumOn(input); });
  attachCheck(input, function () {
    var v = readNumOn(input);
    if (spec.integer) {
      if (spec.refuse && v === spec.refuse) return spec.refuse + " is refused. Use 2 or more, or leave it empty.";
      return checkInt(v, spec.min, spec.max);
    }
    if (spec.pctOpen) return checkPctOpen(v);
    if (spec.positive && v && Number(v) <= 0) return "Enter a number greater than 0.";
    if (spec.min != null) return checkNum(v, spec.min, spec.max == null ? 1e15 : spec.max);
    return "";
  });
  wrap.appendChild(input);
  if (spec.unit) wrap.appendChild(el("span", "unit", spec.unit));
  return wrap;
}
function bindNumber(parent, label, obj, key, help, configKey, spec) {
  parent.appendChild(labeled(label, numberControl(obj, key, spec), help, configKey));
}

function bindText(parent, label, obj, key, placeholder, help, configKey, wide, check) {
  var input = rowInput(obj[key], placeholder, wide);
  input.dataset.raw = obj[key] || "";
  input.addEventListener("input", function () { markDirty(input); obj[key] = input.value.trim(); });
  if (check) attachCheck(input, function () { return check(input.value.trim()); });
  parent.appendChild(labeled(label, input, help, configKey));
  return input;
}

// The hidden g-raw input holds the YAML value as an attribute so a DOM dump
// shows what the file says (the CI settings smoke matches value="10m"); the
// number box only holds the number.
function durationBox(raw, defUnit, withMs) {
  var wrap = el("span", "g-dur");
  var hidden = el("input");
  hidden.type = "hidden";
  hidden.className = "g-raw";
  var num = el("input");
  num.className = "g-num";
  num.min = "0";
  num.step = "any";
  num.spellcheck = false;
  var unit = el("select");
  unit.className = "g-unit";
  unit.setAttribute("aria-label", "Unit");
  var units = withMs ? ["ms", "s", "m", "h"] : ["s", "m", "h"];
  var parsed = splitDur(raw);
  if (parsed && units.indexOf(parsed.u) < 0) units.push(parsed.u);
  units.forEach(function (u) {
    var o = el("option", "", u);
    o.value = u;
    if ((parsed && parsed.u === u) || (!parsed && u === defUnit)) o.setAttribute("selected", "selected");
    unit.appendChild(o);
  });
  raw = raw || "";
  num.dataset.raw = raw;
  if (raw) hidden.setAttribute("value", raw);
  hidden.value = raw;
  if (raw && !parsed) {
    num.type = "text";
    num.value = raw;
    num.setAttribute("value", raw);
    unit.hidden = true;
  } else {
    num.type = "number";
    if (parsed) {
      num.value = parsed.n;
      num.setAttribute("value", parsed.n);
      unit.value = parsed.u;
    }
  }
  function composed() {
    if (num.dataset.dirty !== "1" && unit.dataset.dirty !== "1") return num.dataset.raw || "";
    if (num.type === "text") return num.value.trim();
    var n = num.value.trim();
    return n ? n + unit.value : "";
  }
  wrap._read = composed;
  num.addEventListener("input", function () { markDirty(num); });
  unit.addEventListener("change", function () { markDirty(unit); });
  wrap.appendChild(hidden);
  wrap.appendChild(num);
  wrap.appendChild(unit);
  return wrap;
}
function bindDuration(parent, label, obj, key, help, configKey, defUnit, withMs, minMs, maxMs) {
  var wrap = durationBox(obj[key], defUnit, withMs);
  var publish = function () { obj[key] = wrap._read(); };
  wrap.querySelector("input.g-num").addEventListener("input", publish);
  wrap.querySelector("select").addEventListener("change", publish);
  attachCheck(wrap.querySelector("input.g-num"), function () { return checkDuration(wrap._read(), minMs, maxMs); });
  parent.appendChild(labeled(label, wrap, help, configKey));
}

function bindCIDRs(parent, label, obj, key, help, configKey, rerender) {
  var list = obj[key] || [];
  obj[key] = list;
  var box = el("div", "g-cidr");
  list.forEach(function (p, i) {
    var row = el("div", "row");
    var input = rowInput(p, "192.0.2.0/24", true);
    input.className = (input.className ? input.className + " " : "") + "g-cidr-input";
    input.addEventListener("input", function () { markDirty(input); list[i] = input.value.trim(); });
    attachCheck(input, function () { return checkCIDR(input.value.trim(), true, list, i); });
    var err = el("span", "field-error", "");
    err.hidden = true;
    row.appendChild(input);
    row.appendChild(removeButton(list, i, rerender, "prefix"));
    row.appendChild(err);
    box.appendChild(row);
  });
  var add = el("button", "small", "+ Prefix");
  add.type = "button";
  add.addEventListener("click", function () { list.push(""); rerender(); });
  box.appendChild(add);
  block(parent, label, box, help, configKey);
}

function splitHostPort(s) {
  s = s || "";
  var i = s.lastIndexOf(":");
  if (i < 0) return {host: s, port: ""};
  return {host: s.slice(0, i), port: s.slice(i + 1)};
}
function bindListens(parent, label, obj, key, help, configKey, rerender) {
  var list = obj[key] || [];
  obj[key] = list;
  var box = el("div", "g-listen");
  var sources = guide.sources.map(function (s) { return [s, s]; });
  list.forEach(function (addr, i) {
    var row = el("div", "row");
    var hidden = el("input");
    hidden.type = "hidden";
    hidden.className = "g-raw";
    if (addr) { hidden.value = addr; hidden.setAttribute("value", addr); }
    var parts = splitHostPort(addr);
    var host = comboInput(parts.host, sources, "every address", true);
    host.className += " g-host";
    var port = el("input");
    port.type = "number";
    port.min = "1";
    port.max = "65535";
    port.step = "1";
    port.className = "g-port";
    port.placeholder = "2055";
    port.value = parts.port;
    if (parts.port) port.setAttribute("value", parts.port);
    port.dataset.raw = parts.port;
    function write() {
      var h = host.value.trim();
      var p = port.value.trim();
      if (!h && !p) { list[i] = ""; return; }
      if (h.indexOf(":") >= 0 && h.charAt(0) !== "[") h = "[" + h + "]";
      list[i] = (h || "") + ":" + p;
    }
    host.addEventListener("input", function () { markDirty(host); write(); });
    port.addEventListener("input", function () { markDirty(port); write(); });
    attachCheck(port, function () {
      if (!host.value.trim() && !port.value.trim()) return "";
      if (port.dataset.dirty !== "1" && host.dataset.dirty !== "1") return "";
      return checkPort(port.value.trim(), 1, 65535);
    });
    attachCheck(host, function () {
      var h = host.value.trim();
      if (!h) return "";
      var bare = h.charAt(0) === "[" ? h.slice(1, -1) : h;
      return checkIP(bare) ? "" : "Enter an IP address, or leave the host empty.";
    });
    var err = el("span", "field-error", "");
    err.hidden = true;
    row.appendChild(hidden);
    row.appendChild(host);
    if (host._dl) row.appendChild(host._dl);
    row.appendChild(port);
    row.appendChild(removeButton(list, i, rerender, "listen address"));
    row.appendChild(err);
    box.appendChild(row);
  });
  var add = el("button", "small", "+ Listen");
  add.type = "button";
  add.addEventListener("click", function () { list.push(""); rerender(); });
  box.appendChild(add);
  block(parent, label, box, help, configKey);
}

function bindChips(parent, label, obj, key, help, configKey, rerender) {
  var list = obj[key] || [];
  obj[key] = list;
  var box = el("div", "g-chips");
  list.forEach(function (asn, i) {
    var chip = el("span", "chip");
    var name = asnName(asn);
    chip.appendChild(el("span", "", name ? "AS " + asn + " " + name : "AS " + asn));
    chip.appendChild(removeButton(list, i, rerender, "AS"));
    box.appendChild(chip);
  });
  var opts = guide.asns.map(function (a) {
    var name = asnName(a);
    return [a, name ? "AS " + a + " " + name : "AS " + a];
  });
  var add = comboInput("", opts, "AS number or name");
  add.addEventListener("change", function () { commitASN(add, list, rerender); });
  var err = el("span", "field-error", "");
  err.hidden = true;
  box.appendChild(add);
  if (add._dl) box.appendChild(add._dl);
  box.appendChild(err);
  block(parent, label, box, help, configKey);
}
function commitASN(input, list, rerender) {
  var q = input.value.trim();
  if (!q) return;
  var bare = q.replace(/^AS/i, "");
  if (/[A-Za-z]/.test(q.replace(/^AS/i, ""))) {
    api("GET", "/api/search?q=" + encodeURIComponent(q)).then(function (d) {
      var rows = (d && d.asns && d.asns.rows) || [];
      if (!rows.length) { showErr(input, "No matching AS. Type the AS number."); return; }
      // A loose name match must not silently pick one of several ASes.
      var exact = rows.filter(function (r) { return (r.name || "").toLowerCase() === q.toLowerCase(); });
      if (exact.length === 1) rows = exact;
      if (rows.length > 1) {
        showErr(input, "Several ASes match: " + rows.slice(0, 3).map(function (r) { return "AS" + r.asn + (r.name ? " " + r.name : ""); }).join(", ") + ". Type the AS number.");
        return;
      }
      rememberASN(rows[0].asn, rows[0].name);
      var err = checkASN(String(rows[0].asn), list);
      if (err) { showErr(input, err); return; }
      list.push(String(rows[0].asn));
      rerender();
    }, function () { showErr(input, "Lookup failed. Type the AS number."); });
    return;
  }
  var err = checkASN(bare, list);
  if (err) { showErr(input, err); return; }
  list.push(String(Number(bare)));
  rerender();
}

function bindNames(parent, label, obj, key, help, configKey, placeholder, rerender) {
  var list = obj[key] || [];
  obj[key] = list;
  var box = el("div", "g-multi");
  list.forEach(function (name, i) {
    var chip = el("span", "chip");
    chip.appendChild(el("span", "", name));
    chip.appendChild(removeButton(list, i, rerender, "name"));
    box.appendChild(chip);
  });
  var add = rowInput("", placeholder || "name");
  function commit() {
    var v = add.value.trim();
    if (!v) return;
    if (list.indexOf(v) >= 0) { showErr(add, "That name is already listed."); return; }
    list.push(v);
    rerender();
  }
  add.addEventListener("change", commit);
  add.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); commit(); } });
  box.appendChild(add);
  block(parent, label, box, help, configKey);
}

function bindMulti(parent, label, obj, key, help, configKey, options) {
  var list = obj[key] || [];
  obj[key] = list;
  if (!options.length) {
    bindNames(parent, label, obj, key, help, configKey, "name", function () { renderPolicies(); });
    return;
  }
  var box = el("div", "g-multi");
  var sel = el("select");
  sel.multiple = true;
  sel.size = Math.min(6, Math.max(3, options.length));
  var seen = {};
  options.forEach(function (o) { seen[o[0]] = true; });
  list.forEach(function (v) { if (!seen[v]) options = options.concat([[v, v]]); });
  options.forEach(function (o) {
    var opt = el("option", "", o[1]);
    opt.value = o[0];
    opt.setAttribute("value", o[0]);
    if (list.indexOf(o[0]) >= 0) { opt.selected = true; opt.setAttribute("selected", "selected"); }
    sel.appendChild(opt);
  });
  sel.addEventListener("change", function () {
    markDirty(sel);
    var next = [];
    Array.prototype.forEach.call(sel.selectedOptions, function (o) { next.push(o.value); });
    obj[key] = next;
  });
  box.appendChild(sel);
  block(parent, label, box, help, configKey);
}

function bindCountries(parent, label, obj, key, help, configKey) {
  var list = obj[key] || [];
  obj[key] = list;
  var countries = (typeof isoCountries === "undefined") ? [] : isoCountries;
  if (!countries.length) {
    bindChips(parent, label, obj, key, help, configKey, function () { renderPolicies(); });
    return;
  }
  var box = el("div", "g-country");
  var search = el("input");
  search.type = "search";
  search.className = "g-countries";
  search.placeholder = "Search countries";
  search.spellcheck = false;
  var sel = el("select");
  sel.multiple = true;
  sel.size = 6;
  sel.className = "g-countries";
  var known = {};
  countries.forEach(function (c) { known[c[0]] = true; });
  countries.forEach(function (c) {
    var opt = el("option", "", c[0] + " " + c[1]);
    opt.value = c[0];
    if (list.indexOf(c[0]) >= 0) { opt.selected = true; opt.setAttribute("selected", "selected"); }
    sel.appendChild(opt);
  });
  list.forEach(function (code) {
    if (known[code]) return;
    var opt = el("option", "", code);
    opt.value = code;
    opt.selected = true;
    opt.setAttribute("selected", "selected");
    sel.appendChild(opt);
  });
  search.addEventListener("input", function () {
    var q = search.value.trim().toLowerCase();
    Array.prototype.forEach.call(sel.options, function (o) {
      o.hidden = !!q && o.value.toLowerCase().indexOf(q) < 0 && o.textContent.toLowerCase().indexOf(q) < 0;
    });
  });
  sel.addEventListener("change", function () {
    markDirty(sel);
    var next = [];
    Array.prototype.forEach.call(sel.options, function (o) { if (o.selected) next.push(o.value); });
    obj[key] = next;
  });
  box.appendChild(search);
  box.appendChild(sel);
  block(parent, label, box, help, configKey);
}

function bindGroup(parent, obj) {
  var wrap = el("span", "g-toggle");
  var on = el("input");
  on.type = "checkbox";
  on.setAttribute("aria-label", "In a group");
  if (obj.group) { on.checked = true; on.setAttribute("checked", "checked"); }
  var names = knownGroups().map(function (g) { return [g, g]; });
  var combo = comboInput(obj.group, names, "group name");
  combo.disabled = !obj.group;
  on.addEventListener("change", function () {
    markDirty(on);
    combo.disabled = !on.checked;
    if (!on.checked) { combo.value = ""; obj.group = ""; }
    else obj.group = combo.value.trim();
  });
  combo.addEventListener("input", function () { markDirty(combo); obj.group = on.checked ? combo.value.trim() : ""; });
  wrap.appendChild(on);
  wrap.appendChild(el("span", "", "In a group"));
  wrap.appendChild(combo);
  if (combo._dl) wrap.appendChild(combo._dl);
  block(parent, "Group", wrap, "Optional name shared by providers that balance traffic together. Off clears it.", "exchanges.group");
}

function bindGeo(parent, obj) {
  var input = rowInput(obj.geoip_db, "/etc/packeteer/country.mmdb", true);
  input.dataset.raw = obj.geoip_db || "";
  var note = el("span", "field-note", "");
  input.addEventListener("input", function () { markDirty(input); obj.geoip_db = input.value.trim(); note.textContent = ""; });
  attachCheck(input, function () {
    var v = input.value.trim();
    if (!v) return "";
    if (v.charAt(0) !== "/") return "Enter an absolute path.";
    return "";
  });
  input.addEventListener("blur", function () {
    var v = input.value.trim();
    if (!v || v.charAt(0) !== "/") return;
    var yml = "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: lab-a\n    source_ip: 192.0.2.1\n    next_hop: 192.0.2.2\nprobe: {interval: 30s, timeout: 200ms, packets: 1}\nbgp:\n  neighbors:\n    - address: 192.0.2.254\nsources:\n  - type: static\n    config:\n      targets: [{prefix: 198.51.100.0/24}]\npolicies:\n  - type: rules\n    config:\n      geoip_db: " + yamlQuote(v) + "\n      rules:\n        - name: country\n          action: ignore\n          countries: [US]\n";
    api("POST", "/api/config/validate", {yaml: yml}).then(function (res) {
      if (input.value.trim() !== v) return;
      if (res && res.valid) { note.textContent = "File is readable."; return; }
      var line = ((res && res.errors) || []).filter(function (e) { return String(e).indexOf("geoip_db") >= 0; })[0];
      note.textContent = line || "The file could not be opened.";
    }, function () { if (input.value.trim() === v) note.textContent = "Could not check the file."; });
  });
  var lab = labeled("GeoIP database", input, "Absolute path of a country database file mounted in the container.", "policies.geoip_db");
  lab.appendChild(note);
  parent.appendChild(lab);
}
function yamlQuote(s) { return "'" + String(s).replace(/'/g, "''") + "'"; }

function loadGuides() {
  var pending = 3;
  function done() { if (--pending <= 0) refreshGuideWidgets(); }
  api("GET", "/api/providers").then(function (d) {
    ((d && d.providers) || []).forEach(function (p) {
      rememberSource(p.source);
      rememberHop(p.next_hop);
      if (p.peer_asn) rememberASN(p.peer_asn);
    });
    done();
  }, done);
  api("GET", "/api/prefixes?limit=100").then(function (d) {
    ((d && d.prefixes) || []).forEach(function (row) {
      var paths = row.paths || [];
      paths.forEach(function (p) {
        var ap = p.as_path || [];
        if (!ap.length && row.prefix) pushUnique(guide.originated, row.prefix);
        if (ap.length) rememberASN(ap[ap.length - 1]);
      });
    });
    ((d && d.asn_map) || []).forEach(function (n) { if (n.asn) rememberASN(n.asn); });
    done();
  }, done);
  api("GET", "/api/mitigations").then(function (d) {
    var targets = (d && d.catalog && d.catalog.targets) || [];
    targets.forEach(function (t) { if (t && t.name) pushUnique(guide.targets, t.name); });
    done();
  }, done);
}
function refreshGuideWidgets() {
  if (document.querySelector("[data-dirty='1']")) return;
  renderProviders();
  renderExchanges();
  renderPolicies();
  renderFlows();
  renderVIPs();
  renderOutages();
  renderAnomalyRules();
  paintInboundPrefixes();
  if (typeof renderWzProviders === "function") renderWzProviders();
}

function edStatus(text, errors) {
  document.getElementById("ed-status").textContent = text || "";
  var ul = document.getElementById("ed-errors");
  clear(ul);
  (errors || []).forEach(function (e) { ul.appendChild(el("li", "", e)); });
}

function describe(res) {
  if (!res) return "";
  var parts = [res.valid ? "Valid" : "Invalid"];
  if (res.mode) parts.push("mode " + res.mode);
  if (res.changed && res.changed.length) parts.push("changed: " + res.changed.join(", "));
  if (res.restart_required) parts.push("restart required");
  else if (res.reload_online) parts.push("applies online");
  if (res.enables_inject) parts.push("turns inject on");
  return parts.join(" · ");
}

// explain turns an API error into what the operator should do (#49).
function explain(err) {
  if (err.status === 404) return "The config editor is off. To use it and the wizard, set http.config_editor: true in the mounted file, turn on auth (or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD), mount the file writable, and restart. Until then, edit the file on the host.";
  if (err.status === 401) return "Sign in required. Reload the page to sign in.";
  if (err.status === 403) return err.message + " (the editor and wizard need the admin role, and auth or basic auth).";
  if (!err.status) return "Cannot reach the controller: " + err.message;
  return err.message;
}

function editorOff(err) {
  var off = err.status === 404 || err.status === 403;
  var node = document.getElementById("ed-off");
  node.textContent = explain(err);
  node.hidden = !off;
  ["ed-load", "ed-check", "ed-save", "wz-run", "wz-next", "wz-next-2", "wz-back", "wz-back-3", "wz-add-provider", "wz-sug", "form-apply", "form-reload", "form-add-provider", "form-add-target", "form-add-allow", "sug-refresh", "form-add-flow", "form-add-policy", "form-add-vip", "form-add-outage", "form-add-exchange", "ix-refresh", "form-add-anomaly-rule", "wz-next-3", "wz-back-4", "cs-add-host", "cs-apply"].forEach(function (id) {
    var b = document.getElementById(id);
    if (b) b.disabled = off;
  });
  ["form-fields", "form-flows", "form-policies", "form-vips", "form-outages", "form-inbound"].forEach(function (id) {
    var fields = document.getElementById(id);
    if (fields) fields.disabled = off;
  });
}

function loadConfig() {
  api("GET", "/api/config").then(function (f) {
    base = f.sha256;
    document.getElementById("ed-yaml").value = f.yaml;
    document.getElementById("ed-path").textContent = f.path;
    document.getElementById("ed-sha").textContent = f.sha256.slice(0, 12);
    document.getElementById("ed-off").hidden = true;
    edStatus("Loaded.");
    loadForm(f.yaml);
    loadSuggestions();
    loadDiscovered();
    loadGuides();
  }, function (err) { editorOff(err); edStatus(explain(err)); });
}

function checkConfig() {
  api("POST", "/api/config/validate", {yaml: document.getElementById("ed-yaml").value}).then(function (res) {
    edStatus(describe(res), res.errors);
  }, function (err) { edStatus(err.message); });
}

function saveConfig() {
  var body = {yaml: document.getElementById("ed-yaml").value, base: base,
    confirm_inject: document.getElementById("ed-inject").checked};
  api("PUT", "/api/config", body).then(function (out) {
    base = out.file.sha256;
    document.getElementById("ed-sha").textContent = base.slice(0, 12);
    document.getElementById("ed-inject").checked = false;
    var extra = "";
    if (out.applied && out.applied.length) extra = " Applied online: " + out.applied.join(", ") + ".";
    if (out.apply_error) extra = " Not applied: " + out.apply_error;
    edStatus("Saved. " + describe(out.result) + extra);
  }, function (err) {
    var res = err.data && err.data.result;
    edStatus(err.message + (res ? " — " + describe(res) : ""), res && res.errors);
  });
}

function formStatus(text) {
  document.getElementById("form-status").textContent = text || "";
}

function readKnobs() {
  form.mode = document.getElementById("fm-mode").value;
  form.hold_time = readDur("fm-hold");
  form.max_improvements = readNum("fm-cap");
  form.min_loss_delta_pct = readNum("fm-loss");
  form.min_rtt_delta_ms = readNum("fm-rtt");
  form.min_rtt_delta_pct = readNum("fm-rtt-pct");
  form.confirm_rounds = readNum("fm-rounds");
  form.precedence = document.getElementById("fm-precedence").value;
  form.floor_max_loss_pct = readNum("fm-floor-loss");
  form.floor_max_rtt = readDur("fm-floor-rtt");
  readSections();
}

function readSections() {
  var inb = form.inbound;
  inb.enabled = byId("in-enabled").checked;
  inb.mode = byId("in-mode").value;
  if (byId("in-prefixes").dataset.dirty === "1") inb.prefixes = splitList(byId("in-prefixes").value);
  inb.local_pref = readNum("in-local-pref");
  inb.release_pct = readNum("in-release");
  inb.max_improvements = readNum("in-cap");
  if (byId("in-mod-commit").dataset.dirty === "1" || byId("in-mod-perf").dataset.dirty === "1") {
    inb.moderated = [];
    if (byId("in-mod-commit").checked) inb.moderated.push("commit");
    if (byId("in-mod-perf").checked) inb.moderated.push("performance");
  }
  inb.performance = {enabled: byId("in-perf").checked, loss_pct: readSigned("in-perf-loss"), latency_ms: readSigned("in-perf-latency"),
    min_prefixes: readNum("in-perf-min"), release_pct: readNum("in-perf-release")};
  inb.damping = {disabled: byId("in-damp-off").checked, confirm: readDur("in-damp-confirm"), backoff: readNum("in-damp-backoff"), max_hold: readDur("in-damp-max")};
}

// setVal and setChecked also write the attribute, so the saved value is
// visible in the markup (the UI smoke test reads the rendered DOM).
function setVal(id, value) {
  var n = byId(id);
  n.value = value || "";
  if (value) n.setAttribute("value", value); else n.removeAttribute("value");
}

function setChecked(id, on) {
  var n = byId(id);
  n.checked = !!on;
  if (on) n.setAttribute("checked", "checked"); else n.removeAttribute("checked");
}

function fillSections() {
  fillInbound();
  fillAnomalyState();
}

// modeBadge sets a per-block observe or inject badge (#131).
function modeBadge(id, mode) {
  var b = byId(id);
  var m = mode === "inject" || mode === "suggest" || mode === "observe" ? mode : "unknown";
  b.className = "badge mode-" + m;
  b.textContent = mode || "not configured";
}

function fillInbound() {
  var i = form.inbound;
  setChecked("in-enabled", i.enabled);
  // Inject is offered only while the file already has it.
  var sel = byId("in-mode");
  Array.prototype.slice.call(sel.options).forEach(function (o) { if (o.value === "inject") sel.removeChild(o); });
  if (i.mode === "inject") {
    var o = el("option", "", "inject (set in the YAML)");
    o.value = "inject";
    sel.appendChild(o);
  }
  sel.value = i.mode || "observe";
  delete byId("in-prefixes").dataset.dirty;
  delete byId("in-mod-commit").dataset.dirty;
  delete byId("in-mod-perf").dataset.dirty;
  setVal("in-prefixes", listText(i.prefixes));
  writeNum("in-local-pref", i.local_pref);
  writeNum("in-release", i.release_pct);
  writeNum("in-cap", i.max_improvements);
  setChecked("in-mod-commit", (i.moderated || []).indexOf("commit") >= 0);
  setChecked("in-mod-perf", (i.moderated || []).indexOf("performance") >= 0);
  setChecked("in-perf", i.performance.enabled);
  writeSigned("in-perf-loss", i.performance.loss_pct);
  writeSigned("in-perf-latency", i.performance.latency_ms);
  writeNum("in-perf-min", i.performance.min_prefixes);
  writeNum("in-perf-release", i.performance.release_pct);
  setChecked("in-damp-off", i.damping.disabled);
  writeDur("in-damp-confirm", i.damping.confirm, "m");
  writeNum("in-damp-backoff", i.damping.backoff);
  writeDur("in-damp-max", i.damping.max_hold, "m");
  paintInboundPrefixes();
  modeBadge("in-badge", i.enabled ? i.mode : "");
  byId("in-badge-text").textContent = i.mode === "inject"
    ? "Inject announces steer routes for allowlisted prefixes in the learned RIB."
    : "Observe and suggest announce nothing.";
  byId("in-announcer").textContent = i.enabled ? (i.has_announcer ? "An announcer is configured." : "No announcer is configured, so inject could not start.") : "";
}

function paintInboundPrefixes() {
  var box = byId("in-prefix-box");
  var hidden = byId("in-prefixes");
  if (!box || !hidden || !form.inbound) return;
  clear(box);
  var list = form.inbound.prefixes || [];
  var known = {};
  guide.originated.forEach(function (p) { known[p] = true; });
  if (guide.originated.length) {
    guide.originated.forEach(function (p) {
      var lab = el("label", "check");
      var cb = el("input");
      cb.type = "checkbox";
      cb.value = p;
      cb.setAttribute("value", p);
      if (list.indexOf(p) >= 0) { cb.checked = true; cb.setAttribute("checked", "checked"); }
      cb.addEventListener("change", function () { syncInboundPrefixes(box); });
      lab.appendChild(cb);
      lab.appendChild(el("span", "", p));
      box.appendChild(lab);
    });
  }
  list.forEach(function (p) {
    if (known[p]) return;
    var row = el("div", "row");
    var input = rowInput(p, "203.0.113.0/24", true);
    input.className = "wide-input g-cidr-input";
    input.addEventListener("input", function () { markDirty(input); syncInboundPrefixes(box); });
    attachCheck(input, function () { return checkCIDR(input.value.trim(), true, form.inbound.prefixes, form.inbound.prefixes.indexOf(input.value.trim())); });
    var err = el("span", "field-error", "");
    err.hidden = true;
    row.appendChild(input);
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove prefix";
    minus.addEventListener("click", function () {
      form.inbound.prefixes = (form.inbound.prefixes || []).filter(function (x) { return x !== p; });
      hidden.dataset.dirty = "1";
      paintInboundPrefixes();
    });
    row.appendChild(minus);
    row.appendChild(err);
    box.appendChild(row);
  });
  var add = el("button", "small", "+ Prefix");
  add.type = "button";
  add.addEventListener("click", function () {
    form.inbound.prefixes.push("");
    hidden.dataset.dirty = "1";
    paintInboundPrefixes();
  });
  box.appendChild(add);
  setVal("in-prefixes", listText(list.filter(Boolean)));
}
function syncInboundPrefixes(box) {
  var next = [];
  Array.prototype.forEach.call(box.querySelectorAll("input[type=checkbox]"), function (c) { if (c.checked) next.push(c.value); });
  Array.prototype.forEach.call(box.querySelectorAll(".g-cidr-input"), function (inp) {
    var v = inp.value.trim();
    if (v && next.indexOf(v) < 0) next.push(v);
  });
  form.inbound.prefixes = next;
  var hidden = byId("in-prefixes");
  hidden.dataset.dirty = "1";
  setVal("in-prefixes", listText(next));
}

function fillAnomalyState() {
  var a = form.anomaly;
  modeBadge("an-badge", a.enabled ? (a.mitigation_mode || "observe") : "");
  byId("an-badge-text").textContent = a.mitigation_mode === "inject"
    ? "Mitigation is in inject: a matching rule can announce a rule for a learned prefix."
    : "Mitigation is not in inject: a matching rule is recorded and nothing is announced.";
  byId("an-state").textContent = a.enabled
    ? "Rule prefixes must be inside the mitigation allowlist" + ((a.mitigation_allowlist || []).length ? ": " + a.mitigation_allowlist.join(", ") + "." : ".")
    : "Anomaly detection is not configured. Add an anomaly block with a detector to the YAML first (docs/anomaly.md).";
  byId("form-add-anomaly-rule").disabled = !a.enabled;
}

var ruleActions = [["ignore", "ignore (native routing)"], ["allow", "allow (only these providers)"], ["deny", "deny (never these providers)"],
  ["static", "static (pin one provider)"], ["vip", "vip (admit first at the cap)"]];

function selectInput(options, value) {
  var sel = el("select");
  options.forEach(function (o) {
    var opt = el("option", "", o[1]);
    opt.value = o[0];
    opt.setAttribute("value", o[0]);
    sel.appendChild(opt);
  });
  sel.value = value || "";
  Array.prototype.forEach.call(sel.options, function (o) { if (o.value === (value || "")) o.setAttribute("selected", "selected"); });
  return sel;
}

// moveButtons returns up and down buttons that reorder list in place.
function moveButtons(list, i, rerender, what) {
  var out = [];
  [["▲", -1, "Move " + what + " up"], ["▼", 1, "Move " + what + " down"]].forEach(function (d) {
    var b = el("button", "small", d[0]);
    b.type = "button";
    b.title = d[2];
    b.disabled = i + d[1] < 0 || i + d[1] >= list.length;
    b.addEventListener("click", function () {
      var moved = list.splice(i, 1)[0];
      list.splice(i + d[1], 0, moved);
      rerender();
    });
    out.push(b);
  });
  return out;
}

function removeButton(list, i, rerender, what) {
  var b = el("button", "small", "-");
  b.type = "button";
  b.title = "Remove " + what;
  b.addEventListener("click", function () { list.splice(i, 1); rerender(); });
  return b;
}

// entryCard is one source or policy. Its name is what a second entry of the
// same type needs: the loader requires unique instance names.
function entryCard(root, heading, list, i, rerender, what, ordered) {
  var card = el("div", "card");
  var head = el("div", "card-head");
  head.appendChild(el("strong", "", heading + " " + (i + 1)));
  if (ordered) moveButtons(list, i, rerender, what).forEach(function (b) { head.appendChild(b); });
  head.appendChild(removeButton(list, i, rerender, what));
  card.appendChild(head);
  root.appendChild(card);
  return card;
}

function entryRow(card) {
  var row = el("div", "row");
  card.appendChild(row);
  return row;
}

function renderFlows() {
  var root = byId("form-flows");
  clear(root);
  form.flows.forEach(function (f, i) {
    var card = entryCard(root, "Flow source", form.flows, i, renderFlows, "flow source", false);
    var a = entryRow(card), b = entryRow(card);
    var n = i + 1;
    bindText(a, "Name (flow " + n + ")", f, "name", "flow", "Name of this collector. A second one needs its own name.", "sources.flow.name");
    bindListens(a, "Listen (flow " + n + ")", f, "listen", "Host and UDP port for NetFlow, IPFIX, or sFlow. One row per address.", "sources.flow.listen", renderFlows);
    bindCIDRs(a, "Exclude (flow " + n + ")", f, "exclude", "Prefixes this collector ignores. One per row.", "sources.flow.exclude", renderFlows);
    bindDuration(b, "Window", f, "window", "How long one flow sample covers.", "sources.flow.window", "m", false, 1000, 86400000);
    bindNumber(b, "Top N", f, "top_n", "How many busiest prefixes are probed every round.", "sources.flow.top_n", {min: 1, max: 10000, integer: true, def: 100});
    bindNumber(b, "Max targets", f, "max_targets", "Cap on prefixes this collector adds. Empty uses Top N.", "sources.flow.max_targets", {min: 0, max: 10000, integer: true});
    bindDuration(b, "Tail interval", f, "tail_interval", "How often the prefixes below the top are probed.", "sources.flow.tail_interval", "s", false, 1000, 86400000);
    bindNumber(b, "Min bytes", f, "min_bytes", "Ignore a prefix below this many bytes. Empty is off.", "sources.flow.min_bytes", {min: 0, max: 1e15, integer: true, def: 0});
    bindNumber(b, "Min share", f, "min_pct", "Ignore a prefix below this percent of traffic. Empty is off.", "sources.flow.min_pct", {min: 0, max: 100, unit: "%", def: 0, cls: "g-pct"});
    bindNumber(b, "Aggregate IPv4", f, "aggregate_v4", "Fold IPv4 flows up to this length, from 1 to 32.", "sources.flow.aggregate_v4", {min: 1, max: 32, integer: true, def: 24, unit: "/n", cls: "g-agg"});
    bindNumber(b, "Aggregate IPv6", f, "aggregate_v6", "Fold IPv6 flows up to this length, from 1 to 128.", "sources.flow.aggregate_v6", {min: 1, max: 128, integer: true, def: 48, unit: "/n", cls: "g-agg"});
  });
  if (!form.flows.length) root.appendChild(el("p", "empty", "No flow sources."));
}

var bmpChoices = [["", "off"], ["prefer", "prefer"], ["only", "only"]];

function renderExchanges() {
  var root = byId("form-exchanges");
  clear(root);
  form.exchanges.forEach(function (x, i) {
    var card = entryCard(root, "Exchange", form.exchanges, i, renderExchanges, "exchange", false);
    var a = entryRow(card);
    bindText(a, "Name (exchange " + (i + 1) + ")", x, "name", "ix-lab", "Name of this exchange. It must be unique.", "exchanges.name");
    bindCIDRs(a, "Peering LANs (exchange " + (i + 1) + ")", x, "lans", "Peering LAN prefixes. One per row.", "exchanges.lans", renderExchanges);
    bindGroup(a, x);
    var bmp = selectInput(bmpChoices, x.bmp);
    bmp.className = "g-select";
    bmp.addEventListener("change", function () { x.bmp = bmp.value; });
    a.appendChild(labeled("BMP (exchange " + (i + 1) + ")", bmp, "How this exchange uses BMP. Off leaves the route check to add-path.", "exchanges.bmp"));
    var members = exchangeMembers(x.name);
    var memberHops = hopOptions();
    var memberASNs = guide.asns.slice();
    members.forEach(function (d) {
      pushUnique(memberHops, d.next_hop);
      if (d.asn) pushUnique(memberASNs, String(d.asn));
    });
    x.peers.forEach(function (p, j) {
      var row = entryRow(card);
      bindText(row, "Peer name", p, "name", "ix-peer-a", "Name of this peer. It must be unique.", "exchanges.peers.name");
      var asn = comboInput(p.asn, memberASNs.map(function (a) { return [a, asnName(a) ? "AS " + a + " " + asnName(a) : "AS " + a]; }), "64501");
      asn.addEventListener("input", function () { markDirty(asn); p.asn = readPeerASN(asn.value); });
      attachCheck(asn, function () {
        p.asn = readPeerASN(asn.value);
        return p.asn ? checkASN(p.asn, null) : "";
      });
      row.appendChild(labeled("Peer AS", asn, "Peer AS. Pick a discovered member, or type the number.", "exchanges.peers.asn"));
      var hop = comboInput(p.next_hop, memberHops.map(function (h) { return [h, h]; }), "203.0.113.11");
      hop.addEventListener("input", function () { markDirty(hop); p.next_hop = hop.value.trim(); });
      attachCheck(hop, function () {
        if (!p.next_hop) return "";
        if (!checkIPv4(p.next_hop) && parseV6(p.next_hop) == null) return "Enter an IP address.";
        if (!x.lans.length) return "";
        var addr = parsePrefix(p.next_hop + (p.next_hop.indexOf(":") >= 0 ? "/128" : "/32"));
        var lans = x.lans.map(parsePrefix).filter(Boolean);
        if (addr && lans.length && !lans.some(function (lan) { return prefixInside(addr, lan); })) return "That next hop is not on a peering LAN of this exchange.";
        return "";
      });
      row.appendChild(labeled("Peer next hop", hop, "Next hop on a peering LAN. Pick a discovered member, or type it.", "exchanges.peers.next_hop"));
      var src = comboInput(p.source_ip, guide.sources.map(function (s) { return [s, s]; }), "192.0.2.31");
      src.addEventListener("input", function () { markDirty(src); p.source_ip = src.value.trim(); });
      attachCheck(src, function () {
        if (!p.source_ip) return "";
        return (checkIPv4(p.source_ip) || parseV6(p.source_ip) != null) ? "" : "Enter an IP address.";
      });
      row.appendChild(labeled("Peer probe source", src, "Local address probes to this peer leave from.", "exchanges.peers.source_ip"));
      bindNumber(row, "Peer cost", p, "cost", "Price per Mbps for this peer.", "exchanges.peers.cost", {min: 0, max: 1e12, unit: "per Mbps"});
      if (p.draft) row.appendChild(el("span", "tag", "draft"));
      row.appendChild(removeButton(x.peers, j, renderExchanges, "peer"));
    });
    var add = el("button", "small", "+ Peer");
    add.type = "button";
    add.addEventListener("click", function () { x.peers.push(emptyPeer()); renderExchanges(); });
    card.appendChild(add);
  });
  if (!form.exchanges.length) root.appendChild(el("p", "empty", "No exchanges."));
  renderDiscovered();
}

var runningExchanges = [];

// Discovered LAN members come from the running exchanges (GET
// /api/exchanges), so only an exchange that is already running, matched by
// name, lists any. A member that is already a peer row is not offered again.
function renderDiscovered() {
  var root = byId("form-ix-discovered");
  clear(root);
  var shown = 0;
  form.exchanges.forEach(function (x) {
    var running = runningExchanges.filter(function (r) { return r.name === x.name; })[0];
    if (!running) return;
    var taken = {};
    x.peers.forEach(function (p) { if (p.next_hop) taken[p.next_hop] = true; });
    (running.discovered || []).filter(function (d) { return !taken[d.next_hop]; }).forEach(function (d) {
      shown++;
      var row = el("div", "row");
      row.appendChild(el("span", "tag", x.name));
      row.appendChild(el("span", "mono", d.next_hop));
      row.appendChild(el("span", "tag", d.asn ? "AS " + d.asn : "AS unknown"));
      row.appendChild(el("span", "tag", d.prefixes + " prefixes"));
      var b = el("button", "small", "Accept");
      b.type = "button";
      b.addEventListener("click", function () { acceptDiscovered(x, d); });
      row.appendChild(b);
      root.appendChild(row);
    });
  });
  if (!shown) root.appendChild(el("p", "empty", "No discovered members. Refresh after the exchange has routes."));
}

// acceptDiscovered adds a draft peer row. It does not call the API, so it
// cannot write a peer, start probing, or announce.
function acceptDiscovered(x, d) {
  x.peers.push({key: "", name: "", asn: d.asn ? String(d.asn) : "", next_hop: d.next_hop, source_ip: "", cost: "", draft: true});
  renderExchanges();
  formStatus("Draft peer added to " + x.name + ". Name it and fill in the probe source. Cost stays empty. Nothing is saved.");
}

function loadDiscovered() {
  api("GET", "/api/exchanges").then(function (out) {
    runningExchanges = (out && out.exchanges) || [];
    foldDiscovered();
    if (document.querySelector("[data-dirty='1']")) renderDiscovered();
    else refreshGuideWidgets();
  }, function () { runningExchanges = []; renderDiscovered(); });
}

function renderOutages() {
  var root = byId("form-outages");
  clear(root);
  form.outages.forEach(function (o, i) {
    var card = entryCard(root, "Outage detection", form.outages, i, renderOutages, "outage detection", false);
    var a = entryRow(card);
    bindText(a, "Name (outage " + (i + 1) + ")", o, "name", "outage", "Name of this detector.", "sources.outage.name");
    bindNumber(a, "Min prefixes", o, "min_prefixes", "How many prefixes must fail together. 1 is refused.", "sources.outage.min_prefixes", {min: 0, max: 100000, integer: true, def: 3, refuse: "1"});
    bindDuration(a, "Window", o, "window", "How far back the detector looks.", "sources.outage.window", "m", false, 0, 86400000);
    bindNumber(a, "Loss", o, "loss_pct", "Loss percent that counts as a failure.", "sources.outage.loss_pct", {min: 0, max: 100, unit: "%", def: 20, cls: "g-pct"});
    bindNumber(a, "RTT", o, "rtt_ms", "Latency in milliseconds that counts as a failure. Empty is off.", "sources.outage.rtt_ms", {min: 0, max: 1e12, unit: "ms"});
    bindDuration(a, "Interval", o, "interval", "How often the detector runs.", "sources.outage.interval", "s", false, 0, 86400000);
    bindNumber(a, "Max targets", o, "max_targets", "How many prefixes it re-probes.", "sources.outage.max_targets", {min: 0, max: 100000, integer: true, def: 100});
    bindChips(a, "Ignore ASNs", o, "ignore_asns", "Origin AS numbers this detector skips.", "sources.outage.ignore_asns", renderOutages);
  });
  if (!form.outages.length) root.appendChild(el("p", "empty", "No outage detection."));
}

function renderVIPs() {
  var root = byId("form-vips");
  clear(root);
  form.vips.forEach(function (v, i) {
    var card = entryCard(root, "VIP source", form.vips, i, renderVIPs, "VIP source", false);
    var a = entryRow(card);
    bindText(a, "Name (VIP " + (i + 1) + ")", v, "name", "vip", "Name of this VIP source.", "sources.vip.name");
    bindDuration(a, "Interval", v, "interval", "How often these prefixes are probed.", "sources.vip.interval", "s", false, 1000, 86400000);
    bindNumber(a, "Max targets", v, "max_targets", "Cap on prefixes this source probes. At least 1; empty uses 100.", "sources.vip.max_targets", {min: 1, max: 100000, integer: true, def: 100});
    bindChips(a, "VIP ASNs", v, "asns", "Origin AS numbers probed on this interval.", "sources.vip.asns", renderVIPs);
    v.prefixes.forEach(function (t, j) {
      var row = entryRow(card);
      var prefix = rowInput(t.prefix, "203.0.113.0/24", true);
      prefix.className = "wide-input g-cidr-input";
      prefix.addEventListener("input", function () { markDirty(prefix); t.prefix = prefix.value.trim(); });
      attachCheck(prefix, function () { return checkCIDR(prefix.value.trim(), true, v.prefixes.map(function (x) { return x.prefix; }), j); });
      row.appendChild(labeled("VIP prefix", prefix, "Prefix probed on the VIP interval.", "sources.vip.prefixes"));
      var host = rowInput(t.host, "203.0.113.1");
      host.addEventListener("input", function () { markDirty(host); t.host = host.value.trim(); });
      attachCheck(host, function () {
        if (!t.host) return "";
        if (!(checkIPv4(t.host) || parseV6(t.host) != null)) return "Enter an IP address.";
        var p = parsePrefix(t.prefix);
        var addr = parsePrefix(t.host + (t.host.indexOf(":") >= 0 ? "/128" : "/32"));
        if (p && addr && !prefixInside(addr, p)) return "That host is outside the prefix.";
        return "";
      });
      row.appendChild(labeled("Pinned host", host, "Optional address inside the prefix.", "sources.vip.host"));
      row.appendChild(removeButton(v.prefixes, j, renderVIPs, "VIP prefix"));
    });
    var add = el("button", "small", "+ VIP prefix");
    add.type = "button";
    add.addEventListener("click", function () { v.prefixes.push({key: "", prefix: "", host: ""}); renderVIPs(); });
    card.appendChild(add);
  });
  if (!form.vips.length) root.appendChild(el("p", "empty", "No VIP sources."));
}

function ruleRow(card, p, r, j) {
  var row = entryRow(card);
  var action = selectInput(ruleActions, r.action);
  var traffic = selectInput([["", "any traffic"], ["transit", "transit"], ["local", "local"]], r.traffic);
  action.addEventListener("change", function () { r.action = action.value; });
  traffic.addEventListener("change", function () { r.traffic = traffic.value; });
  bindText(row, "Rule name", r, "name", "name", "Name of this rule.", "policies.rules.name");
  action.className = "g-select";
  row.appendChild(labeled("Action", action, "What the rule does when it matches.", "policies.rules.action"));
  var provOpts = (form.providers || []).map(function (p) { return p.name ? [p.name, p.name] : null; }).filter(Boolean);
  (form.exchanges || []).forEach(function (x) { (x.peers || []).forEach(function (p) { if (p.name) provOpts.push([p.name, p.name]); }); });
  bindMulti(row, "Providers", r, "providers", "Providers this rule names. Pick from the providers above.", "policies.rules.providers", provOpts);
  bindCIDRs(row, "Prefixes", r, "prefixes", "Prefixes this rule matches. One per row.", "policies.rules.prefixes", renderPolicies);
  bindChips(row, "Origin ASNs", r, "asns", "Origin AS numbers this rule matches.", "policies.rules.asns", renderPolicies);
  bindCountries(row, "Countries", r, "countries", "Countries this rule matches. The saved value is the two-letter code.", "policies.rules.countries");
  traffic.className = "g-select";
  row.appendChild(labeled("Traffic class", traffic, "Limit the rule to transit or local traffic, or leave it as any.", "policies.rules.traffic"));
  bindNumber(row, "Max loss (%)", r, "max_loss_pct", "Highest loss a pinned path may show. Only for a static pin.", "policies.rules.max_loss_pct", {min: 0, max: 100, unit: "%", cls: "g-pct"});
  bindDuration(row, "Max RTT", r, "max_rtt", "Highest delay a pinned path may show. Only for a static pin.", "policies.rules.max_rtt", "ms", true, 0, 86400000);
  moveButtons(p.rules, j, renderPolicies, "rule").forEach(function (b) { row.appendChild(b); });
  row.appendChild(removeButton(p.rules, j, renderPolicies, "rule"));
}

// Rule order is evaluation order, so rules and policies both reorder.
function renderPolicies() {
  var root = byId("form-policies");
  clear(root);
  form.policies.forEach(function (p, i) {
    var card = entryCard(root, "Policy", form.policies, i, renderPolicies, "policy", true);
    var head = entryRow(card);
    bindText(head, "Name (policy " + (i + 1) + ")", p, "name", "rules", "Name of this policy. A second one needs its own name.", "policies.name");
    bindGeo(head, p);
    p.rules.forEach(function (r, j) { ruleRow(card, p, r, j); });
    var add = el("button", "small", "+ Rule");
    add.type = "button";
    add.addEventListener("click", function () { p.rules.push(emptyRule()); renderPolicies(); });
    card.appendChild(add);
  });
  if (!form.policies.length) root.appendChild(el("p", "empty", "No policies. Native routing and the normal thresholds apply."));
}

var anomalyActions = [["blackhole", "blackhole"], ["redirect", "redirect"], ["flowspec_drop", "flowspec drop"],
  ["flowspec_rate_limit", "flowspec rate limit"], ["flowspec_redirect", "flowspec redirect"]];

function renderAnomalyRules() {
  var root = byId("form-anomaly-rules");
  clear(root);
  var allow = form.anomaly.mitigation_allowlist || [];
  form.anomaly.rules.forEach(function (r, i) {
    var row = el("div", "row");
    bindText(row, "Anomaly rule name", r, "name", "udp-flood", "Name of this rule. The first match wins.", "anomaly.rules.name");
    if (allow.length) anomalyPrefixPicks(row, r, allow);
    else bindCIDRs(row, "Anomaly rule prefixes", r, "prefixes", "Prefixes this rule matches. One per row.", "anomaly.rules.prefixes", renderAnomalyRules);
    var protoOpts = protoNames.map(function (n) { return [n, n]; });
    bindMulti(row, "Anomaly rule protocols", r, "protocols", "Protocols that must match. Leave none selected to match any.", "anomaly.rules.protocols", protoOpts);
    bindNumber(row, "Anomaly rule min Mbit/s", r, "min_mbps", "Rate that arms this rule.", "anomaly.rules.min_mbps", {min: 0, max: 1e12, unit: "Mbps"});
    var action = selectInput(anomalyActions, r.action);
    action.className = "g-select";
    action.addEventListener("change", function () { r.action = action.value; });
    row.appendChild(labeled("Anomaly rule action", action, "What the mitigation controller is asked to do.", "anomaly.rules.action"));
    var target = comboInput(r.target, guide.targets.map(function (t) { return [t, t]; }), "scrubber");
    target.addEventListener("input", function () { markDirty(target); r.target = target.value.trim(); });
    row.appendChild(labeled("Anomaly rule target", target, "Redirect target. Type a name when none is known yet.", "anomaly.rules.target"));
    bindNumber(row, "Anomaly rule rate Mbit/s", r, "rate_mbps", "Rate cap for a rate-limit action.", "anomaly.rules.rate_mbps", {min: 0, max: 1e12, unit: "Mbps"});
    bindDuration(row, "Anomaly rule TTL", r, "ttl", "How long the mitigation rule stays. Empty uses the mitigation default.", "anomaly.rules.ttl", "m", false, 0, 86400000 * 30);
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove anomaly rule";
    minus.addEventListener("click", function () { form.anomaly.rules.splice(i, 1); renderAnomalyRules(); });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!form.anomaly.rules.length) root.appendChild(el("p", "empty", "No anomaly rules. Anomalies are detected and reported, and no mitigation rule is added."));
}

function anomalyPrefixPicks(row, r, allow) {
  var box = el("div", "g-prefixes");
  var known = {};
  allow.forEach(function (p) { known[p] = true; });
  allow.forEach(function (p) {
    var lab = el("label", "check");
    var cb = el("input");
    cb.type = "checkbox";
    cb.value = p;
    cb.setAttribute("value", p);
    if ((r.prefixes || []).indexOf(p) >= 0) { cb.checked = true; cb.setAttribute("checked", "checked"); }
    cb.addEventListener("change", function () {
      markDirty(cb);
      var next = [];
      Array.prototype.forEach.call(box.querySelectorAll("input[type=checkbox]"), function (c) { if (c.checked) next.push(c.value); });
      (r.prefixes || []).forEach(function (x) { if (!known[x] && next.indexOf(x) < 0) next.push(x); });
      r.prefixes = next;
    });
    lab.appendChild(cb);
    lab.appendChild(el("span", "", p));
    box.appendChild(lab);
  });
  // More-specifics of the allowlist are valid and must be removable. A prefix
  // outside it is an error until this row is removed, or Apply stays blocked.
  // The checkbox handler replaces the prefix list, so this control has to
  // drop the prefix from the list it finds at click time.
  (r.prefixes || []).forEach(function (p) {
    if (known[p]) return;
    var line = el("div", "row");
    line.appendChild(el("span", "", p));
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove prefix";
    minus.addEventListener("click", function () {
      var list = r.prefixes || [];
      var at = list.indexOf(p);
      if (at >= 0) list.splice(at, 1);
      renderAnomalyRules();
    });
    line.appendChild(minus);
    if (!prefixListed(p, allow)) line.appendChild(el("span", "field-error", p + " is not inside the mitigation allowlist."));
    box.appendChild(line);
  });
  block(row, "Anomaly rule prefixes", box, "Pick prefixes inside the mitigation allowlist. A more-specific already in the file is listed and can be removed.", "anomaly.rules.prefixes");
}
function prefixListed(p, allow) {
  var parsed = parsePrefix(p);
  if (!parsed) return false;
  return allow.map(parsePrefix).filter(Boolean).some(function (a) { return prefixInside(parsed, a); });
}

function fillKnobs() {
  fillSections();
  document.getElementById("fm-mode").value = form.mode || "";
  writeDur("fm-hold", form.hold_time, "m");
  writeNum("fm-cap", form.max_improvements);
  writeNum("fm-loss", form.min_loss_delta_pct);
  writeNum("fm-rtt", form.min_rtt_delta_ms);
  writeNum("fm-rtt-pct", form.min_rtt_delta_pct);
  writeNum("fm-rounds", form.confirm_rounds);
  writeNum("fm-floor-loss", form.floor_max_loss_pct);
  writeDur("fm-floor-rtt", form.floor_max_rtt, "ms");
  var sel = document.getElementById("fm-precedence");
  clear(sel);
  var scorer = form.scorer_type || "";
  var note = document.getElementById("fm-scorer");
  if (scorer === "cost") {
    [["performance", "performance wins"], ["cost", "cost wins"]].forEach(function (o) {
      var opt = el("option", "", o[1]);
      opt.value = o[0];
      sel.appendChild(opt);
    });
    sel.value = form.precedence || "performance";
    sel.disabled = false;
    note.textContent = "Scorer is cost. Extra loss and extra delay are the floor a cheaper path must stay inside.";
  } else if (scorer && scorer !== "weighted") {
    var opt = el("option", "", "not used (scorer is " + scorer + ")");
    opt.value = "";
    sel.appendChild(opt);
    sel.value = "";
    sel.disabled = true;
    note.textContent = "These knobs belong to the cost scorer. This file uses " + scorer + ". Change the scorer in the YAML if you mean to replace it.";
  } else {
    [["", "not used (scorer is " + (scorer || "weighted") + ")"], ["performance", "performance wins"], ["cost", "cost wins"]].forEach(function (o) {
      var opt = el("option", "", o[1]);
      opt.value = o[0];
      sel.appendChild(opt);
    });
    sel.value = form.precedence || "";
    sel.disabled = false;
    note.textContent = "Choosing cost or performance, or setting the floor, switches the scorer to cost and keeps its other settings. Leave it unused to keep the current scorer.";
  }
}

function rowInput(value, placeholder, wide) {
  var input = el("input");
  input.type = "text";
  input.value = value || "";
  if (value) input.setAttribute("value", value);
  input.placeholder = placeholder;
  input.spellcheck = false;
  if (wide) input.className = "wide-input";
  return input;
}

// labeled keeps the name visible after the field is filled. The label
// text is the accessible name (#171). help is one visible line. key is
// the config name and stays on the tooltip.
function labeled(text, input, help, key) {
  var lab = el("label", "field");
  var span = el("span", "field-label", text);
  if (key) span.title = key;
  lab.appendChild(span);
  lab.appendChild(input);
  if (input && input._dl) lab.appendChild(input._dl);
  if (help) lab.appendChild(el("span", "field-help", help));
  var err = el("span", "field-error", "");
  err.hidden = true;
  lab.appendChild(err);
  return lab;
}

function renderProviders() {
  var root = document.getElementById("form-providers");
  clear(root);
  var hops = hopOptions().map(function (h) { return [h, h]; });
  var sources = guide.sources.map(function (s) { return [s, s]; });
  form.providers.forEach(function (p, i) {
    var row = el("div", "row");
    var name = rowInput(p.name, "name");
    var src = comboInput(p.source_ip, sources, "probe source");
    var hop = comboInput(p.next_hop, hops, "next hop");
    name.addEventListener("input", function () { markDirty(name); form.providers[i].name = name.value.trim(); });
    src.addEventListener("input", function () { markDirty(src); form.providers[i].source_ip = src.value.trim(); });
    hop.addEventListener("input", function () { markDirty(hop); form.providers[i].next_hop = hop.value.trim(); });
    attachCheck(src, function () {
      var v = form.providers[i].source_ip;
      if (!v) return "";
      return (checkIPv4(v) || parseV6(v) != null) ? "" : "Enter an IP address.";
    });
    attachCheck(hop, function () {
      var v = form.providers[i].next_hop;
      if (!v) return "";
      return (checkIPv4(v) || parseV6(v) != null) ? "" : "Enter an IP address.";
    });
    row.appendChild(labeled("Name", name, "Name of this provider. It must be unique.", "providers.name"));
    row.appendChild(labeled("Probe source", src, "Local address probes leave from. Pick one already in use, or type an address.", "providers.source_ip"));
    row.appendChild(labeled("Next hop", hop, "Provider next hop seen on BGP or BMP, or type an address.", "providers.next_hop"));
    row.appendChild(labeled("Cost", numberControl(p, "cost", {min: 0, max: 1e12, unit: "per Mbps"}), "Price per Mbps.", "providers.cost"));
    row.appendChild(labeled("Commit", numberControl(p, "commit_mbps", {min: 0, max: 1e12, unit: "Mbps", positive: true}), p.commit_bound ? "Billing commit in Mbps." : "Billing commit in Mbps. This provider has no telemetry binding yet.", "providers.commit_mbps"));
    if (p.asn) row.appendChild(el("span", "tag", "AS " + p.asn + " from the session, not saved"));
    else if (p.draft) row.appendChild(el("span", "tag", "draft"));
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove provider";
    minus.addEventListener("click", function () {
      form.providers.splice(i, 1);
      renderProviders();
      renderSuggestions(lastSuggestions);
    });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!form.providers.length) root.appendChild(el("p", "empty", "No providers. Add one before applying."));
}

function renderTargets() {
  var root = document.getElementById("form-targets");
  clear(root);
  form.targets.forEach(function (t, i) {
    var row = el("div", "row");
    var prefix = rowInput(t.prefix, "192.0.2.0/24", true);
    prefix.className = "wide-input g-cidr-input";
    var host = rowInput(t.host, "192.0.2.10");
    prefix.addEventListener("input", function () { markDirty(prefix); form.targets[i].prefix = prefix.value.trim(); });
    host.addEventListener("input", function () { markDirty(host); form.targets[i].host = host.value.trim(); });
    attachCheck(prefix, function () { return checkCIDR(prefix.value.trim(), true, form.targets.map(function (x) { return x.prefix; }), i); });
    attachCheck(host, function () {
      var h = form.targets[i].host;
      if (!h) return "";
      if (!(checkIPv4(h) || parseV6(h) != null)) return "Enter an IP address.";
      var p = parsePrefix(form.targets[i].prefix);
      var addr = parsePrefix(h + (h.indexOf(":") >= 0 ? "/128" : "/32"));
      if (p && addr && !prefixInside(addr, p)) return "That host is outside the prefix.";
      return "";
    });
    row.appendChild(labeled("Prefix", prefix, "Prefix to probe.", "sources.static.prefix"));
    row.appendChild(labeled("Host", host, "Optional address inside the prefix. Empty probes a few addresses inside it.", "sources.static.host"));
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove prefix";
    minus.addEventListener("click", function () { form.targets.splice(i, 1); renderTargets(); });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!form.targets.length) root.appendChild(el("p", "empty", "No static probe prefixes. Other sources in the YAML are unchanged."));
}

function renderAllow() {
  var root = document.getElementById("form-allow");
  clear(root);
  form.allowlist.forEach(function (prefix, i) {
    var row = el("div", "row");
    var input = rowInput(prefix, "192.0.2.0/24", true);
    input.className = "wide-input g-cidr-input";
    input.addEventListener("input", function () { markDirty(input); form.allowlist[i] = input.value.trim(); });
    attachCheck(input, function () { return checkCIDR(input.value.trim(), true, form.allowlist, i); });
    row.appendChild(labeled("Prefix", input, "Prefix that may be injected.", "allowlist"));
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove allowlist prefix";
    minus.addEventListener("click", function () { form.allowlist.splice(i, 1); renderAllow(); });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!form.allowlist.length) root.appendChild(el("p", "empty", "Allowlist is empty. Inject cannot announce until a prefix is listed and the file is saved."));
}

function renderForm() {
  fillKnobs();
  renderProviders();
  renderTargets();
  renderAllow();
  renderFlows();
  renderPolicies();
  renderVIPs();
  renderOutages();
  renderExchanges();
  renderAnomalyRules();
  renderSuggestions(lastSuggestions);
  // commitsetup.js loads after this file and renders once itself.
  if (typeof renderCommitSetup === "function") renderCommitSetup();
}

function loadForm(yaml) {
  formStatus("Reading the form…");
  api("POST", "/api/config/form", {yaml: yaml, apply: false}).then(function (out) {
    form = out.form || emptyForm();
    if (!form.providers) form.providers = [];
    if (!form.targets) form.targets = [];
    if (!form.allowlist) form.allowlist = [];
    loadFormDefaults();
    foldDiscovered();
    renderForm();
    formStatus("");
  }, function (err) {
    formStatus(explain(err) + " The YAML is unchanged. Fix it, then reload the form.");
  });
}

// loadProtectionDefaults fills the #131 sections a reply may leave out.
function loadProtectionDefaults() {
  var blank = emptyForm();
  form.inbound = Object.assign(blank.inbound, form.inbound || {});
  form.inbound.performance = Object.assign(emptyInbound().performance, form.inbound.performance || {});
  form.inbound.damping = Object.assign(emptyInbound().damping, form.inbound.damping || {});
  ["prefixes", "moderated"].forEach(function (k) { if (!form.inbound[k]) form.inbound[k] = []; });
  form.anomaly = Object.assign(blank.anomaly, form.anomaly || {});
  if (!form.anomaly.rules) form.anomaly.rules = [];
  if (!form.anomaly.mitigation_allowlist) form.anomaly.mitigation_allowlist = [];
  form.anomaly.rules.forEach(function (r) {
    ["prefixes", "protocols"].forEach(function (k) { if (!r[k]) r[k] = []; });
  });
}

function loadFormDefaults() {
  form.commit = Object.assign(emptyCommit(), form.commit || {});
  form.commit.hosts = form.commit.hosts || [];
  form.commit.providers = form.commit.providers || [];
  loadProtectionDefaults();
  ["flows", "policies", "vips", "outages", "exchanges"].forEach(function (k) { if (!form[k]) form[k] = []; });
  form.exchanges.forEach(function (x) {
    ["lans", "peers"].forEach(function (k) { if (!x[k]) x[k] = []; });
  });
  form.flows.forEach(function (f) {
    ["listen", "exclude"].forEach(function (k) { if (!f[k]) f[k] = []; });
  });
  form.policies.forEach(function (p) {
    if (!p.rules) p.rules = [];
    p.rules.forEach(function (r) {
      ["providers", "prefixes", "asns", "countries"].forEach(function (k) { if (!r[k]) r[k] = []; });
    });
  });
  form.vips.forEach(function (v) {
    ["prefixes", "asns"].forEach(function (k) { if (!v[k]) v[k] = []; });
  });
  form.outages.forEach(function (o) { if (!o.ignore_asns) o.ignore_asns = []; });
}

function applyForm() {
  readKnobs();
  validateGuided();
  // Wizard fields sit outside the editor. An empty wizard must not block Apply.
  var root = document.getElementById("editor-section") || document;
  var bad = root.querySelectorAll(".field-error");
  for (var i = 0; i < bad.length; i++) {
    if (!bad[i].hidden && bad[i].textContent) {
      formStatus("Fix the highlighted fields before applying. Nothing was written.");
      return;
    }
  }
  postForm(formStatus);
}

// postForm merges the form into the YAML in the editor. It resolves with
// the reply, or with null after report() was given the refusal.
function postForm(report) {
  report("Applying to the YAML…");
  return api("POST", "/api/config/form", {yaml: document.getElementById("ed-yaml").value, apply: true, form: form}).then(function (out) {
    document.getElementById("ed-yaml").value = out.yaml;
    if (out.form) {
      form = out.form;
      loadFormDefaults();
    }
    renderForm();
    report("Applied to the YAML. Not saved. Validate, then Save. Save applies thresholds, policies, sources, probe timing, mode, the allowlist, and bgp.neighbors online. Any other change waits for a restart.");
    return out;
  }, function (err) {
    report(explain(err));
    return null;
  });
}

var lastSuggestions = [];

function renderSuggestions(list) {
  lastSuggestions = list || [];
  var root = document.getElementById("form-suggestions");
  clear(root);
  var hops = {};
  form.providers.forEach(function (p) { if (p.next_hop) hops[p.next_hop] = true; });
  var shown = lastSuggestions.filter(function (s) { return s.next_hop && !hops[s.next_hop]; });
  if (!shown.length) {
    root.appendChild(el("p", "empty", lastSuggestions.length ? "Every suggested next hop is already a row." : "No suggestions. Refresh after the iBGP or BMP session has routes."));
    return;
  }
  shown.forEach(function (s) {
    var row = el("div", "row");
    row.appendChild(el("span", "mono", s.next_hop));
    row.appendChild(el("span", "tag", s.asn ? "AS " + s.asn : "AS unknown"));
    row.appendChild(el("span", "tag", s.prefixes + " prefixes"));
    var b = el("button", "small", "Accept");
    b.type = "button";
    b.addEventListener("click", function () { acceptSuggestion(s); });
    row.appendChild(b);
    root.appendChild(row);
  });
}

// acceptSuggestion adds a draft provider row. It does not call the API,
// so it cannot write a provider, start probing, or announce.
function acceptSuggestion(s) {
  form.providers.push({
    key: "", name: "", source_ip: "", next_hop: s.next_hop || "", cost: "", commit_mbps: "",
    commit_bound: false, asn: s.asn ? String(s.asn) : "", draft: true
  });
  renderProviders();
  renderSuggestions(lastSuggestions);
  formStatus("Draft row added. Name it and fill in the probe source. Cost and commit stay empty until you set them. Nothing is saved.");
}

function loadSuggestions() {
  api("GET", "/api/config/suggestions").then(function (out) {
    var list = (out && out.suggestions) || [];
    list.forEach(function (s) {
      rememberHop(s.next_hop);
      if (s.asn) rememberASN(s.asn);
    });
    renderSuggestions(list);
    refreshGuideWidgets();
  }, function () { renderSuggestions([]); });
}

// The setup wizard (#106) is three steps. It always posts mode observe.
// Inject is not a step, and there is no field for a secret.
var wzProviders = [{name: "", source_ip: "", next_hop: ""}];
var wzSuggestions = [];

function showWizardStep(n) {
  ["wz-1", "wz-2", "wz-3", "wz-4"].forEach(function (id, i) {
    document.getElementById(id).hidden = i + 1 !== n;
    var tab = document.getElementById("wz-tab-" + (i + 1));
    if (tab) tab.className = i + 1 === n ? "on" : "";
  });
}

function renderWzProviders() {
  var root = document.getElementById("wz-providers");
  clear(root);
  wzProviders.forEach(function (p, i) {
    var row = el("div", "row");
    var name = rowInput(p.name, "name");
    var src = comboInput(p.source_ip, guide.sources.map(function (s) { return [s, s]; }), "probe source");
    var hop = comboInput(p.next_hop, hopOptions().map(function (h) { return [h, h]; }), "next hop");
    name.addEventListener("input", function () { wzProviders[i].name = name.value.trim(); });
    src.addEventListener("input", function () { wzProviders[i].source_ip = src.value.trim(); });
    hop.addEventListener("input", function () { wzProviders[i].next_hop = hop.value.trim(); });
    row.appendChild(labeled("Name", name, "Name of this provider.", "providers.name"));
    row.appendChild(labeled("Probe source", src, "Local address probes leave from.", "providers.source_ip"));
    row.appendChild(labeled("Next hop", hop, "Next hop seen on BGP or BMP, or type an address.", "providers.next_hop"));
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = "Remove provider";
    minus.addEventListener("click", function () {
      wzProviders.splice(i, 1);
      renderWzProviders();
      renderWzSuggestions();
    });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!wzProviders.length) root.appendChild(el("p", "empty", "No providers. Add one before continuing."));
}

function renderWzSuggestions() {
  var root = document.getElementById("wz-suggestions");
  clear(root);
  var hops = {};
  wzProviders.forEach(function (p) { if (p.next_hop) hops[p.next_hop] = true; });
  var shown = wzSuggestions.filter(function (s) { return s.next_hop && !hops[s.next_hop]; });
  if (!shown.length) {
    root.appendChild(el("p", "empty", wzSuggestions.length ? "Every suggested next hop is already a row." : "No suggestions yet. Refresh after the edge session has routes, or skip and type the rows."));
    return;
  }
  shown.forEach(function (s) {
    var row = el("div", "row");
    row.appendChild(el("span", "mono", s.next_hop));
    row.appendChild(el("span", "tag", s.asn ? "AS " + s.asn : "AS unknown"));
    var b = el("button", "small", "Add row");
    b.type = "button";
    b.addEventListener("click", function () {
      wzProviders.push({name: "", source_ip: "", next_hop: s.next_hop || ""});
      renderWzProviders();
      renderWzSuggestions();
      document.getElementById("wz-status").textContent = "Row added from the session. Name it and set the probe source. Nothing is saved.";
    });
    row.appendChild(b);
    root.appendChild(row);
  });
}

function edgeProblems() {
  var p = [];
  var asn = document.getElementById("wz-asn").value.trim();
  var router = document.getElementById("wz-router").value.trim();
  var edge = document.getElementById("wz-edge").value.trim();
  if (checkASN(asn, null)) p.push("ASN: enter your AS number (the learn-only iBGP session uses it).");
  if (!checkIPv4(router)) p.push("Router ID: enter an IPv4 address, for example 192.0.2.10.");
  if (!(checkIPv4(edge) || parseV6(edge) != null)) p.push("Edge address: enter the router's address. This session only learns.");
  return p;
}

function providerProblems() {
  var p = [];
  if (!wzProviders.length) p.push("Providers: add at least one row.");
  wzProviders.forEach(function (pr, i) {
    if (!pr.name || !pr.source_ip || !pr.next_hop) p.push("Provider " + (i + 1) + ": needs a name, a probe source, and a next hop.");
  });
  return p;
}

// wizardProblems checks the three steps before generate. Inject is not a step.
function wizardProblems(body) {
  var p = edgeProblems().concat(providerProblems());
  if (!body.prefix && body.host) p.push("Pinned host: enter the prefix it belongs to, or clear the host.");
  if (body.prefix && body.prefix.indexOf("/") < 0) p.push("Prefix: include a length, for example 198.51.100.0/24.");
  return p.concat(flowProblems());
}

// wizardFlowListen is host:port from the optional flow step, or "" when
// the collector is off. An IPv6 address is bracketed.
function wizardFlowListen() {
  if (!byId("wz-flow").checked) return "";
  var addr = byId("wz-flow-addr").value.trim();
  var port = byId("wz-flow-port").value.trim() || "2055";
  if (addr.indexOf(":") >= 0 && addr.charAt(0) !== "[") addr = "[" + addr + "]";
  return addr + ":" + port;
}

function flowProblems() {
  var p = [];
  if (!byId("wz-flow").checked) return p;
  var port = Number(byId("wz-flow-port").value.trim() || "2055");
  if (!(port >= 1 && port <= 65535 && Math.floor(port) === port)) p.push("Flow port: enter a UDP port from 1 to 65535.");
  if (/\s/.test(byId("wz-flow-addr").value.trim())) p.push("Flow address: enter one IP address, or leave it empty.");
  return p;
}

function wzErrors(list) {
  var ul = document.getElementById("wz-errors");
  clear(ul);
  (list || []).forEach(function (e) { ul.appendChild(el("li", "", e)); });
}

function runWizard() {
  var prefix = document.getElementById("wz-prefix").value.trim();
  var host = document.getElementById("wz-host").value.trim();
  var body = {asn: Number(document.getElementById("wz-asn").value) || 0, router_id: document.getElementById("wz-router").value.trim(),
    edge: document.getElementById("wz-edge").value.trim(), providers: wzProviders.map(function (p) {
      return {name: p.name, source_ip: p.source_ip, next_hop: p.next_hop};
    }), storage: document.getElementById("wz-storage").checked};
  if (prefix) body.prefix = prefix;
  if (host) body.host = host;
  var flow = wizardFlowListen();
  if (flow) body.flow = {listen: flow};
  // inject is not a step: the body never carries a mode other than observe,
  // and the server refuses one if it is sent.
  body.mode = "observe";
  var status = document.getElementById("wz-status");
  var problems = wizardProblems(body);
  wzErrors(problems);
  if (problems.length) {
    status.textContent = "Fix the form first.";
    return;
  }
  status.textContent = "Generating…";
  api("POST", "/api/config/wizard", body).then(function (out) {
    document.getElementById("ed-yaml").value = out.yaml;
    status.textContent = "Generated (observe). Review it below, then Save and restart the container. Nothing is written until you save.";
    if (!base) api("GET", "/api/config").then(function (f) { base = f.sha256; }, function () {});
    loadForm(out.yaml);
    checkConfig();
    document.getElementById("editor-section").scrollIntoView();
  }, function (err) {
    status.textContent = explain(err);
    wzErrors(err.data && err.data.errors);
  });
}

function renderSubs() {
  var root = document.getElementById("subs");
  api("GET", "/api/subscriptions").then(function (data) {
    clear(root);
    var subs = (data && data.subscriptions) || [];
    if (!subs.length) {
      root.appendChild(el("p", "empty", "No report subscriptions configured. Add report_subscriptions and an smtp notifier to the config file (docs/ui.md)."));
      return;
    }
    var t = el("table");
    var hr = el("tr");
    ["Name", "Report", "Schedule", "Next (UTC)", "Last sent", "Sent", "Failed", "Last error", ""].forEach(function (h) { hr.appendChild(el("th", "", h)); });
    var th = el("thead");
    th.appendChild(hr);
    t.appendChild(th);
    var tb = el("tbody");
    subs.forEach(function (s) {
      var tr = el("tr");
      [s.name, s.report + " (" + s.days + "d)", s.schedule + (s.weekday ? " " + s.weekday : "") + " " + s.at,
        s.next, s.last_sent || "—", s.sent, s.failed, s.last_error || ""].forEach(function (v) { tr.appendChild(el("td", "", v)); });
      var td = el("td");
      var b = el("button", "small", "Send now");
      b.type = "button";
      b.addEventListener("click", function () {
        document.getElementById("subs-status").textContent = "Sending " + s.name + "…";
        api("POST", "/api/subscriptions/" + encodeURIComponent(s.name) + "/send").then(function () {
          document.getElementById("subs-status").textContent = "Sent " + s.name + ".";
          renderSubs();
        }, function (err) { document.getElementById("subs-status").textContent = err.message; renderSubs(); });
      });
      td.appendChild(b);
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    root.appendChild(t);
  }, function (err) { clear(root); root.appendChild(el("p", "empty", explain(err))); });
}

document.getElementById("ed-load").addEventListener("click", loadConfig);
document.getElementById("ed-check").addEventListener("click", checkConfig);
document.getElementById("ed-save").addEventListener("click", saveConfig);
document.getElementById("wz-run").addEventListener("click", runWizard);
document.getElementById("wz-next").addEventListener("click", function () {
  var problems = edgeProblems();
  wzErrors(problems);
  document.getElementById("wz-status").textContent = problems.length ? "Fix the edge session first. Inject is not a step." : "";
  if (!problems.length) showWizardStep(2);
});
document.getElementById("wz-next-2").addEventListener("click", function () {
  var problems = providerProblems();
  wzErrors(problems);
  document.getElementById("wz-status").textContent = problems.length ? "Fix the provider rows first." : "";
  if (!problems.length) showWizardStep(3);
});
document.getElementById("wz-back").addEventListener("click", function () { showWizardStep(1); });
document.getElementById("wz-back-3").addEventListener("click", function () { showWizardStep(2); });
document.getElementById("wz-next-3").addEventListener("click", function () {
  wzErrors([]);
  document.getElementById("wz-status").textContent = "";
  showWizardStep(4);
});
document.getElementById("wz-back-4").addEventListener("click", function () { showWizardStep(3); });
document.getElementById("wz-add-provider").addEventListener("click", function () {
  wzProviders.push({name: "", source_ip: "", next_hop: ""});
  renderWzProviders();
});
document.getElementById("wz-sug").addEventListener("click", function () {
  api("GET", "/api/config/suggestions").then(function (out) {
    wzSuggestions = (out && out.suggestions) || [];
    renderWzSuggestions();
  }, function () { wzSuggestions = []; renderWzSuggestions(); });
});
renderWzProviders();
showWizardStep(1);
document.getElementById("form-apply").addEventListener("click", applyForm);
document.getElementById("form-reload").addEventListener("click", function () {
  readKnobs();
  loadForm(document.getElementById("ed-yaml").value);
});
document.getElementById("form-add-provider").addEventListener("click", function () {
  form.providers.push({key: "", name: "", source_ip: "", next_hop: "", cost: "", commit_mbps: "", commit_bound: false, draft: true});
  renderProviders();
});
document.getElementById("form-add-target").addEventListener("click", function () {
  form.targets.push({key: "", prefix: "", host: ""});
  renderTargets();
});
document.getElementById("form-add-allow").addEventListener("click", function () {
  form.allowlist.push("");
  renderAllow();
});
document.getElementById("sug-refresh").addEventListener("click", loadSuggestions);
byId("form-add-flow").addEventListener("click", function () {
  form.flows.push(emptyFlow());
  renderFlows();
});
byId("form-add-policy").addEventListener("click", function () {
  var p = emptyPolicy();
  p.rules.push(emptyRule());
  form.policies.push(p);
  renderPolicies();
});
byId("form-add-anomaly-rule").addEventListener("click", function () {
  form.anomaly.rules.push({key: "", name: "", prefixes: [], protocols: [], min_mbps: "", action: "blackhole", target: "", rate_mbps: "", ttl: ""});
  renderAnomalyRules();
});
byId("form-add-exchange").addEventListener("click", function () {
  form.exchanges.push(emptyExchange());
  renderExchanges();
});
byId("ix-refresh").addEventListener("click", loadDiscovered);
byId("form-add-vip").addEventListener("click", function () {
  form.vips.push(emptyVIP());
  renderVIPs();
});
byId("form-add-outage").addEventListener("click", function () {
  form.outages.push(emptyOutage());
  renderOutages();
});
["in-enabled", "in-mode", "in-perf", "in-damp-off"].forEach(function (id) {
  byId(id).addEventListener("change", readSections);
});
["in-local-pref", "in-release", "in-cap", "in-perf-min", "in-perf-release", "in-damp-backoff", "in-perf-loss", "in-perf-latency"].forEach(function (id) {
  byId(id).addEventListener("input", function () { markDirty(byId(id)); readSections(); });
});
["in-perf-loss-on", "in-perf-latency-on", "in-mod-commit", "in-mod-perf"].forEach(function (id) {
  byId(id).addEventListener("change", function () { markDirty(byId(id)); readSections(); });
});
["in-damp-confirm", "in-damp-max"].forEach(function (id) {
  byId(id).addEventListener("input", function () { markDirty(byId(id)); readSections(); });
  byId(id + "-unit").addEventListener("change", function () { markDirty(byId(id + "-unit")); readSections(); });
});
["fm-cap", "fm-loss", "fm-rtt", "fm-rtt-pct", "fm-rounds", "fm-floor-loss"].forEach(function (id) {
  byId(id).addEventListener("input", function () { markDirty(byId(id)); readKnobs(); });
});
["fm-hold", "fm-floor-rtt"].forEach(function (id) {
  byId(id).addEventListener("input", function () { markDirty(byId(id)); readKnobs(); });
  byId(id + "-unit").addEventListener("change", function () { markDirty(byId(id + "-unit")); readKnobs(); });
});
["fm-mode", "fm-precedence"].forEach(function (id) {
  byId(id).addEventListener("change", readKnobs);
});
bindStaticChecks();
loadConfig();
renderSubs();

function bindStaticChecks() {
  attachCheck(byId("fm-hold"), function () { return checkDuration(readDur("fm-hold")); });
  attachCheck(byId("fm-floor-rtt"), function () { return checkDuration(readDur("fm-floor-rtt")); });
  attachCheck(byId("fm-cap"), function () { return checkInt(readNum("fm-cap"), 0, 10000); });
  attachCheck(byId("fm-loss"), function () { return checkNum(readNum("fm-loss"), 0, 100); });
  attachCheck(byId("fm-rtt"), function () { return checkNum(readNum("fm-rtt"), 0, 1e12); });
  attachCheck(byId("fm-rtt-pct"), function () { return checkNum(readNum("fm-rtt-pct"), 0, 100); });
  attachCheck(byId("fm-rounds"), function () { return checkInt(readNum("fm-rounds"), 1, 100); });
  attachCheck(byId("fm-floor-loss"), function () { return checkNum(readNum("fm-floor-loss"), 0, 100); });
  attachCheck(byId("in-local-pref"), function () { var v = readNum("in-local-pref"); return v ? checkInt(v, 1, 4294967295) : ""; });
  attachCheck(byId("in-release"), function () { return checkPctOpen(readNum("in-release")); });
  attachCheck(byId("in-cap"), function () { return checkInt(readNum("in-cap"), 1, 10000); });
  attachCheck(byId("in-perf-min"), function () { return checkInt(readNum("in-perf-min"), 1, 10000); });
  attachCheck(byId("in-perf-release"), function () { return checkPctOpen(readNum("in-perf-release")); });
  attachCheck(byId("in-damp-backoff"), function () { return checkNum(readNum("in-damp-backoff"), 1, 16); });
  attachCheck(byId("in-perf-loss"), function () {
    var err = checkOffNum(readSigned("in-perf-loss"), 100);
    if (err) return err;
    var loss = readSigned("in-perf-loss");
    var lat = readSigned("in-perf-latency");
    if (byId("in-perf").checked && loss !== "" && lat !== "" && Number(loss) < 0 && Number(lat) < 0) return "Loss and latency cannot both be off.";
    return "";
  });
  attachCheck(byId("in-perf-latency"), function () { return checkOffNum(readSigned("in-perf-latency"), 1e9); });
  attachCheck(byId("in-damp-confirm"), function () { return checkDuration(readDur("in-damp-confirm"), 0, 86400000); });
  attachCheck(byId("in-damp-max"), function () { return checkDuration(readDur("in-damp-max"), 0, 30 * 86400000); });
  attachCheck(byId("wz-asn"), function () {
    var v = byId("wz-asn").value.trim();
    return v ? checkASN(v, null) : "Enter your AS number.";
  });
  attachCheck(byId("wz-router"), function () {
    var v = byId("wz-router").value.trim();
    if (!v) return "Enter an IPv4 address.";
    return checkIPv4(v) ? "" : "Enter an IPv4 address, for example 192.0.2.10.";
  });
  attachCheck(byId("wz-edge"), function () {
    var v = byId("wz-edge").value.trim();
    if (!v) return "Enter the router's address.";
    return (checkIPv4(v) || parseV6(v) != null) ? "" : "Enter an IP address.";
  });
  attachCheck(byId("wz-flow-port"), function () {
    if (!byId("wz-flow").checked) return "";
    var v = byId("wz-flow-port").value.trim();
    if (!v) return "";
    return checkInt(v, 1, 65535);
  });
  attachCheck(byId("wz-flow-addr"), function () {
    var v = byId("wz-flow-addr").value.trim();
    if (!v) return "";
    if (/\s/.test(v)) return "Enter one IP address, or leave it empty.";
    var bare = v.charAt(0) === "[" ? v.slice(1, -1) : v;
    return (checkIPv4(bare) || parseV6(bare) != null) ? "" : "Enter an IP address, or leave it empty.";
  });
}
function checkOffNum(v, max) {
  if (!v) return "";
  if (!/^[-+]?(\d+(\.\d+)?|\.\d+)$/.test(v)) return "Enter a number.";
  if (Number(v) > max) return "Enter a number up to " + max + ".";
  return "";
}
