"use strict";
// Page driver for the settings sections smoke test (#330). Headless Chrome
// cannot click, so uiproxy adds this script to /settings.html. Nothing is
// stubbed: the schema, the form, the preview, and the save are the real
// API's, against lab/ui-fixtures/sections/config.yaml mounted writable. The
// driver checks that each section is drawn from the file, makes an edit in
// each, previews the difference, saves once, and writes what it saw into
// the page for lab/ui-smoke.sh to match. Only PUT /api/config counts as a
// write to the file.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  if (((opts && opts.method) || "GET") === "PUT") writes++;
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("sec-jserr", "script error: " + e.message); });

function at(path) { return document.querySelector('[data-path="' + path + '"]'); }
function ctl(path) { return at(path).querySelector("input, select"); }
function yes(v) { return v ? "yes" : "no"; }
function text(id) { return byId(id).textContent; }
function has(sel) { return !!document.querySelector(sel); }

function fire(node, type) { node.dispatchEvent(new Event(type, {bubbles: true})); }
function type(node, value) {
  node.value = value;
  fire(node, "input");
}
function pick(node, value) {
  node.value = value;
  fire(node, "change");
}
function tick(node, on) {
  node.checked = on;
  fire(node, "change");
}
function button(root, label) {
  var all = root.querySelectorAll("button");
  for (var i = 0; i < all.length; i++) if (all[i].textContent === label) return all[i];
  throw new Error("no button " + label);
}
function numberIn(path) { return at(path).querySelector(".g-num"); }

// field finds the input or select of the label with this text under root.
function field(root, label) {
  var spans = root.querySelectorAll(".field-label");
  for (var i = 0; i < spans.length; i++) {
    if (spans[i].textContent === label) return spans[i].parentNode.querySelector("input, select");
  }
  throw new Error("no field " + label);
}
function plugin(kind) {
  var cards = document.querySelectorAll("#form-plugins .plugin-card");
  for (var i = 0; i < cards.length; i++) if (cards[i].querySelector("strong").textContent === kind) return cards[i];
  throw new Error("no plugin " + kind);
}

var W = "policies[maintenance].config.windows[0]";
var yamlBefore = "";
var step = 0;
var steps = [
  // The page is ready once the schema's blocks are drawn from the file.
  function () {
    var y = byId("ed-yaml");
    return !!(y && y.value.indexOf("mode: observe") >= 0 && has('[data-path="bgp.neighbors"]') && has("#form-plugins .plugin-card") && has("#cs-hosts .cs-host"));
  },
  function () {
    note("sec-render",
      "render: scorer " + yes(has("#sc-type") && at("scorer.config.loss_weight")) +
      " | bgp " + yes(ctl("bgp.neighbors[0].address").value === "192.0.2.254") +
      " | bmp " + yes(byId("blk-bmp-on").checked && has('[data-path="rib_sources[bmp].config.routers"] .g-string-input')) +
      " | maintenance " + yes(at(W + ".duration") && at(W + ".start").querySelector(".g-time")) +
      " | announcer " + yes(ctl("inbound.announcer.config.marker").value === "64512:777") +
      " | anomaly " + yes(ctl("anomaly.detector.type").value === "baseline") +
      " | mitigation " + yes(has('[data-path="mitigation.allowlist"] .g-cidr-input')) +
      " | http " + yes(has('[data-path="http.allow_from"] .g-cidr-input')) +
      " | inject " + yes(ctl("packeteer_community").value === "64512:666") +
      " | flow " + yes(has("#form-flows .flow-extra") && ctl("flow[0].problems.failure_pct")) +
      " | peer " + yes(has("#form-exchanges details.advanced")) +
      " | provider-bmp " + yes(has("#form-providers .g-select")) +
      " | plugins " + document.querySelectorAll("#form-plugins .plugin-card").length +
      " | snmp-v3 " + yes(document.querySelectorAll("#cs-hosts .cs-host").length === 2) +
      " | inject-box " + (byId("inject-box").hidden ? "hidden" : "shown") +
      " | raw-yaml " + yes(!byId("raw-yaml").open && byId("raw-yaml").querySelector("summary").textContent === "Advanced: raw YAML"));
    // The URL of the webhook may hold a secret: it is named and never shown.
    note("sec-hidden", "hidden: " + yes(plugin("Notifier webhook").textContent.indexOf("Hidden: it may hold a secret") >= 0) +
      " | url shown " + yes(document.body.textContent.indexOf("127.0.0.1:9/lab") >= 0) +
      " | community shown " + yes(document.body.textContent.indexOf("lab-only-community") >= 0));
  },
  // Apply with nothing edited changes nothing, and nothing is written.
  function () {
    yamlBefore = byId("ed-yaml").value;
    byId("form-apply").click();
  },
  function () { return text("form-status").indexOf("Applied to the YAML") >= 0; },
  function () {
    note("sec-unchanged", "unchanged: yaml-same " + (byId("ed-yaml").value === yamlBefore) + " | writes " + writes);
    // Choosing inject shows the checklist and the confirmation.
    pick(byId("fm-mode"), "inject");
  },
  function () {
    var shown = !byId("inject-box").hidden && !byId("inject-confirm").hidden && byId("inject-box").textContent.indexOf("allowlist") >= 0;
    pick(byId("fm-mode"), "observe");
    note("sec-mode", "mode: inject-box " + shown + " | gone again " + (byId("inject-box").hidden && byId("inject-confirm").hidden));
  },
  // A server error lands on the field it names: a window with both a
  // schedule and a start is refused.
  function () {
    type(ctl(W + ".start"), "2026-12-01T01:00");
    byId("bar-preview").click();
  },
  function () {
    var err = at(W + ".schedule").querySelector(".field-error");
    if (err.hidden || !err.textContent) return false;
    note("sec-mapped", "mapped: " + err.textContent);
    type(ctl(W + ".start"), "");
  },
  // One edit in each section.
  function () {
    type(numberIn("scorer.config.loss_weight"), "200");
    type(ctl("bgp.neighbors[0].description"), "edge-1");
    button(at("bgp.neighbors"), "+ Neighbor").click();
  },
  function () {
    var a = ctl("bgp.neighbors[1].address");
    type(a, "999.1.1.1");
    fire(a, "blur");
    note("sec-badip", "bad ip: " + at("bgp.neighbors[1].address").querySelector(".field-error").textContent);
    type(a, "192.0.2.253");
    fire(a, "blur");
    tick(at("bgp.neighbors[1].add_path").querySelector("input"), true);
    button(at("rib_sources[bmp].config.routers"), "+ Add").click();
  },
  function () {
    var inputs = at("rib_sources[bmp].config.routers").querySelectorAll(".g-string-input");
    type(inputs[inputs.length - 1], "192.0.2.253");
    type(at(W + ".duration").querySelector(".g-num"), "3");
    type(numberIn("inbound.announcer.config.providers[0].prepend"), "3");
    type(numberIn("anomaly.detector.config.sensitivity"), "5");
    type(at("anomaly.interval").querySelector(".g-num"), "30");
    type(numberIn("mitigation.max_rules"), "20");
    button(at("mitigation.allowlist"), "+ Prefix").click();
    button(at("http.allow_from"), "+ Prefix").click();
  },
  function () {
    var m = at("mitigation.allowlist").querySelectorAll(".g-cidr-input");
    type(m[m.length - 1], "203.0.113.0/24");
    var h = at("http.allow_from").querySelectorAll(".g-cidr-input");
    type(h[h.length - 1], "192.0.2.0/24");
    type(numberIn("flow[0].problems.failure_pct"), "30");
    tick(at("flow[0].transit").querySelector("input[type=checkbox]"), true);
  },
  function () { button(at("flow[0].transit"), "+ Prefix").click(); },
  function () {
    var c = at("flow[0].transit.customers").querySelectorAll(".g-cidr-input");
    type(c[c.length - 1], "203.0.113.0/24");
    var peers = byId("form-exchanges").querySelectorAll("details.advanced");
    type(peers[0].querySelector(".g-num"), "60");
    tick(peers[1].querySelector("input[type=checkbox]"), false);
    pick(byId("form-providers").querySelectorAll(".g-select")[1], "only");
    type(field(plugin("Notifier webhook"), "timeout"), "10s");
    var hosts = byId("cs-hosts").querySelectorAll(".cs-host");
    type(field(hosts[0], "Port"), "1161");
    type(field(hosts[1], "Context"), "lab-ctx");
  },
  // Add a prober from the picker.
  function () {
    pick(byId("pl-new-list"), "probers");
    pick(byId("pl-new-type"), "tcp");
    byId("pl-new-add").click();
  },
  // Preview shows the difference and what needs a restart. Nothing is written.
  function () { byId("pv-run").click(); },
  function () {
    var diff = text("pv-diff");
    if (!diff) return false;
    note("sec-preview",
      "preview: " + text("pv-state").slice(0, 5) +
      " | loss_weight " + yes(diff.indexOf("loss_weight: 200") >= 0) +
      " | failure_pct " + yes(diff.indexOf("failure_pct: 30") >= 0) +
      " | neighbor " + yes(diff.indexOf("192.0.2.253") >= 0) +
      " | peer " + yes(diff.indexOf("precedence: 60") >= 0) +
      " | bmp only " + yes(diff.indexOf("bmp: only") >= 0) +
      " | port " + yes(diff.indexOf("port: 1161") >= 0) +
      " | context " + yes(diff.indexOf("context_name: lab-ctx") >= 0) +
      " | prober " + yes(diff.indexOf("type: tcp") >= 0) +
      " | timeout " + yes(diff.indexOf("timeout: 10s") >= 0) +
      " | restart " + yes(text("pv-restart").indexOf("Needs a restart") === 0) +
      " | writes " + writes);
  },
  // Save writes once, from the form.
  function () { byId("bar-save").click(); },
  function () { return /^(Saved |Nothing was saved|Invalid|config is invalid)/.test(text("ed-status")) || text("ed-status").indexOf("refused") >= 0; },
  function () {
    var y = byId("ed-yaml").value;
    note("sec-saved",
      "saved: " + text("ed-status").slice(0, 6) + " | writes " + writes +
      " | comment kept " + yes(y.indexOf("# Config for the settings sections smoke test") === 0) +
      " | loss_weight " + yes(/loss_weight: 200/.test(y)) +
      " | bmp only " + yes(/bmp: only/.test(y)) +
      " | prober " + yes(/type: tcp/.test(y)) +
      " | webhook url kept " + yes(y.indexOf("url: http://127.0.0.1:9/lab") >= 0) +
      " | mode observe " + yes(/^mode: observe$/m.test(y)));
  },
  function () { return text("pv-state").indexOf("Nothing differs from the file") >= 0; },
  function () { note("sec-after", "after save: " + text("pv-state").slice(0, 40)); }
];

var tries = 0;
function next() {
  if (step >= steps.length) return;
  if (tries++ > 800) {
    note("sec-timeout", "timeout at step " + step + " | " + text("ed-status") + " | " + text("form-status") + " | " + text("pv-state"));
    return;
  }
  var ok;
  document.body.setAttribute("data-step", String(step));
  try {
    ok = steps[step]();
  } catch (e) {
    note("sec-error", "error: " + e.message + " (step " + step + ")");
    return;
  }
  if (ok !== false) step++;
  setTimeout(next, 150);
}

next();
