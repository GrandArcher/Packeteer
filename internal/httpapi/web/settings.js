"use strict";

var base = "";
var form = emptyForm();

function emptyForm() {
  return {mode: "", hold_time: "", max_improvements: "", min_loss_delta_pct: "", min_rtt_delta_ms: "",
    min_rtt_delta_pct: "", confirm_rounds: "",
    precedence: "", scorer_type: "", floor_max_loss_pct: "", floor_max_rtt: "",
    providers: [], targets: [], allowlist: [],
    flows: [], policies: [], vips: [], outages: [],
    inbound: emptyInbound(), anomaly: emptyAnomaly()};
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

function emptyOutage() {
  return {key: "", name: "", min_prefixes: "", window: "", loss_pct: "", rtt_ms: "", interval: "", max_targets: "", ignore_asns: []};
}

// Lists in the form's text fields are comma or space separated.
function listText(list) { return (list || []).join(", "); }
function splitList(text) { return text.split(/[\s,]+/).filter(Boolean); }
function byId(id) { return document.getElementById(id); }

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
  ["ed-load", "ed-check", "ed-save", "wz-run", "wz-next", "wz-next-2", "wz-back", "wz-back-3", "wz-add-provider", "wz-sug", "form-apply", "form-reload", "form-add-provider", "form-add-target", "form-add-allow", "sug-refresh", "form-add-flow", "form-add-policy", "form-add-vip", "form-add-outage", "form-add-anomaly-rule", "wz-next-3", "wz-back-4"].forEach(function (id) {
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
  form.hold_time = document.getElementById("fm-hold").value.trim();
  form.max_improvements = document.getElementById("fm-cap").value.trim();
  form.min_loss_delta_pct = document.getElementById("fm-loss").value.trim();
  form.min_rtt_delta_ms = document.getElementById("fm-rtt").value.trim();
  form.min_rtt_delta_pct = document.getElementById("fm-rtt-pct").value.trim();
  form.confirm_rounds = document.getElementById("fm-rounds").value.trim();
  form.precedence = document.getElementById("fm-precedence").value;
  form.floor_max_loss_pct = document.getElementById("fm-floor-loss").value.trim();
  form.floor_max_rtt = document.getElementById("fm-floor-rtt").value.trim();
  readSections();
}

function readSections() {
  var t = function (id) { return byId(id).value.trim(); };
  var inb = form.inbound;
  inb.enabled = byId("in-enabled").checked;
  inb.mode = byId("in-mode").value;
  inb.prefixes = splitList(byId("in-prefixes").value);
  inb.local_pref = t("in-local-pref");
  inb.release_pct = t("in-release");
  inb.max_improvements = t("in-cap");
  inb.moderated = [];
  if (byId("in-mod-commit").checked) inb.moderated.push("commit");
  if (byId("in-mod-perf").checked) inb.moderated.push("performance");
  inb.performance = {enabled: byId("in-perf").checked, loss_pct: t("in-perf-loss"), latency_ms: t("in-perf-latency"),
    min_prefixes: t("in-perf-min"), release_pct: t("in-perf-release")};
  inb.damping = {disabled: byId("in-damp-off").checked, confirm: t("in-damp-confirm"), backoff: t("in-damp-backoff"), max_hold: t("in-damp-max")};
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
  setVal("in-prefixes", listText(i.prefixes));
  setVal("in-local-pref", i.local_pref);
  setVal("in-release", i.release_pct);
  setVal("in-cap", i.max_improvements);
  setChecked("in-mod-commit", (i.moderated || []).indexOf("commit") >= 0);
  setChecked("in-mod-perf", (i.moderated || []).indexOf("performance") >= 0);
  setChecked("in-perf", i.performance.enabled);
  setVal("in-perf-loss", i.performance.loss_pct);
  setVal("in-perf-latency", i.performance.latency_ms);
  setVal("in-perf-min", i.performance.min_prefixes);
  setVal("in-perf-release", i.performance.release_pct);
  setChecked("in-damp-off", i.damping.disabled);
  setVal("in-damp-confirm", i.damping.confirm);
  setVal("in-damp-backoff", i.damping.backoff);
  setVal("in-damp-max", i.damping.max_hold);
  modeBadge("in-badge", i.enabled ? i.mode : "");
  byId("in-badge-text").textContent = i.mode === "inject"
    ? "Inject announces steer routes for allowlisted prefixes in the learned RIB."
    : "Observe and suggest announce nothing.";
  byId("in-announcer").textContent = i.enabled ? (i.has_announcer ? "An announcer is configured." : "No announcer is configured, so inject could not start.") : "";
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
  var b = el("button", "small", "−");
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

// bindField adds a text field that writes straight into obj[key]. A list
// field is comma separated.
function bindField(parent, label, obj, key, placeholder, isList, wide) {
  var input = rowInput(isList ? listText(obj[key]) : obj[key], placeholder, wide);
  input.addEventListener("input", function () { obj[key] = isList ? splitList(input.value) : input.value.trim(); });
  parent.appendChild(labeled(label, input));
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
    bindField(a, "Name (flow " + (i + 1) + ")", f, "name", "flow");
    bindField(a, "Listen (flow " + (i + 1) + ")", f, "listen", "192.0.2.10:2055", true, true);
    bindField(a, "Exclude (flow " + (i + 1) + ")", f, "exclude", "192.0.2.0/24", true);
    bindField(b, "Window", f, "window", "5m");
    bindField(b, "Top N", f, "top_n", "100");
    bindField(b, "Max targets", f, "max_targets", "same as top_n");
    bindField(b, "Tail interval", f, "tail_interval", "60s");
    bindField(b, "Min bytes", f, "min_bytes", "0 (off)");
    bindField(b, "Min share (%)", f, "min_pct", "0 (off)");
    bindField(b, "Aggregate IPv4 (/n)", f, "aggregate_v4", "24");
    bindField(b, "Aggregate IPv6 (/n)", f, "aggregate_v6", "48");
  });
  if (!form.flows.length) root.appendChild(el("p", "empty", "No flow sources."));
}

function renderOutages() {
  var root = byId("form-outages");
  clear(root);
  form.outages.forEach(function (o, i) {
    var card = entryCard(root, "Outage detection", form.outages, i, renderOutages, "outage detection", false);
    var a = entryRow(card);
    bindField(a, "Name (outage " + (i + 1) + ")", o, "name", "outage");
    bindField(a, "Min prefixes", o, "min_prefixes", "3");
    bindField(a, "Window", o, "window", "2m");
    bindField(a, "Loss (%)", o, "loss_pct", "20");
    bindField(a, "RTT (ms)", o, "rtt_ms", "0 (off)");
    bindField(a, "Interval", o, "interval", "5s");
    bindField(a, "Max targets", o, "max_targets", "100");
    bindField(a, "Ignore ASNs", o, "ignore_asns", "64500", true);
  });
  if (!form.outages.length) root.appendChild(el("p", "empty", "No outage detection."));
}

function renderVIPs() {
  var root = byId("form-vips");
  clear(root);
  form.vips.forEach(function (v, i) {
    var card = entryCard(root, "VIP source", form.vips, i, renderVIPs, "VIP source", false);
    var a = entryRow(card);
    bindField(a, "Name (VIP " + (i + 1) + ")", v, "name", "vip");
    bindField(a, "Interval", v, "interval", "10s");
    bindField(a, "Max targets", v, "max_targets", "100");
    bindField(a, "VIP ASNs", v, "asns", "64500", true);
    v.prefixes.forEach(function (t, j) {
      var row = entryRow(card);
      bindField(row, "VIP prefix", t, "prefix", "203.0.113.0/24", false, true);
      bindField(row, "Pinned host", t, "host", "203.0.113.1");
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
  bindField(row, "Rule name", r, "name", "name");
  row.appendChild(labeled("Action", action));
  bindField(row, "Providers", r, "providers", "transit-a", true);
  bindField(row, "Prefixes", r, "prefixes", "203.0.113.0/24", true, true);
  bindField(row, "Origin ASNs", r, "asns", "64500", true);
  bindField(row, "Countries", r, "countries", "DE, FR", true);
  row.appendChild(labeled("Traffic class", traffic));
  bindField(row, "Max loss (%)", r, "max_loss_pct", "static only");
  bindField(row, "Max RTT", r, "max_rtt", "150ms");
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
    bindField(head, "Name (policy " + (i + 1) + ")", p, "name", "rules");
    bindField(head, "GeoIP database (policy " + (i + 1) + ")", p, "geoip_db", "/etc/packeteer/country.mmdb", false, true);
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
  form.anomaly.rules.forEach(function (r, i) {
    var row = el("div", "row");
    var name = rowInput(r.name, "udp-flood");
    var prefixes = rowInput(listText(r.prefixes), "203.0.113.0/24", true);
    var protos = rowInput(listText(r.protocols), "udp, tcp");
    var min = rowInput(r.min_mbps, "0");
    var action = selectInput(anomalyActions, r.action);
    var target = rowInput(r.target, "scrubber");
    var rate = rowInput(r.rate_mbps, "rate limit only");
    var ttl = rowInput(r.ttl, "mitigation default");
    var set = function () {
      var x = form.anomaly.rules[i];
      x.name = name.value.trim();
      x.prefixes = splitList(prefixes.value);
      x.protocols = splitList(protos.value);
      x.min_mbps = min.value.trim();
      x.action = action.value;
      x.target = target.value.trim();
      x.rate_mbps = rate.value.trim();
      x.ttl = ttl.value.trim();
    };
    [name, prefixes, protos, min, target, rate, ttl].forEach(function (n) { n.addEventListener("input", set); });
    action.addEventListener("change", set);
    row.appendChild(labeled("Anomaly rule name", name));
    row.appendChild(labeled("Anomaly rule prefixes", prefixes));
    row.appendChild(labeled("Anomaly rule protocols", protos));
    row.appendChild(labeled("Anomaly rule min Mbit/s", min));
    row.appendChild(labeled("Anomaly rule action", action));
    row.appendChild(labeled("Anomaly rule target", target));
    row.appendChild(labeled("Anomaly rule rate Mbit/s", rate));
    row.appendChild(labeled("Anomaly rule TTL", ttl));
    var minus = el("button", "small", "−");
    minus.type = "button";
    minus.title = "Remove anomaly rule";
    minus.addEventListener("click", function () { form.anomaly.rules.splice(i, 1); renderAnomalyRules(); });
    row.appendChild(minus);
    root.appendChild(row);
  });
  if (!form.anomaly.rules.length) root.appendChild(el("p", "empty", "No anomaly rules. Anomalies are detected and reported, and no mitigation rule is added."));
}

function fillKnobs() {
  fillSections();
  document.getElementById("fm-mode").value = form.mode || "";
  document.getElementById("fm-hold").value = form.hold_time || "";
  document.getElementById("fm-cap").value = form.max_improvements || "";
  document.getElementById("fm-loss").value = form.min_loss_delta_pct || "";
  document.getElementById("fm-rtt").value = form.min_rtt_delta_ms || "";
  document.getElementById("fm-rtt-pct").value = form.min_rtt_delta_pct || "";
  document.getElementById("fm-rounds").value = form.confirm_rounds || "";
  document.getElementById("fm-floor-loss").value = form.floor_max_loss_pct || "";
  document.getElementById("fm-floor-rtt").value = form.floor_max_rtt || "";
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
// text is the accessible name (#171).
function labeled(text, input) {
  var lab = el("label", "field");
  lab.appendChild(el("span", "field-label", text));
  lab.appendChild(input);
  return lab;
}

function renderProviders() {
  var root = document.getElementById("form-providers");
  clear(root);
  form.providers.forEach(function (p, i) {
    var row = el("div", "row");
    var name = rowInput(p.name, "name");
    var src = rowInput(p.source_ip, "probe source");
    var hop = rowInput(p.next_hop, "next hop");
    var cost = rowInput(p.cost, "cost");
    var commit = rowInput(p.commit_mbps, p.commit_bound ? "commit Mbps" : "commit (no binding)");
    name.addEventListener("input", function () { form.providers[i].name = name.value.trim(); });
    src.addEventListener("input", function () { form.providers[i].source_ip = src.value.trim(); });
    hop.addEventListener("input", function () { form.providers[i].next_hop = hop.value.trim(); });
    cost.addEventListener("input", function () { form.providers[i].cost = cost.value.trim(); });
    commit.addEventListener("input", function () { form.providers[i].commit_mbps = commit.value.trim(); });
    row.appendChild(labeled("Name", name));
    row.appendChild(labeled("Probe source", src));
    row.appendChild(labeled("Next hop", hop));
    row.appendChild(labeled("Cost", cost));
    row.appendChild(labeled("Commit", commit));
    if (p.asn) row.appendChild(el("span", "tag", "AS " + p.asn + " from the session, not saved"));
    else if (p.draft) row.appendChild(el("span", "tag", "draft"));
    var minus = el("button", "small", "−");
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
    var prefix = rowInput(t.prefix, "prefix", true);
    var host = rowInput(t.host, "host");
    prefix.addEventListener("input", function () { form.targets[i].prefix = prefix.value.trim(); });
    host.addEventListener("input", function () { form.targets[i].host = host.value.trim(); });
    row.appendChild(prefix);
    row.appendChild(host);
    var minus = el("button", "small", "−");
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
    var input = rowInput(prefix, "prefix", true);
    input.addEventListener("input", function () { form.allowlist[i] = input.value.trim(); });
    row.appendChild(input);
    var minus = el("button", "small", "−");
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
  renderAnomalyRules();
  renderSuggestions(lastSuggestions);
}

function loadForm(yaml) {
  formStatus("Reading the form…");
  api("POST", "/api/config/form", {yaml: yaml, apply: false}).then(function (out) {
    form = out.form || emptyForm();
    if (!form.providers) form.providers = [];
    if (!form.targets) form.targets = [];
    if (!form.allowlist) form.allowlist = [];
    loadFormDefaults();
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
  loadProtectionDefaults();
  ["flows", "policies", "vips", "outages"].forEach(function (k) { if (!form[k]) form[k] = []; });
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
  formStatus("Applying to the YAML…");
  api("POST", "/api/config/form", {yaml: document.getElementById("ed-yaml").value, apply: true, form: form}).then(function (out) {
    document.getElementById("ed-yaml").value = out.yaml;
    if (out.form) {
      form = out.form;
      loadFormDefaults();
    }
    renderForm();
    formStatus("Applied to the YAML. Not saved. Validate, then Save. Save applies thresholds, policies, sources, probe timing, mode, the allowlist, and bgp.neighbors online. Any other change waits for a restart.");
  }, function (err) { formStatus(explain(err)); });
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
    renderSuggestions((out && out.suggestions) || []);
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
    var src = rowInput(p.source_ip, "probe source");
    var hop = rowInput(p.next_hop, "next hop");
    name.addEventListener("input", function () { wzProviders[i].name = name.value.trim(); });
    src.addEventListener("input", function () { wzProviders[i].source_ip = src.value.trim(); });
    hop.addEventListener("input", function () { wzProviders[i].next_hop = hop.value.trim(); });
    row.appendChild(labeled("Name", name));
    row.appendChild(labeled("Probe source", src));
    row.appendChild(labeled("Next hop", hop));
    var minus = el("button", "small", "−");
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
  var asn = Number(document.getElementById("wz-asn").value) || 0;
  var router = document.getElementById("wz-router").value.trim();
  var edge = document.getElementById("wz-edge").value.trim();
  if (!(asn > 0)) p.push("ASN: enter your AS number (the learn-only iBGP session uses it).");
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(router)) p.push("Router ID: enter an IPv4 address, for example 192.0.2.10.");
  if (!edge) p.push("Edge address: enter the router's address. This session only learns.");
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
byId("form-add-vip").addEventListener("click", function () {
  form.vips.push(emptyVIP());
  renderVIPs();
});
byId("form-add-outage").addEventListener("click", function () {
  form.outages.push(emptyOutage());
  renderOutages();
});
["in-enabled", "in-mode", "in-prefixes", "in-local-pref", "in-release", "in-cap", "in-mod-commit", "in-mod-perf", "in-perf",
  "in-perf-loss", "in-perf-latency", "in-perf-min", "in-perf-release", "in-damp-off", "in-damp-confirm", "in-damp-backoff", "in-damp-max"].forEach(function (id) {
  byId(id).addEventListener("change", readSections);
  byId(id).addEventListener("input", readSections);
});
["fm-mode", "fm-hold", "fm-cap", "fm-loss", "fm-rtt", "fm-rtt-pct", "fm-rounds", "fm-precedence", "fm-floor-loss", "fm-floor-rtt"].forEach(function (id) {
  document.getElementById(id).addEventListener("change", readKnobs);
  document.getElementById(id).addEventListener("input", readKnobs);
});
loadConfig();
renderSubs();
