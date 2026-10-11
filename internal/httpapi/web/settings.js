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

// A new entry has an empty key: the server adds it to the file.
function newFlow() {
  return {key: "", name: "", listen: [], window: "", top_n: "", max_targets: "", tail_interval: "", min_bytes: "", min_pct: "",
    aggregate_v4: "", aggregate_v6: "", exclude: []};
}

function newRule() {
  return {key: "", name: "", action: "ignore", providers: [], prefixes: [], asns: [], countries: [], traffic: "", max_loss_pct: "", max_rtt: ""};
}

function newPolicy() {
  return {key: "", name: "", geoip_db: "", rules: [newRule()]};
}

function newVIP() {
  return {key: "", name: "", interval: "", max_targets: "", prefixes: [], asns: []};
}

function newOutage() {
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
  ["form-fields", "form-inbound"].forEach(function (id) {
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

// bindText and bindList make a labeled input that writes into obj[key].
function bindText(obj, key, label, placeholder, wide) {
  var input = rowInput(obj[key], placeholder, wide);
  input.addEventListener("input", function () { obj[key] = input.value.trim(); });
  return labeled(label, input);
}

function bindList(obj, key, label, placeholder, wide) {
  var input = rowInput(listText(obj[key]), placeholder, wide);
  input.addEventListener("input", function () { obj[key] = splitList(input.value); });
  return labeled(label, input);
}

function bindSelect(obj, key, label, options) {
  var sel = selectInput(options, obj[key]);
  sel.addEventListener("change", function () { obj[key] = sel.value; });
  return labeled(label, sel);
}

function smallButton(text, title, onClick) {
  var b = el("button", "small", text);
  b.type = "button";
  b.title = title;
  b.addEventListener("click", onClick);
  return b;
}

// entryCard is one instance of a source or policy. Move buttons show only
// where order matters (the rules policies and the rules in a policy).
function entryCard(heading, list, i, what, rerender, ordered) {
  var card = el("div", "entry-card");
  var head = el("div", "row");
  head.appendChild(el("strong", "", heading + " " + (i + 1)));
  if (ordered && i > 0) head.appendChild(smallButton("↑", "Move " + what + " up", function () {
    list.splice(i - 1, 0, list.splice(i, 1)[0]);
    rerender();
  }));
  if (ordered && i < list.length - 1) head.appendChild(smallButton("↓", "Move " + what + " down", function () {
    list.splice(i + 1, 0, list.splice(i, 1)[0]);
    rerender();
  }));
  head.appendChild(smallButton("−", "Remove " + what, function () { list.splice(i, 1); rerender(); }));
  card.appendChild(head);
  return card;
}

function renderFlows() {
  var root = byId("form-flows");
  clear(root);
  form.flows.forEach(function (f, i) {
    var card = entryCard("Flow collector", form.flows, i, "flow collector", renderFlows, false);
    var row = el("div", "row");
    row.appendChild(bindText(f, "name", "Name", "flow", false));
    row.appendChild(bindList(f, "listen", "Listen (host:port)", "192.0.2.10:2055, 192.0.2.10:6343", true));
    row.appendChild(bindText(f, "window", "Window", "5m"));
    row.appendChild(bindText(f, "top_n", "Priority prefixes (top_n)", "100"));
    row.appendChild(bindText(f, "max_targets", "Probed set (max_targets)", "same as top_n"));
    row.appendChild(bindText(f, "tail_interval", "Tail interval", "60s"));
    row.appendChild(bindText(f, "min_bytes", "Minimum bytes", "0 (off)"));
    row.appendChild(bindText(f, "min_pct", "Minimum share (%)", "0 (off)"));
    row.appendChild(bindText(f, "aggregate_v4", "Aggregate IPv4 length", "24"));
    row.appendChild(bindText(f, "aggregate_v6", "Aggregate IPv6 length", "48"));
    row.appendChild(bindList(f, "exclude", "Exclude prefixes", "192.0.2.0/24", true));
    card.appendChild(row);
    root.appendChild(card);
  });
  if (!form.flows.length) root.appendChild(el("p", "empty", "No flow collector."));
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

function renderPolicies() {
  var root = byId("form-policies");
  clear(root);
  form.policies.forEach(function (p, i) {
    var card = entryCard("Rules policy", form.policies, i, "policy", renderPolicies, true);
    var head = el("div", "row");
    head.appendChild(bindText(p, "name", "Name", "rules"));
    head.appendChild(bindText(p, "geoip_db", "GeoIP database (path in the container)", "/etc/packeteer/GeoLite2-Country.mmdb", true));
    card.appendChild(head);
    p.rules.forEach(function (r, j) {
      var row = el("div", "row");
      row.appendChild(bindText(r, "name", "Rule name", "name"));
      row.appendChild(bindSelect(r, "action", "Action", ruleActions));
      row.appendChild(bindList(r, "providers", "Providers", "transit-a"));
      row.appendChild(bindList(r, "prefixes", "Prefixes", "203.0.113.0/24", true));
      row.appendChild(bindList(r, "asns", "Origin ASNs", "64500"));
      row.appendChild(bindList(r, "countries", "Countries", "DE, FR"));
      row.appendChild(bindSelect(r, "traffic", "Traffic class", [["", "any traffic"], ["transit", "transit"], ["local", "local"]]));
      row.appendChild(bindText(r, "max_loss_pct", "Max loss (%)", "static only"));
      row.appendChild(bindText(r, "max_rtt", "Max RTT", "150ms"));
      if (j > 0) row.appendChild(smallButton("↑", "Move rule up", function () {
        p.rules.splice(j - 1, 0, p.rules.splice(j, 1)[0]);
        renderPolicies();
      }));
      if (j < p.rules.length - 1) row.appendChild(smallButton("↓", "Move rule down", function () {
        p.rules.splice(j + 1, 0, p.rules.splice(j, 1)[0]);
        renderPolicies();
      }));
      row.appendChild(smallButton("−", "Remove rule", function () { p.rules.splice(j, 1); renderPolicies(); }));
      card.appendChild(row);
    });
    card.appendChild(smallButton("+ Rule", "Add a rule to this policy", function () {
      p.rules.push(newRule());
      renderPolicies();
    }));
    root.appendChild(card);
  });
  if (!form.policies.length) root.appendChild(el("p", "empty", "No rules policy. Native routing and the normal thresholds apply."));
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

function renderVIPs() {
  var root = byId("form-vips");
  clear(root);
  form.vips.forEach(function (v, i) {
    var card = entryCard("VIP source", form.vips, i, "VIP source", renderVIPs, false);
    var row = el("div", "row");
    row.appendChild(bindText(v, "name", "Name", "vip"));
    row.appendChild(bindText(v, "interval", "Interval", "10s"));
    row.appendChild(bindText(v, "max_targets", "Max targets", "100"));
    row.appendChild(bindList(v, "asns", "VIP ASNs", "64496, 64497"));
    card.appendChild(row);
    v.prefixes.forEach(function (t, j) {
      var prow = el("div", "row");
      prow.appendChild(bindText(t, "prefix", "VIP prefix", "203.0.113.0/24", true));
      prow.appendChild(bindText(t, "host", "Pinned host", "203.0.113.1"));
      prow.appendChild(smallButton("−", "Remove VIP prefix", function () { v.prefixes.splice(j, 1); renderVIPs(); }));
      card.appendChild(prow);
    });
    card.appendChild(smallButton("+ VIP prefix", "Add a VIP prefix to this source", function () {
      v.prefixes.push({key: "", prefix: "", host: ""});
      renderVIPs();
    }));
    root.appendChild(card);
  });
  if (!form.vips.length) root.appendChild(el("p", "empty", "No VIP source."));
}

function renderOutages() {
  var root = byId("form-outages");
  clear(root);
  form.outages.forEach(function (o, i) {
    var card = entryCard("Outage detection", form.outages, i, "outage source", renderOutages, false);
    var row = el("div", "row");
    row.appendChild(bindText(o, "name", "Name", "outage"));
    row.appendChild(bindText(o, "min_prefixes", "Minimum prefixes", "3"));
    row.appendChild(bindText(o, "window", "Window", "2m"));
    row.appendChild(bindText(o, "loss_pct", "Loss (%)", "20"));
    row.appendChild(bindText(o, "rtt_ms", "RTT (ms)", "0 (off)"));
    row.appendChild(bindText(o, "interval", "Re-probe interval", "5s"));
    row.appendChild(bindText(o, "max_targets", "Max targets", "100"));
    row.appendChild(bindList(o, "ignore_asns", "Ignore ASNs", "64500"));
    card.appendChild(row);
    root.appendChild(card);
  });
  if (!form.outages.length) root.appendChild(el("p", "empty", "No outage detection."));
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

// loadFormDefaults fills the lists a reply may leave out.
function loadFormDefaults() {
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
    if (!v.prefixes) v.prefixes = [];
    if (!v.asns) v.asns = [];
  });
  form.outages.forEach(function (o) { if (!o.ignore_asns) o.ignore_asns = []; });
  loadProtectionDefaults();
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
  form.flows.push(newFlow());
  renderFlows();
});
byId("form-add-policy").addEventListener("click", function () {
  form.policies.push(newPolicy());
  renderPolicies();
});
byId("form-add-anomaly-rule").addEventListener("click", function () {
  form.anomaly.rules.push({key: "", name: "", prefixes: [], protocols: [], min_mbps: "", action: "blackhole", target: "", rate_mbps: "", ttl: ""});
  renderAnomalyRules();
});
byId("form-add-vip").addEventListener("click", function () {
  form.vips.push(newVIP());
  renderVIPs();
});
byId("form-add-outage").addEventListener("click", function () {
  form.outages.push(newOutage());
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
