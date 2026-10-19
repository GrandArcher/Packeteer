"use strict";
// Settings blocks (#330). The sections the older cards do not cover are drawn
// from GET /api/config/schema: bgp, BMP, the scorer knobs, the maintenance
// policy, the inbound announcer, anomaly, mitigation, http, and the inject
// settings. A block is a mapping of fields; a field kind picks the widget, so
// a number is never a text box and a list is never a comma string. The values
// live in form.blocks and go back through POST /api/config/form like every
// other section. This file also draws the plugin list and maps a server error
// back to the field it names. Nothing here writes the config file.

var schema = null;
var schemaFailed = false;

function loadSchema() {
  if (schema) {
    renderBlocks();
    return;
  }
  api("GET", "/api/config/schema").then(function (s) {
    schema = s;
    schemaFailed = false;
    renderBlocks();
  }, function () {
    schemaFailed = true;
    renderBlocks();
  });
}

// blank is the value of a field the file does not have.
function blankValues(fields) {
  var v = {_key: ""};
  fields.forEach(function (f) {
    if (f.kind === "bool") v[f.key] = !!f.default_true;
    else if (f.kind === "list" || f.kind === "cidrs" || f.kind === "rows") v[f.key] = [];
    else if (f.kind === "group") v[f.key] = null;
    else v[f.key] = "";
  });
  return v;
}

var jsChecks = {
  ip: function (v) { return checkIP(v) ? "" : "Enter an IP address."; },
  hostport: function (v) { return listenParts(v).err; },
  ipport: function (v) {
    var p = listenParts(v);
    if (p.err) return p.err;
    return checkIP(p.host) ? "" : "The host must be an IP address.";
  },
  name: function (v) { return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v) ? "" : "Use up to 64 letters, digits, dot, dash, or underscore."; },
  community: function (v) {
    var parts = v.split(":");
    var max = parts.length === 2 ? 65535 : 4294967295;
    var ok = (parts.length === 2 || parts.length === 3) && parts.every(function (p) { return /^\d+$/.test(p) && Number(p) <= max; });
    return ok ? "" : "Use asn:value, or global:data1:data2 for a large community.";
  },
  abspath: function (v) { return v.charAt(0) === "/" ? "" : "Enter an absolute path, starting with /."; }
};

// listenParts splits host:port the way Go's net.SplitHostPort does, so the
// page refuses what the loader refuses: IPv6 needs brackets.
function listenParts(v) {
  var m = /^\[([^\[\]]*)\]:([^:]*)$/.exec(v) || /^([^:\[\]]*):([^:\[\]]*)$/.exec(v);
  if (!m) return {err: "Enter host:port, for example 127.0.0.1:8080. Wrap IPv6 in brackets."};
  return {host: m[1], err: checkPort(m[2], 0, 65535)};
}

function checkFor(f) {
  var fn = jsChecks[f.check];
  if (!fn && !f.required) return null;
  return function (v) {
    if (!v) return f.required ? "This field is required." : "";
    return fn ? fn(v) : "";
  };
}

// suggestions are names the page already knows. They fill a dropdown; any
// value can still be typed.
function suggestFor(key) {
  var names = [];
  switch (key) {
  case "providers":
  case "provider":
    (form.providers || []).forEach(function (p) { pushUnique(names, p.name); });
    (form.exchanges || []).forEach(function (x) {
      pushUnique(names, x.name);
      (x.peers || []).forEach(function (p) { pushUnique(names, p.name); });
    });
    break;
  case "routers":
    ((form.blocks && form.blocks.bgp && form.blocks.bgp.neighbors) || []).forEach(function (n) { pushUnique(names, n.address); });
    break;
  case "source":
    (form.flows || []).forEach(function (f) { pushUnique(names, f.name || "flow"); });
    break;
  case "local_address":
  case "listen_addresses":
    names = guide.sources.slice();
    break;
  }
  return names.filter(Boolean).map(function (n) { return [n, n]; });
}

function withDefault(f) {
  var help = f.help || "";
  if (f.default && f.kind !== "int" && f.kind !== "float" && f.kind !== "bool") help += " Default " + f.default + ".";
  return help;
}

function defaultUnit(f) {
  var m = /([smh])$/.exec(f.default || "");
  return m ? m[1] : "m";
}

function toLocalInput(rfc) {
  if (!rfc) return "";
  var d = new Date(rfc);
  if (isNaN(d.getTime())) return "";
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes());
}
function fromLocalInput(v) {
  if (!v) return "";
  var d = new Date(v);
  return isNaN(d.getTime()) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

// fieldBox wraps one field so an error from the server can find it by path.
function fieldBox(parent, path) {
  var box = el("div", "bfield");
  box.dataset.path = path;
  parent.appendChild(box);
  return box;
}

// renderFields draws the fields of one mapping into parent. Fields marked
// advanced sit under a fold. visible, when given, hides a field.
function renderFields(parent, fields, obj, path, rerender, visible) {
  var advanced = [];
  fields.forEach(function (f) {
    if (visible && !visible(f)) return;
    if (f.advanced) { advanced.push(f); return; }
    renderField(parent, f, obj, path, rerender);
  });
  if (!advanced.length) return;
  var fold = el("details", "advanced");
  fold.appendChild(el("summary", "", "Show advanced"));
  advanced.forEach(function (f) { renderField(fold, f, obj, path, rerender); });
  parent.appendChild(fold);
}

function joinPath(path, key) { return path ? path + "." + key : key; }

function renderField(parent, f, obj, path, rerender) {
  var at = joinPath(path, f.key);
  var box = fieldBox(parent, at);
  var help = withDefault(f);
  var check = checkFor(f);
  switch (f.kind) {
  case "bool":
    renderBool(box, f, obj, help);
    break;
  case "int":
  case "float":
    box.appendChild(labeled(f.label, numberControl(obj, f.key, {
      min: f.min != null ? f.min : 0, max: f.max != null ? f.max : 1e15,
      integer: f.kind === "int", def: f.default !== "" ? f.default : undefined
    }), help, f.key));
    break;
  case "duration":
    bindDuration(box, f.label, obj, f.key, help, f.key, defaultUnit(f), false,
      f.min != null ? f.min * 1000 : 0, f.max != null ? f.max * 1000 : null);
    break;
  case "enum":
    renderEnum(box, f, obj, help);
    break;
  case "time":
    renderTime(box, f, obj, help);
    break;
  case "list":
    renderStrings(box, f, obj, help, check, rerender);
    break;
  case "cidrs":
    bindCIDRs(box, f.label, obj, f.key, help, f.key, rerender);
    break;
  case "rows":
    renderRows(box, f, obj, at, rerender);
    break;
  case "group":
    renderGroup(box, f, obj, at, rerender);
    break;
  default:
    renderText(box, f, obj, help, check);
  }
}

function renderText(box, f, obj, help, check) {
  var options = suggestFor(f.key);
  var input = options.length ? comboInput(obj[f.key], options, f.default || "", true) : rowInput(obj[f.key], f.default || "", true);
  input.dataset.raw = obj[f.key] || "";
  input.addEventListener("input", function () { markDirty(input); obj[f.key] = input.value.trim(); });
  if (check) attachCheck(input, function () { return check(input.value.trim()); });
  box.appendChild(labeled(f.label, input, help, f.key));
}

function renderBool(box, f, obj, help) {
  var lab = el("label", "check");
  lab.title = f.key;
  var cb = el("input");
  cb.type = "checkbox";
  cb.checked = !!obj[f.key];
  if (cb.checked) cb.setAttribute("checked", "checked");
  cb.addEventListener("change", function () { markDirty(cb); obj[f.key] = cb.checked; });
  lab.appendChild(cb);
  lab.appendChild(el("span", "", " " + f.label));
  box.appendChild(lab);
  if (help) box.appendChild(el("span", "field-help", help));
  box.appendChild(el("span", "field-error"));
  box.lastChild.hidden = true;
}

function renderEnum(box, f, obj, help) {
  // A no_inject field offers inject only when the file already has it.
  var choices = (f.options || []).filter(function (o) {
    return o !== "inject" || !f.no_inject || obj[f.key] === "inject";
  });
  var options = choices.map(function (o) {
    return [o, o === "" ? (f.default ? "(default " + f.default + ")" : "(not set)") : o];
  });
  var sel = selectInput(options, obj[f.key]);
  sel.className = "g-select";
  sel.addEventListener("change", function () { markDirty(sel); obj[f.key] = sel.value; });
  box.appendChild(labeled(f.label, sel, help, f.key));
}

function renderTime(box, f, obj, help) {
  var input = el("input");
  input.type = "datetime-local";
  input.className = "g-time";
  input.value = toLocalInput(obj[f.key]);
  if (input.value) input.setAttribute("value", input.value);
  input.addEventListener("input", function () { markDirty(input); obj[f.key] = fromLocalInput(input.value); });
  box.appendChild(labeled(f.label, input, help + (help ? " " : "") + "Shown in your browser's time zone, saved as UTC.", f.key));
}

// renderStrings is a list of single values, one per row.
function renderStrings(box, f, obj, help, check, rerender) {
  var list = obj[f.key] || [];
  obj[f.key] = list;
  var options = suggestFor(f.key);
  var wrap = el("div", "g-strings");
  list.forEach(function (v, i) {
    var row = el("div", "row");
    var input = options.length ? comboInput(v, options, "", true) : rowInput(v, "", true);
    input.className += " g-string-input";
    input.addEventListener("input", function () { markDirty(input); list[i] = input.value.trim(); });
    attachCheck(input, function () {
      var val = input.value.trim();
      if (!val) return "Enter a value or remove the row.";
      if (list.indexOf(val) >= 0 && list.indexOf(val) !== i) return "That value is already listed.";
      return check ? check(val) : "";
    });
    var err = el("span", "field-error");
    err.hidden = true;
    row.appendChild(input);
    if (input._dl) row.appendChild(input._dl);
    row.appendChild(removeButton(list, i, rerender, f.label));
    row.appendChild(err);
    wrap.appendChild(row);
  });
  var add = el("button", "small", "+ Add");
  add.type = "button";
  add.addEventListener("click", function () { list.push(""); rerender(); });
  wrap.appendChild(add);
  block(box, f.label, wrap, help, f.key);
}

function singular(label) {
  return label.replace(/ies$/, "y").replace(/s$/, "");
}

// renderRows is a list of cards, one per mapping. A new row has no key; an
// existing one keeps the key the server gave it so unseen keys survive.
function renderRows(box, f, obj, at, rerender) {
  var list = obj[f.key] || [];
  obj[f.key] = list;
  var wrap = el("div", "g-rows");
  box.appendChild(el("h4", "", f.label));
  if (f.help) box.appendChild(el("p", "field-help", f.help));
  list.forEach(function (row, i) {
    var title = f.row_key && row[f.row_key] ? row[f.row_key] : "";
    var card = entryCard(wrap, singular(f.label), list, i, rerender, singular(f.label).toLowerCase(), true);
    if (title) card.firstChild.appendChild(el("span", "tag", title));
    renderFields(card, f.fields, row, at + "[" + i + "]", rerender);
  });
  if (!list.length) wrap.appendChild(el("p", "empty", "None."));
  var add = el("button", "small", "+ " + singular(f.label));
  add.type = "button";
  add.addEventListener("click", function () { list.push(blankValues(f.fields)); rerender(); });
  wrap.appendChild(add);
  box.appendChild(wrap);
}

// renderGroup is an optional sub-mapping: off means the key is absent.
function renderGroup(box, f, obj, at, rerender) {
  var card = el("div", "card");
  var lab = el("label", "check");
  lab.title = f.key;
  var cb = el("input");
  cb.type = "checkbox";
  cb.checked = obj[f.key] != null;
  if (cb.checked) cb.setAttribute("checked", "checked");
  cb.addEventListener("change", function () {
    obj[f.key] = cb.checked ? blankValues(f.fields) : null;
    rerender();
  });
  lab.appendChild(cb);
  lab.appendChild(el("span", "", " " + f.label));
  card.appendChild(lab);
  if (f.help) card.appendChild(el("span", "field-help", f.help));
  if (obj[f.key] != null) renderFields(card, f.fields, obj[f.key], at, rerender);
  box.appendChild(card);
}

function scorerNow() {
  return (form.commit && form.commit.scorer) || form.scorer_type || "weighted";
}

var scorerChoices = [["weighted", "weighted (performance only)"], ["commit", "commit (commit control and balancing)"], ["cost", "cost (cheapest path inside a performance floor)"]];

// renderScorerType is the scorer type select. It sets commit.scorer, which
// the server turns into a type switch that keeps the knobs every scorer
// shares and drops the rest. It returns false when the file's scorer is one
// the form does not edit.
function renderScorerType(mount, rerender) {
  var cur = form.scorer_type || "weighted";
  if (["weighted", "commit", "cost"].indexOf(cur) < 0) {
    mount.appendChild(el("p", "empty", "This file uses the " + cur + " scorer, which the form does not replace. Use the raw YAML to change it."));
    return false;
  }
  var sel = selectInput(scorerChoices, scorerNow());
  sel.id = "sc-type";
  sel.className = "g-select";
  sel.addEventListener("change", function () {
    markDirty(sel);
    var next = sel.value;
    form.commit.scorer = next === cur ? "" : next;
    // The cost knobs and the balance belong to one scorer each.
    if (next !== "cost") { form.precedence = ""; form.floor_max_loss_pct = ""; form.floor_max_rtt = ""; }
    if (next !== "commit") form.commit.balance = "";
    fillKnobs();
    rerender();
  });
  mount.appendChild(labeled("Scorer", sel, "How paths are ranked. Switching keeps the loss, latency, and jitter weights and drops the other scorer's knobs.", "scorer.type"));
  if (scorerNow() === "commit") {
    var bal = selectInput([["", "(default off)"], ["off", "off"], ["equal", "equal"], ["proportional", "proportional"]], form.commit.balance);
    bal.id = "sc-balance";
    bal.className = "g-select";
    bal.addEventListener("change", function () { markDirty(bal); form.commit.balance = bal.value; });
    mount.appendChild(labeled("Balance in a group", bal, "Off relieves only a provider over its commit. Equal or proportional also shares traffic inside a group.", "scorer.config.balance"));
  }
  return true;
}

function blockVisible(def) {
  if (def.id !== "scorer") return null;
  var now = scorerNow();
  return function (f) { return !f.for || f.for.indexOf(now) >= 0; };
}

function renderBlocks() {
  var mounts = document.querySelectorAll("[data-block]");
  Array.prototype.forEach.call(mounts, function (mount) { renderBlock(mount); });
  if (typeof renderFlowExtras === "function") renderFlowExtras();
  renderPlugins();
}

function renderBlock(mount) {
  clear(mount);
  var id = mount.dataset.block;
  var def = schema && schema.blocks.filter(function (b) { return b.id === id; })[0];
  if (!def) {
    if (schemaFailed) mount.appendChild(el("p", "empty", "This section could not be loaded. Use the raw YAML below."));
    return;
  }
  if (!form.blocks) form.blocks = {};
  var rerender = function () { renderBlock(mount); };
  mount.appendChild(el("h3", "", def.title));
  mount.appendChild(el("p", "tag", def.help));
  if (id === "scorer" && !renderScorerType(mount, rerender)) return;
  if (def.optional) {
    var lab = el("label", "check");
    var cb = el("input");
    cb.type = "checkbox";
    cb.id = "blk-" + id + "-on";
    cb.checked = form.blocks[id] != null;
    if (cb.checked) cb.setAttribute("checked", "checked");
    cb.addEventListener("change", function () {
      form.blocks[id] = cb.checked ? blankValues(def.fields) : null;
      rerender();
      if (id === "anomaly" || id === "inbound_announcer" || id === "bmp") refreshDependents();
    });
    lab.appendChild(cb);
    lab.appendChild(el("span", "", " " + def.title + (cb.checked ? " is set" : " is not set")));
    mount.appendChild(lab);
    if (form.blocks[id] == null) return;
  }
  if (!form.blocks[id]) form.blocks[id] = blankValues(def.fields);
  var body = el("div", "block-body");
  body.dataset.path = def.yaml;
  mount.appendChild(body);
  renderFields(body, def.fields, form.blocks[id], def.yaml, rerender, blockVisible(def));
}

function refreshDependents() {
  if (typeof renderAnomalyRules === "function") renderAnomalyRules();
  if (typeof fillAnomalyState === "function") fillAnomalyState();
}

// renderFlowExtras draws the problems, transit, and subranges groups of each
// flow card, under its Advanced fold.
function renderFlowExtras() {
  if (!schema) return;
  var cards = document.querySelectorAll("#form-flows > .card");
  Array.prototype.forEach.call(cards, function (card, i) {
    var flow = form.flows[i];
    if (!flow) return;
    if (!flow.extra) flow.extra = blankValues(schema.flow_extras);
    var old = card.querySelector(".flow-extra");
    if (old) card.removeChild(old);
    var fold = el("details", "advanced flow-extra");
    fold.appendChild(el("summary", "", "Show advanced: problems, transit, sub-ranges"));
    var rerender = function () { renderFlowExtras(); };
    schema.flow_extras.forEach(function (f) { renderField(fold, f, flow.extra, "flow[" + i + "]", rerender); });
    card.appendChild(fold);
  });
}

var pluginKinds = {
  probers: "Prober", sources: "Source", notifiers: "Notifier", telemetry: "Telemetry",
  policies: "Policy", storage: "Storage"
};

function renderPlugins() {
  var root = byId("form-plugins");
  if (!root) return;
  clear(root);
  var list = form.plugins || [];
  list.forEach(function (p, i) {
    var card = el("div", "card plugin-card");
    card.dataset.path = "plugins[" + i + "]";
    var head = el("div", "card-head");
    var on = el("input");
    on.type = "checkbox";
    on.checked = !!p.enabled;
    if (on.checked) on.setAttribute("checked", "checked");
    on.setAttribute("aria-label", "Keep this plugin");
    on.addEventListener("change", function () { markDirty(on); p.enabled = on.checked; card.classList.toggle("off", !on.checked); });
    head.appendChild(on);
    head.appendChild(el("strong", "", (pluginKinds[p.list] || p.list) + " " + p.type));
    head.appendChild(el("span", "tag", p.enabled ? "on" : "off: removed on Save"));
    if (!p.key) {
      var minus = el("button", "small", "-");
      minus.type = "button";
      minus.title = "Remove plugin";
      minus.addEventListener("click", function () { list.splice(i, 1); renderPlugins(); });
      head.appendChild(minus);
    }
    card.appendChild(head);
    var name = rowInput(p.name, "", true);
    name.addEventListener("input", function () { markDirty(name); p.name = name.value.trim(); });
    attachCheck(name, function () { return name.value.trim() ? jsChecks.name(name.value.trim()) : ""; });
    card.appendChild(labeled("Name", name, "Optional label. It defaults to the type.", "name"));
    renderSettings(card, p, "plugins[" + i + "]", p.type === "exec");
    // The server refuses any change to an exec plugin: it runs a program,
    // so it is edited only in the raw YAML.
    if (p.type === "exec") {
      card.querySelectorAll("input, select, button").forEach(function (c) { c.disabled = true; });
      head.appendChild(el("span", "tag", "read-only: it runs a program, edit it in the raw YAML"));
    }
    root.appendChild(card);
  });
  if (!list.length) root.appendChild(el("p", "empty", "No plugins beyond the cards above."));
  renderAddPlugin(root);
}

function renderSettings(card, p, at, locked) {
  var fold = el("details", "advanced");
  fold.appendChild(el("summary", "", "Show settings"));
  (p.settings || []).forEach(function (s, j) {
    var box = fieldBox(fold, at + ".settings[" + j + "]");
    if (s.kind === "hidden" || s.kind === "nested") {
      var note = s.kind === "hidden" ? "Hidden: it may hold a secret. Edit it in the raw YAML, or use a _env key." : "Nested: kept as it is. Edit it in the raw YAML.";
      box.appendChild(labeled(s.key, el("span", "tag", "kept"), note, "config." + s.key));
      return;
    }
    var control;
    if (s.kind === "bool") {
      control = selectInput([["true", "true"], ["false", "false"]], s.value);
      control.addEventListener("change", function () { markDirty(control); s.value = control.value; });
    } else {
      control = rowInput(s.value, "", true);
      control.dataset.raw = s.value || "";
      control.addEventListener("input", function () { markDirty(control); s.value = control.value.trim(); });
      if (s.kind === "int") attachCheck(control, function () { return control.value.trim() && !/^-?\d+$/.test(control.value.trim()) ? "Enter a whole number." : ""; });
      if (s.kind === "float") attachCheck(control, function () { return control.value.trim() && isNaN(Number(control.value.trim())) ? "Enter a number." : ""; });
    }
    var lab = labeled(s.key, control, "Empty removes the setting.", "config." + s.key);
    box.appendChild(lab);
  });
  if (locked) {
    card.appendChild(fold);
    return;
  }
  var key = rowInput("", "setting name", false);
  var value = rowInput("", "value", false);
  var add = el("button", "small", "+ Setting");
  add.type = "button";
  add.addEventListener("click", function () {
    var k = key.value.trim();
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(k)) { showErr(key, "Use lowercase letters, digits, and underscores."); return; }
    if ((p.settings || []).some(function (s) { return s.key === k; })) { showErr(key, "That setting is already listed."); return; }
    p.settings = (p.settings || []).concat([{key: k, value: value.value.trim(), kind: ""}]);
    renderPlugins();
  });
  var row = el("div", "row");
  row.appendChild(labeled("New setting", key, "A key the plugin documents, such as timeout.", ""));
  row.appendChild(labeled("Value", value, "A secret goes in an environment variable: name it in a _env setting.", ""));
  row.appendChild(add);
  fold.appendChild(row);
  card.appendChild(fold);
}

function renderAddPlugin(root) {
  if (!schema) return;
  var row = el("div", "row");
  var lists = schema.plugin_lists.filter(function (l) { return (schema.plugin_types[l] || []).length; });
  if (!lists.length) return;
  var kind = selectInput(lists.map(function (l) { return [l, pluginKinds[l] || l]; }), lists[0]);
  kind.id = "pl-new-list";
  var type = selectInput([], "");
  type.id = "pl-new-type";
  function fillTypes() {
    clear(type);
    (schema.plugin_types[kind.value] || []).forEach(function (t) {
      var o = el("option", "", t);
      o.value = t;
      o.setAttribute("value", t);
      type.appendChild(o);
    });
  }
  fillTypes();
  kind.addEventListener("change", fillTypes);
  var add = el("button", "small", "+ Plugin");
  add.id = "pl-new-add";
  add.type = "button";
  add.addEventListener("click", function () {
    if (!type.value) return;
    form.plugins = (form.plugins || []).concat([{list: kind.value, key: "", type: type.value, name: "", enabled: true, settings: []}]);
    renderPlugins();
  });
  row.appendChild(labeled("Kind", kind, "Where the plugin goes in the file.", ""));
  row.appendChild(labeled("Type", type, "Only built-in types are offered. An exec plugin is added in the raw YAML.", ""));
  row.appendChild(add);
  root.appendChild(row);
}

var yamlPrefix = /^settings form: /;

// clearServerErrors removes the marks of the last server answer, so a fixed
// field does not keep blocking Apply.
function clearServerErrors() {
  Array.prototype.forEach.call(document.querySelectorAll("[data-server]"), function (n) {
    n.textContent = "";
    n.hidden = true;
    delete n.dataset.server;
  });
}

// showServerErrors marks the field each message names. It returns the
// messages that name no field, for the status list.
function showServerErrors(messages) {
  var boxes = Array.prototype.slice.call(document.querySelectorAll(".bfield[data-path]"));
  clearServerErrors();
  var rest = [];
  (messages || []).forEach(function (raw) {
    var msg = raw.replace(yamlPrefix, "");
    var best = null;
    boxes.forEach(function (b) {
      var p = b.dataset.path;
      if (msg.indexOf(p) === 0 && !/[A-Za-z0-9_]/.test(msg.charAt(p.length) || " ") && (!best || p.length > best.dataset.path.length)) best = b;
    });
    var err = best && best.querySelector(".field-error");
    if (!err) err = legacyField(msg);
    if (!err) { rest.push(raw); return; }
    err.textContent = msg.replace(/^[^:]*: /, "");
    err.hidden = false;
    err.dataset.server = "1";
  });
  return rest;
}

// legacyField finds the row input of the older cards for a message such as
// "providers[1] (transit-b): next_hop ...".
var legacyRoots = {providers: "form-providers", targets: "form-targets", allowlist: "form-allow"};
function legacyField(msg) {
  var m = /^(providers|targets|allowlist)\[(\d+)\][^:]*: ([a-z_]+)/.exec(msg);
  if (!m) return null;
  var root = byId(legacyRoots[m[1]]);
  var row = root && root.children[Number(m[2])];
  if (!row) return null;
  var labels = row.querySelectorAll("label");
  for (var i = 0; i < labels.length; i++) {
    var span = labels[i].querySelector(".field-label");
    if (span && span.title && span.title.slice(-m[3].length) === m[3]) return labels[i].querySelector(".field-error");
  }
  var errs = row.querySelectorAll(".field-error");
  return errs.length === 1 ? errs[0] : null;
}
