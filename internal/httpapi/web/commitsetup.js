"use strict";
// Commit setup (#174): a guided edit of the settings form's commit section.
// Loaded after settings.js, which owns `form`, the editor, and the API
// calls. It never writes the file: Apply copies the choices into the YAML
// text, and Save is the editor's. There is no field for a secret: a new
// SNMP host names the environment variable that holds its community.

var cs = {scorer: "weighted", balance: "", precedence: "performance"};
var CS_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
var CS_PERCENTILES = [["greater_separate", "greater of the in and out 95th"], ["greater", "95th of the larger direction"], ["separate", "in and out apart (out is compared)"]];

function csKey(p) { return p.key || p.name; }

var csRows = new WeakMap();

// csTicks holds the Track commit tick per provider object, not per name: a
// provider the form just added is renamed while it is typed, and a name key
// would lose the tick.
var csTicks = new WeakMap();

// csRow is the commit row of a form provider. A provider the form just
// added has none yet. The row is remembered per provider object because
// csSync renames it to the provider's edited name, after which the file
// name no longer finds it.
function csRow(p) {
  var known = csRows.get(p);
  if (known) return known;
  var rows = form.commit.providers;
  var row = null;
  for (var i = 0; i < rows.length && !row; i++) {
    if (rows[i].name === csKey(p)) row = rows[i];
  }
  if (!row) {
    row = {name: csKey(p), host: "", interface: "", billing_day: "", percentile: "", group: "", precedence: "", cc_disable: false};
    rows.push(row);
  }
  csRows.set(p, row);
  return row;
}

function csTracked(p) { return csTicks.has(p) ? !!csTicks.get(p) : !!p.commit_bound; }

// csProviders are the form's providers that have a name; a draft row waits
// for one.
function csProviders() { return form.providers.filter(function (p) { return p.name; }); }

function csStatus(text) { byId("cs-status").textContent = text || ""; }

function csErrors(list) {
  var ul = byId("cs-errors");
  clear(ul);
  (list || []).forEach(function (e) { ul.appendChild(el("li", "", e)); });
}

function csSelect(options, value, onChange) {
  var sel = el("select");
  options.forEach(function (o) {
    var opt = el("option", "", o[1]);
    opt.value = o[0];
    sel.appendChild(opt);
  });
  sel.value = value;
  sel.addEventListener("change", function () { onChange(sel.value); });
  return sel;
}

// csSync makes the commit rows match the form's providers, in case one was
// renamed or removed in the form above.
function csSync() {
  var rows = [];
  csProviders().forEach(function (p) {
    var row = csRow(p);
    row.name = p.name;
    rows.push(row);
  });
  form.commit.providers = rows;
}

function csShowStep(n) {
  [1, 2, 3, 4].forEach(function (i) {
    byId("cs-" + i).hidden = i !== n;
    byId("cs-tab-" + i).className = i === n ? "on" : "";
  });
}

function csHostNames() {
  return form.commit.hosts.map(function (h) { return h.name; }).filter(Boolean);
}

function csEnvProblem(h, key, what, not) {
  var v = h[key] || "";
  if (CS_ENV_NAME.test(v)) return [];
  return ["SNMP host " + (h.name || "") + ": enter the name of the environment variable that holds " + what + " (letters, digits, underscore), not " + (not || "the secret") + " itself."];
}

// csHostProblems are the checks of one SNMP host, the same as the server's.
function csHostProblems(h) {
  var p = [];
  var who = "SNMP host " + (h.name || "") + ": ";
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(h.name || "")) p.push("SNMP host: enter a name of up to 64 letters, digits, dot, dash, or underscore.");
  if (!h.address) p.push(who + "enter its address.");
  if (h.port && !(/^\d+$/.test(h.port) && Number(h.port) >= 1 && Number(h.port) <= 65535)) p.push(who + "the port is 1 to 65535.");
  if (h.version === "3") {
    p = p.concat(csEnvProblem(h, "username_env", "the SNMP user name"));
    if (h.security_level !== "noAuthNoPriv") p = p.concat(csEnvProblem(h, "auth_env", "the authentication secret"));
    if (h.security_level === "authPriv") p = p.concat(csEnvProblem(h, "priv_env", "the privacy secret"));
  } else {
    p = p.concat(csEnvProblem(h, "community_env", "the community", "the community"));
  }
  return p;
}

function csProblems(step) {
  var p = [];
  if (step === 2) {
    form.commit.hosts.forEach(function (h) { csHostProblems(h).forEach(function (m) { p.push(m); }); });
    csProviders().forEach(function (pr) {
      if (!csTracked(pr)) return;
      var row = csRow(pr);
      var label = "Provider " + pr.name + ": ";
      if (!(Number(pr.commit_mbps) > 0)) p.push(label + "enter a commit greater than zero (Mbps).");
      if (!row.host) p.push(label + "choose an SNMP host.");
      if (!row.interface) p.push(label + "enter the interface name.");
      var day = Number(row.billing_day);
      if (!(day >= 1 && day <= 28 && Math.floor(day) === day)) p.push(label + "billing day is 1 to 28.");
    });
  }
  if (step === 3) {
    csProviders().forEach(function (pr) {
      var row = csRow(pr);
      if (row.precedence !== "" && !(/^\d+$/.test(row.precedence) && Number(row.precedence) <= 10000)) p.push("Provider " + pr.name + ": precedence is a whole number from 0 to 10000 (0 means 100).");
      if (row.group !== "" && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(row.group)) p.push("Provider " + pr.name + ": group is 1 to 64 letters, digits, dot, dash, or underscore.");
    });
  }
  return p;
}

function csGo(from, to) {
  var problems = to > from ? csProblems(from) : [];
  csErrors(problems);
  csStatus(problems.length ? "Fix the fields first." : "");
  if (problems.length) return;
  if (to === 4) renderCsReview();
  csShowStep(to);
}

function renderCsStrategy() {
  var custom = ["weighted", "commit", "cost"].indexOf(form.scorer_type || "weighted") < 0;
  var sel = byId("cs-scorer");
  sel.disabled = custom;
  Array.prototype.slice.call(sel.options).forEach(function (o) {
    if (["weighted", "commit", "cost"].indexOf(o.value) < 0) sel.removeChild(o);
  });
  if (custom) {
    var opt = el("option", "", "custom: " + form.scorer_type);
    opt.value = form.scorer_type;
    sel.appendChild(opt);
  }
  sel.value = cs.scorer;
  byId("cs-balance").value = cs.balance;
  byId("cs-precedence").value = cs.precedence;
  byId("cs-balance-label").hidden = cs.scorer !== "commit";
  byId("cs-precedence-label").hidden = cs.scorer !== "cost";
  var note = {
    weighted: "Probes decide. Nothing is steered for a commit or a price. Usage and 95th are still graphed once a provider has a binding.",
    commit: "Keeps each provider's billable 95th under its commit by moving flow-measured prefixes to a provider with room. Needs a telemetry binding and a commit on the providers, and flow volume (or mbps on a static target).",
    cost: "Moves prefixes to the cheapest provider whose path stays inside the floor. Needs a cost on at least two providers. It does not control commit; use commit for that."
  }[cs.scorer] || "This file uses scorer type " + form.scorer_type + ", which the form does not replace. Use the raw YAML to change it.";
  byId("cs-scorer-note").textContent = note + " Observe stays the default; moves are recommendations until mode is inject.";
}

function csHostUsers(name) {
  return form.commit.providers.filter(function (r) { return r.host === name && name; }).map(function (r) { return r.name; });
}

// csEnvInput is a field for the name of an environment variable.
function csEnvInput(row, h, label, key, help) {
  var input = rowInput(h[key]);
  input.addEventListener("input", function () { markDirty(input); h[key] = input.value.trim(); });
  attachCheck(input, function () {
    var v = input.value.trim();
    return !v || CS_ENV_NAME.test(v) ? "" : "Enter the name of an environment variable, not the secret.";
  });
  row.appendChild(labeled(label, input, help, key));
}

function csSelectField(row, h, label, key, options, help, after) {
  var sel = selectInput(options, h[key]);
  sel.className = "g-select";
  sel.addEventListener("change", function () { markDirty(sel); h[key] = sel.value; if (after) after(); });
  row.appendChild(labeled(label, sel, help, key));
}

function renderCsHosts() {
  var root = byId("cs-hosts");
  clear(root);
  var snmp = (typeof schema === "object" && schema && schema.snmp) || {security_levels: [], auth_protocols: [], priv_protocols: []};
  var opts = function (list) { return list.map(function (v) { return [v, v]; }); };
  form.commit.hosts.forEach(function (h, i) {
    var card = el("div", "card cs-host");
    var head = el("div", "card-head");
    head.appendChild(el("strong", "", h.key ? "SNMP host " + h.key : "New SNMP host"));
    var users = csHostUsers(h.key || h.name);
    var minus = el("button", "small", "-");
    minus.type = "button";
    minus.title = users.length ? "Used by " + users.join(", ") + ": untrack it first" : "Remove host";
    minus.disabled = users.length > 0;
    minus.addEventListener("click", function () {
      form.commit.hosts.splice(i, 1);
      renderCsHosts();
      renderCsProviders();
    });
    head.appendChild(minus);
    card.appendChild(head);
    var row = el("div", "row");
    var name = rowInput(h.name);
    name.addEventListener("input", function () { markDirty(name); h.name = name.value.trim(); });
    var was = h.name;
    name.addEventListener("change", function () {
      // A binding names its host, so a rename follows.
      form.commit.providers.forEach(function (r) { if (was && r.host === was) r.host = h.name; });
      was = h.name;
      renderCsProviders();
    });
    var addr = rowInput(h.address);
    addr.addEventListener("input", function () { markDirty(addr); h.address = addr.value.trim(); });
    row.appendChild(labeled(h.key ? "Host name" : "New SNMP host", name, "Unique name that providers refer to, for example edge1.", "telemetry.snmp.hosts.name"));
    row.appendChild(labeled("Address", addr, "IP address or host name of the SNMP agent, for example 192.0.2.254.", "telemetry.snmp.hosts.address"));
    row.appendChild(labeled("Port", numberControl(h, "port", {min: 1, max: 65535, integer: true, def: 161}), "UDP port of the agent.", "telemetry.snmp.hosts.port"));
    csSelectField(row, h, "SNMP version", "version", [["2c", "2c (community)"], ["3", "3 (user and secrets)"]], "Version 3 is safer. Credentials are environment variable names.", function () {
      if (h.version === "3") {
        h.community_env = "";
        h.security_level = h.security_level || "authPriv";
        h.auth_protocol = h.auth_protocol || "SHA256";
        h.priv_protocol = h.priv_protocol || "AES";
      } else {
        ["username_env", "security_level", "auth_protocol", "auth_env", "priv_protocol", "priv_env", "context_name"].forEach(function (k) { h[k] = ""; });
      }
      renderCsHosts();
    });
    card.appendChild(row);
    var creds = el("div", "row");
    if (h.version === "3") {
      csEnvInput(creds, h, "User variable (name only)", "username_env", "Environment variable that holds the SNMP user name, for example PACKETEER_SNMP_USER.");
      csSelectField(creds, h, "Security level", "security_level", opts(snmp.security_levels), "What the session protects.", function () {
        if (h.security_level === "noAuthNoPriv") ["auth_protocol", "auth_env", "priv_protocol", "priv_env"].forEach(function (k) { h[k] = ""; });
        if (h.security_level === "authNoPriv") { h.priv_protocol = ""; h.priv_env = ""; }
        if (h.security_level !== "noAuthNoPriv") h.auth_protocol = h.auth_protocol || "SHA256";
        if (h.security_level === "authPriv") h.priv_protocol = h.priv_protocol || "AES";
        renderCsHosts();
      });
      if (h.security_level !== "noAuthNoPriv") {
        csSelectField(creds, h, "Authentication", "auth_protocol", opts(snmp.auth_protocols), "Protocol of the authentication secret.");
        csEnvInput(creds, h, "Authentication variable (name only)", "auth_env", "Environment variable that holds the secret (at least 8 characters), for example PACKETEER_SNMP_AUTH.");
      }
      if (h.security_level === "authPriv") {
        csSelectField(creds, h, "Privacy", "priv_protocol", opts(snmp.priv_protocols), "Protocol of the privacy secret.");
        csEnvInput(creds, h, "Privacy variable (name only)", "priv_env", "Environment variable that holds the secret (at least 8 characters), for example PACKETEER_SNMP_PRIV.");
      }
      var ctx = rowInput(h.context_name);
      ctx.addEventListener("input", function () { markDirty(ctx); h.context_name = ctx.value.trim(); });
      creds.appendChild(labeled("Context", ctx, "SNMP context name. Optional, and not a credential.", "telemetry.snmp.hosts.context_name"));
    } else {
      csEnvInput(creds, h, "Community variable (name only)", "community_env", "Environment variable that holds the SNMP community, for example PACKETEER_SNMP_COMMUNITY.");
    }
    card.appendChild(creds);
    root.appendChild(card);
  });
  if (!form.commit.hosts.length) root.appendChild(el("p", "empty", "No SNMP host in the file. Add one: the address of the router, its SNMP version, and the names of the environment variables that hold its credentials."));
}

function renderCsProviders() {
  var root = byId("cs-providers");
  clear(root);
  var list = csProviders();
  list.forEach(function (p) {
    var row = csRow(p);
    var line = el("div", "row");
    var tick = el("input");
    tick.type = "checkbox";
    tick.checked = csTracked(p);
    tick.addEventListener("change", function () {
      csTicks.set(p, tick.checked);
      if (tick.checked) {
        row.host = row.host || csHostNames()[0] || "";
        row.billing_day = row.billing_day || "1";
        row.percentile = row.percentile || "greater_separate";
      } else {
        row.host = row.interface = row.billing_day = row.percentile = "";
        p.commit_mbps = "";
      }
      renderCsProviders();
    });
    var lab = labeled("Track commit on " + p.name, tick);
    lab.className = "field check";
    line.appendChild(lab);
    if (csTracked(p)) {
      var commit = rowInput(p.commit_mbps);
      commit.addEventListener("input", function () { p.commit_mbps = commit.value.trim(); });
      commit.addEventListener("change", renderProviders);
      var iface = rowInput(row.interface);
      iface.addEventListener("input", function () { row.interface = iface.value.trim(); });
      var day = rowInput(row.billing_day);
      day.addEventListener("input", function () { row.billing_day = day.value.trim(); });
      var hosts = [["", "choose a host"]].concat(csHostNames().map(function (n) { return [n, n]; }));
      line.appendChild(labeled("Commit (Mbps)", commit, "Contracted rate in Mbps, for example 1000."));
      line.appendChild(labeled("SNMP host", csSelect(hosts, row.host, function (v) { row.host = v; })));
      line.appendChild(labeled("Interface", iface, "Interface name on the SNMP host, for example ether1."));
      line.appendChild(labeled("Billing day (1-28)", day, "Day of the month the bill cycle starts."));
      line.appendChild(labeled("Percentile", csSelect(CS_PERCENTILES, row.percentile || "greater_separate", function (v) { row.percentile = v; })));
      if (!row.percentile) row.percentile = "greater_separate";
    } else {
      line.appendChild(el("span", "tag", "No commit tracked."));
    }
    root.appendChild(line);
  });
  if (!list.length) root.appendChild(el("p", "empty", "No providers yet. Add and name them in the settings form below, then come back."));
}

function renderCsGroups() {
  var root = byId("cs-groups");
  clear(root);
  var list = csProviders();
  list.forEach(function (p) {
    var row = csRow(p);
    var line = el("div", "row");
    line.appendChild(el("span", "mono", p.name));
    var group = rowInput(row.group);
    var prec = rowInput(row.precedence);
    var cc = el("input");
    cc.type = "checkbox";
    cc.checked = !!row.cc_disable;
    group.addEventListener("input", function () { row.group = group.value.trim(); });
    prec.addEventListener("input", function () { row.precedence = prec.value.trim(); });
    cc.addEventListener("change", function () { row.cc_disable = cc.checked; });
    line.appendChild(labeled("Group", group, "Providers with the same group name share traffic."));
    line.appendChild(labeled("Precedence", prec, "Lower is preferred. Default: 100."));
    var lab = labeled("Leave out of commit control (cc_disable)", cc);
    lab.className = "field check";
    line.appendChild(lab);
    root.appendChild(line);
  });
  if (!list.length) root.appendChild(el("p", "empty", "No providers."));
}

function renderCsReview() {
  var ul = byId("cs-review");
  clear(ul);
  var line = function (text) { ul.appendChild(el("li", "", text)); };
  var was = form.scorer_type || "weighted";
  line("Scorer: " + cs.scorer + (cs.scorer === was ? " (unchanged)" : " (was " + was + ")") + ".");
  if (cs.scorer === "commit") line("Balance in a group: " + (cs.balance || "default (off)") + ".");
  if (cs.scorer === "cost") line("Cost or performance first: " + cs.precedence + ".");
  form.commit.hosts.forEach(function (h) {
    if (h.key && JSON.stringify(h) === csHostSnap[h.key]) return;
    var creds = h.version === "3" ? "user from $" + h.username_env + (h.security_level !== "noAuthNoPriv" ? ", authentication secret from $" + h.auth_env : "") + (h.security_level === "authPriv" ? ", privacy secret from $" + h.priv_env : "") : "community read from the environment variable " + h.community_env;
    line((h.key ? "SNMP host " : "New SNMP host ") + h.name + " at " + h.address + (h.port ? " port " + h.port : "") + ", version " + h.version + ", " + creds + ".");
  });
  var tracked = 0;
  csProviders().forEach(function (p) {
    var row = csRow(p);
    var parts = [];
    if (csTracked(p)) {
      tracked++;
      parts.push("commit " + p.commit_mbps + " Mbps on " + row.host + " " + row.interface + ", billing day " + row.billing_day + ", " + row.percentile);
    }
    if (row.group) parts.push("group " + row.group);
    if (row.precedence) parts.push("precedence " + row.precedence);
    if (row.cc_disable) parts.push("cc_disable");
    if (parts.length) line(p.name + ": " + parts.join("; ") + ".");
  });
  if (cs.scorer === "commit" && !tracked) line("Warning: the commit scorer has no provider with a commit, so it will not steer.");
  if (cs.scorer === "cost" && csProviders().filter(function (p) { return p.cost; }).length < 2) line("Warning: the cost scorer needs a cost on at least two providers; Validate will refuse it.");
  line("Mode, the allowlist, and the improvement cap are not touched. Save, then restart the container for the scorer and telemetry to take effect.");
}

// csHostSnap is each SNMP host as the file has it, to tell the review which
// ones were edited.
var csHostSnap = {};

function renderCommitSetup() {
  if (!byId("commit-setup")) return;
  csHostSnap = {};
  form.commit.hosts.forEach(function (h) { csHostSnap[h.key] = JSON.stringify(h); });
  cs.scorer = (typeof scorerNow === "function" ? scorerNow() : form.scorer_type) || "weighted";
  cs.balance = form.commit.balance || "";
  cs.precedence = form.precedence || "performance";
  csSync();
  renderCsStrategy();
  renderCsHosts();
  renderCsProviders();
  renderCsGroups();
}

function csApply() {
  csErrors([]);
  csSync();
  readKnobs();
  form.commit.scorer = cs.scorer !== (form.scorer_type || "weighted") ? cs.scorer : "";
  form.commit.balance = cs.scorer === "commit" ? cs.balance : "";
  form.precedence = cs.scorer === "cost" ? cs.precedence : "";
  if (cs.scorer !== "cost") {
    form.floor_max_loss_pct = "";
    form.floor_max_rtt = "";
  }
  postForm(csStatus).then(function (out) {
    if (out) {
      checkConfig();
      byId("editor-section").scrollIntoView();
    }
  });
}

byId("cs-scorer").addEventListener("change", function () {
  cs.scorer = byId("cs-scorer").value;
  renderCsStrategy();
});
byId("cs-balance").addEventListener("change", function () { cs.balance = byId("cs-balance").value; });
byId("cs-precedence").addEventListener("change", function () { cs.precedence = byId("cs-precedence").value; });
byId("cs-next-1").addEventListener("click", function () { csGo(1, 2); });
byId("cs-back-2").addEventListener("click", function () { csGo(2, 1); });
byId("cs-next-2").addEventListener("click", function () { csGo(2, 3); });
byId("cs-back-3").addEventListener("click", function () { csGo(3, 2); });
byId("cs-next-3").addEventListener("click", function () { csGo(3, 4); });
byId("cs-back-4").addEventListener("click", function () { csGo(4, 3); });
byId("cs-add-host").addEventListener("click", function () {
  form.commit.hosts.push({key: "", name: "", address: "", port: "", version: "2c", community_env: "", username_env: "", security_level: "",
    auth_protocol: "", auth_env: "", priv_protocol: "", priv_env: "", context_name: ""});
  renderCsHosts();
});
byId("cs-apply").addEventListener("click", csApply);
csShowStep(1);
renderCommitSetup();
