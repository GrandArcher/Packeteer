"use strict";
// Commit setup (#174): a guided edit of the settings form's commit section.
// Loaded after settings.js, which owns `form`, the editor, and the API
// calls. It never writes the file: Apply copies the choices into the YAML
// text, and Save is the editor's. There is no field for a secret: a new
// SNMP host names the environment variable that holds its community.

var cs = {scorer: "weighted", balance: "", precedence: "performance", tracked: {}};
var CS_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
var CS_PERCENTILES = [["greater_separate", "greater of the in and out 95th"], ["greater", "95th of the larger direction"], ["separate", "in and out apart (out is compared)"]];

function csKey(p) { return p.key || p.name; }

var csRows = new WeakMap();

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

function csTracked(p) { return !!(p.commit_bound || cs.tracked[csKey(p)]); }

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

function csProblems(step) {
  var p = [];
  if (step === 2) {
    form.commit.hosts.forEach(function (h) {
      if (h.key) return;
      if (!h.name) p.push("SNMP host: enter a name.");
      if (!h.address) p.push("SNMP host " + (h.name || "") + ": enter its address.");
      if (!CS_ENV_NAME.test(h.community_env || "")) p.push("SNMP host " + (h.name || "") + ": enter the name of the environment variable that holds the community (letters, digits, underscore), not the community itself.");
    });
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
  }[cs.scorer] || "This file uses scorer type " + form.scorer_type + ", which the form does not replace. Change it in the YAML.";
  byId("cs-scorer-note").textContent = note + " Observe stays the default; moves are recommendations until mode is inject.";
}

function renderCsHosts() {
  var root = byId("cs-hosts");
  clear(root);
  form.commit.hosts.forEach(function (h, i) {
    var row = el("div", "row");
    if (h.key) {
      row.appendChild(el("span", "mono", h.name));
      row.appendChild(el("span", "tag", h.address + (h.community_env ? ", community from $" + h.community_env : ", credentials set in the YAML") + ". Edit it in the YAML."));
    } else {
      var name = rowInput(h.name, "edge1");
      var addr = rowInput(h.address, "192.0.2.254");
      var env = rowInput(h.community_env, "PACKETEER_SNMP_COMMUNITY");
      name.addEventListener("input", function () { form.commit.hosts[i].name = name.value.trim(); });
      addr.addEventListener("input", function () { form.commit.hosts[i].address = addr.value.trim(); });
      env.addEventListener("input", function () { form.commit.hosts[i].community_env = env.value.trim(); });
      name.addEventListener("change", renderCsProviders);
      row.appendChild(labeled("New SNMP host", name));
      row.appendChild(labeled("Address", addr));
      row.appendChild(labeled("Community variable (name only)", env));
      var minus = el("button", "small", "−");
      minus.type = "button";
      minus.title = "Remove host";
      minus.addEventListener("click", function () {
        var gone = form.commit.hosts.splice(i, 1)[0];
        form.commit.providers.forEach(function (r) { if (r.host === gone.name && !gone.key) r.host = ""; });
        renderCsHosts();
        renderCsProviders();
      });
      row.appendChild(minus);
    }
    root.appendChild(row);
  });
  if (!form.commit.hosts.length) root.appendChild(el("p", "empty", "No SNMP host in the file. Add one: the address of the router and the name of the environment variable that holds its SNMP community (version 2c). Version 3 hosts are written in the YAML."));
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
    tick.disabled = !!p.commit_bound;
    tick.addEventListener("change", function () {
      cs.tracked[csKey(p)] = tick.checked;
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
      var commit = rowInput(p.commit_mbps, "1000");
      commit.addEventListener("input", function () { p.commit_mbps = commit.value.trim(); });
      commit.addEventListener("change", renderProviders);
      var iface = rowInput(row.interface, "ether1");
      iface.addEventListener("input", function () { row.interface = iface.value.trim(); });
      var day = rowInput(row.billing_day, "1");
      day.addEventListener("input", function () { row.billing_day = day.value.trim(); });
      var hosts = [["", "choose a host"]].concat(csHostNames().map(function (n) { return [n, n]; }));
      line.appendChild(labeled("Commit (Mbps)", commit));
      line.appendChild(labeled("SNMP host", csSelect(hosts, row.host, function (v) { row.host = v; })));
      line.appendChild(labeled("Interface", iface));
      line.appendChild(labeled("Billing day (1-28)", day));
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
    var group = rowInput(row.group, "edge");
    var prec = rowInput(row.precedence, "100");
    var cc = el("input");
    cc.type = "checkbox";
    cc.checked = !!row.cc_disable;
    group.addEventListener("input", function () { row.group = group.value.trim(); });
    prec.addEventListener("input", function () { row.precedence = prec.value.trim(); });
    cc.addEventListener("change", function () { row.cc_disable = cc.checked; });
    line.appendChild(labeled("Group", group));
    line.appendChild(labeled("Precedence", prec));
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
    if (!h.key) line("New SNMP host " + h.name + " at " + h.address + ", version 2c, community read from the environment variable " + h.community_env + ".");
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

function renderCommitSetup() {
  if (!byId("commit-setup")) return;
  cs.scorer = form.scorer_type || "weighted";
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
  form.commit.hosts.push({key: "", name: "", address: "", community_env: ""});
  renderCsHosts();
});
byId("cs-apply").addEventListener("click", csApply);
csShowStep(1);
renderCommitSetup();
