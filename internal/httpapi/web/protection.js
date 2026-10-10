"use strict";
// The Protection page forms (#131): add and remove a mitigation rule over
// POST /api/mitigations and DELETE /api/mitigations/{id}. The server
// checks the allowlist, the cap, the TTL, the learned RIB, and the mode on
// every call; this file only builds the request. Nothing here announces:
// only the controller in inject mode does, and only for a learned prefix.
// Uses el and clear from app.js. No inline script: the CSP allows scripts
// from this origin only.

var protMe = null;
var protData = null;
var protFormKey = "";
var protTimer = null;
var protCanWrite = false;

var PROT_ACTION_TEXT = {
  blackhole: "Blackhole (RTBH)",
  redirect: "Redirect to a target",
  flowspec_drop: "FlowSpec drop",
  flowspec_rate_limit: "FlowSpec rate limit",
  flowspec_redirect: "FlowSpec redirect"
};

function protJSON(method, path, body) {
  var opts = {method: method, cache: "no-store", headers: {Accept: "application/json"}};
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (res) {
    return res.text().then(function (text) {
      var data = null;
      try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
      if (!res.ok) {
        var err = new Error((data && data.error) || res.statusText);
        err.status = res.status;
        throw err;
      }
      return data;
    });
  });
}

// protModeText says what a block's mode means. Observe is the default.
function protModeText(mode) {
  if (mode === "inject") return "inject: rules for learned prefixes inside the allowlist are announced with the community and NO_EXPORT, and withdrawn when the rule ends, the controller stops, or the RIB session drops.";
  return "observe: rules are recorded and shown here. Nothing is announced.";
}

function protRenderBadge(data) {
  var badge = document.getElementById("mit-badge");
  if (!badge) return;
  var mode = data.mitigation_mode || "observe";
  badge.className = "badge mode-" + (mode === "inject" || mode === "observe" ? mode : "unknown");
  badge.textContent = mode;
  var text = document.getElementById("mit-badge-text");
  if (text) text.textContent = protModeText(mode);
}

// protWritable: the page offers the form only when the server says writes
// are on and the account may use the operator routes. The server decides
// again on every call.
function protWritable(data, me) {
  if (!data || !data.enabled || !data.writable) return false;
  if (me && me.auth === "rbac") return me.role === "operator" || me.role === "admin";
  return true;
}

function protActions(data) {
  var out = ["blackhole"];
  var cat = data.catalog || {};
  var fs = data.flowspec || {};
  if ((cat.targets || []).length) out.push("redirect");
  if (fs.enabled) out.push("flowspec_drop", "flowspec_rate_limit");
  if (fs.enabled && (fs.targets || []).length) out.push("flowspec_redirect");
  return out;
}

function protFillTargets(data) {
  var action = document.getElementById("mf-action").value;
  var sel = document.getElementById("mf-target");
  var wrap = document.getElementById("mf-target-wrap");
  var names = [];
  if (action === "redirect") names = ((data.catalog || {}).targets || []).map(function (t) { return t.name; });
  if (action === "flowspec_redirect") names = ((data.flowspec || {}).targets || []).map(function (t) { return t.name; });
  var keep = sel.value;
  clear(sel);
  names.forEach(function (n) {
    var o = el("option", "", n);
    o.value = n;
    sel.appendChild(o);
  });
  if (names.indexOf(keep) >= 0) sel.value = keep;
  wrap.hidden = !names.length;
  var fs = action.indexOf("flowspec_") === 0;
  document.getElementById("mf-flowspec").hidden = !fs;
  document.getElementById("mf-rate-wrap").hidden = action !== "flowspec_rate_limit";
  document.getElementById("mf-countries-wrap").hidden = !fs || !(protData && protData.geoip);
}

function protSetStatus(text, bad) {
  var n = document.getElementById("mf-status");
  if (!n) return;
  n.textContent = text || "";
  n.className = bad ? "bad" : "tag";
}

var protPickerSeq = 0;

// protCandidates asks for learned prefixes inside the allowlist that
// contain q. It only reads.
function protCandidates(q) {
  return protJSON("GET", "/api/mitigations/candidates?q=" + encodeURIComponent(q));
}

function protLoadPicker() {
  var input = document.getElementById("mf-prefix");
  var seq = ++protPickerSeq;
  protCandidates(input.value.trim()).then(function (res) {
    if (seq !== protPickerSeq) return;
    var list = document.getElementById("mf-prefix-list");
    clear(list);
    (res.prefixes || []).forEach(function (p) {
      var o = el("option");
      o.value = p;
      list.appendChild(o);
    });
    if (!res.ready) {
      protSetStatus("The learned RIB view is not ready, so no prefix can be offered yet.", false);
    } else if (!(res.prefixes || []).length) {
      protSetStatus("No learned prefix inside the allowlist matches.", false);
    } else {
      protSetStatus((res.prefixes.length) + (res.truncated ? "+" : "") + " learned prefix(es) offered. Keep typing to narrow the list.", false);
    }
  }, function (err) {
    if (seq === protPickerSeq) protSetStatus(err.message, true);
  });
}

function protSplit(text) { return text.split(/[\s,]+/).filter(Boolean); }

function protBuild() {
  var action = document.getElementById("mf-action").value;
  var body = {prefix: document.getElementById("mf-prefix").value.trim(), action: action};
  var target = document.getElementById("mf-target");
  if (!document.getElementById("mf-target-wrap").hidden && target.value) body.target = target.value;
  var ttl = document.getElementById("mf-ttl").value.trim();
  if (ttl) body.ttl = ttl;
  var reason = document.getElementById("mf-reason").value.trim();
  if (reason) body.reason = reason;
  if (action.indexOf("flowspec_") === 0) {
    var match = {};
    var src = document.getElementById("mf-source").value.trim();
    if (src) match.source = src;
    var protos = protSplit(document.getElementById("mf-protocols").value);
    if (protos.length) match.protocols = protos;
    var dp = protSplit(document.getElementById("mf-dports").value);
    if (dp.length) match.destination_ports = dp;
    var sp = protSplit(document.getElementById("mf-sports").value);
    if (sp.length) match.source_ports = sp;
    if (Object.keys(match).length) body.match = match;
    if (action === "flowspec_rate_limit") {
      var rate = document.getElementById("mf-rate").value.trim();
      if (rate) body.rate_mbps = Number(rate);
    }
    var countries = protSplit(document.getElementById("mf-countries").value);
    if (countries.length) body.source_countries = countries;
  }
  return body;
}

function protSubmit(ev) {
  ev.preventDefault();
  var body = protBuild();
  if (!body.prefix) { protSetStatus("Choose a prefix from the list.", true); return; }
  if (body.action.indexOf("flowspec_") === 0 && body.action === "flowspec_rate_limit" && body.rate_mbps !== undefined && !(body.rate_mbps > 0)) {
    protSetStatus("Rate must be a positive number of Mbit/s.", true);
    return;
  }
  var btn = document.getElementById("mf-add");
  btn.disabled = true;
  protSetStatus("Checking the learned RIB view…", false);
  // The prefix has to be one the picker offers: learned and inside the
  // allowlist. The server checks the allowlist again, and in inject the
  // learned RIB on every sync.
  protCandidates(body.prefix).then(function (res) {
    if ((res.prefixes || []).indexOf(body.prefix) < 0) {
      throw new Error(body.prefix + " is not a learned prefix inside the mitigation allowlist" + (res.ready ? "" : " (the RIB view is not ready)") + ". Nothing was added.");
    }
    return protJSON("POST", "/api/mitigations", body);
  }).then(function (rule) {
    var mode = (protData && protData.mitigation_mode) || "observe";
    protSetStatus("Added " + rule.action + " for " + rule.prefix + (mode === "inject" ? "." : ". Mode is " + mode + ": nothing is announced."), false);
    document.getElementById("mf-reason").value = "";
    if (typeof refresh === "function") refresh();
  }).catch(function (err) {
    protSetStatus(err.status === 401 ? "Sign in required." : err.status === 403 ? err.message + " (needs the operator role)" : err.message, true);
  }).then(function () { btn.disabled = false; });
}

function protBuildForm(data) {
  var actions = protActions(data);
  var key = actions.join(",");
  var sel = document.getElementById("mf-action");
  if (key !== protFormKey) {
    protFormKey = key;
    var keep = sel.value;
    clear(sel);
    actions.forEach(function (a) {
      var o = el("option", "", PROT_ACTION_TEXT[a] || a);
      o.value = a;
      sel.appendChild(o);
    });
    if (actions.indexOf(keep) >= 0) sel.value = keep;
  }
  protFillTargets(data);
  var note = document.getElementById("mit-form-note");
  var ttl = document.getElementById("mf-ttl");
  ttl.placeholder = "default";
  note.textContent = "Mode " + (data.mitigation_mode || "observe") + ". " +
    (data.mitigation_mode === "inject" ? "A rule is announced only while its prefix is in the learned RIB view." : "Nothing is announced.") +
    " Allowlist: " + (data.allowlist || []).join(", ") + ". Rules held: " + data.routes_held + " of " + data.max_rules + ".";
}

// protRemoveCell is the Remove button for a rule row, when the account may
// write. The first click arms it; the second sends the DELETE.
function protRemoveCell(rule) {
  var td = el("td");
  if (!protCanWrite) return td;
  var btn = el("button", "", "Remove");
  btn.type = "button";
  btn.setAttribute("aria-label", "Remove rule " + rule.prefix + " " + rule.action);
  var armed = false;
  btn.addEventListener("click", function () {
    if (!armed) {
      armed = true;
      btn.textContent = "Confirm remove";
      return;
    }
    btn.disabled = true;
    protJSON("DELETE", "/api/mitigations/" + encodeURIComponent(rule.id)).then(function () {
      protSetStatus("Removed " + rule.action + " for " + rule.prefix + ".", false);
      if (typeof refresh === "function") refresh();
    }, function (err) {
      btn.disabled = false;
      armed = false;
      btn.textContent = "Remove";
      protSetStatus(err.message, true);
    });
  });
  td.appendChild(btn);
  return td;
}

// protectionUpdate is called by app.js with every /api/mitigations answer.
function protectionUpdate(data) {
  protData = data;
  if (!data || !data.enabled) return;
  protRenderBadge(data);
  protCanWrite = protWritable(data, protMe);
  var form = document.getElementById("mit-form");
  if (!form) return;
  form.hidden = !protCanWrite;
  if (!protCanWrite) {
    var why = !data.writable ? "Rules can be added once auth or basic auth is on (PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD)." : "Adding and removing rules needs the operator role.";
    var note = document.getElementById("mit-readonly");
    if (!note) {
      note = el("p", "tag");
      note.id = "mit-readonly";
      form.parentNode.appendChild(note);
    }
    note.textContent = why;
    return;
  }
  var ro = document.getElementById("mit-readonly");
  if (ro) ro.remove();
  protBuildForm(data);
}

function protModes() {
  var box = document.getElementById("protection-modes");
  var sec = document.getElementById("protection-links");
  if (!box || !sec) return;
  Promise.allSettled([protJSON("GET", "/api/inbound"), protJSON("GET", "/api/anomalies")]).then(function (r) {
    clear(box);
    var shown = false;
    function add(label, mode, text) {
      shown = true;
      box.appendChild(el("span", "k", label));
      var b = el("span", "badge mode-" + (mode === "inject" || mode === "observe" || mode === "suggest" ? mode : "unknown"), mode);
      box.appendChild(b);
      box.appendChild(el("span", "v", text));
    }
    if (r[0].status === "fulfilled" && r[0].value.enabled) {
      var m = r[0].value.inbound_mode || "observe";
      add("Inbound", m, m === "inject" ? "steers are announced" : "nothing is announced");
    }
    if (r[1].status === "fulfilled" && r[1].value.enabled) {
      var mm = (protData && protData.mitigation_mode) || "observe";
      add("Anomaly rules", mm, "act only through mitigation (" + mm + ")");
    }
    sec.hidden = !shown;
  });
}

function protInit() {
  var form = document.getElementById("mit-form");
  if (!form) return;
  form.addEventListener("submit", protSubmit);
  document.getElementById("mf-action").addEventListener("change", function () { if (protData) protFillTargets(protData); });
  document.getElementById("mf-prefix").addEventListener("input", function () {
    clearTimeout(protTimer);
    protTimer = setTimeout(protLoadPicker, 250);
  });
  document.getElementById("mf-prefix").addEventListener("focus", protLoadPicker);
  protJSON("GET", "/api/me").then(function (me) {
    protMe = me;
    if (protData) protectionUpdate(protData);
  }, function () {});
  protModes();
}

protInit();
