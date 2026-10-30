"use strict";
// The Registry page (#289): the last registry hygiene scan from
// GET /api/registry, each finding with its severity and the exact change.
// A finding with a change a plugin can apply gets a push control, shown to
// admins only and only when the server has pushing on; the push shows the
// diff again, needs a second click, and quotes the digest of the diff that
// was shown. The server checks the role, the digest, and the audit record.
// Nothing here announces a route. Uses el, clear, api, fmtTime, ixpTable,
// ixpCell from ui.js and shellAdmin from shell.js. Cells are built with
// textContent only. No inline script: the CSP allows scripts from this
// origin only.

var REGISTRY_REFRESH_MS = 60000;
var REGISTRY_SEVERITY = {error: "Error", warning: "Warning", info: "Info"};

// registryOpen is the id of the finding whose confirm box is open. It
// survives a refresh so the box does not vanish under the operator.
var registryOpen = "";

function registryBox(id) { return document.getElementById(id); }

function registrySetStatus(text, bad) {
  var n = registryBox("registry-status");
  n.textContent = text || "";
  n.className = bad ? "bad" : "tag";
}

function renderRegistrySections(root, rep) {
  clear(root);
  if (!rep.sections.length) return;
  root.appendChild(el("h2", "", "Scan"));
  root.appendChild(ixpTable(["Part", "Status", "Detail"], rep.sections.map(function (s) {
    return [ixpCell(s.name), ixpCell(s.status, s.status === "error" ? "bad" : ""), ixpCell(s.detail)];
  })));
}

// registryActions is the last cell of a finding: what to do about it.
function registryActions(f, rep, onPush) {
  var td = el("td");
  if (f.pushed) {
    td.appendChild(el("span", "tag", "Pushed " + fmtTime(f.pushed) + ". The next scan shows the result."));
    return td;
  }
  if (!f.diff) return td;
  if (!f.pushable || !rep.writable || !shellAdmin) {
    td.appendChild(el("span", "tag", f.pushable && rep.writable
      ? "An admin can push this change."
      : "Submit this change to the " + f.registry + " registry yourself."));
    return td;
  }
  if (registryOpen !== f.id) {
    var open = el("button", "small", "Review and push");
    open.type = "button";
    open.addEventListener("click", function () { registryOpen = f.id; onPush(null); });
    td.appendChild(open);
    return td;
  }
  var box = el("div", "confirm");
  box.appendChild(el("p", "", "Send exactly this change to " + f.change.registry + " (" + f.change.op + " " + f.change.class + " " + f.change.key + ")? The push is audit-logged and cannot be undone from here."));
  var go = el("button", "", "Confirm push");
  go.type = "button";
  go.addEventListener("click", function () { go.disabled = true; onPush(f); });
  var cancel = el("button", "small", "Cancel");
  cancel.type = "button";
  cancel.addEventListener("click", function () { registryOpen = ""; onPush(null); });
  box.appendChild(go);
  box.appendChild(cancel);
  td.appendChild(box);
  return td;
}

function renderRegistryFindings(root, rep, onPush) {
  clear(root);
  root.appendChild(el("h2", "", "Findings"));
  if (!rep.findings.length) {
    root.appendChild(el("p", "empty", rep.scanned
      ? "No difference found in the parts that answered."
      : "No scan has finished yet. The first one runs about a minute after start."));
    return;
  }
  var t = el("table");
  var hr = el("tr");
  ["Severity", "Registry", "Subject", "What", "Change", ""].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  t.appendChild(el("thead")).appendChild(hr);
  var body = el("tbody");
  rep.findings.forEach(function (f) {
    var tr = el("tr");
    var sev = el("td");
    sev.appendChild(el("span", "badge sev-" + f.severity, REGISTRY_SEVERITY[f.severity] || f.severity));
    tr.appendChild(sev);
    tr.appendChild(el("td", "", f.registry));
    tr.appendChild(el("td", "", f.subject));
    tr.appendChild(el("td", "", f.message));
    var diff = el("td");
    if (f.diff) diff.appendChild(el("pre", "diff", f.diff));
    tr.appendChild(diff);
    tr.appendChild(registryActions(f, rep, onPush));
    body.appendChild(tr);
  });
  t.appendChild(body);
  root.appendChild(t);
}

function renderRegistry(rep, onPush) {
  var head;
  if (!rep.enabled) {
    head = "Registry hygiene is off. Set registry.enabled in the config.";
  } else if (!rep.scanned) {
    head = "No scan has finished yet.";
  } else {
    head = "Last scan " + fmtTime(rep.scanned) + ". " + (rep.writable
      ? "Pushing is on: each push needs an admin to confirm its diff."
      : "Read only: pushing is off, so each change is for you to submit.");
  }
  registrySetStatus(head, false);
  renderRegistrySections(registryBox("registry-sections"), rep);
  if (rep.enabled) renderRegistryFindings(registryBox("registry-findings"), rep, onPush);
  else clear(registryBox("registry-findings"));
}

var registryReport = null;

function loadRegistry() {
  return api("GET", "/api/registry").then(function (rep) {
    registryReport = rep;
    renderRegistry(rep, onRegistryPush);
  }, function (err) {
    registrySetStatus("Could not load the registry report: " + err.message, true);
  });
}

// onRegistryPush redraws on a null finding (a box opened or closed) and
// posts the confirmed one otherwise.
function onRegistryPush(f) {
  if (!f) {
    renderRegistry(registryReport, onRegistryPush);
    return;
  }
  api("POST", "/api/registry/push", {id: f.id, digest: f.digest}).then(function () {
    registryOpen = "";
    return loadRegistry();
  }, function (err) {
    registryOpen = "";
    return loadRegistry().then(function () {
      registrySetStatus("Push refused or failed: " + err.message, true);
    });
  });
}

function startRegistryPage() {
  registryBox("refresh").addEventListener("click", loadRegistry);
  loadRegistry();
  setInterval(loadRegistry, REGISTRY_REFRESH_MS);
}

if (typeof document !== "undefined" && document.getElementById("registry-body")) startRegistryPage();
