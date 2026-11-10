"use strict";
// RPKI-invalid only paths on the Registry page (#401), from
// GET /api/rpki/only-invalid. An operator proposes a SLURM exception for
// a likely stale ROA; the box shows the exact RFC 8416 entries, the
// validity before and after, and the digest, and only an admin can
// approve it or remove an exception. The server checks the roles, the
// digest, and the audit record. Nothing here announces a route. Uses el,
// clear, api, fmtTime, ixpTable, ixpCell from ui.js and shellAdmin from
// shell.js. Cells are built with textContent only.

var ONLY_INVALID_REFRESH_MS = 60000;

// oiProposal is the proposal whose box is open, kept across a refresh.
var oiProposal = null;

function oiBox(id) { return document.getElementById(id); }

function oiStatus(text, bad) {
  var n = oiBox("only-invalid-status");
  n.textContent = text || "";
  n.className = bad ? "bad" : "tag";
}

function oiButton(label, cls, onClick) {
  var b = el("button", cls, label);
  b.type = "button";
  b.addEventListener("click", function () { b.disabled = true; onClick(); });
  return b;
}

// oiCases lists the open cases with a propose button where one is allowed.
function oiCases(root, data, act) {
  clear(root);
  var slurm = data.slurm || {};
  var held = {};
  (slurm.held || []).forEach(function (p) { held[p] = true; });
  if (!data.cases.length) {
    root.appendChild(el("p", "empty", data.scanned ? "No RPKI-invalid only path in the last scan." : "No scan has finished yet. The first one runs about a minute after start."));
    return;
  }
  var t = ixpTable(["Prefix", "Origin", "Class", "Score", "Suggested action", ""], data.cases.map(function (c) {
    return [{text: c.prefix, href: "/prefix/" + encodeURIComponent(c.prefix)}, ixpCell("AS" + c.origin),
      ixpCell(c.class, c.class === "hijack" ? "bad" : ""), ixpCell(c.score), ixpCell(c.action), ixpCell("")];
  }));
  var rows = t.children[1].children;
  data.cases.forEach(function (c, i) {
    var td = rows[i].children[5];
    clear(td);
    if (held[c.prefix]) td.appendChild(el("span", "tag", "An exception is in the file."));
    else if (c.class !== "stale_roa") td.appendChild(el("span", "tag", "No exception: not a likely stale ROA."));
    else if (!slurm.enabled) td.appendChild(el("span", "tag", "Exceptions are off (rpki.only_invalid.slurm)."));
    else if (!slurm.writable) td.appendChild(el("span", "tag", "Exceptions can be proposed once auth or basic auth is on (PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD)."));
    else td.appendChild(oiButton("Propose exception", "small", function () { act({op: "propose", prefix: c.prefix}); }));
  });
  root.appendChild(t);
}

// oiProposalBox is the review step: exactly what approval adds.
function oiProposalBox(p, act) {
  var box = el("div", "confirm");
  box.appendChild(el("p", "", "Proposed " + p.kind + " for " + p.prefix + " AS" + p.origin + ": the route goes from " + p.state_before + " to " + p.state_after +
    ". Approving adds exactly this to " + p.path + ". Nothing is written until an admin approves. Expires " + fmtTime(p.expires) + "."));
  box.appendChild(el("pre", "diff", JSON.stringify(p.entries, null, 2)));
  box.appendChild(el("p", "tag", "Digest " + p.digest + ", audit " + p.id + ". Evidence: " +
    (p.evidence.signals || []).map(function (s) { return s.name + " " + (s.points > 0 ? "+" : "") + s.points; }).join(", ") + "."));
  if (shellAdmin) box.appendChild(oiButton("Approve and write", "", function () { act({op: "approve", proposal: p}); }));
  else box.appendChild(el("span", "tag", "An admin must approve this exception."));
  box.appendChild(oiButton("Cancel", "small", function () { act({op: "cancel"}); }));
  return box;
}

function oiExceptions(root, slurm, act) {
  clear(root);
  if (!slurm.enabled) return;
  root.appendChild(el("h3", "", "SLURM exceptions in " + slurm.path));
  if (slurm.error) {
    root.appendChild(el("p", "bad", slurm.error));
    return;
  }
  if (!slurm.exceptions.length) {
    root.appendChild(el("p", "empty", "None."));
    return;
  }
  var t = ixpTable(["Id", "Kind", "Prefix", "AS", "Comment", "Review", ""], slurm.exceptions.map(function (x) {
    return [ixpCell(x.id, "mono"), ixpCell(x.kind), ixpCell(x.prefix), ixpCell(x.asn == null ? "" : "AS" + x.asn), ixpCell(x.comment),
      ixpCell(x.review_due ? "due" : ""), ixpCell("")];
  }));
  if (shellAdmin && slurm.writable) {
    var rows = t.children[1].children;
    slurm.exceptions.forEach(function (x, i) {
      var td = rows[i].children[6];
      clear(td);
      td.appendChild(oiButton("Remove", "small", function () { act({op: "remove", id: x.id}); }));
    });
  }
  root.appendChild(t);
}

var oiData = null;

function renderOnlyInvalidPage(data, act) {
  oiBox("only-invalid-body").hidden = !data.enabled;
  if (!data.enabled) return;
  oiStatus((data.scanned ? "Last scan " + fmtTime(data.scanned) + "." : "") + (data.note ? " " + data.note : ""), false);
  var cases = oiBox("only-invalid-cases");
  oiCases(cases, data, act);
  if (oiProposal) cases.appendChild(oiProposalBox(oiProposal, act));
  oiExceptions(oiBox("only-invalid-exceptions"), data.slurm || {}, act);
}

function oiLoad() {
  return api("GET", "/api/rpki/only-invalid").then(function (data) {
    oiData = data;
    renderOnlyInvalidPage(data, onOnlyInvalid);
  }, function (err) {
    oiStatus("Could not load the RPKI-invalid only paths: " + err.message, true);
  });
}

function onOnlyInvalid(a) {
  var refused = function (what) {
    return function (err) {
      oiProposal = null;
      return oiLoad().then(function () { oiStatus(what + " refused or failed: " + err.message, true); });
    };
  };
  if (a.op === "cancel") {
    oiProposal = null;
    renderOnlyInvalidPage(oiData, onOnlyInvalid);
  } else if (a.op === "propose") {
    api("POST", "/api/rpki/only-invalid/propose", {prefix: a.prefix}).then(function (p) {
      oiProposal = p;
      renderOnlyInvalidPage(oiData, onOnlyInvalid);
    }, refused("Proposal"));
  } else if (a.op === "approve") {
    api("POST", "/api/rpki/exceptions", {id: a.proposal.id, digest: a.proposal.digest}).then(function () {
      oiProposal = null;
      return oiLoad().then(function () { oiStatus("Written to " + a.proposal.path + ".", false); });
    }, refused("Approval"));
  } else if (a.op === "remove") {
    api("DELETE", "/api/rpki/exceptions/" + encodeURIComponent(a.id)).then(oiLoad, refused("Removal"));
  }
}

function startOnlyInvalid() {
  oiLoad();
  setInterval(oiLoad, ONLY_INVALID_REFRESH_MS);
}

if (typeof document !== "undefined" && document.getElementById("only-invalid-body")) startOnlyInvalid();
