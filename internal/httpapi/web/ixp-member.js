"use strict";
// The IXP member page (#166): GET /api/ixp/members/{asn} for one member's
// connections, latest fabric round by vantage, and route-server sessions,
// and GET /api/ixp/routeservers/history for each session's filter history.
// With no ASN in the path it lists the members. Read-only. Rows are built
// with textContent only. Uses api, el, clear, fmtTime, and the ixp helpers
// from ui.js. No inline script: the CSP allows scripts from this origin only.

var MEMBER_PATH = "/ixp/member/";
var MEMBER_REFRESH_MS = 15000;
var HISTORY_ROWS = 24;

var memberASN = (function () {
  var path = window.location.pathname;
  if (path.indexOf(MEMBER_PATH) !== 0) return "";
  var rest = path.slice(MEMBER_PATH.length);
  return /^[0-9]{1,10}$/.test(rest) ? rest : "";
})();

function renderList(data) {
  var members = data.members || [];
  document.getElementById("member-title").textContent = "IXP members";
  document.title = "Packeteer IXP members";
  document.getElementById("member-list-section").hidden = false;
  if (!members.length) {
    ixpSetBox("member-list", el("p", "empty", "No members. Set ixp.members to import the IX-F member list."));
    return;
  }
  ixpSetBox("member-list", ixpTable(["AS", "Name"], members.map(function (m) {
    return [{text: "AS" + m.asn, cls: "mono", href: MEMBER_PATH + m.asn}, ixpCell(m.name)];
  })));
}

function renderLinks(d) {
  var box = document.getElementById("member-links");
  clear(box);
  // The URL comes from the controller's own import config; it is still
  // checked so a page can never carry a javascript: link.
  if (d.ixp_manager_url && /^https?:\/\//.test(d.ixp_manager_url)) {
    var a = el("a", "", "Open in IXP Manager");
    a.id = "member-ixpm";
    a.href = d.ixp_manager_url;
    a.rel = "noopener noreferrer";
    box.appendChild(a);
    box.appendChild(el("span", "tag", " (IXP Manager asks you to sign in)"));
  }
}

function renderConnections(d) {
  var rows = [];
  (d.connections || []).forEach(function (c) {
    var addrs = (c.addresses || []).map(function (a) { return a.address; }).join(", ");
    var ifs = c.interfaces || [];
    if (!ifs.length) rows.push([ixpCell(c.ixp_id), ixpCell(c.state), ixpCell(""), ixpCell(""), ixpCell(""), ixpCell(addrs, "mono")]);
    ifs.forEach(function (i) {
      rows.push([ixpCell(c.ixp_id), ixpCell(c.state), ixpCell(i.switch || i.switch_id), ixpCell(i.colo), ixpCell(i.speed_mbps ? i.speed_mbps + " Mbit/s" : ""), ixpCell(addrs, "mono")]);
    });
  });
  if (!rows.length) {
    ixpSetBox("member-connections", el("p", "empty", "Not in the IX-F member list."));
    return;
  }
  ixpSetBox("member-connections", ixpTable(["IXP", "State", "Switch", "Colo", "Speed", "Addresses"], rows));
}

function renderFabric(d) {
  var f = d.fabric || {};
  if (!f.configured) {
    ixpSetBox("member-fabric", el("p", "empty", "Fabric probing is not configured (ixp.fabric)."));
    return;
  }
  var samples = f.samples || [];
  if (!samples.length) {
    ixpSetBox("member-fabric", el("p", "empty", f.stale ? "The member list is stale, so nothing is probed." : "No address of this member was measured in the latest round (no Can Ping, or no matching vantage)."));
    return;
  }
  ixpSetBox("member-fabric", ixpTable(["Vantage", "Address", "VLAN", "Loss", "RTT", "Jitter", "State", "At"], samples.map(function (s) {
    var state = s.error ? "error: " + s.error : (s.past_tolerance ? "past tolerance" : "ok");
    var bad = s.error || s.past_tolerance ? "bad" : "";
    return [ixpCell(s.vantage), ixpCell(s.address, "mono"), ixpCell(s.vlan_id),
      ixpCell(s.error ? "" : ixpNum(s.loss_pct, " %")), ixpCell(s.error ? "" : ixpNum(s.rtt_ms, " ms")), ixpCell(s.error ? "" : ixpNum(s.jitter_ms, " ms")),
      ixpCell(state, bad), ixpCell(s.at ? fmtTime(s.at) : "")];
  })));
}

function reasonText(reasons) {
  return (reasons || []).map(function (r) { return r.reason + ": " + r.count; }).join(", ");
}

function renderSessions(d) {
  var sessions = d.route_server_sessions || [];
  if (!sessions.length) {
    ixpSetBox("member-sessions", el("p", "empty", "No route-server session for this member (ixp.routeservers)."));
    return;
  }
  ixpSetBox("member-sessions", ixpTable(["Server", "Session", "State", "Received", "Accepted", "Filtered", "Reasons"], sessions.map(function (s) {
    return [ixpCell(s.server), ixpCell(s.neighbor || s.session, "mono"), ixpCell(s.state, s.established ? "" : "bad"),
      ixpCell(s.counted ? s.received : ""), ixpCell(s.counted ? s.accepted : ""), ixpCell(s.counted ? s.filtered : ""), ixpCell(s.counted ? reasonText(s.reasons) : s.error)];
  })));
}

function historyPanel(s, data) {
  var box = el("div");
  box.setAttribute("data-history", s.server + "/" + s.session);
  var samples = (data.samples || []).slice().reverse();
  box.appendChild(el("h4", "", "Filter history: " + s.server + " " + (s.neighbor || s.session)));
  if (!samples.length) {
    box.appendChild(el("p", "empty", "No samples yet."));
    return box;
  }
  var shown = samples.slice(0, HISTORY_ROWS);
  box.appendChild(el("p", "tag", "Latest " + shown.length + " of " + samples.length + " samples, newest first. History is in memory and a restart empties it."));
  box.appendChild(ixpTable(["At", "State", "Accepted", "Filtered", "Reasons"], shown.map(function (x) {
    return [ixpCell(fmtTime(x.at)), ixpCell(x.established ? "Established" : "Down", x.established ? "" : "bad"),
      ixpCell(x.counted ? x.accepted : ""), ixpCell(x.counted ? x.filtered : ""), ixpCell(x.counted ? reasonText(x.reasons) : "")];
  })));
  return box;
}

function loadHistory(d) {
  var root = document.getElementById("member-history");
  var sessions = d.route_server_sessions || [];
  Promise.all(sessions.map(function (s) {
    var q = "?server=" + encodeURIComponent(s.server) + "&session=" + encodeURIComponent(s.session);
    return api("GET", "/api/ixp/routeservers/history" + q).then(function (h) { return historyPanel(s, h); }, function (err) {
      var box = el("div");
      box.appendChild(el("p", "empty", s.server + " " + s.session + ": " + err.message));
      return box;
    });
  })).then(function (panels) {
    clear(root);
    panels.forEach(function (p) { root.appendChild(p); });
  });
}

function renderMember(d) {
  var title = "AS" + d.asn + (d.name ? " " + d.name : "");
  document.getElementById("member-title").textContent = title;
  document.title = "Packeteer IXP " + title;
  document.getElementById("member-detail").hidden = false;
  renderLinks(d);
  renderConnections(d);
  renderFabric(d);
  renderSessions(d);
  loadHistory(d);
}

function loadMemberPage() {
  var status = document.getElementById("member-status");
  var path = memberASN ? "/api/ixp/members/" + memberASN : "/api/ixp/members";
  return api("GET", path).then(function (data) {
    status.textContent = "";
    status.className = "tag";
    if (memberASN) renderMember(data); else renderList(data);
  }, function (err) {
    status.textContent = err.status === 404 && memberASN ? "AS" + memberASN + " is not an IXP member Packeteer knows." : err.message;
    status.className = "bad";
  });
}

document.getElementById("refresh").addEventListener("click", loadMemberPage);
loadMemberPage();
setInterval(loadMemberPage, MEMBER_REFRESH_MS);
