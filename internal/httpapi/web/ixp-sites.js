"use strict";
// The IXP sites page (#167): GET /api/ixp/sites for every site's health,
// the core links between sites, and where each incident is. Read-only. Rows
// are built with textContent only. Uses api, el, clear, fmtTime, and the ixp
// helpers from ui.js. No inline script: the CSP allows scripts from this
// origin only.

var SITES_REFRESH_MS = 15000;

var SCOPE_TEXT = {
  fabric: "Fabric", vantage: "Vantage", route_server: "Route server", core: "Core", site: "Site"
};

function siteName(s) {
  return s.self ? s.name + " (this site)" : s.name;
}

function renderIncidents(d) {
  var rows = (d.incidents || []).map(function (i) {
    return [ixpCell(i.site), ixpCell(i.peer), ixpCell(SCOPE_TEXT[i.scope] || i.scope, "bad"), ixpCell(i.detail)];
  });
  if (!rows.length) {
    ixpSetBox("sites-incidents", el("p", "empty", "No incident at any site."));
    return;
  }
  ixpSetBox("sites-incidents", ixpTable(["Site", "To", "Where", "Detail"], rows));
}

function renderSites(d) {
  var sites = d.sites || [];
  ixpSetBox("sites-list", ixpTable(["Site", "Status", "Last seen", "Members measured", "Past tolerance", "Vantages up", "Route servers down", "Fabric round"], sites.map(function (s) {
    var bad = s.status === "ok" ? "" : "bad";
    var seen = s.self ? "" : (s.last_seen ? fmtTime(s.last_seen) : "never");
    return [ixpCell(siteName(s)), ixpCell(s.status, bad), ixpCell(seen), ixpCell(s.members_measured), ixpCell(s.members_past_tolerance),
      ixpCell(s.vantages_up + " of " + s.vantages), ixpCell(s.route_servers_down + " of " + s.route_servers), ixpCell(s.round ? fmtTime(s.round) : "")];
  })));
}

function renderLinks(d) {
  var links = d.links || [];
  if (!links.length) {
    ixpSetBox("sites-links", el("p", "empty", "No core link is measured (ixp.core and ixp.core_links on a site)."));
    return;
  }
  ixpSetBox("sites-links", ixpTable(["From", "To", "Link", "Loss", "RTT", "Jitter", "State"], links.map(function (l) {
    var state = l.error ? "error: " + l.error : (!l.up ? "no reply" : (l.degraded ? "degraded" : "ok"));
    var bad = l.degraded ? "bad" : "";
    return [ixpCell(l.site), ixpCell(l.peer), ixpCell(l.name),
      ixpCell(l.error ? "" : ixpNum(l.loss_pct, " %")), ixpCell(l.error ? "" : ixpNum(l.rtt_ms, " ms")), ixpCell(l.error ? "" : ixpNum(l.jitter_ms, " ms")),
      ixpCell(state, bad)];
  })));
}

function renderMembers(d) {
  var rows = [];
  (d.sites || []).forEach(function (s) {
    (s.past_tolerance || []).forEach(function (m) {
      rows.push([ixpCell(s.name), {text: "AS" + m.asn, cls: "mono", href: s.self ? "/ixp/member/" + m.asn : ""}, ixpCell(m.vlan_id), ixpCell(m.vantage), ixpCell(m.family),
        ixpCell(ixpNum(m.loss_pct, " %")), ixpCell(ixpNum(m.rtt_ms, " ms")), ixpCell(ixpNum(m.jitter_ms, " ms"))]);
    });
  });
  if (!rows.length) {
    ixpSetBox("sites-members", el("p", "empty", "No member path is past tolerance at any site."));
    return;
  }
  ixpSetBox("sites-members", ixpTable(["Site", "AS", "VLAN", "Vantage", "Family", "Loss", "RTT", "Jitter"], rows));
}

function loadSitesPage() {
  var status = document.getElementById("sites-status");
  return api("GET", "/api/ixp/sites").then(function (d) {
    var body = document.getElementById("sites-body");
    if (!d.enabled) {
      status.textContent = "Multi-site health needs ixp and federation in this site's config.";
      status.className = "tag";
      body.hidden = true;
      return;
    }
    status.textContent = "";
    status.className = "tag";
    body.hidden = false;
    renderIncidents(d);
    renderSites(d);
    renderLinks(d);
    renderMembers(d);
  }, function (err) {
    status.textContent = err.message;
    status.className = "bad";
  });
}

document.getElementById("refresh").addEventListener("click", loadSitesPage);
loadSitesPage();
setInterval(loadSitesPage, SITES_REFRESH_MS);
