"use strict";
// The exchange view of the Providers & Exchanges page (#148): per exchange,
// its peers, the improvements onto them with the Mbps they move, and the
// members on the peering LAN that are not peers. Reads GET /api/exchanges
// and the stored exchanges report. Read-only. Rows are built with
// textContent only. Uses getJSON, el, clear, and fmtTime from app.js. No
// inline script: the CSP allows scripts from this origin only.

var EXCHANGE_REFRESH_MS = 5000;
var EXCHANGE_REPORT_DAYS = 7;
var VIA_LABELS = {route_server: "route server", bilateral: "bilateral", unknown: "unknown"};

function exMbps(v) {
  return v > 0 ? Number(v).toFixed(1) + " Mbps" : "—";
}

function exTable(headers, rows) {
  var table = el("table");
  var head = el("tr");
  headers.forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  rows.forEach(function (cells) {
    var tr = el("tr");
    cells.forEach(function (c) {
      tr.appendChild(c instanceof Node ? c : el("td", "", c));
    });
    body.appendChild(tr);
  });
  table.appendChild(body);
  return table;
}

function exCell(text, className) {
  return el("td", className || "", text);
}

function exPeerRow(p) {
  var asn = exCell("AS" + p.asn, "mono");
  if (p.observed_asn) {
    var mismatch = el("span", "badge warn", "sees AS" + p.observed_asn);
    mismatch.title = "Most paths through this next hop start with AS" + p.observed_asn + ", not the configured AS" + p.asn + ". The route check refuses them.";
    asn.appendChild(mismatch);
  }
  var up = el("td");
  up.appendChild(el("span", p.up ? "dot up" : "dot down", p.up ? "up" : "down"));
  var moved = p.improvements > 0 && !(p.moved_mbps > 0) ? "unknown" : exMbps(p.moved_mbps);
  return [exCell(p.name), asn, exCell(p.next_hop, "mono"), exCell(VIA_LABELS[p.via] || p.via || "unknown"), exCell(p.prefixes), up,
    exCell(p.improvements), exCell(moved)];
}

function renderExchange(root, ex) {
  var section = el("div");
  section.setAttribute("data-exchange", ex.name);
  section.appendChild(el("h3", "", ex.name));
  section.appendChild(el("p", "tag", "Peering LAN " + (ex.lans || []).join(", ") + ": " + ex.prefixes + " paths seen, " + ex.improvements + " active improvements."));

  var peers = ex.peers || [];
  if (!peers.length) {
    section.appendChild(el("p", "empty", "No peers in the config."));
  } else {
    section.appendChild(exTable(["Peer", "AS", "Next hop", "Type", "Prefixes", "Probe source", "Improvements", "Moved"], peers.map(exPeerRow)));
  }

  var moves = [];
  peers.forEach(function (p) {
    (p.moves || []).forEach(function (m) { moves.push([exCell(p.name), exCell(m.prefix, "mono"), exCell(fmtTime(m.since)), exCell(exMbps(m.volume_mbps))]); });
  });
  section.appendChild(el("h4", "", "Improvements onto " + ex.name));
  if (!moves.length) section.appendChild(el("p", "empty", "No improvement onto a peer of this exchange."));
  else section.appendChild(exTable(["Peer", "Prefix", "Since", "Moved"], moves));

  section.appendChild(el("h4", "", "Discovered members"));
  var found = ex.discovered || [];
  if (!found.length) {
    section.appendChild(el("p", "empty", "Every next hop on the LAN is a peer."));
  } else {
    section.appendChild(el("p", "tag", "Next hops on the LAN that are not peers. They are never probed or used."));
    section.appendChild(exTable(["Next hop", "AS", "Prefixes"], found.map(function (d) {
      return [exCell(d.next_hop, "mono"), exCell(d.asn ? "AS" + d.asn : "unknown"), exCell(d.prefixes)];
    })));
  }
  root.appendChild(section);
}

function renderExchanges(data) {
  var root = document.getElementById("exchanges");
  clear(root);
  var list = (data && data.exchanges) || [];
  if (!list.length) {
    root.appendChild(el("p", "empty", "No exchanges in the config."));
    return;
  }
  list.forEach(function (ex) { renderExchange(root, ex); });
}

function renderExchangeReport(rep) {
  var root = document.getElementById("exchange-report");
  clear(root);
  var rows = (rep && rep.rows) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No exchange peers in the stored history."));
    return;
  }
  root.appendChild(exTable(["Exchange", "Peer", "Improvements", "Active now", "Prefixes", "Moved", "Steered (h)"], rows.map(function (r) {
    return [exCell(r.exchange), exCell(r.peer), exCell(r.improvements), exCell(r.active), exCell(r.prefixes), exCell(exMbps(r.volume_mbps)), exCell(r.steered_hours)];
  })));
}

function loadExchanges() {
  var status = document.getElementById("exchanges-status");
  getJSON("/api/exchanges").then(function (data) {
    status.textContent = "";
    status.className = "tag";
    renderExchanges(data);
  }, function (err) {
    status.textContent = err.status === 403 ? "Your account may not read this page." : err.message;
    status.className = "bad";
  });
  var note = document.getElementById("exchange-report-note");
  getJSON("/api/reports/exchanges?days=" + EXCHANGE_REPORT_DAYS).then(function (rep) {
    note.textContent = "";
    renderExchangeReport(rep);
  }, function (err) {
    clear(document.getElementById("exchange-report"));
    note.textContent = err.status === 404 ? "History is off. Set storage.type: sqlite to keep improvements across restarts." : err.message;
  });
}

document.getElementById("refresh").addEventListener("click", loadExchanges);
loadExchanges();
setInterval(loadExchanges, EXCHANGE_REFRESH_MS);
