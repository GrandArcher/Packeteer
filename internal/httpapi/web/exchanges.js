"use strict";
// The exchange view of the Providers & Exchanges page (#148): per exchange,
// its peers, the improvements onto them with the Mbps they move, and the
// members on the peering LAN that are not peers. Per member it compares the
// prefixes seen via the route server, bilaterally, or both (#156). Reads
// GET /api/exchanges, GET /api/exchanges/member, and the stored exchanges
// report. Read-only. Rows are built with
// textContent only. Uses getJSON, el, clear, and fmtTime from app.js. No
// inline script: the CSP allows scripts from this origin only.

var EXCHANGE_REFRESH_MS = 5000;
var EXCHANGE_REPORT_DAYS = 7;
var VIA_LABELS = {route_server: "route server", bilateral: "bilateral", unknown: "unknown"};
var FLAG_LABELS = {
  rs_partial: ["RS partial", "Some prefixes arrive only bilaterally. The route server feed is partial or filtered."],
  rs_missing: ["RS missing", "No path arrives via a route server, though the exchange has one for other members. The feed is filtered or the member is not on it."]
};
var MEMBER_CLASSES = [
  ["route_server_only", "Only via the route server"],
  ["bilateral_only", "Only bilateral"],
  ["both", "Both"]
];
var openMembers = {};

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

function exPeerRow(exName, p) {
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
    exCell(p.improvements), exCell(moved), exCell(p.availability.route_server_only), exCell(p.availability.bilateral_only), exCell(p.availability.both),
    exFlagCell(p.availability), exMemberButton(exName, p.next_hop)];
}

function exFlagCell(a) {
  var td = el("td");
  var f = FLAG_LABELS[a.flag];
  if (f) {
    var badge = el("span", "badge warn", f[0]);
    badge.title = f[1];
    td.appendChild(badge);
  }
  return td;
}

// The prefixes and recorded counts of one member. Nothing is written.
function exMemberButton(exName, nextHop) {
  var key = exName + "/" + nextHop;
  var cell = el("td");
  var btn = el("button", "", "Compare");
  btn.type = "button";
  var detail = el("div");
  detail.setAttribute("data-member", key);
  btn.addEventListener("click", function () {
    if (openMembers[key]) {
      delete openMembers[key];
      clear(detail);
      return;
    }
    openMembers[key] = true;
    loadMember(exName, nextHop, detail);
  });
  cell.appendChild(btn);
  cell.appendChild(detail);
  if (openMembers[key]) loadMember(exName, nextHop, detail);
  return cell;
}

function loadMember(exName, nextHop, box) {
  var base = "/api/exchanges/member?exchange=" + encodeURIComponent(exName) + "&next_hop=" + encodeURIComponent(nextHop);
  Promise.all(MEMBER_CLASSES.map(function (c) { return getJSON(base + "&class=" + c[0] + "&limit=50"); })).then(function (answers) {
    clear(box);
    var hist = (answers[0].history || []).slice(-12);
    box.appendChild(el("p", "tag", "Counts every 15 minutes, kept in memory (a restart empties them)."));
    if (hist.length) {
      box.appendChild(exTable(["At", "RS only", "Bilateral only", "Both"], hist.map(function (h) {
        return [exCell(fmtTime(h.at)), exCell(h.route_server_only), exCell(h.bilateral_only), exCell(h.both)];
      })));
    }
    answers.forEach(function (a, i) {
      var list = a.prefixes || [];
      var more = a.prefixes_total > list.length ? " (first " + list.length + " of " + a.prefixes_total + ")" : "";
      box.appendChild(el("h5", "", MEMBER_CLASSES[i][1] + ": " + a.prefixes_total + more));
      if (list.length) box.appendChild(el("p", "mono", list.join(" ")));
    });
  }, function (err) {
    clear(box);
    box.appendChild(el("p", "bad", err.message));
  });
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
    section.appendChild(exTable(["Peer", "AS", "Next hop", "Type", "Prefixes", "Probe source", "Improvements", "Moved", "RS only", "Bilateral only", "Both", "RS feed", ""],
      peers.map(function (p) { return exPeerRow(ex.name, p); })));
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
    section.appendChild(exTable(["Next hop", "AS", "Prefixes", "RS only", "Bilateral only", "Both", "RS feed", ""], found.map(function (d) {
      return [exCell(d.next_hop, "mono"), exCell(d.asn ? "AS" + d.asn : "unknown"), exCell(d.prefixes), exCell(d.availability.route_server_only),
        exCell(d.availability.bilateral_only), exCell(d.availability.both), exFlagCell(d.availability), exMemberButton(ex.name, d.next_hop)];
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
