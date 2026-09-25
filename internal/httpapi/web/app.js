"use strict";

var REFRESH_MS = 5000;
var refreshing = false;
var lastProviders = null;
var lastPrefixes = null;
var lastImprovements = null;
var lastReady = null;

function el(tag, className, text) {
  var n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null && text !== "") n.textContent = String(text);
  return n;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fmtMs(v) {
  if (v == null || Number.isNaN(Number(v))) return "—";
  return Number(v).toFixed(1) + " ms";
}

function fmtPct(v) {
  if (v == null || Number.isNaN(Number(v))) return "—";
  return Number(v).toFixed(1) + "%";
}

function fmtTime(s) {
  if (!s) return "—";
  var d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function getJSON(path) {
  return fetch(path, {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) {
        try { body = JSON.parse(text); } catch (e) { body = null; }
      }
      if (!res.ok) {
        var msg = (body && body.error) || (body && body.status) || res.statusText;
        var err = new Error(path + " failed: " + msg);
        err.status = res.status;
        throw err;
      }
      return body;
    });
  });
}

function renderProviders(data) {
  var root = document.getElementById("providers");
  clear(root);
  var rows = (data && data.providers) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No providers."));
    return;
  }
  var table = el("table");
  var head = el("tr");
  ["Provider", "Source", "Next hop", "Health", "Since", "Detail"].forEach(function (h) {
    head.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(head);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (p) {
    var tr = el("tr");
    var name = el("td");
    name.appendChild(document.createTextNode(p.name || ""));
    if (p.exclude) name.appendChild(el("span", "badge", "excluded"));
    tr.appendChild(name);
    tr.appendChild(el("td", "mono", p.source || "—"));
    tr.appendChild(el("td", "mono", p.next_hop || "—"));
    var health = el("td");
    health.appendChild(el("span", p.up ? "dot up" : "dot down", p.up ? "up" : "down"));
    tr.appendChild(health);
    tr.appendChild(el("td", "", fmtTime(p.since)));
    tr.appendChild(el("td", "", p.reason || ""));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);

  var bgp = data && data.bgp;
  if (!bgp || !bgp.configured) return;
  root.appendChild(el("h3", "", "BGP sessions"));
  var peers = bgp.peers || [];
  if (!peers.length) {
    root.appendChild(el("p", "empty", "No neighbors."));
    return;
  }
  var pt = el("table");
  var phr = el("tr");
  ["Peer", "Description", "State", "Since"].forEach(function (h) {
    phr.appendChild(el("th", "", h));
  });
  var pth = el("thead");
  pth.appendChild(phr);
  pt.appendChild(pth);
  var pb = el("tbody");
  peers.forEach(function (peer) {
    var tr = el("tr");
    tr.appendChild(el("td", "mono", peer.address || ""));
    tr.appendChild(el("td", "", peer.description || ""));
    var st = el("td");
    st.appendChild(el("span", peer.established ? "dot up" : "dot down", peer.state || "down"));
    tr.appendChild(st);
    tr.appendChild(el("td", "", fmtTime(peer.since)));
    pb.appendChild(tr);
  });
  pt.appendChild(pb);
  root.appendChild(pt);
}

function renderPrefixes(data) {
  var root = document.getElementById("prefixes");
  clear(root);
  var rows = (data && data.prefixes) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No probed prefixes yet."));
    return;
  }
  rows.forEach(function (row) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    head.appendChild(el("h3", "mono", row.prefix));
    var exits = el("p", "exits");
    exits.appendChild(el("span", "k", "Current"));
    exits.appendChild(el("span", "v", row.current || "—"));
    exits.appendChild(el("span", "k", "Recommended"));
    var differs = row.recommended && row.recommended !== row.current;
    exits.appendChild(el("span", differs ? "v diff" : "v", row.recommended || "—"));
    head.appendChild(exits);
    if (row.action) head.appendChild(el("span", "badge", row.action));
    head.appendChild(el("span", row.in_rib ? "badge" : "badge muted", row.in_rib ? "in RIB" : "not in RIB"));
    card.appendChild(head);
    if (row.reason) card.appendChild(el("p", "reason", row.reason));
    var table = el("table");
    var hr = el("tr");
    ["Provider", "Loss", "RTT", "Jitter", "Probe"].forEach(function (h) {
      hr.appendChild(el("th", "", h));
    });
    var thead = el("thead");
    thead.appendChild(hr);
    table.appendChild(thead);
    var tb = el("tbody");
    (row.probes || []).forEach(function (pr) {
      var tr = el("tr");
      var cls = "";
      if (row.current && pr.provider === row.current) cls = "is-current";
      if (row.recommended && pr.provider === row.recommended) cls = (cls + " is-recommended").trim();
      if (cls) tr.className = cls;
      tr.appendChild(el("td", "", pr.provider));
      if (!pr.ok) {
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "", "—"));
        tr.appendChild(el("td", "bad", pr.error || "failed"));
      } else {
        tr.appendChild(el("td", "num", fmtPct(pr.loss_pct)));
        tr.appendChild(el("td", "num", fmtMs(pr.rtt_avg_ms)));
        tr.appendChild(el("td", "num", fmtMs(pr.jitter_ms)));
        tr.appendChild(el("td", "", pr.prober || "ok"));
      }
      tb.appendChild(tr);
    });
    table.appendChild(tb);
    card.appendChild(table);
    root.appendChild(card);
  });
}

function renderImprovements(data) {
  var root = document.getElementById("improvements");
  clear(root);
  var rows = (data && data.improvements) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No active improvements."));
    return;
  }
  var table = el("table");
  var hr = el("tr");
  ["Prefix", "Native exit", "Steered to", "Since", "Reason"].forEach(function (h) {
    hr.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (im) {
    var tr = el("tr");
    tr.appendChild(el("td", "mono", im.prefix));
    tr.appendChild(el("td", "", im.native || "—"));
    tr.appendChild(el("td", "", im.provider || "—"));
    tr.appendChild(el("td", "", fmtTime(im.since)));
    tr.appendChild(el("td", "", im.reason || ""));
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  root.appendChild(table);
}

function renderStatus(err) {
  var node = document.getElementById("status");
  clear(node);
  var mode = (lastProviders && lastProviders.mode) || "—";
  node.appendChild(el("span", "badge", mode));
  var ready = lastReady && lastReady.ready;
  node.appendChild(el("span", ready ? "dot up" : "dot down", ready ? "ready" : "not ready"));
  if (lastProviders && lastProviders.version) node.appendChild(el("span", "muted", lastProviders.version));
  if (lastProviders && lastProviders.generated_at) {
    node.appendChild(el("span", "muted", "updated " + fmtTime(lastProviders.generated_at)));
  }
  if (err) node.appendChild(el("span", "bad", err.message));
}

function refresh() {
  if (refreshing) return;
  refreshing = true;
  var readyReq = fetch("/readyz", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.json();
  });
  Promise.allSettled([
    getJSON("/api/providers"),
    getJSON("/api/prefixes"),
    getJSON("/api/improvements"),
    readyReq
  ]).then(function (results) {
    var err = null;
    if (results[0].status === "fulfilled") lastProviders = results[0].value;
    else err = results[0].reason;
    if (results[1].status === "fulfilled") lastPrefixes = results[1].value;
    else if (!err) err = results[1].reason;
    if (results[2].status === "fulfilled") lastImprovements = results[2].value;
    else if (!err) err = results[2].reason;
    if (results[3].status === "fulfilled") lastReady = results[3].value;
    else if (!err) err = results[3].reason;
    if (lastProviders) renderProviders(lastProviders);
    if (lastPrefixes) renderPrefixes(lastPrefixes);
    if (lastImprovements) renderImprovements(lastImprovements);
    renderStatus(err);
  }).then(function () {
    refreshing = false;
  }, function () {
    refreshing = false;
  });
}

document.getElementById("refresh").addEventListener("click", refresh);
refresh();
setInterval(refresh, REFRESH_MS);
