"use strict";
// Prefixes page (#183): one server-filtered page of the measured prefixes
// as a compact table. A row opens the existing prefix card. The filter,
// order, and page live in the URL. Loaded before app.js, which fetches
// prefixListQuery() on every refresh and calls renderPrefixes. Read-only.

var PREFIX_SIZES = [25, 50, 100, 200];
var PREFIX_SORTS = ["prefix", "gain", "loss", "rtt"];
var PREFIX_TYPING_MS = 300;

var prefixView = prefixViewFromURL();
var prefixExpanded = {};
var prefixTyping = null;

function prefixViewFromURL() {
  var q = new URLSearchParams(window.location.search);
  var size = parseInt(q.get("size"), 10);
  var page = parseInt(q.get("page"), 10);
  var sort = q.get("sort");
  return {
    prefix: q.get("prefix") || "",
    asn: q.get("asn") || "",
    provider: q.get("provider") || "",
    differs: q.get("differs") === "1",
    sort: PREFIX_SORTS.indexOf(sort) >= 0 ? sort : "prefix",
    page: page >= 1 ? page : 1,
    size: PREFIX_SIZES.indexOf(size) >= 0 ? size : 50
  };
}

function prefixASNValid(v) {
  return /^(AS)?[0-9]+$/i.test(v) && parseInt(v.replace(/^AS/i, ""), 10) > 0;
}

// prefixListQuery is the API query for the visible page.
function prefixListQuery() {
  var v = prefixView;
  var q = new URLSearchParams();
  if (v.prefix) q.set("prefix", v.prefix);
  if (v.asn && prefixASNValid(v.asn)) q.set("asn", v.asn.replace(/^AS/i, ""));
  if (v.provider) q.set("provider", v.provider);
  if (v.differs) q.set("differs", "true");
  q.set("sort", v.sort);
  q.set("limit", String(v.size));
  q.set("offset", String((v.page - 1) * v.size));
  return q.toString();
}

// prefixSyncURL keeps the page URL equal to the view, with defaults left out.
function prefixSyncURL() {
  var v = prefixView;
  var q = new URLSearchParams();
  if (v.prefix) q.set("prefix", v.prefix);
  if (v.asn) q.set("asn", v.asn);
  if (v.provider) q.set("provider", v.provider);
  if (v.differs) q.set("differs", "1");
  if (v.sort !== "prefix") q.set("sort", v.sort);
  if (v.size !== 50) q.set("size", String(v.size));
  if (v.page > 1) q.set("page", String(v.page));
  var qs = q.toString();
  window.history.replaceState(null, "", window.location.pathname + (qs ? "?" + qs : ""));
}

// prefixMarkASN flags an origin AS that is left out of the API query, so the
// unfiltered table is not mistaken for a filtered one.
function prefixMarkASN() {
  var bad = !!prefixView.asn && !prefixASNValid(prefixView.asn);
  document.getElementById("prefix-asn").setAttribute("aria-invalid", bad ? "true" : "false");
  document.getElementById("prefix-asn-error").hidden = !bad;
}

// prefixLinkASN shows the link-outs for the origin AS in the filter.
function prefixLinkASN() {
  var root = document.getElementById("prefix-asn-links");
  clear(root);
  if (!prefixView.asn || !prefixASNValid(prefixView.asn)) return;
  var asn = String(parseInt(prefixView.asn.replace(/^AS/i, ""), 10));
  root.appendChild(el("span", "k", "AS" + asn));
  root.appendChild(linkoutSpan("asn", asn));
}

function prefixApply(resetPage) {
  var v = prefixView;
  v.prefix = document.getElementById("prefix-filter").value.trim();
  v.asn = document.getElementById("prefix-asn").value.trim();
  v.provider = document.getElementById("prefix-provider").value;
  v.differs = document.getElementById("prefix-changes").checked;
  v.sort = document.getElementById("prefix-sort").value;
  v.size = parseInt(document.getElementById("prefix-size").value, 10);
  if (resetPage) v.page = 1;
  prefixMarkASN();
  prefixLinkASN();
  prefixSyncURL();
  refresh();
}

function prefixGoto(page) {
  prefixView.page = page;
  prefixSyncURL();
  refresh();
}

function prefixFillProviders() {
  var sel = document.getElementById("prefix-provider");
  var names = ((lastProviders && lastProviders.providers) || []).map(function (p) { return p.name; });
  if (prefixView.provider && names.indexOf(prefixView.provider) < 0) names.push(prefixView.provider);
  var have = Array.prototype.map.call(sel.options, function (o) { return o.value; }).slice(1).join("\n");
  if (have === names.join("\n")) return;
  while (sel.options.length > 1) sel.remove(1);
  names.forEach(function (n) {
    var o = el("option", "", n);
    o.value = n;
    sel.appendChild(o);
  });
  sel.value = prefixView.provider;
}

function prefixOpen(tr, row, open) {
  var btn = tr.querySelector("button");
  btn.textContent = open ? "Hide" : "Details";
  btn.setAttribute("aria-expanded", open ? "true" : "false");
  var next = tr.nextSibling;
  var showing = next && next.className === "prefix-detail";
  if (!open && showing) next.parentNode.removeChild(next);
  if (open && !showing) {
    var detail = el("tr", "prefix-detail");
    var td = el("td");
    td.colSpan = 8;
    var links = el("p", "linkout-row");
    links.appendChild(linkoutSpan("prefix", row.prefix));
    td.appendChild(links);
    td.appendChild(prefixCard(row));
    detail.appendChild(td);
    tr.parentNode.insertBefore(detail, tr.nextSibling);
  }
}

function prefixRow(row, body) {
  var tr = el("tr", "prefix-row");
  var td = el("td");
  var btn = el("button", "small", "Details");
  btn.type = "button";
  btn.setAttribute("aria-label", "Details for " + row.prefix);
  btn.addEventListener("click", function () {
    var open = !prefixExpanded[row.prefix];
    if (open) prefixExpanded[row.prefix] = true;
    else delete prefixExpanded[row.prefix];
    prefixOpen(tr, row, open);
  });
  td.appendChild(btn);
  tr.appendChild(td);
  tr.appendChild(prefixCell(row.prefix));
  tr.appendChild(el("td", "", row.current || "—"));
  var differs = row.recommended && row.recommended !== row.current;
  tr.appendChild(el("td", differs ? "diff" : "", row.recommended || "—"));
  tr.appendChild(el("td", "num", row.gain ? row.gain.toFixed(2) : "—"));
  tr.appendChild(el("td", "num", row.exit_loss_pct == null ? "—" : fmtPct(row.exit_loss_pct)));
  tr.appendChild(el("td", "num", row.exit_rtt_ms == null ? "—" : fmtMs(row.exit_rtt_ms)));
  tr.appendChild(el("td", "", row.in_rib ? "yes" : "no"));
  body.appendChild(tr);
  if (prefixExpanded[row.prefix]) prefixOpen(tr, row, true);
}

function prefixPager(pages) {
  var v = prefixView;
  var bar = el("div", "controls pager");
  var prev = el("button", "small", "Previous");
  prev.type = "button";
  prev.disabled = v.page <= 1;
  prev.addEventListener("click", function () { prefixGoto(v.page - 1); });
  var next = el("button", "small", "Next");
  next.type = "button";
  next.disabled = v.page >= pages;
  next.addEventListener("click", function () { prefixGoto(v.page + 1); });
  bar.appendChild(prev);
  bar.appendChild(el("span", "tag", "Page " + v.page + " of " + pages));
  bar.appendChild(next);
  return bar;
}

function renderPrefixes(data) {
  var root = document.getElementById("prefixes");
  if (!root) return;
  clear(root);
  prefixFillProviders();
  var rows = (data && data.prefixes) || [];
  if (!data || !data.measured) {
    var o = lastOverview;
    var msg = "No probed prefixes yet.";
    if (o && !(o.sources || []).length) msg = "Nothing to probe: the config has no sources. See the setup checklist on Overview.";
    else if (o) msg = "No probed prefixes yet. The first probe round fills this in.";
    root.appendChild(el("p", "empty", msg));
    return;
  }
  var v = prefixView;
  var pages = Math.max(1, Math.ceil(data.total / v.size));
  if (!rows.length && data.total > 0) {
    // The table shrank under the page; go to the last page that exists.
    prefixGoto(pages);
    return;
  }
  var first = data.total ? data.offset + 1 : 0;
  root.appendChild(el("p", "tag", "Showing " + first + "–" + (data.offset + rows.length) + " of " + data.total +
    (data.total !== data.measured ? " matching (" + data.measured + " measured)" : " measured") + " prefixes."));
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No prefix matches the filter."));
    return;
  }
  var labels = exitLabels();
  var t = table(["More", "Prefix", labels.now, labels.pick, "Expected gain", "Loss", "RTT", "On router"]);
  var keep = {};
  rows.forEach(function (row) {
    prefixRow(row, t.body);
    if (prefixExpanded[row.prefix]) keep[row.prefix] = true;
  });
  prefixExpanded = keep;
  root.appendChild(t.table);
  root.appendChild(prefixPager(pages));
}

function initPrefixList() {
  var v = prefixView;
  document.getElementById("prefix-filter").value = v.prefix;
  document.getElementById("prefix-asn").value = v.asn;
  prefixMarkASN();
  prefixLinkASN();
  document.getElementById("prefix-changes").checked = v.differs;
  document.getElementById("prefix-sort").value = v.sort;
  document.getElementById("prefix-size").value = String(v.size);
  prefixFillProviders();
  ["prefix-filter", "prefix-asn"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", function () {
      clearTimeout(prefixTyping);
      prefixTyping = setTimeout(function () { prefixApply(true); }, PREFIX_TYPING_MS);
    });
  });
  ["prefix-provider", "prefix-changes", "prefix-sort", "prefix-size"].forEach(function (id) {
    document.getElementById(id).addEventListener("change", function () { prefixApply(true); });
  });
}

window.addEventListener("DOMContentLoaded", initPrefixList);
