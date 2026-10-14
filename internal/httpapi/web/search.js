"use strict";
// The Search page (#172): GET /api/search for the q in the URL, grouped by
// type. Read-only. Cells are built with textContent only. Uses api, el,
// clear, and fmtTime from ui.js and shellMeReady, shellRecentSearches from
// shell.js. No inline script: the CSP allows scripts from this origin only.

var SEARCH_KIND_TEXT = {
  prefix: "a prefix or address: exact, covering, and more specific matches",
  asn: "an AS number: prefixes it originates",
  name: "an AS name: the AS numbers whose known name contains it, and their prefixes"
};

function searchLink(text, href) {
  var a = el("a", "", text);
  a.href = href;
  return a;
}

function prefixHref(prefix) {
  return "/prefix/" + encodeURIComponent(prefix);
}

function searchCell(content, className) {
  var td = el("td", className || "");
  if (content != null && typeof content === "object") td.appendChild(content);
  else td.textContent = content == null || content === "" ? "—" : String(content);
  return td;
}

// searchLinks are the click-throughs of one result: the prefix page, the
// improvements history for that prefix or AS, and the Probe tool.
function searchLinks(prefix, asn) {
  var span = el("span", "linkouts");
  if (prefix) {
    span.appendChild(searchLink("Prefix page", prefixHref(prefix)));
    span.appendChild(searchLink("Improvement history", "/reports.html?report=improvements&prefix=" + encodeURIComponent(prefix)));
    span.appendChild(searchLink("Probe", "/troubleshooting.html?tool=probe&target=" + encodeURIComponent(prefix)));
  } else if (asn) {
    span.appendChild(searchLink("Prefixes", "/prefixes.html?asn=" + asn));
    span.appendChild(searchLink("Improvement history", "/reports.html?report=improvements&asn=" + asn));
    span.appendChild(searchLink("Whois", "/troubleshooting.html?tool=whois&target=AS" + asn));
  }
  return span;
}

function searchPrefixCell(prefix) {
  return searchCell(searchLink(prefix, prefixHref(prefix)), "mono");
}

function searchGroup(root, id, title, hint, g, headers, row) {
  var section = el("section", "search-group");
  section.id = id;
  var shown = (g && g.rows) || [];
  var total = (g && g.total) || 0;
  section.appendChild(el("h3", "", title + " (" + total + ")"));
  if (!shown.length) {
    section.appendChild(el("p", "empty", hint));
    root.appendChild(section);
    return;
  }
  if (total > shown.length) {
    section.appendChild(el("p", "tag", "Showing the newest " + shown.length + " of " + total + ". Narrow the search to see the rest."));
  }
  var table = el("table");
  var head = el("tr");
  headers.forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  shown.forEach(function (r) {
    var tr = el("tr");
    row(r).forEach(function (cell) { tr.appendChild(cell); });
    body.appendChild(tr);
  });
  table.appendChild(body);
  section.appendChild(table);
  root.appendChild(section);
}

function searchAS(n) {
  return n ? "AS" + n : "—";
}

function renderSearch(data) {
  var root = document.getElementById("search-results");
  clear(root);
  var inject = data.mode === "inject";
  var status = document.getElementById("search-status");
  status.className = "tag";
  status.textContent = "Searched " + (SEARCH_KIND_TEXT[data.kind] || data.kind) + ". Newest first, at most " + data.limit + " rows per list.";
  if (!data.history.enabled || data.history.note) {
    root.appendChild(el("p", "reason", data.history.note || "History is off, so only live data was searched."));
  }
  searchGroup(root, "search-asns", "AS numbers", "No AS number to follow.", data.asns, ["AS", "Name", "Known from", "Open"], function (r) {
    return [searchCell("AS" + r.asn, "mono"), searchCell(r.name), searchCell(r.source === "provider" ? "config (exchange peer)" : r.source === "whois" ? "whois lookup" : "—"),
      searchCell(searchLinks("", r.asn))];
  });
  searchGroup(root, "search-measured", "Measured prefixes", "No measured prefix matches.", data.measured,
    ["Prefix", "Match", "Origin", "Current", inject ? "Steered to" : "Recommended", "Last probe", "Open"], function (r) {
      return [searchPrefixCell(r.prefix), searchCell(r.relation || "origin"), searchCell(searchAS(r.origin_asn)), searchCell(r.current),
        searchCell(r.recommended), searchCell(r.probed ? fmtTime(r.probed) : "—"), searchCell(searchLinks(r.prefix))];
    });
  searchGroup(root, "search-rib", "Learned routes (RIB)", "No learned route matches.", data.rib,
    ["Prefix", "Match", "Origin", "Next hop", "Provider", "Since", "Open"], function (r) {
      return [searchPrefixCell(r.prefix), searchCell(r.relation || "origin"), searchCell(searchAS(r.origin_asn)), searchCell(r.next_hop, "mono"),
        searchCell(r.provider), searchCell(r.since ? fmtTime(r.since) : "—"), searchCell(searchLinks(r.prefix))];
    });
  searchGroup(root, "search-now", inject ? "Current improvements" : "Current recommendations",
    "No current " + (inject ? "improvement" : "recommendation") + " matches.", data.recommendations,
    ["Prefix", "Match", "Native exit", inject ? "Steered to" : "Recommended", "Cause", "Since", "Open"], function (r) {
      return [searchPrefixCell(r.prefix), searchCell(r.relation || "origin"), searchCell(r.native), searchCell(r.provider), searchCell(r.cause),
        searchCell(r.since ? fmtTime(r.since) : "—"), searchCell(searchLinks(r.prefix))];
    });
  var days = data.history.days || 0;
  searchGroup(root, "search-history", "Stored improvements" + (days ? ", last " + days + " days" : ""),
    data.history.enabled ? "No stored improvement matches." : "History is off.", data.improvements,
    ["Prefix", "Match", "Origin", "Provider", "Native exit", "Cause", "Mode", "Start", "End", "Open"], function (r) {
      return [searchPrefixCell(r.prefix), searchCell(r.relation || "origin"), searchCell(searchAS(r.origin_asn)), searchCell(r.provider), searchCell(r.native),
        searchCell(r.cause), searchCell(r.mode), searchCell(fmtTime(r.start)), searchCell(r.end ? fmtTime(r.end) : "open"), searchCell(searchLinks(r.prefix))];
    });
  searchGroup(root, "search-rollups", "Probe rollups" + (days ? ", last " + days + " days" : ""),
    data.history.enabled ? "No stored probe rollup matches." : "History is off.", data.rollups,
    ["Prefix", "Match", "Origin", "Providers", "Last day", "Probes", "Failed", "Loss %", "RTT ms", "Open"], function (r) {
      return [searchPrefixCell(r.prefix), searchCell(r.relation || "origin"), searchCell(searchAS(r.origin_asn)), searchCell((r.providers || []).join(", ")),
        searchCell(r.last_day), searchCell(r.probes), searchCell(r.failed), searchCell(r.loss_pct), searchCell(r.rtt_ms), searchCell(searchLinks(r.prefix))];
    });
}

function renderRecent() {
  var node = document.getElementById("search-recent");
  var list = shellRecentSearches();
  clear(node);
  node.hidden = !list.length;
  if (!list.length) return;
  node.appendChild(document.createTextNode("Recent searches: "));
  list.forEach(function (q, i) {
    if (i) node.appendChild(document.createTextNode(", "));
    node.appendChild(searchLink(q, "/search.html?q=" + encodeURIComponent(q)));
  });
}

function runSearch() {
  var q = new URLSearchParams(window.location.search).get("q");
  var status = document.getElementById("search-status");
  if (q == null || q.trim() === "") {
    status.textContent = "Type a prefix, an address, an AS number, or an AS name in the search box and press Enter.";
    return;
  }
  var input = document.getElementById("top-search");
  if (input && !input.value) input.value = q;
  status.textContent = "Searching…";
  api("GET", "/api/search?q=" + encodeURIComponent(q)).then(renderSearch, function (err) {
    clear(document.getElementById("search-results"));
    status.className = "bad";
    if (err.status === 429) status.textContent = "Too many searches. Wait a moment and search again.";
    else if (err.status === 403) status.textContent = "Your account may not search.";
    else status.textContent = err.message;
  });
}

document.getElementById("refresh").addEventListener("click", runSearch);
shellMeReady.then(renderRecent);
runSearch();
