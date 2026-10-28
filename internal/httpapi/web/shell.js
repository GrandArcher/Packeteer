"use strict";
// Shared chrome (#170): current page, account menu, role-gated nav, and
// the mode line on pages that do not load app.js. The sign-in page (#176)
// loads it only for these helpers. Same-origin only.

var SHELL_REFRESH_MS = 5000;
var shellLastOK = null;

// The events indicator counts warnings (and worse) newer than the time the
// Events page was last opened in this browser. The time is the
// controller's own clock, kept in localStorage; nothing is stored on the
// controller.
var EVENTS_SEEN_KEY = "packeteer.events.seen";
var EVENTS_BADGE_MS = 15000;
var EVENTS_BADGE_MAX = 100;

var SHELL_MODE_TEXT = {
  observe: "Observe mode: Packeteer measures and recommends. It announces nothing.",
  suggest: "Suggest mode: Packeteer measures and publishes recommendations. It announces nothing.",
  inject: "Inject mode: improvements for allowlisted prefixes are announced to the edge routers."
};

// The top bar search (#172) keeps the last few searches in this browser,
// under the signed-in user's name. Nothing is stored on the controller.
var SEARCH_RECENT_KEY = "packeteer.search.recent.";
var SEARCH_RECENT_MAX = 5;
var shellUser = "";
// shellAdmin is false only for a signed-in account below the admin role.
var shellAdmin = true;

// REPORT_TITLES are the report names as people read them (#351). The API
// keeps the lowercase ids for URLs and CSV file names.
var REPORT_TITLES = {summary: "Summary", improvements: "Improvements", causes: "Causes", performance: "Performance",
  timeseries: "Time series", providers: "Providers", prefixes: "Prefixes", asns: "ASNs", countries: "Countries",
  probes: "Probes", probe_asns: "Probes by ASN", savings: "Savings", mitigations: "Mitigations", anomalies: "Anomalies", exchanges: "Exchanges"};

function reportTitle(name) {
  return REPORT_TITLES[name] || name;
}

// bgpState words a BGP session state for people (#351). Active, Connect and
// the Open states mean the router has not finished the handshake yet, not
// that the session works, so they are amber. The raw state is the tooltip.
var BGP_CONNECTING = {connect: "Connect", active: "Active", opensent: "OpenSent", openconfirm: "OpenConfirm"};

function bgpState(state, established) {
  var raw = String(state || "").toLowerCase();
  var title = "BGP state: " + (state || "unknown");
  if (established || raw === "established") return {label: "Up", level: "up", title: title};
  if (BGP_CONNECTING[raw]) return {label: "Connecting (" + BGP_CONNECTING[raw] + ")", level: "degraded", title: title};
  return {label: "Down", level: "down", title: title};
}

function shellEl(tag, className, text) {
  var n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null && text !== "") n.textContent = String(text);
  return n;
}

// docLink is an anchor to a dashboard page (a path) or, for a doc, a URL
// under the project repository: the image carries no docs. A doc opens in a
// new tab, so the dashboard stays open, and sends no referrer.
function docLink(url, text) {
  var a = shellEl("a", "doc-link", text);
  a.href = url;
  if (url.charAt(0) !== "/") {
    a.target = "_blank";
    a.rel = "noopener noreferrer";
  }
  return a;
}

function shellClear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function shellTime(s) {
  if (!s) return "—";
  var d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function shellBadge(mode) {
  var name = mode === "observe" || mode === "suggest" || mode === "inject" ? mode : "unknown";
  return shellEl("span", "badge mode-" + name, mode || "—");
}

function shellJSON(path) {
  return fetch(path, {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.text().then(function (text) {
      var body = null;
      if (text) {
        try { body = JSON.parse(text); } catch (e) { body = null; }
      }
      if (!res.ok) {
        var msg = (body && body.error) || res.statusText;
        var err = new Error(path + " failed: " + msg);
        err.status = res.status;
        // The first-run password may only be changed, so go and change it (#328).
        if (body && body.code === "password_change_required" && window.location.pathname !== "/signin.html") {
          window.location.href = "/signin.html?change=1";
        }
        throw err;
      }
      return body;
    });
  });
}

function shellMarkCurrent() {
  var page = document.body.getAttribute("data-page");
  var links = document.querySelectorAll(".sidenav a[data-page]");
  for (var i = 0; i < links.length; i++) {
    if (links[i].getAttribute("data-page") === page) links[i].setAttribute("aria-current", "page");
    else links[i].removeAttribute("aria-current");
  }
}

// shellSetupRedirect sends an admin from the overview to the setup wizard
// while the first-run setup is pending (#416). Other pages stay reachable.
function shellSetupRedirect(me) {
  if (me && me.setup_pending && document.body.getAttribute("data-page") === "overview") {
    window.location.replace("/settings.html#wizard");
  }
}

// Settings and Admin are admin pages. With role-based auth, a lower role
// does not see them in the nav. A deep link to Admin shows the same 403
// text the dashboard uses. Settings keeps its own editor message.
function shellApplyMe(me) {
  shellUser = (me && me.user) || "";
  var rbac = me && me.auth === "rbac";
  var admin = !rbac || me.role === "admin";
  shellAdmin = admin;
  shellSetupRedirect(me);
  var gated = document.querySelectorAll("[data-min-role='admin']");
  for (var i = 0; i < gated.length; i++) gated[i].hidden = !admin;
  var who = document.getElementById("account-who");
  if (who) {
    if (!me || me.auth === "off" || !me.user) who.textContent = "Local install";
    else who.textContent = me.user + (me.role ? " (" + me.role + ")" : "");
  }
  var out = document.getElementById("account-out");
  if (out) out.hidden = !(me && me.session);
  if (!admin && document.body.getAttribute("data-page") === "admin") {
    var denied = document.getElementById("page-denied");
    var body = document.getElementById("admin-body");
    if (denied) {
      denied.textContent = "Your account may not read this page.";
      denied.hidden = false;
    }
    if (body) body.hidden = true;
  }
}

function shellRecentSearches() {
  try {
    var list = JSON.parse(localStorage.getItem(SEARCH_RECENT_KEY + (shellUser || "local")) || "[]");
    return Array.isArray(list) ? list.filter(function (q) { return typeof q === "string"; }).slice(0, SEARCH_RECENT_MAX) : [];
  } catch (e) { return []; }
}

function shellRememberSearch(q) {
  var list = shellRecentSearches().filter(function (old) { return old !== q; });
  list.unshift(q);
  try {
    localStorage.setItem(SEARCH_RECENT_KEY + (shellUser || "local"), JSON.stringify(list.slice(0, SEARCH_RECENT_MAX)));
  } catch (e) { /* storage blocked: the list is not kept */ }
}

function shellFillRecent() {
  var list = document.getElementById("top-search-recent");
  if (!list) return;
  shellClear(list);
  shellRecentSearches().forEach(function (q) {
    var o = document.createElement("option");
    o.value = q;
    list.appendChild(o);
  });
}

function shellSearchGo(q) {
  shellMeReady.then(function () {
    shellRememberSearch(q);
    window.location.href = "/search.html?q=" + encodeURIComponent(q);
  });
}

function shellSearch() {
  var input = document.getElementById("top-search");
  if (!input) return;
  input.addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter") return;
    var q = input.value.trim();
    if (q) shellSearchGo(q);
  });
}

function shellRenderEventsBadge(n) {
  var link = document.querySelector("#events-slot a");
  if (!link) return;
  var old = link.querySelector(".events-count");
  if (old) link.removeChild(old);
  link.removeAttribute("aria-label");
  if (!n) return;
  var text = n >= EVENTS_BADGE_MAX ? EVENTS_BADGE_MAX + "+" : String(n);
  link.appendChild(shellEl("span", "events-count", text));
  link.setAttribute("aria-label", "Events, " + text + " warnings since you last opened the page");
}

function shellMarkEventsSeen(nowISO) {
  if (!nowISO) return;
  try { localStorage.setItem(EVENTS_SEEN_KEY, nowISO); } catch (e) { /* storage blocked: the count stays */ }
  shellRenderEventsBadge(0);
}

function shellEventsBadge() {
  var seen = null;
  try { seen = localStorage.getItem(EVENTS_SEEN_KEY); } catch (e) { seen = null; }
  var path = "/api/events?severity=warning&limit=" + EVENTS_BADGE_MAX;
  if (seen) path += "&from=" + encodeURIComponent(seen);
  shellJSON(path).then(function (body) {
    shellRenderEventsBadge((body.events || []).length);
  }, function () { /* the indicator is optional: keep the last count */ });
}

function shellRenderBanner(mode) {
  var node = document.getElementById("banner");
  if (!node) return;
  if (!mode || !SHELL_MODE_TEXT[mode]) { node.hidden = true; return; }
  node.textContent = SHELL_MODE_TEXT[mode];
  node.className = "banner " + (mode === "inject" ? "banner-inject" : "banner-observe");
  node.hidden = false;
}

// Synthesize announces routes that are not in the learned RIB (#122). The
// text is the server's warning.
function shellRenderSynthBanner(text) {
  var node = document.getElementById("synth-banner");
  if (!text) {
    if (node) node.hidden = true;
    return;
  }
  if (!node) {
    var mode = document.getElementById("banner");
    if (!mode) return;
    node = shellEl("div", "banner banner-warn", "");
    node.id = "synth-banner";
    node.setAttribute("role", "alert");
    mode.parentNode.insertBefore(node, mode.nextSibling);
  }
  node.textContent = text;
  node.hidden = false;
}

// With sign-in off, anyone who reaches the port reads everything (#328).
function shellRenderAuthBanner(auth) {
  var node = document.getElementById("auth-banner");
  if (auth !== "off") {
    if (node) node.hidden = true;
    return;
  }
  if (!node) {
    var mode = document.getElementById("banner");
    if (!mode) return;
    node = shellEl("div", "banner banner-warn", "");
    node.id = "auth-banner";
    node.setAttribute("role", "alert");
    mode.parentNode.insertBefore(node, mode.nextSibling);
  }
  node.textContent = "Sign-in is off (auth.enabled: false): anyone who can reach this page can read it. Remove that line from the config and restart to require sign-in.";
  node.hidden = false;
}

function shellRenderStatus(ov, ready, err) {
  var node = document.getElementById("status");
  if (!node) return;
  shellClear(node);
  node.appendChild(shellBadge(ov && ov.mode));
  var up = ready && ready.ready;
  node.appendChild(shellEl("span", up ? "dot up" : "dot down", up ? "ready" : "not ready"));
  if (ov && ov.version) node.appendChild(shellEl("span", "muted", ov.version));
  if (ov && ov.generated_at) node.appendChild(shellEl("span", "muted", "updated " + shellTime(ov.generated_at)));
  if (err) node.appendChild(shellEl("span", "bad", "stale"));
}

function shellRenderConn(err) {
  var node = document.getElementById("conn");
  if (!node) return;
  document.body.classList.toggle("stale", !!err);
  if (!err) { node.hidden = true; shellClear(node); return; }
  shellClear(node);
  var msg;
  if (err.status === 401) msg = "Sign in required. Reload the page to sign in.";
  else if (err.status === 403) msg = "Your account may not read this page.";
  else if (err.status) msg = "The controller answered with an error: " + err.message;
  else msg = "Cannot reach the controller. Is the container running?";
  node.appendChild(shellEl("strong", "", msg));
  node.appendChild(shellEl("span", "", shellLastOK ? " Showing data from " + shellTime(shellLastOK) + "." : " No data loaded yet."));
  node.appendChild(shellEl("span", "muted", " Retrying every " + (SHELL_REFRESH_MS / 1000) + " seconds."));
  node.hidden = false;
}

function shellRefresh() {
  var readyReq = fetch("/readyz", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (res) {
    return res.json();
  });
  Promise.allSettled([shellJSON("/api/overview"), readyReq]).then(function (results) {
    var err = null;
    var ov = null;
    if (results[0].status === "fulfilled") ov = results[0].value;
    else err = results[0].reason;
    var ready = results[1].status === "fulfilled" ? results[1].value : null;
    if (results[1].status !== "fulfilled" && !err) err = results[1].reason;
    if (!err) shellLastOK = new Date().toISOString();
    shellRenderBanner(ov && ov.mode);
    shellRenderAuthBanner(ov && ov.auth);
    shellRenderSynthBanner(ov && ov.synthesize_warning);
    shellRenderStatus(ov, ready, err);
    shellRenderConn(err);
  });
}

function shellAccount() {
  var btn = document.getElementById("account-btn");
  var menu = document.getElementById("account-menu");
  if (!btn || !menu) return;
  btn.addEventListener("click", function () {
    menu.hidden = !menu.hidden;
    btn.setAttribute("aria-expanded", menu.hidden ? "false" : "true");
  });
  document.addEventListener("click", function (ev) {
    if (menu.hidden) return;
    if (btn === ev.target || btn.contains(ev.target) || menu.contains(ev.target)) return;
    menu.hidden = true;
    btn.setAttribute("aria-expanded", "false");
  });
  var out = document.getElementById("account-out");
  if (out) {
    out.addEventListener("click", function () {
      fetch("/auth/logout", {method: "POST", cache: "no-store"}).then(function () {
        window.location.href = "/";
      });
    });
  }
}

// Below 760px the nav links sit behind the Menu button (#352). Escape
// closes the menu and returns focus to the button.
function shellNavMenu() {
  var btn = document.getElementById("nav-toggle");
  var nav = document.querySelector(".sidenav");
  if (!btn || !nav) return;
  function set(open) {
    nav.classList.toggle("open", open);
    document.body.classList.toggle("nav-open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  }
  btn.addEventListener("click", function () { set(!nav.classList.contains("open")); });
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape" || !nav.classList.contains("open")) return;
    set(false);
    btn.focus();
  });
}

// On a phone a table row is a card (app.css), so each cell needs its
// column name. The names are copied from the header only while the screen is
// narrow, and removed when it is not, so a wide page keeps its plain markup.
// A table inside .table-wrap scrolls sideways instead.
var shellNarrow = window.matchMedia("(max-width: 759px)");

function shellStackTable(t) {
  var narrow = shellNarrow.matches && !t.closest(".table-wrap");
  var heads = t.querySelectorAll(":scope > thead th");
  t.classList.toggle("stacked", narrow);
  for (var b = 0; b < t.tBodies.length; b++) {
    for (var r = 0; r < t.tBodies[b].rows.length; r++) {
      var cells = t.tBodies[b].rows[r].cells;
      // A row with a spanning cell (a prefix's details) has no column names.
      for (var c = 0; c < cells.length; c++) {
        var name = narrow && cells.length === heads.length ? heads[c].textContent.trim() : "";
        if (name) cells[c].setAttribute("data-label", name);
        else cells[c].removeAttribute("data-label");
      }
    }
  }
  if (!narrow && !t.className) t.removeAttribute("class");
}

function shellStackAll(root) {
  var tables = root.querySelectorAll("table");
  for (var i = 0; i < tables.length; i++) shellStackTable(tables[i]);
}

function shellStackTables() {
  var pending = new Set();
  new MutationObserver(function (list) {
    if (!shellNarrow.matches) return;
    list.forEach(function (m) {
      var own = m.target.closest && m.target.closest("table");
      if (own) pending.add(own);
      m.addedNodes.forEach(function (n) {
        if (n.nodeType !== 1) return;
        if (n.matches("table")) pending.add(n);
        n.querySelectorAll("table").forEach(function (t) { pending.add(t); });
      });
    });
    pending.forEach(shellStackTable);
    pending.clear();
  }).observe(document.body, {childList: true, subtree: true});
  shellNarrow.addEventListener("change", function () { shellStackAll(document); });
  shellStackAll(document);
}

if (document.body.getAttribute("data-page") !== "signin") {
  shellMarkCurrent();
  shellNavMenu();
  shellStackTables();
  shellAccount();
  var shellMeReady = shellJSON("/api/me").then(function (me) {
    shellApplyMe(me);
    shellFillRecent();
    return me;
  }, function () { return null; });
  shellSearch();
  if (document.body.getAttribute("data-page") !== "events") {
    shellEventsBadge();
    setInterval(shellEventsBadge, EVENTS_BADGE_MS);
  }
  if (document.body.getAttribute("data-live") !== "app") {
    var refreshBtn = document.getElementById("refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", function () {
        shellRefresh();
        if (typeof renderGrid === "function") renderGrid();
      });
    }
    shellRefresh();
    setInterval(shellRefresh, SHELL_REFRESH_MS);
  }
}
