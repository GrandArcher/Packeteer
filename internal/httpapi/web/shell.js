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

function shellEl(tag, className, text) {
  var n = document.createElement(tag);
  if (className) n.className = className;
  if (text != null && text !== "") n.textContent = String(text);
  return n;
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

// Settings and Admin are admin pages. With role-based auth, a lower role
// does not see them in the nav. A deep link to Admin shows the same 403
// text the dashboard uses. Settings keeps its own editor message.
function shellApplyMe(me) {
  shellUser = (me && me.user) || "";
  var rbac = me && me.auth === "rbac";
  var admin = !rbac || me.role === "admin";
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

if (document.body.getAttribute("data-page") !== "signin") {
  shellMarkCurrent();
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
