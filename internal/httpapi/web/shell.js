"use strict";
// Shared chrome (#170): current page, account menu, role-gated nav, and
// the mode line on pages that do not load app.js. Same-origin only.

var SHELL_REFRESH_MS = 5000;
var shellLastOK = null;

var SHELL_MODE_TEXT = {
  observe: "Observe mode: Packeteer measures and recommends. It announces nothing.",
  suggest: "Suggest mode: Packeteer measures and publishes recommendations. It announces nothing.",
  inject: "Inject mode: improvements for allowlisted prefixes are announced to the edge routers."
};

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
  if (out) out.hidden = !(me && me.sso);
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

shellMarkCurrent();
shellAccount();
shellJSON("/api/me").then(shellApplyMe, function () {});
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
