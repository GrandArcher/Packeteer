"use strict";
// The Tokens page (#175): list, create, and revoke the signed-in user's API
// tokens over /api/tokens. The server checks the role ceiling, the lifetime,
// the per-user cap, and writes the audit record; this file only builds the
// calls. The secret in the create answer is put in the page once, in one
// element, and removed when the box is closed or the page is left. It is
// not put in the list, a cookie, or any storage. Uses api, el, clear, and
// fmtTime from ui.js. No inline script: the CSP allows scripts from this
// origin only.

var ROLE_ORDER = ["viewer", "operator", "admin"];

function tokensStatus(text, bad) {
  var n = document.getElementById("tokens-status");
  n.textContent = text;
  n.className = bad ? "bad" : "tag";
}

function hideSecret() {
  var box = document.getElementById("token-secret");
  document.getElementById("token-secret-value").textContent = "";
  box.hidden = true;
}

function showSecret(secret) {
  document.getElementById("token-secret-value").textContent = secret;
  document.getElementById("token-secret").hidden = false;
}

function copySecret() {
  var code = document.getElementById("token-secret-value");
  var text = code.textContent;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(function () { tokensStatus("Copied.", false); },
      function () { tokensStatus("Copy failed. Select the token and copy it by hand.", true); });
    return;
  }
  var range = document.createRange();
  range.selectNodeContents(code);
  var sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
  tokensStatus("Selected. Press Ctrl+C to copy.", false);
}

function tokenState(t) {
  return t.expired ? "expired" : "active";
}

function revokeCell(t) {
  var td = el("td");
  var b = el("button", "small", "Revoke");
  b.type = "button";
  b.setAttribute("aria-label", "Revoke token " + t.name + " of " + t.user);
  b.addEventListener("click", function () {
    if (b.textContent === "Revoke") { b.textContent = "Confirm revoke"; return; }
    api("DELETE", "/api/tokens/" + encodeURIComponent(t.id)).then(function () {
      tokensStatus("Revoked " + t.name + ".", false);
    }, function (err) {
      tokensStatus(err.message, true);
    }).then(loadTokens);
  });
  td.appendChild(b);
  return td;
}

function renderTokens(list) {
  var root = document.getElementById("tokens");
  clear(root);
  if (!list.length) {
    root.appendChild(el("p", "empty", "No API tokens."));
    return;
  }
  var table = el("table");
  var head = el("tr");
  ["Name", "User", "Role", "Created", "Expires", "Status", "Actions"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  list.forEach(function (t) {
    var tr = el("tr");
    tr.appendChild(el("td", "", t.name));
    tr.appendChild(el("td", "", t.user));
    tr.appendChild(el("td", "", t.role));
    tr.appendChild(el("td", "", fmtTime(t.created)));
    tr.appendChild(el("td", "", fmtTime(t.expires)));
    tr.appendChild(el("td", "", tokenState(t)));
    tr.appendChild(revokeCell(t));
    body.appendChild(tr);
  });
  table.appendChild(body);
  root.appendChild(table);
}

function loadTokens() {
  return api("GET", "/api/tokens").then(function (data) {
    renderTokens(data.tokens || []);
  }, function (err) {
    tokensStatus(err.message, true);
  });
}

// tokenTTL turns hours into a duration string, or "" for the server's
// default. The server checks the range again.
function tokenTTL(text) {
  text = text.trim();
  if (text === "") return "";
  if (!/^\d+$/.test(text) || Number(text) < 1 || Number(text) > 8760) return null;
  return text + "h";
}

function createToken(ev) {
  ev.preventDefault();
  var name = document.getElementById("tf-name").value.trim();
  var ttl = tokenTTL(document.getElementById("tf-ttl").value);
  if (ttl === null) {
    tokensStatus("Lifetime is a whole number of hours, 1 to 8760.", true);
    return;
  }
  var body = {name: name, role: document.getElementById("tf-role").value};
  if (ttl !== "") body.ttl = ttl;
  hideSecret();
  api("POST", "/api/tokens", body).then(function (made) {
    showSecret(made.token);
    document.getElementById("tf-name").value = "";
    tokensStatus("Created " + made.name + ". Copy the token now.", false);
  }, function (err) {
    tokensStatus(err.message, true);
  }).then(loadTokens);
}

// A token cannot create tokens, so a request signed with one only lists and
// revokes. Roles above the signed-in user's are not offered.
function buildForm(me) {
  var form = document.getElementById("token-form");
  if (me.method === "token") {
    form.hidden = true;
    var note = el("p", "tag", "This request is signed with an API token. A token cannot create tokens; sign in with a password or single sign-on to create one.");
    form.parentNode.insertBefore(note, form);
    return;
  }
  var sel = document.getElementById("tf-role");
  ROLE_ORDER.slice(0, ROLE_ORDER.indexOf(me.role) + 1).forEach(function (r) {
    var o = el("option", "", r);
    o.value = r;
    sel.appendChild(o);
  });
  document.getElementById("token-form-note").textContent = "The role may not exceed yours (" + me.role + "). The lifetime is capped at one year.";
  form.addEventListener("submit", createToken);
}

function tokensInit() {
  api("GET", "/api/me").then(function (me) {
    if (me.auth !== "rbac") {
      document.getElementById("tokens-off").hidden = false;
      return;
    }
    document.getElementById("tokens-on").hidden = false;
    document.getElementById("token-done").addEventListener("click", hideSecret);
    document.getElementById("token-copy").addEventListener("click", copySecret);
    document.getElementById("refresh").addEventListener("click", loadTokens);
    window.addEventListener("pagehide", hideSecret);
    buildForm(me);
    loadTokens();
  }, function () {});
}

tokensInit();
