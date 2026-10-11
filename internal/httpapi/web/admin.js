"use strict";
// The Users section of the Admin page (#175): list, add, change role,
// reset password, disable or enable, and delete over /api/users. The
// server checks the admin role, the last-admin lockout, and the password
// rules, and writes the audit record on every call; this file only builds
// the requests. A password is read from its field, sent, and the field is
// cleared; it is never kept in a variable or storage. Uses api, el, clear,
// and fmtTime from ui.js. No inline script: the CSP allows scripts from
// this origin only.

var ROLES = ["viewer", "operator", "admin"];
var usersMe = null;

function usersStatus(text, bad) {
  var n = document.getElementById("users-status");
  n.textContent = text;
  n.className = bad ? "bad" : "tag";
}

function userPath(name) {
  return "/api/users/" + encodeURIComponent(name);
}

// userChange sends one call and reloads the list, which also resets any
// armed button. The server's message is shown as it is, so a refused
// change (the last admin, a weak password) says why.
function userChange(method, path, body, done) {
  api(method, path, body).then(function () {
    usersStatus(done, false);
  }, function (err) {
    usersStatus(err.message, true);
  }).then(loadUsers);
}

function userButton(label, aria, onclick) {
  var b = el("button", "small", label);
  b.type = "button";
  b.setAttribute("aria-label", aria);
  b.addEventListener("click", onclick);
  return b;
}

function userRoleCell(u) {
  var td = el("td");
  if (u.source !== "local") {
    td.appendChild(document.createTextNode(u.role));
    td.appendChild(el("span", "tag", " set by the identity provider"));
    return td;
  }
  var sel = el("select");
  sel.setAttribute("aria-label", "Role for " + u.name);
  ROLES.forEach(function (r) {
    var o = el("option", "", r);
    o.value = r;
    if (r === u.role) o.selected = true;
    sel.appendChild(o);
  });
  td.appendChild(sel);
  td.appendChild(userButton("Change role", "Change role of " + u.name, function () {
    if (sel.value === u.role) { usersStatus("Role of " + u.name + " is already " + u.role + ".", false); return; }
    userChange("PATCH", userPath(u.name), {role: sel.value}, "Role of " + u.name + " is now " + sel.value + ".");
  }));
  return td;
}

function userPasswordForm(u) {
  var form = el("form", "inline-form");
  form.hidden = true;
  form.autocomplete = "off";
  var lab = el("label", "", "New password for " + u.name + " ");
  var input = el("input");
  input.type = "password";
  input.minLength = 12;
  input.maxLength = 256;
  input.autocomplete = "new-password";
  lab.appendChild(input);
  form.appendChild(lab);
  var set = el("button", "small", "Set password");
  set.type = "submit";
  form.appendChild(set);
  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var pw = input.value;
    input.value = "";
    userChange("PATCH", userPath(u.name), {password: pw}, "Password of " + u.name + " was reset. Their sessions ended.");
  });
  return form;
}

function userActionsCell(u) {
  var td = el("td");
  if (u.source === "local") {
    var pwForm = userPasswordForm(u);
    td.appendChild(userButton("Reset password", "Reset password of " + u.name, function () {
      pwForm.hidden = !pwForm.hidden;
      if (!pwForm.hidden) pwForm.querySelector("input").focus();
    }));
    td.appendChild(pwForm);
  }
  td.appendChild(userButton(u.disabled ? "Enable" : "Disable", (u.disabled ? "Enable " : "Disable ") + u.name, function () {
    userChange("PATCH", userPath(u.name), {disabled: !u.disabled}, u.name + (u.disabled ? " is enabled." : " is disabled."));
  }));
  var del = userButton("Delete", "Delete " + u.name, function () {
    if (del.textContent === "Delete") { del.textContent = "Confirm delete"; return; }
    userChange("DELETE", userPath(u.name), undefined, "Deleted " + u.name + " and its tokens.");
  });
  td.appendChild(del);
  return td;
}

function renderUsers(list) {
  var root = document.getElementById("users");
  clear(root);
  var table = el("table");
  var head = el("tr");
  ["Name", "Role", "Source", "Status", "Updated", "Actions"].forEach(function (h) { head.appendChild(el("th", "", h)); });
  table.appendChild(el("thead")).appendChild(head);
  var body = el("tbody");
  list.forEach(function (u) {
    var tr = el("tr");
    var name = el("td", "", u.name);
    if (usersMe && usersMe.user === u.name) name.appendChild(el("span", "tag", " (you)"));
    tr.appendChild(name);
    tr.appendChild(userRoleCell(u));
    tr.appendChild(el("td", "", u.source === "local" ? "local" : "SSO"));
    tr.appendChild(el("td", "", u.disabled ? "disabled" : "enabled"));
    tr.appendChild(el("td", "", fmtTime(u.updated)));
    tr.appendChild(userActionsCell(u));
    body.appendChild(tr);
  });
  table.appendChild(body);
  root.appendChild(table);
}

function loadUsers() {
  return api("GET", "/api/users").then(function (data) {
    renderUsers(data.users || []);
  }, function (err) {
    usersStatus(err.message, true);
  });
}

function addUser(ev) {
  ev.preventDefault();
  var name = document.getElementById("uf-name").value.trim();
  var role = document.getElementById("uf-role").value;
  var pwField = document.getElementById("uf-password");
  var pw = pwField.value;
  pwField.value = "";
  api("POST", "/api/users", {name: name, role: role, password: pw}).then(function () {
    document.getElementById("uf-name").value = "";
    usersStatus("Added " + name + " as " + role + ".", false);
    loadUsers();
  }, function (err) {
    usersStatus(err.message, true);
  });
}

function usersInit() {
  api("GET", "/api/me").then(function (me) {
    usersMe = me;
    if (me.auth !== "rbac") {
      document.getElementById("users-off").hidden = false;
      return;
    }
    if (me.role !== "admin") return;
    document.getElementById("users-on").hidden = false;
    document.getElementById("user-form").addEventListener("submit", addUser);
    document.getElementById("refresh").addEventListener("click", loadUsers);
    loadUsers();
  }, function () {});
}

usersInit();
