"use strict";
// Sign-in page for local users. Same-origin only. The password is sent
// once in the POST body and is not kept anywhere in the page.

function signinError(msg) {
  var node = document.getElementById("signin-error");
  node.textContent = msg;
  node.hidden = !msg;
}

// The generated first-run password only buys a password change (#328).
function showChangeForm() {
  document.getElementById("signin-form").hidden = true;
  document.getElementById("signin-sso").hidden = true;
  document.getElementById("change-form").hidden = false;
  document.getElementById("change-current").focus();
}

function changeError(msg) {
  var node = document.getElementById("change-error");
  node.textContent = msg;
  node.hidden = !msg;
}

function changeSubmit(ev) {
  ev.preventDefault();
  var cur = document.getElementById("change-current");
  var next = document.getElementById("change-new");
  var again = document.getElementById("change-again");
  var btn = document.getElementById("change-submit");
  changeError("");
  if (next.value !== again.value) { changeError("The two new passwords differ."); return; }
  btn.disabled = true;
  fetch("/api/account/password", {
    method: "POST",
    cache: "no-store",
    headers: {"Content-Type": "application/json", Accept: "application/json"},
    body: JSON.stringify({current_password: cur.value, new_password: next.value})
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (body) {
      if (res.ok) {
        window.location.href = "/";
        return;
      }
      cur.value = next.value = again.value = "";
      if (res.status === 401) changeError("Your session ended. Sign in again.");
      else changeError(body.error || "The password was not changed.");
      btn.disabled = false;
    });
  }, function () {
    changeError("Cannot reach the controller. Is the container running?");
    btn.disabled = false;
  });
}

function signinSubmit(ev) {
  ev.preventDefault();
  var name = document.getElementById("signin-name");
  var pass = document.getElementById("signin-password");
  var btn = document.getElementById("signin-submit");
  signinError("");
  btn.disabled = true;
  fetch("/auth/signin", {
    method: "POST",
    cache: "no-store",
    headers: {"Content-Type": "application/json", Accept: "application/json"},
    body: JSON.stringify({name: name.value, password: pass.value})
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (body) {
      if (res.ok) {
        // A Secure cookie is dropped over plain http away from localhost.
        return fetch("/api/me", {cache: "no-store", headers: {Accept: "application/json"}}).then(function (me) {
          if (me.ok) {
            if (body.must_change) { pass.value = ""; btn.disabled = false; showChangeForm(); return; }
            window.location.href = "/";
            return;
          }
          pass.value = "";
          signinError("Signed in, but the browser did not keep the session cookie. Open this page over https or on localhost.");
          btn.disabled = false;
        });
      }
      pass.value = "";
      if (res.status === 429) signinError("Too many failed sign-ins from this address. Try again in a few minutes.");
      else if (res.status === 401) signinError("Wrong user name or password.");
      else signinError(body.error || "Sign-in failed.");
      btn.disabled = false;
    });
  }, function () {
    signinError("Cannot reach the controller. Is the container running?");
    btn.disabled = false;
  });
}

document.getElementById("signin-form").addEventListener("submit", signinSubmit);
document.getElementById("change-form").addEventListener("submit", changeSubmit);
// A page that was refused for a forced change sends the browser here.
if (window.location.search.indexOf("change=1") >= 0) showChangeForm();
shellJSON("/auth/signin").then(function (info) {
  shellRenderBanner(info.mode);
  document.getElementById("signin-sso").hidden = !info.sso;
}, function () {});
