"use strict";
// Sign-in page for local users. Same-origin only. The password is sent
// once in the POST body and is not kept anywhere in the page.

function signinError(msg) {
  var node = document.getElementById("signin-error");
  node.textContent = msg;
  node.hidden = !msg;
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
        window.location.href = "/";
        return;
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
shellJSON("/auth/signin").then(function (info) {
  shellRenderBanner(info.mode);
  document.getElementById("signin-sso").hidden = !info.sso;
}, function () {});
