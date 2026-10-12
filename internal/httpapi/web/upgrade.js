"use strict";
// Version and upgrade (#196) on the Settings page. Release notes come from
// GitHub and are shown as text only. Nothing here upgrades without the
// Confirm button.

var upStatus = null;
var upAction = null; // {kind: "apply"|"rollback", tag: string}

function upSay(text) { document.getElementById("up-status").textContent = text || ""; }

function upSummary(st) {
  var box = document.getElementById("up-summary");
  clear(box);
  var line = "Running " + (st.version || "unknown") + " (" + (st.install || "binary") + ", " + (st.arch || "") + ")";
  if (st.staged) line += ", a staged version";
  box.appendChild(el("span", "", line + ". "));
  if (!st.enabled) {
    box.appendChild(el("span", "", "Upgrade is off. Set upgrade.enabled and upgrade.public_key in the config file (docs/ui.md)."));
    return;
  }
  if (st.pending) box.appendChild(el("strong", "", "Switching to " + st.pending + ". "));
  if (st.checked_at) box.appendChild(el("span", "", "Last check " + fmtTime(st.checked_at) + ". "));
  else box.appendChild(el("span", "", "Not checked yet. "));
  if (st.check_error) box.appendChild(el("span", "bad", "Check failed: " + st.check_error + ". "));
  if (st.check_interval) box.appendChild(el("span", "", "Background check every " + st.check_interval + " (notify only). "));
  if (st.available && st.latest) box.appendChild(el("strong", "", "A newer release is available: " + st.latest.tag + ". "));
  else if (st.checked_at && !st.check_error) box.appendChild(el("span", "", "No newer release. "));
  if (st.last_error) box.appendChild(el("span", "bad", "Last problem: " + st.last_error));
}

function upRelease(st, r) {
  var tr = el("tr");
  tr.appendChild(el("td", "", r.tag + (r.prerelease ? " (pre-release)" : "") + (r.current ? " (running)" : "")));
  tr.appendChild(el("td", "", fmtTime(r.published)));
  var notes = el("td");
  if (r.notes) {
    var d = el("details");
    d.appendChild(el("summary", "", "Release notes"));
    d.appendChild(el("pre", "", r.notes));
    notes.appendChild(d);
  }
  tr.appendChild(notes);
  var act = el("td");
  if (r.current) {
    act.appendChild(el("span", "tag", "running"));
  } else if (!r.installable) {
    act.appendChild(el("span", "tag", "no signed binary for " + st.arch));
  } else {
    var b = el("button", "small", (r.newer ? "Upgrade to " : "Switch to ") + r.tag);
    b.type = "button";
    b.disabled = !!st.pending;
    b.addEventListener("click", function () { upAsk({kind: "apply", tag: r.tag}, st); });
    act.appendChild(b);
  }
  tr.appendChild(act);
  return tr;
}

function upReleases(st) {
  var root = document.getElementById("up-releases");
  clear(root);
  if (!st.enabled) return;
  if (!st.releases || !st.releases.length) {
    root.appendChild(el("p", "empty", st.checked_at ? "No releases found." : "Press Check for updates to read the releases."));
    return;
  }
  var t = el("table");
  var hr = el("tr");
  ["Release", "Published", "Notes", ""].forEach(function (h) { hr.appendChild(el("th", "", h)); });
  var th = el("thead");
  th.appendChild(hr);
  t.appendChild(th);
  var tb = el("tbody");
  st.releases.forEach(function (r) { tb.appendChild(upRelease(st, r)); });
  t.appendChild(tb);
  root.appendChild(t);
}

function upRender(st) {
  upStatus = st;
  upSummary(st);
  upReleases(st);
  var check = document.getElementById("up-check");
  check.disabled = !st.enabled || !!st.pending;
  var rb = document.getElementById("up-rollback");
  rb.hidden = !(st.enabled && st.rollback);
  rb.disabled = !!st.pending;
  if (st.rollback) rb.textContent = "Roll back to " + st.rollback.version;
}

function upAsk(action, st) {
  upAction = action;
  var text;
  if (action.kind === "apply") {
    text = "Upgrade from " + st.version + " to " + action.tag + "? Packeteer shuts down now like on SIGTERM: every Packeteer route is withdrawn from the edge, then the new version starts in the configured mode and learns the RIB again before it injects. Observe stays observe.";
  } else {
    text = "Roll back from " + st.version + " to " + st.rollback.version + "? The same shutdown and withdraw happen, and the config file is kept as it is.";
  }
  document.getElementById("up-confirm-title").textContent = text;
  var ha = document.getElementById("up-confirm-ha");
  ha.hidden = !st.needs_standby_upgraded;
  document.getElementById("up-standby").checked = false;
  document.getElementById("up-confirm").hidden = false;
  document.getElementById("up-confirm-go").focus();
}

function upClose() {
  upAction = null;
  document.getElementById("up-confirm").hidden = true;
}

function upLoad() {
  return api("GET", "/api/upgrade").then(upRender, function (err) {
    document.getElementById("up-summary").textContent = err.status === 403 ? "Your account may not read this page." : err.message;
  });
}

function upCheck() {
  upSay("Checking releases…");
  api("POST", "/api/upgrade/check", {}).then(function (st) {
    upRender(st);
    upSay("Checked. Nothing was changed.");
  }, function (err) { upSay(err.message); upLoad(); });
}

// upWatch polls until the controller answers with another version, or
// the same one after the shutdown, so the page shows what runs now.
function upWatch(before) {
  var tries = 0;
  var tick = function () {
    tries++;
    api("GET", "/api/upgrade").then(function (st) {
      if (st.version !== before || !st.pending) {
        upRender(st);
        upSay(st.version !== before ? "Now running " + st.version + "." : "The controller is back on " + st.version + ".");
        return;
      }
      if (tries < 90) setTimeout(tick, 2000);
    }, function () {
      upSay("Packeteer is restarting. Routes were withdrawn first.");
      if (tries < 90) setTimeout(tick, 2000);
    });
  };
  setTimeout(tick, 2000);
}

function upGo() {
  var a = upAction;
  if (!a) return;
  var before = upStatus.version;
  var body = {confirm: true, standby_upgraded: document.getElementById("up-standby").checked};
  var path = "/api/upgrade/rollback";
  if (a.kind === "apply") {
    body.tag = a.tag;
    path = "/api/upgrade/apply";
  }
  upClose();
  upSay("Verifying the release and checking the new version against this config…");
  api("POST", path, body).then(function (res) {
    upSay(res.message);
    upWatch(before);
  }, function (err) { upSay("Nothing was changed: " + err.message); upLoad(); });
}

document.getElementById("up-check").addEventListener("click", upCheck);
document.getElementById("up-rollback").addEventListener("click", function () {
  if (upStatus && upStatus.rollback) upAsk({kind: "rollback"}, upStatus);
});
document.getElementById("up-confirm-go").addEventListener("click", upGo);
document.getElementById("up-confirm-cancel").addEventListener("click", function () { upClose(); upSay("Cancelled. Nothing was changed."); });
upLoad();
