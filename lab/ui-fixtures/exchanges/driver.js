"use strict";
// Page driver for the UI smoke test (#155). Headless Chrome cannot click,
// so uiproxy adds this script to /settings.html. It waits for the form,
// presses Accept on a discovered exchange member, and writes what the form
// then holds into the page for lab/ui-smoke.sh to match. It also counts
// the calls that could write the config, which accepting must not make.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  var method = (opts && opts.method) || "GET";
  var body = (opts && opts.body) || "";
  if (method !== "GET" && (method !== "POST" || String(url).indexOf("/api/config/form") < 0 || body.indexOf('"apply":true') >= 0)) writes++;
  return realFetch.apply(window, arguments);
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function rows() {
  return document.querySelectorAll("#form-ix-discovered .row");
}

function peerField(row, label) {
  var f = Array.prototype.find.call(row.querySelectorAll("label"), function (l) { return l.firstChild.textContent === label; });
  return f.querySelector("input").value;
}

function peerRows() {
  return Array.prototype.filter.call(document.querySelectorAll("#form-exchanges .row"), function (r) { return r.querySelector("input") && r.textContent.indexOf("Peer name") >= 0; });
}

var steps = [
  function () { return rows().length > 0 && !!rows()[0].querySelector("button"); },
  function () {
    note("fixture-before", "before: " + rows().length + " members " + Array.prototype.map.call(rows(), function (r) { return r.textContent; }).join(" | "));
    rows()[0].querySelector("button").click();
  },
  function () {
    var added = peerRows()[2];
    note("fixture-after", "after: peers " + peerRows().length + " members " + rows().length +
      " draft " + (added.textContent.indexOf("draft") >= 0) +
      " name [" + peerField(added, "Peer name") + "] as [" + peerField(added, "Peer AS") + "] hop [" + peerField(added, "Peer next hop") +
      "] source [" + peerField(added, "Peer probe address") + "] cost [" + peerField(added, "Peer cost") + "] writes " + writes);
  }
];

var tries = 0;
function next() {
  if (!steps.length || tries++ > 40) return;
  if (steps[0]() !== false) steps.shift();
  setTimeout(next, 300);
}

next();
