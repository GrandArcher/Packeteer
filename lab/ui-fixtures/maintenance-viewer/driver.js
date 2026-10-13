"use strict";
// Page driver for the UI smoke test (#177), viewer case. uiproxy answers
// /api/me as a viewer and /api/maintenance with one window per state. The
// driver writes what the page offers: the form must stay hidden, no row may
// have a Close button, and no call but a GET may be made.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  if (opts && opts.method && opts.method !== "GET") writes++;
  return realFetch.apply(window, arguments);
};

function rows() {
  return Array.prototype.map.call(document.querySelectorAll("#maint-list tbody tr"), function (tr) {
    return Array.prototype.map.call(tr.children, function (td) { return td.textContent; }).join("|");
  });
}

var tries = 0;
function next() {
  if (rows().length === 3 && !document.getElementById("maint-readonly").hidden) {
    var p = document.createElement("p");
    p.id = "fixture-viewer";
    p.textContent = "viewer: form hidden " + document.getElementById("maint-form").hidden +
      " close buttons " + document.querySelectorAll("#maint-list button").length +
      " writes " + writes + " rows " + rows().join(" ; ");
    document.querySelector("main").appendChild(p);
    return;
  }
  if (tries++ < 40) setTimeout(next, 300);
}

next();
