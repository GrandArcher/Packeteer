"use strict";
// Page driver for the first-run UI smoke test (#575). The running file is the
// example install: an AS number, a router ID, and providers, with no setup
// state saved. uiproxy answers /api/me with setup_pending so the page sees the
// first run (the real flag needs a sign-in session). The driver writes what the
// settings page shows into the page for lab/ui-smoke.sh to match: the wizard is
// open with the running values filled, "Run setup again" is not offered, the
// header is in view, and nothing was written.

var writes = 0;
var realFetch = window.fetch;
window.fetch = function (url, opts) {
  if (((opts && opts.method) || "GET") !== "GET") writes++;
  return realFetch.apply(window, arguments);
};

function byId(id) { return document.getElementById(id); }

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

var tries = 0;
function next() {
  if (tries++ > 60) return;
  // The page is loaded once the wizard fields are filled from the file.
  if (!byId("wz-asn").value || !byId("setup-skip") || byId("setup-skip").hidden) { setTimeout(next, 300); return; }
  var brand = document.querySelector(".brand").getBoundingClientRect();
  note("fixture-wizard", "wizard open: " + !byId("wz-body").hidden + ", run again hidden: " + byId("wz-again").hidden);
  note("fixture-values", "asn " + byId("wz-asn").value + ", router " + byId("wz-router").value + ", provider rows " + byId("wz-providers").children.length);
  note("fixture-button", "button: " + byId("wz-run").textContent);
  note("fixture-view", "header in view: " + (window.scrollY === 0 && brand.top >= 0) + ", observe banner in view: " + (byId("banner").getBoundingClientRect().top >= 0));
  note("fixture-writes", "writes: " + writes);
}

next();
