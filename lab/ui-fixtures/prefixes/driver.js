"use strict";
// Page driver for the UI smoke test (#183). Headless Chrome cannot click,
// so uiproxy adds this script to /prefixes.html. It opens a row, goes to the
// next page, then types an origin AS and picks a sort order, and writes what
// it sees into the page for lab/ui-smoke.sh to match.

function press(label, scope) {
  var b = Array.prototype.find.call((scope || document).querySelectorAll("button"), function (x) { return x.textContent === label; });
  b.click();
}

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function firstPrefix() {
  return document.querySelector(".prefix-row a").textContent;
}

function fire(id, type, set) {
  var n = document.getElementById(id);
  set(n);
  n.dispatchEvent(new Event(type, {bubbles: true}));
}

var steps = [
  function () { press("Details", document.querySelector(".prefix-row")); },
  function () {
    var d = document.querySelector(".prefix-detail");
    var t = d ? d.textContent : "";
    note("fixture-card", "card: " + (d ? "open" : "closed") + (t.indexOf("MED breaks ties between exits to one neighbor AS") >= 0 ? " with MED tie break" : "") +
      (t.indexOf("Overrides AS64496's MED: lab-b (MED 200) is chosen over lab-a (MED 100)") >= 0 ? " and MED override" : "") +
      (d && Array.prototype.some.call(d.querySelectorAll(".badge.warn"), function (b) { return b.textContent === "overrides MED"; }) ? " with badge" : "") +
      ", rows " + document.querySelectorAll(".prefix-row").length);
  },
  function () {
    var m = document.getElementById("asn-map").textContent;
    note("fixture-asn", "asn map: " + (m.indexOf("Showing the first 2 of 1234 origin ASNs") >= 0 ? "bounded" : "unbounded") +
      (m.indexOf("33334 (") >= 0 && m.indexOf("+33326") >= 0 ? ", counts kept" : ", counts lost") +
      ", links " + document.querySelectorAll("#asn-map a[href='/prefixes.html?asn=64500']").length);
  },
  function () { press("Next"); },
  function () { note("fixture-page2", "page 2: " + window.location.search + " first " + firstPrefix() + " cards " + document.querySelectorAll(".prefix-detail").length); },
  function () { fire("prefix-sort", "change", function (n) { n.value = "gain"; }); },
  function () { fire("prefix-asn", "input", function (n) { n.value = "AS64500"; }); },
  function () { note("fixture-filtered", "filtered: " + window.location.search + " first " + firstPrefix() + " rows " + document.querySelectorAll(".prefix-row").length); }
];

function next() {
  if (!steps.length) return;
  steps.shift()();
  setTimeout(next, 400);
}

window.addEventListener("load", function () { setTimeout(next, 800); });
