"use strict";
// Page driver for the 1440 px smoke test (#580). Settings, Improvements and
// Providers are each loaded in a 1440x900 iframe (the frame has its own media
// queries) and measured. On Settings the Decision settings must start on the
// first screen with the long sections closed. On Improvements and Providers
// no word or AS number may wrap into fragments, nothing may stick out of the
// viewport, Mbps and Probes must be fully on screen, and the "Open in" links
// must sit behind one menu per provider row. Improvements and Providers are
// answered from canned files on documentation prefixes and ASNs. Results are
// written into the page for lab/ui-smoke.sh to match.

// The injected page is also loaded inside the frames; only the top page measures.
if (window.top !== window) throw new Error("desktop driver: frame");

var W = 1440, H = 900;

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("desk-jserr", "script error: " + e.message); });

function yes(v) { return v ? "yes" : "no"; }

// load opens href in a frame and resolves once ready(document) is true, or
// after about 8 seconds, so a page that never gets there fails its checks
// instead of hanging.
function load(href, ready) {
  return new Promise(function (resolve, reject) {
    var f = document.createElement("iframe");
    f.style.cssText = "position:absolute;left:-10000px;top:0;border:0;width:" + W + "px;height:" + H + "px";
    f.src = href;
    f.onload = function () {
      var tries = 0;
      var poll = setInterval(function () {
        var d = f.contentDocument;
        var banner = d.getElementById("banner");
        if ((banner && !banner.hidden && ready(d)) || ++tries > 80) {
          clearInterval(poll);
          resolve(f);
        }
      }, 100);
    };
    f.onerror = function () { reject(new Error(href)); };
    document.body.appendChild(f);
  });
}

// fits is true when nothing in main sticks out of the viewport: no sideways
// scroll, and every table cell shows all of its content.
function fits(f) {
  var d = f.contentDocument, w = f.contentWindow;
  if (d.documentElement.scrollWidth > w.innerWidth) return false;
  var cells = d.querySelectorAll("main tbody td, main tbody th");
  for (var i = 0; i < cells.length; i++) {
    var r = cells[i].getBoundingClientRect();
    if (r.width > 0 && (r.right > w.innerWidth || cells[i].scrollWidth > cells[i].clientWidth + 1)) return false;
  }
  return true;
}

// oneLine is true when the cell's text sits on a single line, so a word or
// an AS number was not broken up.
function oneLine(d, cell) {
  var range = d.createRange();
  range.selectNodeContents(cell);
  return range.getClientRects().length === 1;
}

function folds(d) {
  var ids = ["wizard", "preflight", "router-snippet", "blast"];
  var closed = ids.every(function (id) {
    var det = d.getElementById(id);
    return det && !det.open;
  });
  var raw = d.getElementById("raw-yaml");
  return closed && raw && !raw.open;
}

function settings(f) {
  var d = f.contentDocument;
  var hold = d.getElementById("fm-hold").getBoundingClientRect();
  var onScreen = hold.height > 0 && hold.top >= 0 && hold.bottom <= H;
  return "settings: closed " + yes(folds(d)) + " | hold time on first screen " + yes(onScreen) +
    " | h1 " + d.querySelectorAll("main h1").length;
}

function opens(f, id) {
  var det = f.contentDocument.getElementById(id);
  return !!det && det.open;
}

function improvements(f) {
  var d = f.contentDocument;
  var table = d.querySelector("#improvements table");
  var rows = d.querySelectorAll("#improvements tbody tr");
  var whole = rows.length > 0;
  var tokens = d.querySelectorAll('#improvements td.nw');
  for (var i = 0; i < tokens.length; i++) if (!oneLine(d, tokens[i])) whole = false;
  var asn = d.querySelector('#improvements td[data-label="ASN"]');
  var cause = d.querySelector('#improvements td[data-label="Cause"]');
  return "improvements: " + rows.length + " rows | cards " + yes(table && table.classList.contains("stacked")) +
    " | tokens whole " + yes(whole && tokens.length > 0) +
    " | asn " + (asn ? asn.textContent : "none") + " | cause " + (cause ? cause.textContent : "none") +
    " | fits " + yes(fits(f));
}

// shown is true when a link is drawn. A link inside a closed details element
// is skipped by the browser, which checkVisibility reports.
function shown(a) { return a.checkVisibility() && a.getClientRects().length > 0; }

function providers(f) {
  var d = f.contentDocument, w = f.contentWindow;
  var table = d.querySelector("#providers table");
  var rows = d.querySelectorAll("#providers tbody tr");
  var numbers = rows.length > 0;
  for (var n = 0; n < rows.length; n++) {
    var cells = rows[n].querySelectorAll('td[data-label="Mbps"], td[data-label="Probes"]');
    if (cells.length !== 2) numbers = false;
    for (var c = 0; c < cells.length; c++) {
      var r = cells[c].getBoundingClientRect();
      if (r.width === 0 || r.right > w.innerWidth || cells[c].scrollWidth > cells[c].clientWidth + 1) numbers = false;
    }
  }
  var menus = d.querySelectorAll("#providers tbody details.linkout-menu");
  var links = d.querySelectorAll("#providers tbody a[target=_blank]");
  var hidden = links.length > 0;
  for (var i = 0; i < links.length; i++) if (shown(links[i])) hidden = false;
  var line = "providers: " + rows.length + " rows | cards " + yes(table && table.classList.contains("stacked")) +
    " | mbps and probes on screen " + yes(numbers) + " | menus " + menus.length +
    " | links hidden " + yes(hidden) + " | fits " + yes(fits(f));

  // Every menu opens over its row: all five links show, the row keeps its
  // height, and the list is not cut off by the container or the window.
  var most = 0, least = 99, same = true, inside = true;
  var providersBox = d.getElementById("providers");
  var overflow = w.getComputedStyle(providersBox).overflowY;
  for (var m = 0; m < menus.length; m++) {
    var row = menus[m].closest("tr");
    var before = row.getBoundingClientRect().height;
    menus[m].querySelector("summary").click();
    var list = menus[m].querySelector(".linkout-list");
    var count = Array.prototype.filter.call(list.querySelectorAll("a"), shown).length;
    most = Math.max(most, count);
    least = Math.min(least, count);
    var box = list.getBoundingClientRect();
    if (Math.abs(row.getBoundingClientRect().height - before) >= 1) same = false;
    if (box.right > w.innerWidth || box.bottom > d.documentElement.scrollHeight) inside = false;
    d.dispatchEvent(new w.KeyboardEvent("keydown", {key: "Escape", bubbles: true}));
    if (menus[m].open) inside = false;
  }
  line += "\nmenu: opens " + (most === least ? most : least + "-" + most) + " links | row height same " + yes(same) +
    " | inside " + yes(inside && overflow === "visible");

  // The page redraws every 5 seconds; an open menu must survive that.
  menus[0].querySelector("summary").click();
  var id = menus[0].closest("tr").id;
  w.refresh();
  return new Promise(function (resolve) { setTimeout(resolve, 1500); }).then(function () {
    var again = d.getElementById(id);
    var kept = !!again && !!again.querySelector("details.linkout-menu[open]");
    return line + " | open after refresh " + yes(kept);
  });
}

var settingsReady = function (d) { var h = d.getElementById("fm-hold"); return h && h.getBoundingClientRect().height > 0; };
var tableReady = function (sel) { return function (d) { return !!d.querySelector(sel); }; };
var providersReady = function (d) {
  var rows = d.querySelectorAll("#providers tbody tr").length;
  return rows > 0 && d.querySelectorAll("#providers tbody details.linkout-menu").length === rows;
};

Promise.all([
  load("/settings.html", settingsReady),
  load("/settings.html#wizard", settingsReady),
  load("/settings.html#commit-setup", settingsReady),
  load("/improvements.html", tableReady("#improvements table")),
  load("/providers.html", providersReady)
]).then(function (frames) {
  note("desk-settings", settings(frames[0]) + " | #wizard opens " + yes(opens(frames[1], "wizard")) +
    " | #commit-setup opens " + yes(opens(frames[2], "commit-setup")));
  note("desk-improvements", improvements(frames[3]));
  return providers(frames[4]).then(function (text) { note("desk-providers", text.replace("\n", " | ")); });
}).then(null, function (e) { note("desk-jserr", "load: " + e.message); });
