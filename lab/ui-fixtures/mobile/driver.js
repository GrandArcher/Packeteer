"use strict";
// Page driver for the phone-width smoke test (#352). Headless Chrome will not
// open a window narrower than 500 px, so each nav page is loaded in a 390x844
// iframe and measured there: the iframe gets its own media queries. The
// checks per page are that the nav links are behind the Menu button, the
// first content (the h1, or the notice above it) starts within 150 px, and the page has no sideways
// scroll. On /providers.html the Health text of every provider must be fully
// visible, and the Menu button must open and close from the keyboard path
// (click, then Escape returning focus to the button). Results are written
// into the page for lab/ui-smoke.sh to match.

// The injected page is also loaded inside the frames; only the top page measures.
if (window.top !== window) throw new Error("mobile driver: frame");

var W = 390, H = 844, TOP_MAX = 150;
// A table to wait for before measuring, for the pages that draw one.
var TABLE = {
  "/providers.html": "#providers table",
  "/improvements.html": "#improvements table",
  "/events.html": "#events table",
  "/prefixes.html": "#prefixes table"
};

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("mobile-jserr", "script error: " + e.message); });

function yes(v) { return v ? "yes" : "no"; }

function load(href) {
  return new Promise(function (resolve, reject) {
    var f = document.createElement("iframe");
    f.style.cssText = "position:absolute;left:-10000px;top:0;border:0;width:" + W + "px;height:" + H + "px";
    f.src = href;
    f.onload = function () {
      var tries = 0;
      var poll = setInterval(function () {
        var d = f.contentDocument;
        var banner = d.getElementById("banner");
        var wait = TABLE[href];
        if ((banner && !banner.hidden && (!wait || d.querySelector(wait))) || ++tries > 60) {
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

function measure(href, f) {
  var d = f.contentDocument, w = f.contentWindow;
  var btn = d.getElementById("nav-toggle");
  var links = d.getElementById("nav-links");
  var collapsed = !!btn && btn.getAttribute("aria-expanded") === "false" && w.getComputedStyle(links).display === "none";
  // Settings shows its "editor is off" notice above main; that is the first content.
  var first = d.querySelector("#ed-off:not([hidden]), main h1");
  var top = first ? first.getBoundingClientRect().top : H;
  return href + " collapsed " + yes(collapsed) + " | top " + yes(top < TOP_MAX) + " | fits " + yes(fits(f));
}

// The button is operable: it has a name and a 44 px target, opens the list
// and the search box, and Escape closes it with focus back on the button.
function menu(f) {
  var d = f.contentDocument, w = f.contentWindow;
  var btn = d.getElementById("nav-toggle");
  var r = btn.getBoundingClientRect();
  var named = btn.textContent.trim() === "Menu" && btn.getAttribute("aria-controls") === "nav-links";
  var closedSearch = d.getElementById("top-search").offsetParent !== null;
  btn.focus();
  btn.click();
  var first = d.querySelector("#nav-links a").getBoundingClientRect();
  var open = btn.getAttribute("aria-expanded") === "true" && first.height > 0 && first.bottom <= H;
  var search = d.getElementById("top-search").getBoundingClientRect();
  var openSearch = search.height > 0 && search.bottom <= H;
  d.dispatchEvent(new w.KeyboardEvent("keydown", {key: "Escape", bubbles: true}));
  var closed = btn.getAttribute("aria-expanded") === "false" && d.activeElement === btn;
  return "menu: named " + yes(named) + " | target " + yes(r.width >= 44 && r.height >= 44) + " | opens " + yes(open) +
    " | search " + yes(!closedSearch && openSearch) + " | escape closes " + yes(closed);
}

// health lists each provider row's Health cell and whether all of its text
// is inside the viewport (a Range measures the text itself).
function health(f) {
  var d = f.contentDocument, w = f.contentWindow;
  var rows = d.querySelectorAll("#providers table tbody tr");
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var cell = rows[i].querySelector('td[data-label="Health"]');
    var name = rows[i].querySelector('td[data-label="Provider"]');
    if (!cell || !name) { out.push("no label"); continue; }
    var range = d.createRange();
    range.selectNodeContents(cell);
    var box = range.getBoundingClientRect();
    var seen = box.left >= 0 && box.right <= w.innerWidth && cell.scrollWidth <= cell.clientWidth + 1;
    out.push(name.textContent + "=" + cell.textContent + " " + (seen ? "whole" : "clipped"));
  }
  return "health: " + rows.length + " rows | " + out.join(" ; ");
}

var hrefs = Array.prototype.map.call(document.querySelectorAll(".sidenav a:not(.brand)"), function (a) { return a.getAttribute("href"); });
Promise.all(hrefs.map(function (href) {
  return load(href).then(function (f) {
    var line = measure(href, f);
    if (href === "/providers.html") {
      note("mobile-menu", menu(f));
      note("mobile-health", health(f));
    }
    return line;
  });
})).then(function (lines) {
  note("mobile-pages", "pages " + lines.length + ": " + lines.sort().join(" ; "));
}, function (e) { note("mobile-jserr", "load: " + e.message); });
