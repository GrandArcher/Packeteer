"use strict";
// Page driver for the improvements explanation smoke test (#348). It loads
// /improvements.html in a 1440 px and a 390 px frame (headless Chrome will
// not open a window under 500 px) and checks, per frame, that the plain
// sentence and the Latency, Loss, Gain, Mbps, ASN, and AS name columns
// render, that nothing is clipped or scrolls sideways, and that the text is
// a readable size. Results are written into the page for lab/ui-smoke.sh.

// The injected page is also loaded inside the frames; only the top page measures.
if (window.top !== window) throw new Error("explain driver: frame");

var HEADS = ["Prefix", "Default route via", "Recommended", "Cause", "Latency", "Loss", "Gain", "Mbps", "ASN", "AS name", "Why"];
var SENTENCE = "lab-b is 40 ms faster (60 -> 20 ms, 67%), loss equal. Threshold 15 ms. Recommended since";
var HOLD = "Hold time: 2m 10s left before it can change.";
var MIN_FONT_PX = 13;

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("explain-jserr", "script error: " + e.message); });

function yes(v) { return v ? "yes" : "no"; }

function load(width) {
  return new Promise(function (resolve, reject) {
    var f = document.createElement("iframe");
    f.style.cssText = "position:absolute;left:-10000px;top:0;border:0;width:" + width + "px;height:900px";
    f.src = "/improvements.html";
    f.onload = function () {
      f.contentDocument.documentElement.style.scrollbarWidth = "none";
      var tries = 0;
      var poll = setInterval(function () {
        if (f.contentDocument.querySelector("#improvements table tbody tr") || ++tries > 60) {
          clearInterval(poll);
          resolve(f);
        }
      }, 100);
    };
    f.onerror = function () { reject(new Error("frame " + width)); };
    document.body.appendChild(f);
  });
}

// columns is true when every column is drawn: as a header on a wide screen,
// as the data-label of the first row's cells on a narrow one.
function columns(d) {
  var heads = Array.prototype.map.call(d.querySelectorAll("#improvements thead th"), function (th) { return th.textContent.trim(); });
  if (heads.join("|") !== HEADS.join("|")) return false;
  var cells = d.querySelectorAll("#improvements tbody tr:first-child td");
  var table = d.querySelector("#improvements table");
  if (!table.classList.contains("stacked")) return cells.length === HEADS.length;
  return Array.prototype.every.call(cells, function (td, i) { return td.getAttribute("data-label") === HEADS[i]; });
}

function fits(f) {
  var d = f.contentDocument, w = f.contentWindow;
  if (d.documentElement.scrollWidth > w.innerWidth) return false;
  var cells = d.querySelectorAll("main tbody td");
  for (var i = 0; i < cells.length; i++) {
    var r = cells[i].getBoundingClientRect();
    if (r.width > 0 && (r.right > w.innerWidth || cells[i].scrollWidth > cells[i].clientWidth + 1)) return false;
  }
  return true;
}

// readable is true when the sentence cell is a normal text size and wide
// enough that the sentence does not become a column of single words.
function readable(f, minWidth) {
  var w = f.contentWindow;
  var cell = f.contentDocument.querySelector("#improvements tbody td.why");
  var r = cell.getBoundingClientRect();
  return parseFloat(w.getComputedStyle(cell).fontSize) >= MIN_FONT_PX && r.width >= minWidth && r.height > 0;
}

function measure(width, minWidth, f) {
  var d = f.contentDocument;
  var rows = d.querySelectorAll("#improvements tbody tr");
  var why = rows.length ? rows[0].querySelector("td.why").textContent : "";
  var second = rows.length > 1 ? rows[1].textContent : "";
  return width + ": rows " + rows.length + " | sentence " + yes(why.indexOf(SENTENCE) === 0 && why.indexOf(HOLD) > 0) +
    " | flow " + yes(second.indexOf("no flow data") >= 0 && rows[0].textContent.indexOf("12.5") >= 0) +
    " | asn " + yes(rows.length && rows[0].textContent.indexOf("AS64496") >= 0 && rows[0].textContent.indexOf("Example Origin One") >= 0) +
    " | columns " + yes(columns(d)) + " | fits " + yes(fits(f)) + " | readable " + yes(readable(f, minWidth));
}

Promise.all([[1440, 250], [390, 200]].map(function (c) {
  return load(c[0]).then(function (f) { return measure(c[0], c[1], f); });
})).then(function (lines) {
  note("explain-result", lines.sort().join(" ; "));
}, function (e) { note("explain-jserr", "load: " + e.message); });
