"use strict";
// Page driver for the per-provider figures smoke test (#349). Headless Chrome
// will not open a window narrower than 500 px, so Overview and Providers are
// loaded in a 390x844 iframe and measured there, against the real API and the
// history lab/mkhistory seeded. On Overview the two charts must be drawn with
// data, inside the viewport, with no sideways scroll. On Providers every
// provider card must show Latency, Loss, Jitter, Trend, and Mbps whole, with
// the sparkline drawn. Results are written into the page for lab/ui-smoke.sh
// to match.

// The injected page is also loaded inside the frames; only the top page measures.
if (window.top !== window) throw new Error("provider stats driver: frame");

var W = 390, H = 844;

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("stats-jserr", "script error: " + e.message); });

function yes(v) { return v ? "yes" : "no"; }

// load opens href in a phone-width frame and resolves once ready() says the
// page has drawn what it needs.
function load(href, ready) {
  return new Promise(function (resolve, reject) {
    var f = document.createElement("iframe");
    f.style.cssText = "position:absolute;left:-10000px;top:0;border:0;width:" + W + "px;height:" + H + "px";
    f.src = href;
    f.onload = function () {
      f.contentDocument.documentElement.style.scrollbarWidth = "none";
      var tries = 0;
      var poll = setInterval(function () {
        if (ready(f.contentDocument) || ++tries > 80) {
          clearInterval(poll);
          resolve(f);
        }
      }, 100);
    };
    f.onerror = function () { reject(new Error(href)); };
    document.body.appendChild(f);
  });
}

// inside is true when the element is drawn and lies within the frame's width.
function inside(f, node) {
  if (!node) return false;
  var r = node.getBoundingClientRect();
  return r.width > 100 && r.left >= 0 && r.right <= f.contentWindow.innerWidth;
}

function noSideways(f) { return f.contentDocument.documentElement.scrollWidth <= f.contentWindow.innerWidth; }

// pointsDrawn counts the data points of a chart: one circle per point.
function pointsDrawn(svg) { return svg ? svg.querySelectorAll("circle").length : 0; }

function overview() {
  return load("/", function (d) {
    return d.querySelector("#chart-latency svg") && d.querySelector("#chart-improvements svg");
  }).then(function (f) {
    var d = f.contentDocument;
    var lat = d.querySelector("#chart-latency svg"), imp = d.querySelector("#chart-improvements svg");
    var legend = Array.prototype.map.call(d.querySelectorAll("#chart-latency .ts-key"), function (n) { return n.textContent; }).join(" ; ");
    var impLegend = Array.prototype.map.call(d.querySelectorAll("#chart-improvements .ts-key"), function (n) { return n.textContent; }).join(" ; ");
    var first = d.querySelector("#tiles .tile .k");
    note("stats-overview", "overview: latency chart " + yes(inside(f, lat)) + " | latency points " + (pointsDrawn(lat) > 20 ? "many" : "few") +
      " | improvements chart " + yes(inside(f, imp)) + " | improvement points " + (pointsDrawn(imp) > 20 ? "many" : "few") +
      " | no sideways scroll " + yes(noSideways(f)) + " | first tile " + (first ? first.textContent : "none") +
      " | mode tile " + yes(Array.prototype.some.call(d.querySelectorAll("#tiles .tile .k"), function (n) { return n.textContent === "Mode"; })));
    note("stats-overview-legend", "latency legend: " + legend + " | improvements legend: " + impLegend);
  });
}

function providers() {
  return load("/providers.html", function (d) {
    return d.querySelector("#providers table tbody tr svg.spark");
  }).then(function (f) {
    var d = f.contentDocument, w = f.contentWindow;
    var rows = d.querySelectorAll("#providers table tbody tr");
    var out = [];
    Array.prototype.forEach.call(rows, function (row) {
      var name = row.querySelector('td[data-label="Provider"]');
      var cells = ["Latency", "Loss", "Jitter", "Trend, 24 h", "Mbps"].map(function (label) {
        var cell = row.querySelector('td[data-label="' + label + '"]');
        if (!cell) return label + " missing";
        var range = d.createRange();
        range.selectNodeContents(cell);
        var box = range.getBoundingClientRect();
        var whole = box.right <= w.innerWidth && cell.scrollWidth <= cell.clientWidth + 1;
        return label + " " + (whole ? "whole" : "clipped");
      });
      out.push((name ? name.textContent : "?") + ": " + cells.join(", ") + ", spark " + yes(row.querySelector("svg.spark")) +
        ", text " + Array.prototype.map.call(row.querySelectorAll("td.stat"), function (c) { return c.textContent; }).join("/"));
    });
    note("stats-providers", "providers " + rows.length + " | no sideways scroll " + yes(noSideways(f)) + " | " + out.join(" ; "));
  });
}

overview().then(providers).then(function () { note("stats-done", "done"); }, function (e) { note("stats-jserr", "load: " + e.message); });
