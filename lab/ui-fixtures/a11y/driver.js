"use strict";
// Page driver for the keyboard and screen reader smoke test (#353). Headless
// Chrome cannot press keys, so uiproxy adds this script to /settings.html.
// The first Tab lands on the first focusable element in document order, so
// the driver takes that element and focuses it. On this live page it checks
// the skip link is first, visible on focus, and moves focus to main when
// activated, that the focus ring is 2 px or more with 3:1 contrast against the
// nav and the content, and that the YAML editor has a label. Every nav page is
// fetched and parsed for the same first-focusable, main, and one h1 rules.
// Results are written into the page for lab/ui-smoke.sh to match.

var FOCUSABLE = 'a[href], button:not([disabled]), input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

window.addEventListener("error", function (e) { note("a11y-jserr", "script error: " + e.message); });

function yes(v) { return v ? "yes" : "no"; }

function channels(css) {
  var m = css.match(/\d+(\.\d+)?/g).map(Number);
  return m.slice(0, 3);
}

function luminance(css) {
  var c = channels(css).map(function (v) {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

function contrast(a, b) {
  var la = luminance(a), lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

// ring focuses el and reports the outline width and its contrast with bg.
function ring(el, bg) {
  el.focus();
  var cs = getComputedStyle(el);
  return {width: parseFloat(cs.outlineWidth), style: cs.outlineStyle, ratio: contrast(cs.outlineColor, bg)};
}

function ringOK(r) { return r.style !== "none" && r.width >= 2 && r.ratio >= 3; }

function structure(doc) {
  var first = doc.querySelector(FOCUSABLE);
  var main = doc.getElementById("main");
  return yes(first && first.classList.contains("skip-link") && first.getAttribute("href") === "#main") +
    " skip first | " + yes(main && main.tagName === "MAIN" && main.getAttribute("tabindex") === "-1") +
    " main | h1 " + doc.querySelectorAll("h1").length;
}

function live() {
  var skip = document.querySelector(FOCUSABLE);
  skip.focus();
  var r = skip.getBoundingClientRect();
  var inView = r.width > 0 && r.height > 0 && r.top >= 0 && r.left >= 0 && r.bottom <= window.innerHeight && r.right <= window.innerWidth;
  note("a11y-skip", "skip link: " + yes(document.activeElement === skip) + " focused | " + yes(inView) + " visible | " + skip.textContent);
  var nav = ring(document.querySelector(".sidenav a"), getComputedStyle(document.querySelector(".sidenav")).backgroundColor);
  var shown = Array.prototype.filter.call(document.querySelectorAll("main button"), function (b) { return b.offsetParent !== null; });
  var content = ring(shown[0], getComputedStyle(document.body).backgroundColor);
  note("a11y-ring", "focus ring: nav " + yes(ringOK(nav)) + " | content " + yes(ringOK(content)) + " | " + nav.width + "px");
  var ed = document.getElementById("ed-yaml");
  note("a11y-label", "yaml label: " + (ed.labels.length === 1 ? ed.labels[0].textContent : "none"));
  skip.focus();
  skip.click();
  setTimeout(function () {
    var a = document.activeElement;
    note("a11y-activate", "after skip: focus in main " + yes(a && a.closest("main")) + " | " + (a && a.id));
  }, 100);
}

function pages() {
  var links = document.querySelectorAll(".sidenav a:not(.brand)");
  var out = [];
  for (var i = 0; i < links.length; i++) out.push(links[i].getAttribute("href"));
  out.push("/signin.html");
  return Promise.all(out.map(function (href) {
    return fetch(href, {credentials: "same-origin"}).then(function (res) { return res.text(); }).then(function (html) {
      return href + " " + structure(new DOMParser().parseFromString(html, "text/html"));
    });
  }));
}

live();
pages().then(function (rows) {
  note("a11y-pages", "pages " + rows.length + ": " + rows.join(" ; "));
}, function (e) { note("a11y-jserr", "fetch: " + e.message); });
