"use strict";
// Page driver for the UI smoke test (#182). Headless Chrome cannot click or
// press keys, so uiproxy adds this script to /dashboards.html. It reorders
// and resizes widgets with the keyboard, the list buttons and menus, and a
// drag, changes a time window and a refresh, saves, and writes what it sees
// into the page for lab/ui-smoke.sh to match. Nothing is stubbed: the
// answers are the real API's.

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function layout() {
  return Array.prototype.map.call(document.querySelectorAll("#db-grid article"), function (a) {
    return a.querySelector("h3").textContent + " " + a.className.replace("card widget ", "");
  }).join(" | ");
}

function card(title) {
  return Array.prototype.find.call(document.querySelectorAll("#db-grid article"), function (a) {
    return a.querySelector("h3").textContent === title;
  });
}

function key(node, k) {
  node.focus();
  node.dispatchEvent(new KeyboardEvent("keydown", {key: k, bubbles: true, cancelable: true}));
}

function listControl(label) {
  return Array.prototype.find.call(document.querySelectorAll("#db-widgets [aria-label]"), function (n) {
    return n.getAttribute("aria-label") === label;
  });
}

function choose(label, value) {
  var sel = listControl(label);
  sel.value = value;
  sel.dispatchEvent(new Event("change", {bubbles: true}));
}

function drag(from, to) {
  var data = new DataTransfer();
  card(from).querySelector(".grip-move").dispatchEvent(new DragEvent("dragstart", {bubbles: true, dataTransfer: data}));
  card(to).dispatchEvent(new DragEvent("drop", {bubbles: true, cancelable: true, dataTransfer: data}));
  card(from).querySelector(".grip-move").dispatchEvent(new DragEvent("dragend", {bubbles: true}));
}

var before = "";

var steps = [
  function () { note("fixture-open", "open: " + document.getElementById("db-name").value + " | favorite " + document.getElementById("db-favorite").checked + " | " + layout()); },
  // Keyboard: Readiness moves later, then its width and height grow.
  function () { key(card("Readiness").querySelector(".grip-move"), "ArrowRight"); },
  function () { note("fixture-key-move", "key move: " + layout() + " | focus " + document.activeElement.className); },
  function () { key(card("Readiness").querySelector(".grip-size"), "ArrowRight"); key(card("Readiness").querySelector(".grip-size"), "ArrowDown"); key(card("Readiness").querySelector(".grip-size"), "ArrowDown"); },
  function () { note("fixture-key-size", "key size: " + layout() + " | " + document.getElementById("db-live").textContent); },
  // The list: a button and menus.
  function () { var b = listControl("Move Improvements by cause earlier"); b.focus(); b.click(); },
  function () { note("fixture-list-move", "list move: " + layout() + " | focus " + document.activeElement.getAttribute("aria-label")); },
  function () { choose("Width of Improvements by cause", "12"); choose("Height of Improvements by cause", "2"); },
  function () { choose("Time window of Improvements by cause", "30"); choose("Refresh of Provider usage vs commit", "60"); },
  function () { note("fixture-list-size", "list size: " + layout() + " | causes window " + listControl("Time window of Improvements by cause").value + " | commit refresh " + listControl("Refresh of Provider usage vs commit").value); },
  // Drag the graphs widget to the front.
  function () { drag("Before/after graphs: 50% or more better", "Providers"); },
  function () { note("fixture-drag", "drag: " + layout()); before = JSON.stringify(current.widgets); },
  function () { document.getElementById("db-save").click(); },
  // Save reloads the dashboard from the server; the layout must be the same.
  function () {
    note("fixture-save", "save: " + document.getElementById("db-status").textContent + " | " + layout() + " | identical " + (JSON.stringify(current.widgets) === before));
  }
];

function next() {
  if (!steps.length) return;
  steps.shift()();
  setTimeout(next, 400);
}

window.addEventListener("load", function () { setTimeout(next, 1500); });
