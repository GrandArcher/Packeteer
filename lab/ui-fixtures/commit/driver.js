"use strict";
// Page driver for the UI smoke test (#174). Headless Chrome cannot click, so
// uiproxy adds this script to /settings.html. It walks the Commit setup:
// picks the commit scorer, tries a community instead of a variable name,
// adds a new SNMP host, tracks a commit on a provider that has no binding,
// sets a group, renames a just-added provider after ticking its commit,
// applies, and writes what it sees into the page for
// lab/ui-smoke.sh to match. Nothing is stubbed: the answers are the real
// API's, and nothing is saved.

function note(id, text) {
  var p = document.createElement("p");
  p.id = id;
  p.textContent = text;
  document.querySelector("main").appendChild(p);
}

function byId(id) { return document.getElementById(id); }

// field finds a labelled input or select under root (an element or an id).
function field(root, label) {
  var spans = (typeof root === "string" ? byId(root) : root).querySelectorAll(".field-label");
  for (var i = 0; i < spans.length; i++) {
    if (spans[i].textContent === label) return spans[i].parentNode.querySelector("input, select");
  }
  throw new Error("no field " + label);
}

// providerRow is the Commit setup row of one provider.
function providerRow(name) {
  var rows = byId("cs-providers").querySelectorAll(".row");
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].querySelector(".field-label").textContent === "Track commit on " + name) return rows[i];
  }
  throw new Error("no row for " + name);
}

function set(node, value, type) {
  if (node.type === "checkbox") node.checked = value;
  else node.value = value;
  node.dispatchEvent(new Event(type || "input", {bubbles: true}));
  if (type !== "change" && node.tagName !== "INPUT") node.dispatchEvent(new Event("change", {bubbles: true}));
}

function texts(sel) {
  return Array.prototype.map.call(document.querySelectorAll(sel), function (n) { return n.textContent; }).join(" | ");
}

var steps = [
  function () {
    note("cs-start", "start: " + byId("form-providers").querySelectorAll(".row").length + " providers | scorer " + byId("cs-scorer").value);
  },
  function () {
    set(byId("cs-scorer"), "commit", "change");
    set(byId("cs-balance"), "equal", "change");
    note("cs-balance-shown", "balance shown: " + !byId("cs-balance-label").hidden + " | precedence shown: " + !byId("cs-precedence-label").hidden);
    byId("cs-next-1").click();
  },
  function () { byId("cs-add-host").click(); },
  function () {
    set(field("cs-hosts", "New SNMP host"), "edge2");
    set(field("cs-hosts", "Address"), "192.0.2.253");
    set(field("cs-hosts", "Community variable (name only)"), "s3cret-community");
    byId("cs-next-2").click();
  },
  function () {
    note("cs-refused", "refused: " + texts("#cs-errors li") + " | step 2 shown: " + !byId("cs-2").hidden);
    set(field("cs-hosts", "Community variable (name only)"), "PACKETEER_SNMP_COMMUNITY");
    set(providerRow("lab-d").querySelector("input[type=checkbox]"), true, "change");
  },
  function () {
    var row = providerRow("lab-d");
    set(field(row, "Commit (Mbps)"), "300");
    set(field(row, "SNMP host"), "edge2", "change");
    set(field(row, "Interface"), "ether2");
    set(field(row, "Billing day (1-28)"), "5");
  },
  function () {
    var lastRow = function () {
      var rows = byId("form-providers").querySelectorAll(".row");
      return rows[rows.length - 1];
    };
    var tick = function (name) { return providerRow(name).querySelector("input[type=checkbox]"); };
    // A named draft reaches the setup list when the page renders it again.
    // renderCommitSetup would also reset the scorer choice made above.
    var refresh = function () { csSync(); renderCsProviders(); };
    byId("form-add-provider").click();
    set(field(lastRow(), "Name"), "lab-x");
    refresh();
    set(tick("lab-x"), true, "change");
    set(field(lastRow(), "Name"), "lab-y");
    byId("cs-next-2").click();
    refresh();
    note("cs-renamed", "renamed: " + texts("#cs-errors li") + " | step 2 shown: " + !byId("cs-2").hidden + " | lab-y tracked: " + tick("lab-y").checked);
    set(tick("lab-y"), false, "change");
    lastRow().querySelector("button[title='Remove provider']").click();
    refresh();
    byId("cs-next-2").click();
  },
  function () {
    var rows = byId("cs-groups").querySelectorAll(".row");
    var ccD = false;
    Array.prototype.forEach.call(rows, function (row) {
      if (row.querySelector(".mono").textContent === "lab-d") ccD = row.querySelectorAll("input")[2].checked;
    });
    note("cs-case", "case: lab-c percentile " + field(providerRow("lab-c"), "Percentile").value + " | lab-d cc_disable " + ccD);
    Array.prototype.forEach.call(rows, function (row) {
      var name = row.querySelector(".mono").textContent;
      var inputs = row.querySelectorAll("input");
      if (name === "lab-a" || name === "lab-d") {
        inputs[0].value = "pair";
        inputs[0].dispatchEvent(new Event("input", {bubbles: true}));
      }
      if (name === "lab-d") {
        inputs[1].value = "200";
        inputs[1].dispatchEvent(new Event("input", {bubbles: true}));
      }
    });
    byId("cs-next-3").click();
  },
  function () {
    note("cs-review-text", "review: " + texts("#cs-review li"));
    byId("cs-apply").click();
  },
  function () {
    var y = byId("ed-yaml").value;
    var has = function (s) { return y.indexOf(s) >= 0; };
    note("cs-yaml", "yaml: commit scorer " + has("type: commit") + " | balance equal " + has("balance: equal") + " | host edge2 " + has("name: edge2") +
      " | env name " + has("community_env: PACKETEER_SNMP_COMMUNITY") + " | commit 300 " + has("commit_mbps: 300") + " | interface ether2 " + has("interface: ether2") +
      " | billing day 5 " + has("billing_day: 5") + " | precedence 200 " + has("precedence: 200") + " | group pair " + has("group: pair") +
      " | cc_disable kept " + /cc_disable: true/i.test(y) + " | mode observe " + has("mode: observe") + " | no community " + (!has("lab-only-community") && !has("s3cret")));
  },
  function () {
    note("cs-valid", "validated: " + byId("ed-status").textContent);
  }
];

function next() {
  if (!steps.length) return;
  steps.shift()();
  setTimeout(next, 500);
}

window.addEventListener("load", function () { setTimeout(next, 1500); });
