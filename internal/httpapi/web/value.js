"use strict";
// Value page (#588): the value report (#583) in plain language, with the
// estimated savings of the summary report beside it. Loaded after app.js (el,
// clear, getJSON) and charts.js (tsChart, tsDay, plural). Read-only; it
// recomputes nothing, it only words and places what the reports return.

// A basis is how a move was made. Only inject announces; the rest is advice,
// so the wording never says traffic moved for an estimate.
var VALUE_BASES = ["announced", "estimate"];
var VALUE_TITLES = {announced: "Announced", estimate: "Recommended (estimate)"};

function valueRows(rows, scope, basis) {
  return rows.filter(function (r) { return r.scope === scope && r.basis === basis; });
}

function valueNum(v) {
  return String(Math.round(v * 1000) / 1000);
}

// valueChange words a signed avoided figure. Positive is better, a move onto a
// path that measured worse is negative, and a row with no measurement says so
// instead of showing 0.
function valueChange(v, unit) {
  if (v == null) return "not measured";
  if (v === 0) return "no change";
  return valueNum(Math.abs(v)) + " " + unit + (v > 0 ? " lower" : " higher");
}

// valueBeforeAfter keeps the report's three decimals; fmtNum would round 0.75
// to 0.8 and the page would no longer match the report.
function valueBeforeAfter(before, after, unit) {
  if (before == null || after == null) return "\u2014";
  return valueNum(before) + " \u2192 " + valueNum(after) + " " + unit;
}

// valueLead is the one-sentence answer for a basis. The announced sentence
// says what went on the wire; the estimate sentence says nothing did.
function valueLead(basis, t) {
  var moves = plural(t.improvements, "move", "moves");
  var gain = " None of them has a measurement of both paths, so no gain is shown.";
  if (t.measured) {
    gain = " Measured when each move started, the chosen path had loss " + valueChange(t.loss_avoided_pct, "points") +
      (t.rtt_avoided_ms == null ? "" : " and latency " + valueChange(t.rtt_avoided_ms, "ms")) + " than the native path (" +
      (t.weighting === "flow" ? "weighted by traffic volume" : "equal weight per move") + ")." +
      (t.rtt_avoided_ms == null ? " Latency is not compared because a path gave no reply." : "");
  }
  if (basis === "announced") return "Packeteer announced " + moves + " in this range." + gain;
  return "Packeteer recommended " + moves + " and announced none of them. Traffic did not change path; this is an estimate of what the moves would have avoided." + gain;
}

function valueTile(label, text, note) {
  var d = el("div", "tile");
  d.appendChild(el("div", "k", label));
  d.appendChild(el("div", "tile-v", text));
  if (note) d.appendChild(el("div", "tile-note tag", note));
  return d;
}

function valueTotals(basis, t) {
  var wrap = el("div", "tiles");
  var steered = basis === "announced" ? "Steered" : "Recommended for";
  wrap.appendChild(valueTile("Moves", String(t.improvements), t.measured + " with both paths measured"));
  wrap.appendChild(valueTile("Loss", t.measured ? valueChange(t.loss_avoided_pct, "points") : "not measured", valueBeforeAfter(t.before_loss_pct, t.after_loss_pct, "%")));
  wrap.appendChild(valueTile("Latency", t.rtt_avoided_ms == null && t.measured ? "not compared" : valueChange(t.rtt_avoided_ms, "ms"), valueBeforeAfter(t.before_rtt_ms, t.after_rtt_ms, "ms")));
  wrap.appendChild(valueTile(steered, valueNum(t.steered_hours) + " h", basis === "announced" ? "routes on the wire" : "advice only"));
  return wrap;
}

// valueProviders is the per-provider table for one basis. down maps a
// provider that is down now to its detail: its row stays, since the moves
// happened, but is marked so it does not read as helping now.
function valueProviders(basis, rows, down) {
  var table = el("table");
  var hr = el("tr");
  ["Provider", "Moves", "Measured", "Loss", "Loss avoided", "Latency", "Latency avoided", basis === "announced" ? "Steered (h)" : "Recommended (h)"].forEach(function (h) {
    hr.appendChild(el("th", "", h));
  });
  var thead = el("thead");
  thead.appendChild(hr);
  table.appendChild(thead);
  var tb = el("tbody");
  rows.forEach(function (r) {
    var isDown = Object.prototype.hasOwnProperty.call(down, r.provider);
    var tr = el("tr", isDown ? "value-provider-down" : "");
    var name = el("td", "", r.provider);
    if (isDown) name.appendChild(el("span", "dot down", "down now"));
    tr.appendChild(name);
    var later = isDown ? " (earlier moves)" : "";
    [String(r.improvements), String(r.measured), valueBeforeAfter(r.before_loss_pct, r.after_loss_pct, "%"),
      valueChange(r.loss_avoided_pct, "points") + (r.measured ? later : ""), valueBeforeAfter(r.before_rtt_ms, r.after_rtt_ms, "ms"),
      valueChange(r.rtt_avoided_ms, "ms") + (r.rtt_avoided_ms == null ? "" : later), valueNum(r.steered_hours)].forEach(function (v) {
      tr.appendChild(el("td", "", v));
    });
    tb.appendChild(tr);
  });
  table.appendChild(tb);
  return table;
}

// valueDays draws the per-day before and after lines from the day rows that
// have both figures. A day with no measurement is left out so it is a gap in
// the line, not a zero.
function valueDays(basis, rows, data) {
  var loss = rows.filter(function (r) { return r.before_loss_pct != null && r.after_loss_pct != null; });
  var rtt = rows.filter(function (r) { return r.before_rtt_ms != null && r.after_rtt_ms != null; });
  var wrap = el("div");
  if (!loss.length) {
    wrap.appendChild(el("p", "empty", "No day in this range has both paths measured, so there is nothing to chart."));
    return wrap;
  }
  var all = rows.map(function (r) { return tsDay(r.day); }).filter(function (d) { return d != null; });
  var first = Math.min.apply(null, all), last = Math.max.apply(null, all);
  var from = tsDay(String(data.from || "").slice(0, 10)), to = tsDay(String(data.to || "").slice(0, 10));
  if (from != null && from < first) first = from;
  if (to != null && to > last) last = to;
  var charts = el("div", "ts-charts");
  charts.appendChild(tsChart("Loss", "%", loss, "before_loss_pct", "after_loss_pct", first, last));
  if (rtt.length) charts.appendChild(tsChart("Latency", "ms", rtt, "before_rtt_ms", "after_rtt_ms", first, last));
  wrap.appendChild(charts);
  var legend = el("p", "ts-legend tag");
  legend.appendChild(el("span", "ts-key ts-before", "Dashed: the native path"));
  legend.appendChild(document.createTextNode(" "));
  legend.appendChild(el("span", "ts-key ts-after", basis === "announced" ? "Solid: the chosen path" : "Solid: the recommended path"));
  wrap.appendChild(legend);
  return wrap;
}

// valueSavings words the summary report's estimated savings. Shown only when
// there is a figure; it adds no arithmetic of its own. Nothing accrues unless
// a route was announced, so without announced moves the figure is what the
// recommendations would have saved.
function valueSavings(s, announced) {
  if (!s || (!s.est_savings_accrued && !s.est_savings_rate)) return null;
  var p = el("p", "tag value-savings");
  var accrued = s.est_savings_accrued;
  p.textContent = "Estimated cost: " + (accrued < 0 ? "extra spend of " + valueNum(-accrued) : "savings of " + valueNum(accrued)) +
    (announced ? " accrued in this range" : " in this range if the recommendations were followed") + ", and " + valueNum(s.est_savings_rate) + " per month from the improvements active now. " +
    "These are estimates from your provider prices and prefix volumes, not billing. The Savings report has the detail.";
  return p;
}

// renderValue fills root from the value report rows. ctx.down is the map of
// providers that are down now and ctx.savings the summary row, both optional.
function renderValue(root, data, ctx) {
  clear(root);
  var rows = (data && data.rows) || [];
  if (!rows.length) {
    root.appendChild(el("p", "empty", "No improvements started in this range, so there is nothing to show. Observe and suggest mode record recommendations here once Packeteer finds a better path."));
    return;
  }
  var down = (ctx && ctx.down) || {};
  VALUE_BASES.forEach(function (basis) {
    var totals = valueRows(rows, "total", basis);
    if (!totals.length) return;
    var sec = el("section", "value-basis value-" + basis);
    sec.appendChild(el("h2", "", VALUE_TITLES[basis]));
    sec.appendChild(el("p", "", valueLead(basis, totals[0])));
    sec.appendChild(valueTotals(basis, totals[0]));
    sec.appendChild(el("h3", "", "By provider"));
    sec.appendChild(valueProviders(basis, valueRows(rows, "provider", basis), down));
    sec.appendChild(el("h3", "", "By day (UTC)"));
    sec.appendChild(valueDays(basis, valueRows(rows, "day", basis), data));
    root.appendChild(sec);
  });
  var cost = valueSavings(ctx && ctx.savings, valueRows(rows, "total", "announced").length > 0);
  if (cost) root.appendChild(cost);
}

// valueDownText names the providers that are down now, or returns "" when
// none is.
function valueDownText(down) {
  var names = Object.keys(down);
  if (!names.length) return "";
  return "Down now: " + names.map(function (n) { return down[n] ? n + " (" + down[n] + ")" : n; }).join(", ") +
    ". The figures for " + (names.length === 1 ? "it" : "them") + " come from earlier moves; " +
    (names.length === 1 ? "it is" : "they are") + " not helping now.";
}

function valueDownMap(overview) {
  var down = {};
  ((overview && overview.providers) || []).forEach(function (p) {
    if (p.state === "down") down[p.name] = p.detail || "";
  });
  return down;
}

function valueURL(format) {
  var url = "/api/reports/value?days=" + encodeURIComponent(document.getElementById("value-days").value || "7");
  return format ? url + "&format=" + format : url;
}

function valueMessage(text) {
  var root = document.getElementById("value");
  clear(root);
  root.appendChild(el("p", "empty", text));
}

function loadValue() {
  var days = document.getElementById("value-days").value || "7";
  document.getElementById("value-csv").setAttribute("href", valueURL("csv"));
  Promise.allSettled([getJSON(valueURL("")), getJSON("/api/overview"), getJSON("/api/reports/summary?days=" + encodeURIComponent(days))]).then(function (res) {
    if (res[0].status !== "fulfilled") {
      valueMessage(res[0].reason.message);
      return;
    }
    var down = valueDownMap(res[1].status === "fulfilled" ? res[1].value : null);
    var banner = document.getElementById("value-down");
    banner.textContent = valueDownText(down);
    banner.hidden = !banner.textContent;
    var summary = res[2].status === "fulfilled" && res[2].value && res[2].value.rows && res[2].value.rows[0];
    renderValue(document.getElementById("value"), res[0].value, {down: down, savings: summary});
  });
}

function initValue() {
  if (!document.getElementById("value-days")) return;
  document.getElementById("value-days").addEventListener("change", loadValue);
  document.getElementById("value-load").addEventListener("click", loadValue);
  getJSON("/api/reports").then(function (data) {
    if (!data || !data.enabled) {
      valueMessage("History is off, so there is nothing to show and no figure is estimated. Add storage: {type: sqlite} to the config and mount /var/lib/packeteer.");
      return;
    }
    loadValue();
  }, function (err) {
    valueMessage(err.message);
  });
}

initValue();
