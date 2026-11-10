"use strict";
// Page driver for the UI smoke test (#401). Headless Chrome cannot click,
// so uiproxy adds this script to /registry.html. It presses Propose
// exception on the fixture case once the section has rendered, and writes
// a marker once the review box with the exact entries is shown, for
// lab/ui-smoke.sh to match. It never presses Approve and write.

var tries = 0;
var timer = setInterval(function () {
  tries++;
  var propose = Array.prototype.filter.call(document.querySelectorAll("#only-invalid-cases button"), function (b) {
    return b.textContent === "Propose exception";
  })[0];
  var approve = Array.prototype.filter.call(document.querySelectorAll("#only-invalid-cases button"), function (b) {
    return b.textContent === "Approve and write";
  })[0];
  if (approve) {
    clearInterval(timer);
    var p = document.createElement("p");
    p.id = "fixture-proposed";
    p.textContent = "driver: review box shown, nothing approved";
    document.querySelector("main").appendChild(p);
  } else if (propose && !propose.disabled) {
    propose.click();
  }
  if (tries > 100) clearInterval(timer);
}, 100);
