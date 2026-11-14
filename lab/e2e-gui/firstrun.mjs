// Browser walk of lab/e2e-firstrun.sh (#587). Lab only: documentation
// addresses and ASNs, a stock image on its unchanged example config.
//
//   node firstrun.mjs setup     sign in with the generated password, choose a
//                               new one, run the wizard, copy the FRR router
//                               config, save
//   node firstrun.mjs finish    sign in again after the restart, see the
//                               checklist incomplete, apply host policy routing
//                               from Settings, wait for "Setup complete"
//
// It only clicks and types in the pages. It never touches the YAML editor:
// every selector goes through put(), which refuses #ed-yaml, so a step that
// needs a YAML edit fails the walk instead of passing it.
//
// Environment: PK_URL, PK_USER, PK_FIRST_PASSWORD (setup), PK_NEW_PASSWORD,
// PK_OUT (directory for the results and failure screenshots), CHROME (browser
// binary, default google-chrome), PK_STORAGE_PATH, PK_COMPLETE_MS (how long finish waits for
// "Setup complete", default 600000). Passwords are never printed.
import { chromium } from "playwright-core";
import fs from "node:fs";
import path from "node:path";

const phase = process.argv[2];
const url = process.env.PK_URL || "http://127.0.0.1:18587";
const user = process.env.PK_USER || "admin";
const out = process.env.PK_OUT || ".";
// The stock image keeps its history under /var/lib/packeteer; a run outside a
// container may point the check at its own directory.
const storagePath = process.env.PK_STORAGE_PATH || "/var/lib/packeteer/packeteer.db";
const completeMs = Number(process.env.PK_COMPLETE_MS || 600000);

function need(name) {
  const v = process.env[name];
  if (!v) throw new Error("walk: " + name + " is not set");
  return v;
}

function log(msg) {
  console.log("walk: " + msg);
}

function put(sel) {
  if (sel.includes("ed-yaml")) throw new Error("walk: the YAML editor is off limits: " + sel);
  return sel;
}

const lab = {
  asn: "64512",
  routerID: "192.0.2.10",
  edge: "192.0.2.254",
  prefix: "198.51.100.0/24",
  host: "198.51.100.1",
  providers: [
    { name: "transit-a", source: "192.0.2.11", hop: "192.0.2.21" },
    { name: "transit-b", source: "192.0.2.12", hop: "192.0.2.22" },
  ],
};

async function signIn(page, password) {
  await page.goto(url + "/signin.html");
  await page.fill(put("#signin-name"), user);
  await page.fill(put("#signin-password"), password);
  await page.click("#signin-submit");
}

async function changePassword(page, first, next) {
  await page.waitForSelector("#change-form:not([hidden])");
  await page.fill(put("#change-current"), first);
  await page.fill(put("#change-new"), next);
  await page.fill(put("#change-again"), next);
  await page.click("#change-submit");
}

// openFold opens a collapsed panel the way an operator does: by clicking its
// heading. A panel that is already open is left alone.
async function openFold(page, sel) {
  if (!(await page.locator(sel).evaluate((d) => d.open))) await page.click(sel + " > summary");
}

async function wizard(page) {
  // A pending first run lands on Settings with the wizard open and the
  // example values filled in.
  await page.waitForURL("**/settings.html");
  await openFold(page, "#wizard");
  await page.waitForSelector("#wz-body:not([hidden])");
  await page.waitForFunction(() => document.getElementById("wz-asn").value !== "");

  await page.fill(put("#wz-asn"), lab.asn);
  await page.fill(put("#wz-router"), lab.routerID);
  await page.fill(put("#wz-edge"), lab.edge);
  await page.click("#wz-next");

  await page.waitForSelector("#wz-2:not([hidden])");
  const rows = page.locator("#wz-providers .row");
  await rows.first().waitFor();
  const n = await rows.count();
  if (n !== lab.providers.length) throw new Error("walk: the example has " + n + " provider rows, expected " + lab.providers.length);
  for (let i = 0; i < n; i++) {
    const inputs = rows.nth(i).locator("input");
    await inputs.nth(0).fill(lab.providers[i].name);
    await inputs.nth(1).fill(lab.providers[i].source);
    await inputs.nth(2).fill(lab.providers[i].hop);
  }
  await page.click("#wz-next-2");

  await page.waitForSelector("#wz-3:not([hidden])");
  await page.fill(put("#wz-prefix"), lab.prefix);
  await page.fill(put("#wz-host"), lab.host);
  if (!(await page.isChecked("#wz-storage"))) throw new Error("walk: report history is not ticked by default");
  await page.click("#wz-next-3");

  await page.waitForSelector("#wz-4:not([hidden])");
  await page.click("#wz-run");
  const problems = page.locator("#wz-errors li");
  await page.waitForFunction(() => {
    const confirm = document.getElementById("wz-confirm");
    const status = document.getElementById("wz-status").textContent;
    return (confirm && !confirm.hidden) || /^Generated/.test(status) || /Fix the form first/.test(status);
  });
  if ((await problems.count()) > 0) throw new Error("walk: the wizard refused the answers: " + (await problems.allTextContents()).join("; "));
  if (await page.isVisible("#wz-confirm")) await page.click("#wz-confirm-yes");
  await page.waitForFunction(() => /^Generated/.test(document.getElementById("wz-status").textContent));

  const yaml = await page.inputValue("#ed-yaml");
  for (const want of ["mode: observe", "type: sqlite", storagePath, "192.0.2.254", "192.0.2.21", "192.0.2.22", lab.prefix]) {
    if (!yaml.includes(want)) throw new Error("walk: the generated config lacks " + want);
  }
  const live = yaml.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  if (/^\s*mode:\s*inject|^\s*announcer:/m.test(live)) throw new Error("walk: the generated config turns inject on");
  log("wizard generated an observe config with sqlite history");
}

async function copyRouterConfig(page, file) {
  await openFold(page, "#router-snippet");
  await page.selectOption("#pf-vendor", "frr");
  await page.click("#pf-snippet-show");
  await page.waitForSelector("#pf-snippet:not([hidden])");
  const text = await page.textContent("#pf-snippet");
  for (const want of ["neighbor 192.0.2.10 remote-as 64512", "route-map packeteer-in", "neighbor 192.0.2.10 graceful-restart-disable", "route-map ebgp-out deny 10"]) {
    if (!text.includes(want)) throw new Error("walk: the router config lacks " + want);
  }
  fs.writeFileSync(file, text + "\n");
  log("router config copied for the edge");
}

async function save(page) {
  const saved = [];
  page.on("response", async (res) => {
    if (res.request().method() !== "PUT" || !res.url().endsWith("/api/config")) return;
    try {
      const body = await res.json();
      if (body.file && body.file.sha256) saved.push(body.file.sha256);
    } catch {
      // A refused save has no file; the status text below says why.
    }
  });
  await page.click("#bar-save");
  // A change to sources asks for a reviewed preview first (#576).
  await page.waitForFunction(() => {
    const review = document.getElementById("review");
    const status = document.getElementById("bar-msg").textContent;
    return (review && !review.hidden) || /^Saved /.test(status) || /Nothing was saved|refused|cannot|not valid/i.test(status);
  });
  if (await page.isVisible("#review")) await page.click("#rv-confirm");
  await page.waitForFunction(() => /^Saved /.test(document.getElementById("bar-msg").textContent));
  const status = await page.textContent("#bar-msg");
  if (!/restart required/.test(status)) throw new Error("walk: the save did not say a restart is needed: " + status);
  if (saved.length !== 1) throw new Error("walk: expected one saved file, got " + saved.length);
  log("config saved from the wizard; restart required");
  return saved[0];
}

async function setup() {
  const first = need("PK_FIRST_PASSWORD");
  const next = need("PK_NEW_PASSWORD");
  const { page, close } = await open();
  try {
    await signIn(page, first);
    await changePassword(page, first, next);
    log("first-run password changed");
    await wizard(page);
    await copyRouterConfig(page, path.join(out, "router-frr.txt"));
    const sha = await save(page);
    fs.writeFileSync(path.join(out, "saved.json"), JSON.stringify({ sha256: sha }) + "\n");
  } catch (err) {
    await fail(page, "setup", err);
  } finally {
    await close();
  }
}

async function overviewSetup(page) {
  await page.goto(url + "/");
  await page.waitForSelector("#setup [data-setup]");
  return {
    state: await page.getAttribute("#setup [data-setup]", "data-setup"),
    text: (await page.textContent("#setup [data-setup]")).trim(),
  };
}

async function policyRouting(page) {
  await page.goto(url + "/settings.html");
  await openFold(page, "#pbr");
  await page.click("#pbr-show");
  await page.waitForFunction(() => /^Nothing was changed\./.test(document.getElementById("pbr-status").textContent));
  const lines = await page.textContent("#pbr-lines");
  for (const p of lab.providers) {
    if (!lines.includes("ip rule add from " + p.source)) throw new Error("walk: the plan has no rule for " + p.name + ":\n" + lines);
    if (!lines.includes("via " + p.hop)) throw new Error("walk: the plan has no route via " + p.hop + ":\n" + lines);
  }
  if ((await page.locator("#pbr-paths li.pf-fail").count()) !== lab.providers.length) throw new Error("walk: the host already sends every source through its next hop");
  if (!(await page.isDisabled("#pbr-apply"))) throw new Error("walk: Apply is enabled before the confirmation");
  // A second look changes nothing: the plan and its token stay the same.
  await page.click("#pbr-show");
  await page.waitForFunction(() => /^Nothing was changed\./.test(document.getElementById("pbr-status").textContent));
  if ((await page.textContent("#pbr-lines")) !== lines) throw new Error("walk: showing the plan twice gave different plans");
  log("policy routing plan shown, nothing applied");

  await page.check("#pbr-confirm");
  await page.click("#pbr-apply");
  await page.waitForFunction(() => !/^(Nothing was changed|Applying)/.test(document.getElementById("pbr-status").textContent), null, { timeout: 60000 });
  const status = await page.textContent("#pbr-status");
  if (!/Every provider's probes leave through its next hop/.test(status)) throw new Error("walk: policy routing did not verify: " + status);
  if ((await page.locator("#pbr-paths li.pf-pass").count()) !== lab.providers.length) throw new Error("walk: not every provider passes after the apply");
  log("policy routing applied and verified: " + status);
}

async function finish() {
  const next = need("PK_NEW_PASSWORD");
  const { page, close } = await open();
  try {
    await signIn(page, next);
    await page.waitForURL(url + "/");
    const before = await overviewSetup(page);
    if (before.state !== "incomplete") throw new Error("walk: the checklist says setup is complete before policy routing: " + before.text);
    log("checklist: " + before.text);
    await policyRouting(page);

    const deadline = Date.now() + completeMs;
    for (;;) {
      const now = await overviewSetup(page);
      if (now.state === "complete") {
        if (!/^Setup complete, still observe\./.test(now.text)) throw new Error("walk: complete, but not still observe: " + now.text);
        log("checklist: " + now.text);
        break;
      }
      if (Date.now() > deadline) throw new Error("walk: the checklist did not reach Setup complete in " + completeMs / 1000 + "s: " + now.text);
      await page.waitForTimeout(10000);
    }
  } catch (err) {
    await fail(page, "finish", err);
  } finally {
    await close();
  }
}

async function open() {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME || "/usr/bin/google-chrome",
    args: ["--no-sandbox"],
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(30000);
  return { page, close: () => browser.close() };
}

async function fail(page, name, err) {
  console.error(err && err.stack ? err.stack : String(err));
  try {
    await page.screenshot({ path: path.join(out, "fail-" + name + ".png"), fullPage: true });
    fs.writeFileSync(path.join(out, "fail-" + name + ".html"), await page.content());
  } catch {
    // The browser may be gone; the error above stands.
  }
  process.exitCode = 1;
}

if (phase === "setup") await setup();
else if (phase === "finish") await finish();
else {
  console.error("usage: node firstrun.mjs setup|finish");
  process.exit(2);
}
