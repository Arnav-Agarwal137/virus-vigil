// Licences and credits / Privacy / Terms (29 Sep 2026, LEGAL-CHECK.md; his words "put some legal
// notices ... we credit these people"). usage: node legal.mjs <cdp port>   (exit 1 on any fault)
// Setup: tests/page/run.sh legal.mjs. Each footer link must open the dialog on the RIGHT page (read
// from the frame's own heading, not from the button), and Close must shut it. Screenshots of each,
// at laptop and phone width, go to $VV_SHOTS when set (for a person to look at).
import fs from "node:fs";
const port = process.argv[2];
const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = list.find((t) => t.type === "page" && t.url.includes("8767"));
const ws = new WebSocket(page.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pend = new Map(); ws.onmessage = (m) => { const d = JSON.parse(m.data); if (pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const send = (method, params) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = (expression) => send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })
  .then((d) => d.result.exceptionDetails ? "ERR " + (d.result.exceptionDetails.exception?.description || d.result.exceptionDetails.text) : d.result.result.value);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
await send("Page.enable", {});
await send("Page.addScriptToEvaluateOnNewDocument", { source: `window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));` });
const fails = [];
const want = (name, ok, got) => { console.log((ok ? "ok   " : "FAIL ") + name + (ok ? "" : "  got: " + JSON.stringify(got).slice(0, 300))); if (!ok) fails.push(name); };
const shots = process.env.VV_SHOTS;

const PAGES = [
  { file: "credits.html", button: "Licences and credits", heading: "Licences and credits", must: [/ReversingLabs/, /bartblaze/, /Echap/, /YARA-X/, /Atkinson Hyperlegible/, /\d{3} Rust libraries/, /CyberStrike/, /CERT Polska/, /PolyForm Noncommercial License 1\.0\.0/, /Arnav Agarwal/], mustNot: [] },
  { file: "privacy.html", button: "Privacy", heading: "Privacy", must: [/fingerprint/i, /CIRCL/, /CERT Polska/, /never uploads a file/, /Ask to uninstall apps/, /github\.com\/Arnav-Agarwal137/], mustNot: [/page where you got/] },
  { file: "terms.html", button: "Terms", heading: "Terms of use", must: [/No security tool catches everything/, /"as is"/, /Consumer Protection Act, 2019/, /PolyForm Noncommercial/, /written permission/, /Uninstall box/], mustNot: [/resell/i, /amount you paid/, /take apart/] },
];

for (const [w, h, label] of [[1180, 780, "laptop"], [390, 844, "phone"]]) {
  await send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: label === "phone" });
  await send("Page.reload", { ignoreCache: true }); await sleep(2500);
  for (const p of PAGES) {
    const clicked = await ev(`(() => { const b = [...document.querySelectorAll("[data-legal]")].find((x) => x.textContent.trim() === ${JSON.stringify(p.button)}); if (!b) return "no button"; b.scrollIntoView(); b.click(); return b.dataset.legal; })()`);
    want(`${label}: "${p.button}" button exists and names ${p.file}`, clicked === p.file, clicked);
    await sleep(900);
    const got = await ev(`(() => { const d = document.querySelector("#legal"); const f = d?.querySelector("iframe"); const doc = f?.contentDocument;
      return { open: !!d?.open, h1: doc?.querySelector("h1")?.textContent || null, text: doc?.body?.innerText || "", w: f?.getBoundingClientRect().width || 0, scrollW: doc?.documentElement.scrollWidth || 0, fw: doc?.documentElement.clientWidth || 0 }; })()`);
    want(`${label}: ${p.file} opens in the dialog`, got.open === true, got.open);
    want(`${label}: the frame shows "${p.heading}" (read from the frame)`, got.h1 === p.heading, got.h1);
    for (const re of p.must) want(`${label}: ${p.file} says ${re}`, re.test(got.text), got.text.slice(0, 120));
    for (const re of p.mustNot) want(`${label}: ${p.file} no longer says ${re}`, !re.test(got.text), (got.text.match(re) || [""])[0]);
    want(`${label}: ${p.file} has no sideways scroll`, got.scrollW <= got.fw + 1, [got.scrollW, got.fw]);
    if (shots) { const s = await send("Page.captureScreenshot", { format: "png" }); fs.writeFileSync(`${shots}/legal-${label}-${p.file.replace(".html", "")}.png`, Buffer.from(s.result.data, "base64")); }
    await ev(`document.querySelector("#legal .legal-close").click()`);
    await sleep(300);
    want(`${label}: Close shuts ${p.file}`, (await ev(`document.querySelector("#legal").open`)) === false, "still open");
  }
}
// The full texts the credits page links to must be there and name what it credits.
const lic = await ev(`fetch("licenses.txt").then((r) => r.ok ? r.text() : "HTTP " + r.status)`);
want("licenses.txt is served and holds the MIT and OFL texts", /Permission is hereby granted/.test(lic) && /SIL OPEN FONT LICENSE/.test(lic), lic.slice(0, 80));
const pf = await ev(`fetch("polyform-noncommercial-1.0.0.txt").then((r) => r.ok ? r.text() : "HTTP " + r.status)`);
want("the PolyForm licence the credits page links to is served", /# PolyForm Noncommercial License 1\.0\.0/.test(pf) && /No Liability/.test(pf), pf.slice(0, 80));
const errs = await ev("window.__errs");
want("no page errors", Array.isArray(errs) && errs.length === 0, errs);
console.log(fails.length ? `${fails.length} FAILED` : "all passed");
ws.close(); process.exit(fails.length ? 1 : 0);
