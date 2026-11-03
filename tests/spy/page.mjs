// Drives the page (served with mock.js, phone UA) through the spy-app row checks.
// Setup: copy app/src to a folder, copy page-mock.js in as mock.js, add <script src="mock.js"></script> before main.js in its index.html,
// serve it on :8765 (python -m http.server), start headless Chrome with an Android --user-agent, --remote-debugging-port and its own --user-data-dir.
// Passed 24 Sep 2026: row names both (package + certificate), payment = danger, hacked = severe slip + Open buttons, trust re-flags only a NEW spy app, 0 page errors, dark + light at 390 px.
// usage: node spy.mjs <cdp port> <dark|light> <shot.png>
import fs from "node:fs";
const [port, scheme, shot] = process.argv.slice(2);
const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = list.find((t) => t.type === "page" && t.url.includes("8765"));
if (!page) { console.log("no page", list.map((t) => t.url)); process.exit(1); }
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pend = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const send = (method, params) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = (expression) => send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })
  .then((d) => d.result.exceptionDetails ? { err: d.result.exceptionDetails.text + " " + (d.result.exceptionDetails.exception?.description || "") } : d.result.result.value);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] });
await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
await send("Page.enable", {});
await send("Page.addScriptToEvaluateOnNewDocument", { source: `window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));` });
await ev("localStorage.clear()");
await send("Page.reload", { ignoreCache: true });
await sleep(3000);

await ev(`window.__wait = async (n) => { const s = (ms) => new Promise((r) => setTimeout(r, ms));
  for (let k = 0; k < 40; k++) { await s(120); if (document.querySelectorAll(".msg.vigil").length > n && !document.querySelector(".thinking")) break; } await s(300); };
window.__read = (n) => { const ms = [...document.querySelectorAll(".msg.vigil")].slice(n).filter((m) => !m.classList.contains("thinking"));
  return { said: ms.map((m) => m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim()),
    btns: [...(document.querySelectorAll(".choices")[document.querySelectorAll(".choices").length - 1]?.querySelectorAll(".choice") || [])].map((b) => b.textContent) }; };
window.__tap = async (label) => { const n = document.querySelectorAll(".msg.vigil").length;
  const rows = [...document.querySelectorAll(".choices")]; const row = rows[rows.length - 1];
  const b = row && [...row.querySelectorAll(".choice")].find((x) => x.textContent === label);
  if (!b) return { err: "no button: " + label, btns: row ? [...row.querySelectorAll(".choice")].map((x) => x.textContent) : [] };
  b.click(); await __wait(n); return __read(n); };
window.__click = async (sel) => { const n = document.querySelectorAll(".msg.vigil").length; const el = document.querySelector(sel);
  if (!el) return { err: "no element " + sel }; el.click(); await __wait(n); return __read(n); };
window.__row = () => { const r = document.querySelector('[data-id="p-spy"]'); return r ? { state: r.dataset.state, text: r.textContent.replace(/\\s+/g, " ").trim(), index: [...document.querySelectorAll("#card-body .dose")].indexOf(r) } : null; };
true`);

const out = {};
const R = (k, v) => { out[k] = v; };
R("row0", await ev("__row()"));
R("payment", (await ev(`__tap("More checks ›")`)).err ? await ev("__read(0)") : await ev(`__tap("Before a big payment")`));
R("hacked", await ev(`__click('.pin[data-go=hacked]')`));
if (shot) {
  const s = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  fs.writeFileSync(shot, Buffer.from(s.result.data, "base64"));
}
R("guide", await ev(`__click('[data-guide="p-spy"]')`));
R("trust", await ev(`__tap("I set these up myself")`));
R("rowTrusted", await ev("__row()"));
await ev(`window.__extraApps.push({ pkg: "com.apspy.app", label: "Battery Saver", installer: "com.android.vending", granted: [], offers: [], certs: [] }); true`);
R("recheck", await ev(`__click('.pin[data-go=checkup]')`));
R("rowNew", await ev("__row()"));
R("ticks", await ev(`localStorage.getItem("vv.ticks")`));
R("errs", await ev("__errs"));
console.log(JSON.stringify(out, null, 1));
ws.close();
