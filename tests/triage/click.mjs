// Drives the real page (served with tests/answers/mock.js) through triage conversations.
// usage: node click.mjs <cdp port> <page url substring> <out.json> [phone]
// Each script step: {type: "text"} or {tap: "button label"}. Records Vigil's replies + buttons.
import fs from "node:fs";
const [port, urlPart, outFile, mode] = process.argv.slice(2);
const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = list.find((t) => t.type === "page" && t.url.includes(urlPart));
if (!page) { console.log("no page", list.map((t) => t.url)); process.exit(1); }
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pend = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const send = (method, params) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = (expression) => send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })
  .then((d) => d.result.exceptionDetails ? { err: d.result.exceptionDetails.text + " " + (d.result.exceptionDetails.exception?.description || "") } : d.result.result.value);

if (mode === "phone") {
  await send("Emulation.setUserAgentOverride", { userAgent: "Mozilla/5.0 (Linux; Android 12; V2111) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0 Mobile Safari/537.36" });
  await send("Page.reload", {});
  await new Promise((r) => setTimeout(r, 2500));
}
const HELPERS = `
window.__errs = window.__errs || []; addEventListener("error", (e) => __errs.push(e.message));
window.__wait = async (n) => { const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  for (let k = 0; k < 40; k++) { await sleep(120); if (document.querySelectorAll(".msg.vigil").length > n && !document.querySelector(".thinking")) break; }
  await sleep(300); };
window.__read = (n) => { const ms = [...document.querySelectorAll(".msg.vigil")].slice(n).filter((m) => !m.classList.contains("thinking"));
  return { said: ms.map((m) => { const c = m.querySelector(".bubble").cloneNode(true); c.querySelectorAll(".deep").forEach((d) => d.remove()); return c.innerText.replace(/\\s+/g, " ").trim(); }),
    deep: ms.map((m) => m.querySelector(".deep")?.innerText || "").filter(Boolean),
    btns: [...document.querySelectorAll(".choices .choice")].map((b) => b.textContent) }; };
window.__type = async (t) => { const n = document.querySelectorAll(".msg.vigil").length;
  const i = document.querySelector("#ask-input"); i.value = t; document.querySelector("#ask").requestSubmit(); await __wait(n); return __read(n); };
window.__tap = async (label) => { const n = document.querySelectorAll(".msg.vigil").length;
  const rows = [...document.querySelectorAll(".choices")]; const row = rows[rows.length - 1];
  const b = row && [...row.querySelectorAll(".choice")].find((x) => x.textContent === label);
  if (!b) return { err: "no button: " + label, btns: row ? [...row.querySelectorAll(".choice")].map((x) => x.textContent) : [] };
  b.click(); await __wait(n); return __read(n); };
true`;
await ev(HELPERS);
const SCRIPTS = JSON.parse(fs.readFileSync(new URL("./click-scripts.json", import.meta.url), "utf8"));
const out = [];
for (const s of SCRIPTS.filter((x) => (x.mode || "laptop") === (mode || "laptop"))) {
  const conv = { name: s.name, turns: [] };
  for (const step of s.steps) {
    const r = step.type ? await ev(`__type(${JSON.stringify(step.type)})`) : await ev(`__tap(${JSON.stringify(step.tap)})`);
    conv.turns.push({ step, ...r });
  }
  out.push(conv);
}
out.push({ errs: await ev("__errs") });
fs.writeFileSync(outFile, JSON.stringify(out, null, 1));
console.log("conversations:", out.length - 1, "page errors:", JSON.stringify(out[out.length - 1].errs));
ws.close();
