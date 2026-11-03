// usage: node audit.mjs <cdp port> <page url substring> <questions.json> <out.json>
import fs from "node:fs";
const [port, urlPart, qFile, outFile] = process.argv.slice(2);
const qs = JSON.parse(fs.readFileSync(qFile, "utf8"));
const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = list.find((t) => t.type === "page" && t.url.includes(urlPart));
if (!page) { console.log("no page with", urlPart, list.map((t) => t.url)); process.exit(1); }
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pend = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const ev = (expression) => new Promise((r) => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method: "Runtime.evaluate", params: { expression, awaitPromise: true, returnByValue: true } })); })
  .then((d) => d.result.exceptionDetails ? { err: d.result.exceptionDetails.text + " " + (d.result.exceptionDetails.exception?.description || "") } : d.result.result.value);
const ASK = `async (t) => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const n = document.querySelectorAll(".msg.vigil").length;
  const i = document.querySelector("#ask-input"); i.value = t; document.querySelector("#ask").requestSubmit();
  for (let k = 0; k < 40; k++) { await sleep(150); if (document.querySelectorAll(".msg.vigil").length > n && !document.querySelector(".thinking")) break; }
  await sleep(400);
  const ms = [...document.querySelectorAll(".msg.vigil")].slice(n).filter((m) => !m.classList.contains("thinking"));
  const text = ms.map((m) => { const c = m.querySelector(".bubble").cloneNode(true); c.querySelectorAll(".deep").forEach((d) => d.remove()); return c.innerText.replace(/\\s+/g, " "); }).join(" || ");
  const btns = [...document.querySelectorAll(".choices .choice")].map((b) => b.textContent);
  return { text, btns };
}`;
await ev(`window.__ask = ${ASK}; window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); true`);
const out = [];
for (const [cat, q] of qs) {
  const r = await ev(`__ask(${JSON.stringify(q)})`);
  out.push({ cat, q, ...r });
}
out.push({ errs: await ev("__errs") });
fs.writeFileSync(outFile, JSON.stringify(out, null, 1));
console.log("wrote", out.length - 1);
ws.close();
