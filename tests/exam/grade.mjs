// node grade.mjs <port> <exam.json> <out.json>
// Asks the real app (over CDP) to forget what it remembers and sweep the phone's storage, then marks
// every exam file: CAUGHT (named in found, with its level) / MISSED / for controls, CLEAN or FALSE ALARM.
import fs from "node:fs";
const [port, keyFile, outFile] = process.argv.slice(2);
const key = JSON.parse(fs.readFileSync(keyFile, "utf8"));
const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const page = list.find((t) => t.type === "page") || list[0];
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let id = 0; const waiting = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (waiting.has(d.id)) { waiting.get(d.id)(d.result); waiting.delete(d.id); } };
const ev = (expression) => new Promise((r) => { const i = ++id; waiting.set(i, (res) => r(res?.exceptionDetails ? { ERR: res.exceptionDetails.exception?.description } : res?.result?.value)); ws.send(JSON.stringify({ id: i, method: "Runtime.evaluate", params: { expression, awaitPromise: true, returnByValue: true } })); });
const inv = (cmd, args = {}) => ev(`window.__TAURI_INTERNALS__.invoke(${JSON.stringify(cmd)}, ${JSON.stringify(args)}).then(r => r, e => ({INVOKE_ERR: String(e)}))`);
console.log("forget:", JSON.stringify(await inv("forget_fingerprints")));
const t0 = Date.now();
const res = await inv("check_folders");
console.log(`sweep ${(Date.now() - t0) / 1000}s checked=${res?.checked} files=${res?.files}`);
fs.writeFileSync(outFile, JSON.stringify(res, null, 1));
const found = res?.found || [];
const text = JSON.stringify(res);
const rows = key.map((k) => {
  const base = k.path.split("/").pop();
  const hit = found.find((f) => JSON.stringify(f).includes(base));
  let mark;
  if (k.expect === "clean") mark = hit ? "FALSE ALARM" : "clean (right)";
  else if (k.expect === "say-locked") mark = hit ? "said" : text.includes(base) ? "named somewhere" : "SILENT";
  else mark = hit ? "CAUGHT" : "MISSED";
  return { id: k.id, mark, level: hit ? (hit.weak ? "look" : "HARMFUL") : "", what: k.what, why: hit ? JSON.stringify(hit).slice(0, 220) : "" };
});
for (const r of rows) console.log(`${r.id}  ${r.mark.padEnd(14)} ${String(r.level).padEnd(10)} ${r.what}${r.why ? "\n      " + r.why : ""}`);
const want = key.filter((k) => k.expect !== "clean").length;
console.log(`SCORE caught ${rows.filter((r) => r.mark === "CAUGHT" || r.mark === "said").length} of ${want}; false alarms ${rows.filter((r) => r.mark === "FALSE ALARM").length}`);
ws.close(); process.exit(0);
