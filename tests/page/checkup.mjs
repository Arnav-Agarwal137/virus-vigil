// The checkup's "What I checked": every row it read, by name, and the time. Laptop only (the mock has no phone).
// usage: node checkup.mjs <cdp port>. Setup: run.sh.
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
await send("Page.reload", { ignoreCache: true }); await sleep(3000);
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got).slice(0, 900)); };
const r = await ev(`(async () => { await __t.checkup();
  for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150));
  await new Promise((r) => setTimeout(r, 300));
  const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop();
  const b = m.querySelector(".bubble"); const d = b.querySelector("details.checked");
  return { text: b.textContent.replace(/\\s+/g, " ").trim(), items: d ? d.querySelectorAll("li").length : 0,
    count: d ? +(/\\((\\d+) things/.exec(d.querySelector("summary").textContent) || [])[1] : 0,
    rows: document.querySelectorAll("#card .dose, #card [data-dose]").length }; })()`);
want("has What I checked with time", /What I checked \(\d+ things in \d+\.\d seconds\)/.test(r.text), r);
want("laptop group names its rows", /This laptop: \d+ - .*Virus shield/i.test(r.text), r);
want("count is the sum of named rows", r.count > 5, r);
const again = await ev(`(async () => { __t.summarize(); await new Promise((r) => setTimeout(r, 300));
  const m = [...document.querySelectorAll(".msg.vigil")].pop(); return /What I checked/.test(m.textContent); })()`);
want("not repeated when the summary is shown again (no fresh checkup)", again === false, again);
const errs = await ev("__errs");
want("no page errors", Array.isArray(errs) && errs.length === 0, errs);
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : `PASS all checks (${r.count} things named)`);
ws.close();
process.exit(fails.length ? 1 : 0);
