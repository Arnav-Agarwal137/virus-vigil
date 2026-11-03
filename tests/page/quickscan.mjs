// The Defender quick scan's "What I checked" (25 Sep: "the scan completes too fast, which takes the
// confidence off"). It must show Defender's OWN start/finish times, definitions and engine (scan_record),
// the threat record it read, and Vigil's own startup read - and never a line for something not read.
// usage: node quickscan.mjs <cdp port>. Setup: run.sh (mock = scan-calls-mock.js).
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
const run = (setup) => ev(`(async () => { ${setup}; await __t.scanFlow();
  for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150));
  await new Promise((r) => setTimeout(r, 300));
  const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop();
  const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1];
  return { text: m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim(), btns: row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : [] }; })()`);
const out = {};

out.clean = await run(`__mode = "clean"; __trick = false; __noRecord = false`);
want("clean: found nothing", /quick scan found nothing/.test(out.clean.text), out.clean);
want("clean: Defender's own times", /What I checked \(5\)/.test(out.clean.text) && /by its own record: started .+ finished .+ \(61 seconds\)/.test(out.clean.text), out.clean);
want("clean: definitions + engine + age", /definitions 1\.459\.388\.0 \(updated 5 hours ago\) and engine 1\.1\.26080\.3/.test(out.clean.text), out.clean);
want("clean: threat record read", /ever caught here \(1\) - none from this scan/.test(out.clean.text), out.clean);
want("clean: startup read", /all 2 programs that start by themselves: 1 signed by their maker, none using a malware trick/.test(out.clean.text), out.clean);
want("clean: no file count invented", !/files? scanned|\d+ files/.test(out.clean.text), out.clean);

out.trick = await run(`__mode = "clean"; __trick = true`);
want("trick: flagged, with a button", /1 program that starts by itself uses a trick malware uses/.test(out.trick.text) && /\(Updater\)/.test(out.trick.text) && out.trick.btns.includes("What starts by itself?"), out.trick);
want("trick: counted in the list", /all 3 programs .* 1 using a malware trick/.test(out.trick.text), out.trick);

out.caught = await run(`__mode = "caught"; __trick = false`);
want("caught: from this scan counted", /caught 1 thing/.test(out.caught.text) && /ever caught here \(2\) - 1 from this scan/.test(out.caught.text), out.caught);

out.norecord = await run(`__mode = "clean"; __noRecord = true`);
want("no record: says so, no invented times", /its own record of the times couldn't be read/.test(out.norecord.text) && !/by its own record: started/.test(out.norecord.text) && !/definitions/.test(out.norecord.text), out.norecord);

out.failed = await run(`__mode = "fail"; __noRecord = false`);
want("failed scan: no What I checked", /didn't run/.test(out.failed.text) && !/What I checked/.test(out.failed.text), out.failed);

out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks (clean, trick, caught, no record, failed)");
ws.close();
process.exit(fails.length ? 1 : 0);
