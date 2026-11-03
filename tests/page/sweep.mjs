// The first-run "scan everything" sweep (his rule 25 Sep 13:45) and the confident all-clear (13:50).
// A sweep counts as clean ONLY on Defender's own record of a full scan that began after Vigil started
// it and caught nothing. Stopped / an older scan / caught must never give the "Every file scanned" row,
// and the all-clear must never show while any row is not done.
// usage: node sweep.mjs <cdp port>. Setup: run.sh (mock = scan-calls-mock.js).
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
await send("Page.addScriptToEvaluateOnNewDocument", { source: `window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));
  try { localStorage.removeItem("vv.sweep"); localStorage.removeItem("vv.ticks"); } catch {}` });
await send("Page.reload", { ignoreCache: true }); await sleep(3500);
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got).slice(0, 900)); };

// Snapshot: last Vigil message, its buttons, the sweep row, the stored sweep.
const SNAP = `(() => {
  const ms = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking"));
  const text = ms.slice(-3).map((m) => m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim()).join(" || ");
  const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1];
  const r = document.querySelector('#card-body [data-id="sweep-full"]');
  const last = ms.length ? ms[ms.length - 1].querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim() : "";
  return { text, last, btns: row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : [],
    row: r ? { state: r.dataset.state, text: r.textContent.replace(/\\s+/g, " ").trim() } : null,
    sweep: JSON.parse(localStorage.getItem("vv.sweep") || "null"), clean: __t.sweepClean() };
})()`;
// Start a sweep with the given mock setup and wait until the finish message (or timeout) lands.
const start = async (setup, until) => {
  await ev(`(async () => { localStorage.removeItem("vv.sweep"); ${setup}; await __t.sweepStart(); })()`);
  for (let k = 0; k < 40; k++) { const s = await ev(SNAP); if (until.test(s.text)) return s; await sleep(150); }
  return ev(SNAP);
};
const out = {};

// 0. Before any sweep: the checkup summary offers it first, the row is due, no all-clear.
out.before = await ev(`(async () => { __t.summarize(); return ${SNAP}; })()`);
want("before: 'Scan everything first' is the first button", out.before.btns[0] === "Scan everything first", out.before);
want("before: row due", out.before.row?.state === "due" && /Not done yet/.test(out.before.row.text), out.before);
want("before: no all-clear", !/No threats found in anything I checked/.test(out.before.text), out.before);
out.more = await ev(`(async () => { await __t.moreChecks(); return ${SNAP}; })()`);
want("More checks lists Scan everything", out.more.btns.includes("Scan everything"), out.more);

// 1. Clean: Defender's record shows OUR full scan finished, nothing caught.
out.clean = await start(`__alive = false; __fullRec = "ours"; __mode = "clean"`, /found nothing/);
want("clean: said found nothing, with Defender's own times", /Defender opened every file on this laptop and found nothing/.test(out.clean.text) && /by its own record: started .+ finished/.test(out.clean.text), out.clean);
want("clean: stored found 0 + fullEnd", out.clean.sweep?.found === 0 && !!out.clean.sweep?.fullEnd && out.clean.clean === true, out.clean);
want("clean: row given", out.clean.row?.state === "given", out.clean);
want("clean: followed OUR pid", (await ev("__alivePids")).includes(4242), null);
out.cleanSum = await ev(`(async () => { __t.summarize(); return ${SNAP}; })()`);
want("clean: summary no longer offers the sweep", !out.cleanSum.btns.includes("Scan everything first"), out.cleanSum);

// 2. All-clear: every row ticked AND sweep clean -> the confident line. Untick one -> gone.
out.allclear = await ev(`(async () => {
  __t.state.folders = { checked: true, found: [], files: 10, bytes: 1e9, roots: [{ name: "Downloads" }], list: { checked: true, count: 5 }, yara: { ran: true, read: 10, tag: "300" } };
  for (const d of Object.values(__t.allDoses()).flat()) if (d.manual) __t.setTick(d.id, true);
  const left = Object.values(__t.allDoses()).flat().filter((d) => __t.doseState(d) !== "given").map((d) => d.id);
  __t.summarize(); return { left, ...${SNAP} }; })()`);
want("all-clear test reached: every row given under the mock", out.allclear.left.length === 0, out.allclear.left);
if (out.allclear.left.length) {
  // Some automatic rows are not given under this mock scan: the all-clear must NOT show then.
  want("all-clear withheld while auto rows are not done (" + out.allclear.left.join(",") + ")", !/No threats found in anything I checked/.test(out.allclear.text), out.allclear);
}
want("all-clear shown when every row is given", out.allclear.left.length > 0 || (/No threats found in anything I checked on this laptop\./.test(out.allclear.last) && /No app can promise a laptop is 100% safe/.test(out.allclear.last) && !/as well as the best security apps/.test(out.allclear.last)), out.allclear);
out.untick = await ev(`(async () => { __t.setTick("sweep-second", false); __t.summarize(); return ${SNAP}; })()`);
want("all-clear credits Defender when it is the scanner", /Windows Defender opened every file and found nothing/.test(out.allclear.last), out.allclear.last);
want("all-clear gone after unticking the second scanner", !/No threats found in anything I checked/.test(out.untick.last) && /protections I can check are on/.test(out.untick.last), out.untick);
await ev(`(async () => { for (const d of Object.values(__t.allDoses()).flat()) if (d.manual) __t.setTick(d.id, false); })()`);

// 3. Caught: the full scan finished and caught something -> row open, never clean.
out.caught = await start(`__alive = false; __fullRec = "ours"; __mode = "caught"`, /caught 1 thing/);
want("caught: said caught 1 thing", /Defender opened every file and caught 1 thing/.test(out.caught.text), out.caught);
want("caught: stored found 1, not clean, row open", out.caught.sweep?.found === 1 && out.caught.clean === false && out.caught.row?.state === "open", out.caught);

// 4. Stopped before finishing: the scanner exited but Defender records no full scan of ours.
out.stopped = await start(`__alive = false; __fullRec = "none"; __mode = "clean"`, /stopped before it finished/);
want("stopped: said so, offers start again", /The full scan stopped before it finished/.test(out.stopped.text) && out.stopped.btns.includes("Start it again"), out.stopped);
want("stopped: never clean, row due", out.stopped.clean === false && out.stopped.row?.state === "due" && !!out.stopped.sweep?.stopped, out.stopped);

// 5. An OLDER full scan in Defender's record (3 days ago) must not be read as ours finishing.
out.old = await start(`__alive = false; __fullRec = "old"; __mode = "clean"`, /stopped before it finished/);
want("old record: not taken as ours", /stopped before it finished/.test(out.old.text) && out.old.clean === false, out.old);

// 6. Didn't start at all.
out.nostart = await start(`__fullFail = true`, /didn't start/);
want("no start: says so, nothing stored", /The full scan didn't start/.test(out.nostart.text) && out.nostart.sweep === null, out.nostart);
await ev(`__fullFail = false`);

// 7. Another antivirus is primary: the row is a manual tick naming it; no sweep offer.
out.otherav = await ev(`(async () => { __av = "mcafee"; await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100)); const s = ${SNAP}; __av = "defender"; return s; })()`);
want("other AV: row names it, manual, no sweep offer", /Every file scanned \(by McAfee\)/.test(out.otherav.row?.text || "") && out.otherav.row?.state === "due" && !out.otherav.btns.includes("Scan everything first"), out.otherav);
await ev(`(async () => { await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100)); })()`);

// 7b. Another antivirus on duty, every row ticked: the all-clear must not say Defender scanned (31 Oct 2026).
out.otherClear = await ev(`(async () => { __av = "mcafee"; await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100));
  __t.state.folders = { checked: true, found: [], files: 10, bytes: 1e9, roots: [{ name: "Downloads" }], list: { checked: true, count: 5 }, yara: { ran: true, read: 10, tag: "300" } };
  for (const d of Object.values(__t.allDoses()).flat()) if (d.manual) __t.setTick(d.id, true);
  const left = Object.values(__t.allDoses()).flat().filter((d) => __t.doseState(d) !== "given").map((d) => d.id);
  __t.summarize(); const s = ${SNAP}; __av = "defender"; return { left, ...s }; })()`);
want("other AV all-clear: reached (every row given)", out.otherClear.left.length === 0, out.otherClear.left);
want("other AV all-clear: shown, and does NOT credit Defender", /No threats found in anything I checked/.test(out.otherClear.last) && !/Windows Defender opened every file/.test(out.otherClear.last), out.otherClear.last);
await ev(`(async () => { for (const d of Object.values(__t.allDoses()).flat()) if (d.manual) __t.setTick(d.id, false); __t.state.folders = null; await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100)); })()`);

// 7c. Defender's record could not be read after the full scan: never "found nothing", never clean.
out.unread = await start(`__alive = false; __fullRec = "ours"; __mode = "clean"; __thFail = true`, /couldn't read what it found/);
want("unread: says it couldn't read, not found nothing", /couldn't read what it found/.test(out.unread.text) && !/found nothing/.test(out.unread.last), out.unread);
want("unread: not clean, found not 0, row not given", out.unread.clean === false && out.unread.sweep?.found !== 0 && out.unread.row?.state !== "given" && /couldn't be read/.test(out.unread.row?.text || ""), out.unread);
out.unreadHacked = await ev(`(async () => { await __t.hacked(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100)); return ${SNAP}; })()`);
want("unread: Was I hacked says it couldn't read, no Good news", /couldn't read Windows Defender's record/.test(out.unreadHacked.last) && !/Good news/.test(out.unreadHacked.last), out.unreadHacked.last);
await ev(`__thFail = false`);

// 7d. scan.ps1 could not count past threats (threatCount null): the past row is not given.
out.countNull = await ev(`(async () => { __thCount = null; await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100));
  const d = __t.allDoses().past.find((x) => x.id === "past-reviewed"); const r = { note: d.note, st: __t.doseState(d) }; __thCount = undefined; return r; })()`);
want("count null: past row says couldn't read, not given", /couldn't read Defender's record/.test(out.countNull.note) && out.countNull.st !== "given", out.countNull);
out.countZero = await ev(`(async () => { __thCount = 0; await __t.checkup(); for (let k = 0; k < 60 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 100));
  const d = __t.allDoses().past.find((x) => x.id === "past-reviewed"); const r = { note: d.note, st: __t.doseState(d) }; __thCount = undefined; return r; })()`);
want("count 0: past row given (caught nothing)", /caught nothing/.test(out.countZero.note) && out.countZero.st === "given", out.countZero);

// 8. Still running (LAST: its 20 s timer stays armed): row due with "opening every file now".
out.running = await start(`__alive = true; __fullRec = "none"`, /Scanning every file/);
want("running: live line + row due, not clean", /Scanning every file/.test(out.running.text) && out.running.row?.state === "due" && /opening every file now/.test(out.running.row.text) && out.running.clean === false, out.running);

out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks (before, clean, all-clear, caught, stopped, old record, no start, other AV, other-AV all-clear, unread record, unread count, running)");
if (out.allclear.left.length) console.log("note: auto rows not given under the mock: " + out.allclear.left.join(","));
ws.close();
process.exit(fails.length ? 1 : 0);
