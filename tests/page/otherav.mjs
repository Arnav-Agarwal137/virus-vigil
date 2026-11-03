// Another antivirus on duty (McAfee/ESET/Norton): Windows switches Defender off by itself, so Vigil must
// not call the shield "off", must not read Defender's stale rows, and must not offer Defender scans as if
// they work. usage: node otherav.mjs <cdp port>
// Setup as scan-calls.mjs (copy app/src, scan-calls-mock.js as mock.js, serve on :8767) and append to the
// COPIED main.js: window.__t = { scanIntro, fullScanIntro, offlineIntro, hacked, checkFile, laptopDoses, deeperDoses, checkup, state };
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
await send("Emulation.setUserAgentOverride", { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36" });
await send("Page.reload", { ignoreCache: true }); await sleep(3000);
await ev(`window.__idle = async () => { for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 300)); };
window.__said = (n) => [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).slice(-n).map((m) => m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim().slice(0, 1200));
window.__btns = () => { const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1]; return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : []; };
true`);

const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got)); };
const out = {};
for (const av of ["defender", "mcafee", "stale"]) {
  // Card rows, straight from the checkup the page itself runs.
  const rows = await ev(`(async () => { window.__av = ${JSON.stringify(av)}; __t.state.scan = null; await __t.checkup(); await __idle();
    const s = __t.state.scan; return [...__t.laptopDoses(s), ...__t.deeperDoses(s)].filter((d) => /shield|tamper|sigs|otherav/.test(d.id)).map((d) => ({ id: d.id, ok: d.ok, name: d.name, note: d.note, how: d.how })); })()`);
  out[av + "-rows"] = rows;
  const ids = rows.map((r) => r.id);
  const shield = rows.find((r) => r.id === "shield");
  const second = rows.find((r) => r.id === "deep-otherav");
  if (av === "defender") {
    want("defender: shield ok", shield?.ok === true && !/McAfee/.test(shield.name), shield);
    want("defender: tamper+sigs shown", ids.includes("tamper") && ids.includes("sigs"), ids);
    want("defender: McAfee off, Defender does the job", /switched off - Defender does the job/.test(second?.note), second);
  } else {
    want(av + ": shield names McAfee", /McAfee/.test(shield?.name), shield);
    want(av + ": shield ok iff up to date", shield?.ok === (av === "mcafee"), shield);
    want(av + ": no Defender tamper/sigs rows", !ids.includes("tamper") && !ids.includes("sigs"), ids);
    if (av === "mcafee") want("mcafee: second-AV note not backwards", /your antivirus now/.test(second?.note) && !/Defender does the job/.test(second?.note), second);
    if (av === "stale") want("stale: guide is the other-AV one", shield?.how === "otherav" && second?.how === "otherav", [shield, second]);
  }
  // Scan buttons: the three intros.
  for (const f of ["scanIntro", "fullScanIntro", "offlineIntro"]) {
    const r = await ev(`(async () => { await __t.${f}(); await __idle(); return { said: __said(1)[0], btns: __btns() }; })()`);
    out[av + "-" + f] = r;
    const other = av !== "defender";
    if (f === "offlineIntro") want(av + " offline heads-up", other === /Heads-up/.test(r.said), r);
    else want(av + " " + f + " sends to McAfee", other === /run (a full scan|the scan) inside McAfee/.test(r.said), r);
    if (other && f !== "offlineIntro") want(av + " " + f + " offers second opinion", r.btns.includes("Get a second opinion"), r.btns);
    if (!other && f === "scanIntro") want("defender scanIntro unchanged", r.btns.includes("Start the scan"), r.btns);
  }
  // Was I hacked before? and a checked file.
  const h = await ev(`(async () => { await __t.hacked(); await __idle(); return __said(2); })()`);
  out[av + "-hacked"] = h;
  // McAfee installed but OFF (his laptop) is not pointed at; only an antivirus that is on.
  want(av + " hacked names McAfee's record iff it is on", (av !== "defender") === /McAfee keeps its own/.test(h.join(" ")), h);
  const cf = await ev(`(async () => { await __t.checkFile("C:\\\\x\\\\a.exe"); await __idle(); return __said(1)[0]; })()`);
  out[av + "-file"] = cf;
  // VirusTotal is a website link (never the API, never an upload): the main button only when no engine here scanned.
  const vt = await ev(`(() => { const rows = document.querySelectorAll(".choices"); const b = [...rows[rows.length - 1].querySelectorAll(".choice")].find((x) => /VirusTotal/.test(x.textContent)); return b ? b.classList.contains("main") : "no button"; })()`);
  want(av + " VirusTotal button main iff no engine scanned", vt === (av !== "defender"), vt);
  want(av + " VirusTotal note warns against upload", /don't press Upload there/.test(cf) && (av !== "defender") === /No virus scanner here looked/.test(cf), cf);
  if (av === "defender") want("defender file clean line", /scanned it and found nothing known/.test(cf), cf);
  else want(av + " file warns nothing was scanned", /may mean nothing was really scanned/.test(cf) && !/found nothing known/.test(cf), cf);
}
out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(JSON.stringify(out, null, 1));
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks");
ws.close();
process.exit(fails.length ? 1 : 0);
