// Scan flow (laptop) + helpline call buttons (phone vs laptop). usage: node scan.mjs <port>
// Setup as tests/spy/page.mjs (copy app/src, this mock as mock.js, serve on :8767) PLUS append "window.__t = { scanIntro };" to the COPIED main.js.
// Passed 24 Sep 2026: scan clean/caught/failed, laptop has no call button, phone "Call 1930" opens tel:1930, 4 spy phrasings -> safety-first answer, torch app -> app answer, 0 page errors.
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
const HELP = `
window.__idle = async () => { for (let k = 0; k < 100 && (document.querySelector(".thinking")); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 300)); };
window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop();
  const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1];
  return { said: m ? m.querySelector(".bubble").textContent.replace(/[ \\n\\t]+/g, " ").trim().slice(0, 500) : "", btns: row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : [] }; };
window.__tap = async (label) => { const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1];
  const b = row && [...row.querySelectorAll(".choice")].find((x) => x.textContent === label); if (!b) return "no button " + label;
  b.click(); await new Promise((r) => setTimeout(r, 200)); await __idle(); return __last(); };
window.__type = async (t) => { document.querySelector("#ask-input").value = t; document.querySelector("#ask").requestSubmit(); await new Promise((r) => setTimeout(r, 200)); await __idle(); return __last(); };
window.__skipAll = async () => { let r = __last(); for (let k = 0; k < 8 && r.btns.includes("Skip - just tell me what to do"); k++) r = await __tap("Skip - just tell me what to do"); return r; };
true`;
const out = {};
async function load(ua) {
  await send("Emulation.setUserAgentOverride", { userAgent: ua });
  await send("Page.reload", { ignoreCache: true }); await sleep(3000);
  await ev(HELP); await ev("__idle()");
}
// Laptop: scan flow, three outcomes.
await load("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36");
for (const mode of ["clean", "caught", "fail"]) {
  await ev(`window.__mode = ${JSON.stringify(mode)}; window.__t.scanIntro(); true`);
  out["intro-" + mode] = await ev("__last()");
  out["tick-" + mode] = await ev(`(async () => { const rows = document.querySelectorAll(".choices"); [...rows[rows.length-1].querySelectorAll(".choice")].find((x) => x.textContent === "Start the scan").click();
    await new Promise((r) => setTimeout(r, 1800)); return document.querySelector(".msg.thinking")?.textContent || "no thinking"; })()`);
  await ev("__idle()");
  out["result-" + mode] = await ev("__last()");
}
out.laptopMoney = await ev(`(async () => { await __type("I lost 20000 rupees in a UPI fraud today"); return __skipAll(); })()`);
out.laptopErrs = await ev("__errs");
// Phone: the same money story must offer Call 1930, and tapping it opens tel:1930.
await load("Mozilla/5.0 (Linux; Android 12; V2111) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0 Mobile Safari/537.36");
out.phoneMoney = await ev(`(async () => { await __type("I lost 20000 rupees in a UPI fraud today"); return __skipAll(); })()`);
out.phoneCall = await ev(`(async () => { await __tap("Call 1930 (cyber fraud)"); return window.__opened; })()`);
out.phoneSpy = await ev(`(async () => { await __type("my husband installed a spy app on my phone and I am scared"); return __skipAll(); })()`);
out["spy0"] = await ev(`(async () => { await __type("someone put mspy on my phone"); const r = await __skipAll(); return { said: r.said.slice(0, 260), btns: r.btns }; })()`);
out["spy1"] = await ev(`(async () => { await __type("my wife installed spyware on my mobile"); const r = await __skipAll(); return { said: r.said.slice(0, 260), btns: r.btns }; })()`);
out["spy2"] = await ev(`(async () => { await __type("I think my boyfriend is tracking me with an app"); const r = await __skipAll(); return { said: r.said.slice(0, 260), btns: r.btns }; })()`);
out["spy3"] = await ev(`(async () => { await __type("I installed a torch app and it wants SMS permission"); const r = await __skipAll(); return { said: r.said.slice(0, 260), btns: r.btns }; })()`);
out.phoneErrs = await ev("__errs");
console.log(JSON.stringify(out, null, 1)); ws.close();
// Until 25 Sep evening this file only PRINTED, so it could not fail (it was read by eye on 24 Sep).
// The assertions below are what that reading checked.
const fails = [];
const want = (name, cond) => { if (!cond) fails.push(name + " :: " + JSON.stringify(out[name] ?? null).slice(0, 300)); };
const said = (k) => out[k]?.said || "", btns = (k) => out[k]?.btns || [];
for (const m of ["clean", "caught", "fail"]) want("intro-" + m, btns("intro-" + m).includes("Start the scan"));
want("result-clean", /found nothing/.test(said("result-clean")) && /What I checked/.test(said("result-clean")));
want("result-caught", /caught 1 thing/.test(said("result-caught")) && /DIAGNOSIS/.test(said("result-caught")));
want("result-fail", /didn't run/.test(said("result-fail")) && !/found nothing/.test(said("result-fail")));
want("laptopMoney", /Call 1930 now/.test(said("laptopMoney")) && !btns("laptopMoney").some((b) => /^Call /.test(b)));
want("phoneMoney", btns("phoneMoney").includes("Call 1930 (cyber fraud)"));
want("phoneCall", JSON.stringify(out.phoneCall) === JSON.stringify(["tel:1930"]));
for (const k of ["phoneSpy", "spy0", "spy1", "spy2"]) want(k, /Someone may be watching/.test(said(k)) && btns(k).includes("Call 181 (women helpline)"));
want("spy3", btns("spy3").includes("Check my apps") && !/Someone may be watching/.test(said("spy3")));
want("laptopErrs", Array.isArray(out.laptopErrs) && out.laptopErrs.length === 0);
want("phoneErrs", Array.isArray(out.phoneErrs) && out.phoneErrs.length === 0);
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks (3 scan outcomes, call buttons, 5 spy/app answers, 0 errors)");
process.exit(fails.length ? 1 : 0);
