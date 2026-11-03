// Phone "Do it all for me" (his words 8 Oct 2026): Vigil re-reads apps and files itself, then walks
// through every step Android keeps for the person, one at a time, saying Android won't let an app do
// it and that a laptop does it by itself. usage: bash run.sh phoneall.mjs
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
await send("Emulation.setUserAgentOverride", { userAgent: "Mozilla/5.0 (Linux; Android 12; V2111) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36" });

const APPS = [
  // Offers notification access, so the hand-checked "Who reads your notifications" step carries an app
  // list too - and must NOT get Uninstall buttons (only the malware/remote/Trojan rows do; mutant 8 Oct 2026).
  { pkg: "com.calc", label: "Calculator", installer: "com.android.vending", paths: ["/data/app/a/base.apk"], granted: [], offers: ["android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"], certs: [] },
  { pkg: "com.flash.update", label: "Flash Player Update", installer: null, paths: ["/data/app/b/base.apk"], granted: [], offers: [], certs: [] },
];
const PAT = { ran: true, tag: "t", read: 2, remembered: 0, failed: 0, reason: null, recovered: false, crashSkipped: [] };
const FOUND = { checked: true, apps: 2, files: 2, unread: [], found: [{ pkg: "com.flash.update", path: "/data/app/b/base.apk", sha256: "ab".repeat(32) }], count: 1143288, full: true, recent: 2257, ageHours: 5, fresh: 2, ms: 900, error: null, patterns: PAT, ruleHits: [] };
const CLEAN = { ...FOUND, found: [] };
const NOACCESS = { checked: false, needsAccess: true, files: 0, found: [], sdk: 31 };
const SWEPT = { checked: true, files: 10, fresh: 10, total: 10, found: [], roots: [{ name: "Download", files: 10 }], ms: 300 };

const HELP = `window.__idle = async () => { await new Promise((r) => setTimeout(r, 200)); for (let k = 0; k < 120 && (document.querySelector(".thinking") || __t.state.busy); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 400)); };
window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop(); return m ? m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim() : ""; };
window.__row = () => { const rows = document.querySelectorAll(".choices"); return rows[rows.length - 1]; };
window.__btns = () => { const row = __row(); return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent + (b.classList.contains("main") ? "*" : "")) : []; };
window.__click = async (label) => { const b = [...(__row()?.querySelectorAll(".choice") || [])].find((x) => x.textContent === label); if (!b) return "no button " + label; b.click(); await __idle(); return "ok"; };
true`;
async function load(scan, known, folders) {
  await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.clear(); } catch {} window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));
    window.__phoneScan = ${JSON.stringify({ apps: APPS, ...scan })}; window.__known = ${JSON.stringify(known)}; window.__folders = ${JSON.stringify(folders)}; window.__settings = [];` });
  await send("Page.reload", { ignoreCache: true }); await sleep(3500);
  await ev(HELP); await ev("__idle()"); await sleep(600);
  await ev(`(async () => { await __t.checkup(); await __idle(); })()`);
}
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got).slice(0, 500)); };
const out = {};

// 1. Malware app + no screen lock + files not allowed yet.
await load({ lock: false }, FOUND, NOACCESS);
const sum = await ev(`__btns()`);
out.summary = sum;
want("malware catch keeps Show me how as the one main button", sum[0] !== "Do it all for me*" && sum.includes("Do it all for me") && sum.filter((b) => b.endsWith("*")).length === 1, sum);
want("Allow and sweep no longer the main button", !sum.includes("Allow and sweep*"), sum);

await ev(`__click("Do it all for me")`);
const intro = await ev(`({ said: __last(), btns: __btns() })`);
out.intro = intro;
want("intro: what Vigil does itself", /What I do myself: check every app against the known-malware list/.test(intro.said), intro.said);
want("intro: Android won't let an app", /Android doesn't let any app - not even a security app - change this for you/.test(intro.said), intro.said);
want("intro: laptop does it itself", /On a laptop, Virus Vigil does steps like this by itself/.test(intro.said), intro.said);
want("intro names the screen lock + malware app", /The phone has no screen lock/.test(intro.said) && /An installed app is known malware/.test(intro.said), intro.said);
want("intro: files permission first", /Android asks you once to let me read your files/.test(intro.said), intro.said);
want("intro buttons", JSON.stringify(intro.btns) === JSON.stringify(["Start*", "Not now"]), intro.btns);

// Start: re-check, then step 1 = the files switch (Android's own permission).
await ev(`window.__folders = ${JSON.stringify(NOACCESS)}`);
await ev(`__click("Start")`); await sleep(500); await ev(`__idle()`);
const s1 = await ev(`({ said: __last(), btns: __btns() })`);
out.step1 = s1;
want("step 1 = files switch", /^Step 1 of \d+: Let Virus Vigil read your files/.test(s1.said), s1.said);
want("step 1 opens the switch", s1.btns.includes("Open the switch") && s1.btns.includes("Done - sweep my files*"), s1.btns);
await ev(`__click("Open the switch")`);
want("Open the switch -> allFiles page", JSON.stringify(await ev(`__settings.map((x) => x.page)`)).includes("allFiles"), await ev(`__settings`));
// He switched it on: the sweep now reads files.
await ev(`window.__folders = ${JSON.stringify(SWEPT)}`);
await ev(`__click("Done - sweep my files")`); await sleep(1800); await ev(`__idle()`);

// Steps 2..n: each one names Android, opens its page, and the malware app gets an uninstall box.
const seen = [];
for (let k = 0; k < 8; k++) {
  const st = await ev(`({ said: __last(), btns: __btns() })`);
  if (!/^Step \d+ of \d+/.test(st.said)) { out.end = st; break; }
  seen.push(st);
  want(`step ${k + 2} says Android won't let an app`, /Android doesn't let any app/.test(st.said), st.said.slice(0, 200));
  if (/known malware/.test(st.said)) {
    want("malware step: uninstall box button", st.btns.includes("Uninstall Flash Player Update"), st.btns);
    await ev(`__click("Uninstall Flash Player Update")`);
    want("uninstall -> ACTION_DELETE page for its package", JSON.stringify(await ev(`__settings.at(-1)`)) === JSON.stringify({ page: "uninstall", pkg: "com.flash.update" }), await ev(`__settings.at(-1)`));
  }
  if (/no screen lock/.test(st.said)) want("lock step opens lock page", st.btns.includes("Set a screen lock"), st.btns);
  if (/Who reads your notifications/.test(st.said)) { out.notifSeen = true; want("notification step: no Uninstall button", !st.btns.some((b) => /^Uninstall /.test(b)), st.btns); }
  const done = st.btns.find((b) => /^Done - (next step|finish)\*$/.test(b));
  want(`step ${k + 2} has a Done button`, !!done, st.btns);
  if (!done) break;
  await ev(`__click(${JSON.stringify(done.replace(/\*$/, ""))})`);
}
out.steps = seen.map((s) => s.said.slice(0, 70));
const titles = seen.map((s) => s.said);
want("notification step present (it is what proves Uninstall stays off other rows)", out.notifSeen === true, out.steps);
want("lock step present",titles.some((t) => /no screen lock/.test(t)), out.steps);
want("malware step present", titles.some((t) => /known malware/.test(t)), out.steps);
want("Play Protect + USB hand steps present", titles.some((t) => /Play Protect/.test(t)) && titles.some((t) => /USB debugging/.test(t)), out.steps);
want("numbering consistent", seen.every((s, i) => new RegExp(`^Step ${i + 2} of ${seen.length + 1}:`).test(s.said)), out.steps);
want("chain ends with Check again", /That's every step/.test(out.end?.said || "") && (out.end?.btns || []).includes("Check again*"), out.end);
want("hand steps got stamped", (await ev(`JSON.parse(localStorage.getItem("vv.ticks") || "{}")`))["p-usb"] != null, "p-usb not ticked");

// 2. No catch, only hand steps left: Do it all is the main button.
await load({ lock: false }, CLEAN, SWEPT);
const plain = await ev(`__btns()`);
out.plain = plain;
want("no catch: Do it all is main", plain[0] === "Do it all for me*", plain);

// 3. Nothing left to tap: no Do it all on a phone that is all done.
await load({ lock: true }, CLEAN, SWEPT);
await ev(`(async () => { __t.setTick("p-play", true); __t.setTick("p-usb", true); __t.setTick("p-notif", true); __t.summarize(); await __idle(); })()`);
const done2 = await ev(`__btns()`);
out.allDone = done2;
want("all done: no Do it all", !done2.some((b) => /Do it all/.test(b)), done2);

// 31 Oct 2026: a check Android refused has NO row - it must read as "not checked", never as clean.
const FULL = { lock: true, accessibility: [], notifReaders: [], admins: [], sms: { pkg: "com.google.android.apps.messaging", label: "Messages", system: true } };
const pastState = `(() => { const d = __t.allDoses().past.find((x) => x.id === "past-reviewed"); return d ? __t.doseState(d) : "none"; })()`;
// A. Partial: screen control, notification readers, admins and texts were not given by Android.
await load({ lock: true }, CLEAN, SWEPT);
out.hackPartial = await ev(`(async () => { await __t.hacked(); await __idle(); return { said: __last(), past: ${pastState} }; })()`);
want("partial: names what it couldn't check", /I couldn't check .*screen control/.test(out.hackPartial.said) && /device-admin power/.test(out.hackPartial.said) && /not a full all-clear/.test(out.hackPartial.said), out.hackPartial);
want("partial: no blanket Good news", !/Good news/.test(out.hackPartial.said), out.hackPartial);
want("partial: takeover row NOT ticked", out.hackPartial.past !== "given", out.hackPartial);
out.allPartial = await ev(`(async () => {
  __t.state.folders = { checked: true, phone: true, files: 10, bytes: 1e9, found: [], roots: [{ name: "Download" }], list: { checked: true, count: 5, full: true }, yara: { ran: true, read: 10, tag: "300" } };
  for (const d of Object.values(__t.allDoses()).flat()) if (d.manual) __t.setTick(d.id, true);
  const left = Object.values(__t.allDoses()).flat().filter((d) => __t.doseState(d) !== "given").map((d) => d.id);
  __t.summarize(); await __idle(); return { left, said: __last() }; })()`);
// Every row that IS shown is given, so only the missing (unchecked) rows can be what withholds the all-clear.
want("partial: every shown row given (test reaches the all-clear decision)", out.allPartial.left.length === 0, out.allPartial.left);
want("partial: no all-clear even with every shown row ticked", !/No threats found in anything I checked/.test(out.allPartial.said), out.allPartial);
// B. Everything given and clean: the full Good news, and the row ticks.
await load(FULL, CLEAN, SWEPT);
out.hackFull = await ev(`(async () => { await __t.hacked(); await __idle(); return { said: __last(), past: ${pastState} }; })()`);
want("full: Good news, nothing unchecked", /Good news: I found none of the usual signs/.test(out.hackFull.said) && !/couldn't check/.test(out.hackFull.said), out.hackFull);
want("full: takeover row ticked", out.hackFull.past === "given", out.hackFull);
// B2. phoneVerdict: the app check must belong to THIS scan (knownRow's rule). Control first: same time = complete.
const VERDICT = (stale) => `(async () => {
  __t.state.folders = { checked: true, phone: true, files: 10, bytes: 1e9, found: [], roots: [{ name: "Download" }], list: { checked: true, count: 5, full: true }, yara: { ran: true, read: 10, tag: "300" } };
  __t.state.known = { ...${JSON.stringify(CLEAN)}, time: ${stale} ? "an-earlier-scan" : __t.state.scan.time };
  __t.state.checkMs = 1; __t.summarize(); await __idle();
  return [...document.querySelectorAll(".msg.vigil .verdict")].pop()?.textContent.replace(/\\s+/g, " ").trim() || ""; })()`;
out.verdictFresh = await ev(VERDICT(false));
want("verdict control: this scan's app check = complete", /Scan complete - every check ran to the end/.test(out.verdictFresh), out.verdictFresh);
out.verdictStale = await ev(VERDICT(true));
want("verdict: an earlier scan's app check is not this scan's", !/Scan complete/.test(out.verdictStale) && /not everything was checked/.test(out.verdictStale), out.verdictStale);
// C. Android refused one outside-store app's details (offers null): never "no banking-Trojan powers".
await load({ ...FULL, apps: APPS.map((a) => a.pkg === "com.flash.update" ? { ...a, offers: null } : a) }, CLEAN, SWEPT);
out.blind = await ev(`(() => { const d = __t.allDoses().deeper.find((x) => x.id === "p-trojan"); return d ? { note: d.note, st: __t.doseState(d), manual: !!d.manual } : null; })()`);
want("offers null: Trojan row says Android wouldn't show, not given", out.blind && /Android wouldn't show me what Flash Player Update can do/.test(out.blind.note) && out.blind.st !== "given", out.blind);

out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(JSON.stringify(out, null, 1).slice(0, 5000));
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks");
ws.close();
process.exit(fails.length ? 1 : 0);
