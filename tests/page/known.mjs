// Installed apps against known malware on the PHONE (25 Sep: check_installed). usage: node known.mjs <cdp port>
// Setup: tests/page/run.sh known.mjs. The mock answers "phone scan" from window.__phoneScan and
// "check_installed" from window.__known (set before the page loads, so the startup checkup uses them).
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
  { pkg: "com.calc", label: "Calculator", installer: "com.android.vending", paths: ["/data/app/~~a/com.calc-1/base.apk"], granted: [], offers: [], certs: [] },
  { pkg: "com.flash.update", label: "Flash Player Update", installer: null, paths: ["/data/app/~~b/com.flash.update-2/base.apk", "/data/app/~~b/com.flash.update-2/split_config.arm64_v8a.apk"], granted: [], offers: [], certs: [] },
];
// 29 Sep: the code inside every app file is read too (patterns + ruleHits).
const PAT = { ran: true, tag: "1413r420f", read: 3, remembered: 0, failed: 0, reason: null, recovered: false, crashSkipped: [] };
const FOUND = { checked: true, apps: 2, files: 3, unread: [], found: [{ pkg: "com.flash.update", path: APPS[1].paths[0], sha256: "ab".repeat(32) }], count: 1143288, full: true, recent: 2257, ageHours: 5, fresh: 3, ms: 900, error: null, patterns: PAT, ruleHits: [] };
const CLEAN = { ...FOUND, found: [] };
const RECENT = { ...FOUND, found: [], full: false, count: 0 };
const NOLIST = { checked: false, apps: 2, files: 0, found: [], unread: [], error: "no list yet" };

const HELP = `window.__idle = async () => { for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 400)); };
window.__all = () => [...document.querySelectorAll(".msg.vigil .bubble")].map((b) => b.textContent.replace(/\\s+/g, " ").trim()).join(" || ");
window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop(); return m ? m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim() : ""; };
window.__btns = () => { const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1]; return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : []; };
window.__row = () => Object.values(__t.allDoses()).flat().find((d) => d.id === "p-known") || null;
true`;
async function load(known, folders = null, system = null, extra = {}) {
  // Empty storage: earlier suites in the same browser leave records (a "running" laptop sweep) behind.
  await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.clear(); } catch {} window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));
    window.__phoneScan = ${JSON.stringify({ apps: APPS, ...(system ? { systemApps: system } : {}), ...extra })}; window.__known = ${JSON.stringify(known)}; window.__folders = ${JSON.stringify(folders)};` });
  await send("Page.reload", { ignoreCache: true }); await sleep(3500);
  await ev(HELP); await ev("__idle()"); await sleep(600); await ev("__idle()");
}
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got).slice(0, 400)); };

// 1. A known malware app: the phone's own paths (splits too) are sent; the chat says it at once;
//    the card row is red, names the app, cannot be vouched away, and opens its own guide.
await load(FOUND);
const args = await ev("window.__knownArgs");
want("sent: every app with every path", Array.isArray(args) && args.length >= 1 && JSON.stringify(args[0].apps) === JSON.stringify(APPS.map((a) => ({ pkg: a.pkg, paths: a.paths }))), args);
const all = await ev("__all()");
want("found: said at once", /Stop - I found a known malware app/.test(all) && /Flash Player Update/.test(all) && /DIAGNOSIS/.test(all), all);
const row = await ev("__row()");
want("found: row red", row && row.ok === false && row.apps?.length === 1 && row.apps[0].pkg === "com.flash.update", row);
want("found: not vouchable", row && row.trustable === false, row);
want("found: note names it", row && /Flash Player Update is on the public list of known malware/.test(row.note), row);
const btns = await ev(`[...document.querySelectorAll(".choices .choice")].map((b) => b.textContent)`);
want("found: buttons", btns.includes("Open Flash Player Update") && btns.includes("Show me how"), btns);
const how = await ev(`(async () => { const btn = [...document.querySelectorAll(".choices .choice")].filter((b) => b.textContent === "Show me how").pop(); btn.click(); await __idle(); return __last(); })()`);
want("found: guide opens", /Uninstall/.test(how) && /Safe mode/.test(how), how);
const hacked = await ev(`(async () => { await __t.phoneHacked(); await __idle(); return __last(); })()`);
want("hacked-before lists it first", /Known malware app/.test(hacked) && hacked.indexOf("Known malware app") < (hacked.indexOf("DIAGNOSIS", hacked.indexOf("Known malware app") + 1) + 1 || 1e9), hacked);
// A repeat run with the same catch does not shout again.
const n0 = await ev(`[...document.querySelectorAll(".msg.vigil .bubble")].filter((b) => /Stop - I found a known malware app/.test(b.textContent)).length`);
await ev(`(async () => { await __t.refreshKnown(); await __idle(); })()`);
const n1 = await ev(`[...document.querySelectorAll(".msg.vigil .bubble")].filter((b) => /Stop - I found a known malware app/.test(b.textContent)).length`);
want("found: not repeated", n0 === 1 && n1 === 1, { n0, n1 });
want("found: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 1b. 29 Sep: an installed app whose file is an Echap stalkerware sample is named as that spy app,
//     in the Stop and on the row, and never credited to MalwareBazaar.
await load({ ...FOUND, found: [{ ...FOUND.found[0], stalkerware: "Cerberus" }] });
const spAll = await ev("__all()"), spRow = await ev("__row()");
want("spy sample: Stop names it, Echap", /Stop - I found a known malware app/.test(spAll) && /Its exact file is Cerberus, a known spy app \(stalkerware\)/.test(spAll) && !/MalwareBazaar/.test(spAll), spAll.slice(0, 900));
want("spy sample: row names it, Echap", spRow && spRow.ok === false && /Flash Player Update is Cerberus, a known spy app \(stalkerware\): its exact file is on the Echap list/.test(spRow.note) && !/MalwareBazaar/.test(spRow.note), spRow?.note);

// 1c. 29 Sep: an installed app named ONLY by the online checker (CIRCL) is a Stop credited to that
//     checker and the collection that reported it - never to MalwareBazaar's list.
await load({ ...FOUND, found: [{ ...FOUND.found[0], online: "malshare.com" }] });
const onAll = await ev("__all()"), onRow = await ev("__row()");
want("online: Stop credits CIRCL", /Stop - I found a known malware app/.test(onAll) && /known as malware to a free public checker \(CIRCL hashlookup; reported by malshare\.com\)/.test(onAll) && !/MalwareBazaar/.test(onAll), onAll.slice(0, 900));
want("online: row credits CIRCL", onRow && onRow.ok === false && /Flash Player Update is known as malware to a free public checker \(CIRCL hashlookup; reported by malshare\.com\)/.test(onRow.note) && !/MalwareBazaar/.test(onRow.note), onRow?.note);
// A clean result says what was asked online, and that only fingerprints left.
await load({ ...CLEAN, online: { ran: true, asked: 1, remembered: 1, bad: 0, known: 1, unknown: 1, failed: 0, notAsked: 0, error: null } });
const onc = await ev("__row()");
want("online clean: said on the row", onc && onc.ok === true && /asked a free public checker \(CIRCL\) about 2 fingerprints/.test(onc.note) && /only the fingerprints left this phone, never the files/.test(onc.note) && /None is known as malware; 1 known as ordinary files; 1 never seen/.test(onc.note), onc?.note);

// 2. Clean: row green with the list size in words; nothing said.
await load(CLEAN);
const c = await ev("__row()");
want("clean: row green", c && c.ok === true && /none is one of 11,43,288 known malware samples/.test(c.note), c);
want("clean: nothing shouted", !/Stop - I found/.test(await ev("__all()")), "");
const sw = await ev(`(async () => { await __t.phoneSweep(); await __idle(); return __all(); })()`);
want("clean: sweep says what it read", /Here is exactly what I read/.test(sw) && /3 app files of 2 apps \(2 you installed, 0 that came with the phone\), each fingerprint compared with 11,43,288/.test(sw), sw.slice(-900));
want("clean: sweep offers the full re-read", (await ev("__btns()")).includes("Read everything again from scratch"), await ev("__btns()"));

// 3. Recent list only (mobile data): said as such, never passed off as the full list.
await load(RECENT);
const r = await ev("__row()");
want("recent: said as the 48-hour list", r && r.ok === true && /last 48 hours' 2,257 known malware samples/.test(r.note), r);

// 4. No list yet: NO row (not a green "none found"), and the receipt says it is not done.
await load(NOLIST);
want("no list: no row", (await ev("__row()")) === null, await ev("__row()"));
const rec = await ev("__all()");
want("no list: says NOT compared, why, and not complete", /Apps against known malware: NOT compared - no list yet/.test(rec) && /not everything was checked/.test(rec) && !/Scan complete/.test(rec), rec.slice(0, 600));
want("no list: no errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 5. The phone maker's apps (29 Sep): their files are sent too, after the ones he installed.
const SYS = [{ pkg: "com.vivo.gallery", paths: ["/system/app/Gallery/Gallery.apk"] }];
await load({ ...CLEAN, apps: 3, files: 4 }, null, SYS);
const args5 = await ev("window.__knownArgs");
want("maker: their files are sent too, marked", Array.isArray(args5) && JSON.stringify(args5[0].apps) === JSON.stringify([...APPS.map((a) => ({ pkg: a.pkg, paths: a.paths })), ...SYS.map((a) => ({ ...a, maker: true }))]), args5);
const r5 = await ev("__row()");
want("maker: row counts both", r5 && r5.ok === true && /2 you installed and 1 that came with it/.test(r5.note), r5);

// 6. Phone storage, switch off: NOT read - never green, never "0 files clean"; offers the switch.
const PFOLD = { checked: true, phone: true, list: { checked: true, count: 1143288, full: true, recent: 2257, ageHours: 5 },
  yara: { ran: true, tag: "1381r418f", read: 517, big: 3, failed: 0, maxMb: 64 }, roots: [{ name: "Phone storage", path: "/storage/emulated/0", files: 520 }],
  files: 520, bytes: 4.2e9, fresh: 520, unread: 0, unreadNames: [], blocked: [], cloud: 0, badDirs: 0, skippedDirs: 0, sealed: 2, found: [], total: 520, capped: false, left: 0, ms: 61000, walkMs: 900 };
await load(CLEAN, { checked: false, needsAccess: true, files: 0, found: [], sdk: 31 });
const fr = await ev(`Object.values(__t.allDoses()).flat().find((d) => d.id === "d-folders") || null`);
want("storage off: row is there, not green", fr && fr.ok === undefined && fr.flowLabel === "Allow and sweep" && /All files access/.test(fr.note) && !/None of the/.test(fr.note), fr);
const sw6 = await ev(`(async () => { await __t.phoneSweep(); await __idle(); return __all(); })()`);
want("storage off: receipt says not read", /Phone storage:<?\/?b?>? ?not read - Android needs you to switch on/.test(sw6) || /Phone storage: not read - Android needs/.test(sw6), sw6.slice(-900));
want("storage off: offers the switch", (await ev("__btns()")).includes("Allow and sweep"), await ev("__btns()"));

// 7. Phone storage swept clean: green, counts in words, the sealed folders said.
await load(CLEAN, PFOLD);
const f7 = await ev(`Object.values(__t.allDoses()).flat().find((d) => d.id === "d-folders") || null`);
want("storage clean: green with counts", f7 && f7.ok === true && /None of the 520 files in Phone storage \(4\.2 GB\)/.test(f7.note) && /Android\/data/.test(f7.note) && f7.name === "Every file in phone storage swept", f7);

// 8. Phone storage with a harmful file: said at once, on THIS PHONE, with the phone's treatment.
await load(CLEAN, { ...PFOLD, found: [{ path: "/storage/emulated/0/Download/KYC-update.apk", name: "KYC-update.apk", root: "Phone storage", sha256: "cd".repeat(32), list: true, listWeak: false, rules: [], weak: false }] });
const all8 = await ev("__all()");
want("storage found: said at once on this phone", /Stop - I found a harmful file on this phone/.test(all8) && /KYC-update\.apk/.test(all8) && /Files app/.test(all8), all8.slice(-900));
want("storage: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 9. 29 Sep busy guard: an earlier page's check is still running, so the first call answers busy.
//    The page waits for it to end (sweep_progress stops saying "running"), asks again, and the row
//    gets the real answer - never left empty.
await load(CLEAN);
const b9 = await ev(`(async () => { __knownArgs = []; __busyLeft = 1; __runningPolls = 2; const t = Date.now(); const k = await __t.refreshKnown(); await __idle();
  return { calls: __knownArgs.length, checked: k && k.checked, busy: k && k.busy, waited: Date.now() - t, row: Object.values(__t.allDoses()).flat().find((d) => d.id === "p-known") || null }; })()`);
want("busy: asked again after the running one ended", b9 && b9.calls === 2 && b9.checked === true && !b9.busy && b9.waited >= 1000, b9);
want("busy: row has the real answer", b9 && b9.row && b9.row.ok === true, b9 && b9.row);
want("busy: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 10. 29 Sep, his "It took 2 seconds to scan my phone how???": "Check my phone" WAITS for the file
//     reading (the mock's sweep takes 1.2 s) and only then sums up, with a confident verdict that
//     counts what was read. The summary's own text must carry the storage count - proof it waited.
const sumOf = `[...document.querySelectorAll(".msg.vigil .bubble")].map((b) => b.textContent.replace(/\\s+/g, " ")).filter((t) => /What I checked/.test(t)).pop() || ""`;
await load(CLEAN, PFOLD);
const s10 = await ev(sumOf);
want("waits: summary counts storage", /Every file in phone storage: 520 files/.test(s10), s10.slice(0, 900));
want("verdict: confident when all ran", /Scan complete - every check ran to the end, and nothing harmful was found/.test(s10) && /all 520 files/.test(s10) && /1,381 malware patterns/.test(s10) && /3 very large files/.test(s10), s10.slice(0, 900));
want("verdict: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 11. Storage switch off: never the confident line; says what was not read, offers the switch.
await load(CLEAN, { checked: false, needsAccess: true, files: 0, found: [], sdk: 31 });
const s11 = await ev(sumOf);
want("verdict: switch off is not complete", !/Scan complete/.test(s11) && /not everything was checked/.test(s11) && /All files access/.test(s11) && /Phone storage: NOT read/.test(s11), s11.slice(0, 900));
want("verdict: offers the switch", (await ev("__btns()")).includes("Allow and sweep"), await ev("__btns()"));

// 12. Only the 48-hour list on the phone: not complete either.
await load(RECENT, PFOLD);
const s12 = await ev(sumOf);
want("verdict: recent-only list is not complete", !/Scan complete/.test(s12) && /full known-malware list/.test(s12), s12.slice(0, 900));

// 13. A file that made the app stop last time: named, and the verdict is not "complete".
await load(CLEAN, { ...PFOLD, recovered: true, crashSkipped: ["/storage/emulated/0/DCIM/odd.mp4"], yara: { ...PFOLD.yara, failed: 1 } });
const s13 = await ev(sumOf);
want("verdict: crash file named, not complete", !/Scan complete/.test(s13) && /made Virus Vigil stop before/.test(s13) && /DCIM\/odd\.mp4/.test(s13) && !/files the pattern check could not read/.test(s13), s13.slice(0, 900));

// 14. 29 Sep: an app whose CODE hides the test file (no list hit): said at once in plain words,
//     row red with the words, verdict counts it; the clean receipt says the code was read.
const CODEHIT = { ...CLEAN, ruleHits: [{ pkg: "com.flash.update", path: APPS[1].paths[0], maker: false, weak: false,
  rules: [{ set: "Vigil", rule: "TestFileInside", weak: false }], why: ["The antivirus TEST file (EICAR) is hidden inside it (an archive or app file)."] }] };
await load(CODEHIT, PFOLD);
const a14 = await ev("__all()");
want("code: said at once with its words", /Stop - I found an app with harmful code on this phone/.test(a14) && /Harmful code inside/.test(a14) && /TEST file \(EICAR\) is hidden inside it/.test(a14), a14.slice(0, 1200));
const r14 = await ev("__row()");
want("code: row red, words, uninstall", r14 && r14.ok === false && r14.care === "An installed app has harmful code" && /Flash Player Update: The antivirus TEST file/.test(r14.note) && /Uninstall it now/.test(r14.note), r14);
want("code: verdict counts it", /Scan finished - I found 1 harmful thing/.test(await ev(sumOf)), (await ev(sumOf)).slice(0, 400));
want("code: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));
// A list hit AND a code hit on the same app: said once, counted once.
await load({ ...FOUND, ruleHits: CODEHIT.ruleHits }, PFOLD);
want("both: one app, one Stop", !/harmful code on this phone/.test(await ev("__all()")) && /Stop - I found a known malware app/.test(await ev("__all()")), (await ev("__all()")).slice(0, 600));
want("both: counted once", /I found 1 harmful thing/.test(await ev(sumOf)), (await ev(sumOf)).slice(0, 300));

// 15. A weak code hit: never shouted, row stays green, named as worth a look.
await load({ ...CLEAN, ruleHits: [{ pkg: "com.calc", path: APPS[0].paths[0], maker: false, weak: true,
  rules: [{ set: "Vigil", rule: "ArchiveLocked", weak: true }], why: ["It is locked with a password, so no scanner can look inside."] }] }, PFOLD);
const r15 = await ev("__row()");
want("weak code: green, worth a look", r15 && r15.ok === true && /read the code inside every one of them/.test(r15.note) && /Worth a look, not harmful: Calculator - It is locked with a password/.test(r15.note), r15?.note);
want("weak code: not shouted", !/Stop - I found/.test(await ev("__all()")), "");
want("weak code: verdict still complete", /Scan complete/.test(await ev(sumOf)) && /and the code inside each/.test(await ev(sumOf)), (await ev(sumOf)).slice(0, 500));

// 16. The code read did not run, or an app file stopped the app before: never "Scan complete".
await load({ ...CLEAN, patterns: { ran: false, reason: "the malware rules are not ready on this device" } }, PFOLD);
const s16 = await ev(sumOf);
want("code not read: not complete, said", !/Scan complete/.test(s16) && /the code inside your apps - the malware rules are not ready on this device/.test(s16), s16.slice(0, 900));
want("code not read: row says so", /Their code was not read \(the malware rules are not ready/.test((await ev("__row()"))?.note || ""), await ev("__row()"));
await load({ ...CLEAN, patterns: { ...PAT, read: 2, failed: 1, recovered: true, crashSkipped: ["/data/app/~~b/com.flash.update-2/base.apk"] } }, PFOLD);
const s16b = await ev(sumOf);
want("app crash: named, not complete", !/Scan complete/.test(s16b) && /1 app file that made Virus Vigil stop before/.test(s16b) && /com\.flash\.update-2\/base\.apk/.test(s16b) && !/pattern check could not read/.test(s16b), s16b.slice(0, 900));

// 17. 29 Sep: who ACTUALLY has notification access (notifReaders). An installed app with it is red and
// named; a system one is not counted; one row only; with no answer the old "who could" row stays.
const notifRows = "Object.values(__t.allDoses()).flat().filter((d) => d.id === 'p-notif')";
await load(CLEAN, null, null, { notifReaders: [{ pkg: "com.flash.update", label: "Flash Player Update", system: false }, { pkg: "com.android.systemui", label: "System UI", system: true }] });
const nr = await ev(notifRows);
want("notif: one row, red, names the app", Array.isArray(nr) && nr.length === 1 && nr[0].ok === false && /Flash Player Update is allowed to read every notification/.test(nr[0].note) && !/System UI/.test(nr[0].note), nr);
await load(CLEAN, null, null, { notifReaders: [{ pkg: "com.android.systemui", label: "System UI", system: true }] });
const ns = await ev(notifRows);
want("notif: system only = green", Array.isArray(ns) && ns.length === 1 && ns[0].ok === true && /No app you installed can read your notifications/.test(ns[0].note), ns);
await load(CLEAN);
const nf = await ev(notifRows);
want("notif: no answer = old row", Array.isArray(nf) && nf.length === 1 && /can be made to read notifications/.test(nf[0].note), nf);

ws.close();
if (fails.length) { console.log("FAIL known.mjs\n  " + fails.join("\n  ")); process.exit(1); }
console.log("PASS known.mjs (found: sent+said+red+guide+hacked+no repeat; clean; recent-only; no list; busy waits then asks again; code read: hit, both, weak, not run, crash)");
