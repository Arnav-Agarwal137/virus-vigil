// Laptop folder sweep: Downloads, Desktop and Temp against the known-malware list + YARA (25 Sep:
// check_folders). usage: node folders.mjs <cdp port>  (setup: tests/page/run.sh folders.mjs).
// The mock answers "check_folders" from window.__folders (set before the page loads); unset = the
// same failure any unknown call gets.
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

const ROOTS = [{ name: "Downloads", path: "C:\\Users\\x\\Downloads", files: 22000 }, { name: "Desktop", path: "C:\\Users\\x\\Desktop", files: 34 }, { name: "Temp", path: "C:\\Users\\x\\AppData\\Local\\Temp", files: 600 }];
const LIST = { checked: true, count: 1143288, recent: 2257, full: true, ageHours: 5, error: null };
const YARA = { ran: true, tag: "1381r418f", read: 22596, big: 1038, failed: 0, reason: null, maxMb: 64 };
const CLEAN = { checked: true, list: LIST, yara: YARA, roots: ROOTS, files: 22634, bytes: 26.5e9, fresh: 22634, unread: 2142, unreadNames: ["a.tmp", "b.tmp"],
  blocked: [], cloud: 0, badDirs: 0, skippedDirs: 1977, found: [], total: 22634, capped: false, left: 0, leftNewestMs: null, ms: 90000, walkMs: 2000 };
const SETUP = { path: "C:\\Users\\x\\Downloads\\GameSetup.exe", name: "GameSetup.exe", root: "Downloads", sha256: "ab".repeat(32), list: true, rules: [] };
const DROP = { path: "C:\\Users\\x\\AppData\\Local\\Temp\\run.js", name: "run.js", root: "Temp", sha256: "cd".repeat(32), list: false, rules: [{ set: "signature-base", rule: "SUSP_JS_Dropper" }] };
const BLOCK = { path: "C:\\Users\\x\\Desktop\\crack.exe", name: "crack.exe", root: "Desktop" };
const FOUND = { ...CLEAN, found: [SETUP, DROP], blocked: [BLOCK] };
const CAPPED = { ...CLEAN, capped: true, left: 5000, leftNewestMs: Date.UTC(2026, 8, 1, 12) };
// 26 Sep 2026: his own shortcut and a stock Vite template were called harmful. Loose-only catches.
const LNK = { path: "C:\\Users\\x\\Desktop\\Jarvis.lnk", name: "Jarvis.lnk", root: "Desktop", sha256: "ef".repeat(32), list: false, listWeak: false, weak: true, rules: [{ set: "bartblaze", rule: "Script_in_LNK", weak: true }] };
const VITE = { path: "C:\\Users\\x\\Desktop\\site\\vite.config.js", name: "vite.config.js", root: "Desktop", sha256: "4d".repeat(32), list: true, listWeak: true, weak: true, rules: [] };
const LOOSE = { ...CLEAN, found: [LNK, VITE] };
const MIXED = { ...CLEAN, found: [LNK, VITE, SETUP] };
// 29 Sep: Vigil's own checks (deeplook) send plain words as `why`; the page shows them, not a rule name.
const ZIPT = { path: "C:\\Users\\x\\Downloads\\backup.zip", name: "backup.zip", root: "Downloads", sha256: "aa".repeat(32), list: false, weak: false,
  rules: [{ set: "Vigil", rule: "TestFileInside", weak: false }], why: ["The antivirus TEST file (EICAR) is hidden inside it (an archive or app file)."] };
const CHAT = { path: "C:\\Users\\x\\Downloads\\SBI_KYC.apk", name: "SBI_KYC.apk", root: "Downloads", sha256: "bb".repeat(32), list: false, weak: true,
  rules: [{ set: "Vigil", rule: "AppFromChat", weak: true }], why: ["It is an Android app file that arrived through a chat app."] };
const OWN = { ...CLEAN, found: [ZIPT] };
const OWNWEAK = { ...CLEAN, found: [CHAT, LNK] };
const NOYARA = { ...CLEAN, yara: { ran: false, tag: null, read: 0, big: 0, failed: 0, reason: "rules not compiled", maxMb: 64 } };

const HELP = `window.__idle = async () => { for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 400)); };
window.__all = () => [...document.querySelectorAll(".msg.vigil .bubble")].map((b) => b.textContent.replace(/\\s+/g, " ").trim()).join(" || ");
window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop(); return m ? m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim() : ""; };
window.__btns = () => { const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1]; return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : []; };
window.__row = () => { const d = Object.values(__t.allDoses()).flat().find((d) => d.id === "d-folders"); return d ? { ...d, state: __t.doseState(d), flow: !!d.flow } : null; };
window.__stops = () => [...document.querySelectorAll(".msg.vigil .bubble")].filter((b) => /Stop - I found/.test(b.textContent)).length;
true`;
async function load(folders) {
  await send("Page.addScriptToEvaluateOnNewDocument", { source: `try { localStorage.clear(); } catch {} window.__errs = []; addEventListener("error", (e) => __errs.push(e.message)); addEventListener("unhandledrejection", (e) => __errs.push("rej " + e.reason));
    window.__folders = ${JSON.stringify(folders)};` });
  await send("Page.reload", { ignoreCache: true }); await sleep(3500);
  await ev(HELP);
  await ev(`(async () => { await __t.checkup(); await __idle(); await new Promise((r) => setTimeout(r, 2000)); await __idle(); })()`);
}
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got).slice(0, 500)); };

// 1. Two catches + one file Windows refused: said at once with each full path, row red, guide opens,
//    a repeat sweep with the same catches does not shout again.
await load(FOUND);
want("found: the checkup started a sweep", (await ev("window.__foldersCalls")) >= 1, await ev("window.__foldersCalls"));
const all = await ev("__all()");
want("found: said at once", /Stop - I found 3 harmful files on this laptop/.test(all), all.slice(0, 800));
want("found: each file with its path", /GameSetup\.exe/.test(all) && /Downloads\\GameSetup\.exe/.test(all) && /run\.js/.test(all) && /crack\.exe/.test(all), all.slice(0, 1500));
want("found: why, per kind", /public list of malware samples/.test(all) && /SUSP_JS_Dropper/.test(all) && /Windows refused to open it/.test(all), all.slice(0, 1500));
const row = await ev("__row()");
want("found: row red, not vouchable", row && row.state === "open" && row.ok === false && row.trustable === false, row);
want("found: note names them + first path", row && /GameSetup\.exe, run\.js, crack\.exe are harmful/.test(row.note) && /Downloads\\GameSetup\.exe/.test(row.note), row);
want("found: deep has hashes", row && row.deep.includes("ab".repeat(32)) && /blocked by Windows/.test(row.deep), row);
// A checkup summary that lands AFTER the Stop (the page's own checkup on load + this one) wipes the
// Stop's buttons, so it must carry the catch itself: never "All protections are on" and nothing else.
const last = await ev("__last()");
want("found: later summary names the catch", /things? needs? care/.test(last) && /A harmful file is in your folders/.test(last) && /GameSetup\.exe/.test(last), last.slice(0, 600));
const sBtns = await ev("__btns()");
want("found: later summary's way to the guide", sBtns.includes("Show me how to fix the rest"), sBtns);
const how0 = await ev(`(async () => { [...document.querySelectorAll(".choices .choice")].find((b) => b.textContent === "Show me how to fix the rest").click(); await __idle(); return __last(); })()`);
want("found: summary's guide opens", /Shift\+Delete/.test(how0), how0);
// The Stop's own buttons, where it IS the last word: a sweep that newly finds a file after the summary.
await ev(`(async () => { window.__folders = { ...window.__folders, found: [...window.__folders.found, { ...window.__folders.found[0], path: "C:\\\\Users\\\\x\\\\Desktop\\\\new.exe", name: "new.exe", root: "Desktop" }] }; await __t.refreshFolders(); await __idle(); })()`);
const btns = await ev("__btns()");
want("found: Stop's buttons", /Stop - I found a harmful file/.test(await ev("__last()")) && btns.includes("Show me how"), { btns, last: await ev("__last()") });
const how = await ev(`(async () => { [...document.querySelectorAll(".choices .choice")].find((b) => b.textContent === "Show me how").click(); await __idle(); return __last(); })()`);
want("found: guide opens", /Shift\+Delete/.test(how) && /Don't open the file/.test(how), how);
const n0 = await ev("__stops()");
await ev(`(async () => { await __t.refreshFolders(); await __idle(); })()`);
want("found: not repeated", n0 === 2 && (await ev("__stops()")) === 2, { n0, n1: await ev("__stops()") });
// Pressing the row's own sweep again with the same catches shows the guide instead of silence.
const again = await ev(`(async () => { await __t.sweepFoldersNow(); await __idle(); return __last(); })()`);
want("found: sweeping again shows the guide", /Shift\+Delete/.test(again), again);
want("found: no page errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

// 2. Clean: row given, the note says what was read in numbers; nothing shouted.
await load(CLEAN);
const c = await ev("__row()");
want("clean: row given", c && c.state === "given", c);
want("clean: note in numbers", c && /None of the 22,634 files in Downloads, Desktop, Temp \(26\.5 GB\) is one of 11,43,288 known malware samples, and 22,596 of them were read by 1,381 malware rules \(1,038 files over 64 MB/.test(c.note), c?.note);
want("clean: no loose words", c && !/apart from|loose pattern/.test(c.note), c?.note);
want("clean: skipped folders said", c && /1,977 program-building folders were skipped \(like node_modules/.test(c.note) && !/not read/.test(c.note), c?.note);
want("clean: unread said", c && /2,142 files were in use and could not be read/.test(c.note), c?.note);
want("clean: nothing shouted", (await ev("__stops()")) === 0, "");
const sw = await ev(`(async () => { await __t.sweepFoldersNow(); await __idle(); return __last(); })()`);
want("clean: sweep now reports", /None of the 22,634 files/.test(sw), sw);

// 2b. Loose-only catches: never "harmful", never shouted, row can still be given; said in words.
await load(LOOSE);
const lo = await ev("__row()");
want("loose: row given, not red", lo && lo.state === "given", lo);
want("loose: said as loose, not harmful", lo && /is one of 11,43,288 known malware samples - apart from the short text files mentioned below/.test(lo.note) && /2 files only matched loose patterns: 1 shortcut starts a script or a web address; 1 short text file is on the list only because ordinary templates get uploaded next to malware\. That is common/.test(lo.note) && !/ (is|are) harmful/.test(lo.note) && /not calling them harmful/.test(lo.note) && !/Delete/.test(lo.note) && /in the folded list “2 files worth a look”/.test(lo.note) && !/Jarvis\.lnk/.test(lo.note), lo?.note);
const lf = await ev(`(() => { const d = document.querySelector('.dose[data-id="d-folders"] details.look-fold'); return d ? { open: d.open, sum: d.querySelector("summary").textContent, items: [...d.querySelectorAll("li")].map((l) => l.textContent.replace(/\\s+/g, " ")) } : null; })()`);
want("loose: one folded line on the card, closed, both listed with words", lf && lf.open === false && lf.sum === "2 files worth a look" && lf.items.length === 2 && /Jarvis\.lnk C:\\Users\\x\\Desktop\\Jarvis\.lnk A shortcut that starts a script/.test(lf.items[0]) && /vite\.config\.js .*ordinary templates get uploaded/.test(lf.items[1]), lf);
want("loose: nothing shouted", (await ev("__stops()")) === 0, await ev("__all()"));
want("loose: summary names no catch", !/A harmful file is in your folders/.test(await ev("__all()")), "");
// Mixed: only the strong one is harmful and shouted.
await load(MIXED);
const mx = await ev("__row()");
want("mixed: red for the strong one only", mx && mx.state !== "given" && /^GameSetup\.exe is harmful/.test(mx.note), mx?.note);
want("mixed: one Stop, naming only the strong file", (await ev("__stops()")) === 1 && /Stop - I found a harmful file/.test(await ev("__all()")) && !/Stop[^|]*Jarvis\.lnk/.test(await ev("__all()")), await ev("__all()"));

// 2c. Vigil's own finds: the Stop says WHY in plain words (never "a few safe tools look alike");
//     a weak own find is named with its words on the row, not shouted, and the loose ones still said.
await load(OWN);
const oa = await ev("__all()");
want("own: said at once with its plain words", /Stop - I found a harmful file/.test(oa) && /TEST file \(EICAR\) is hidden inside it/.test(oa) && !/a few safe tools look alike/.test(oa), oa.slice(0, 1200));
await load(OWNWEAK);
const ow = await ev("__row()");
want("own weak: row given, said as worth a look, no names in the sentence", ow && ow.state === "given" && /1 file is worth a look, not harmful\./.test(ow.note) && !/SBI_KYC/.test(ow.note), ow?.note);
const owf = await ev(`[...document.querySelectorAll('.dose[data-id="d-folders"] details.look-fold li')].map((l) => l.textContent.replace(/\\s+/g, " "))`);
want("own weak: its plain words in the folded list", Array.isArray(owf) && owf.some((x) => /SBI_KYC\.apk C:\\Users\\x\\Downloads\\SBI_KYC\.apk It is an Android app file that arrived through a chat app\./.test(x)), owf);
want("own weak: the loose one still said", ow && /1 file only matched a loose pattern: 1 shortcut starts/.test(ow.note) && /“2 files worth a look”/.test(ow.note), ow?.note);
// His laptop, 29 Sep: ~300 finds worth a look. One line, the list capped, the rest counted.
await load({ ...CLEAN, found: Array.from({ length: 300 }, (_, i) => ({ ...LNK, name: `s${i}.lnk`, path: `C:\\Users\\x\\Desktop\\s${i}.lnk` })) });
const many = await ev(`(() => { const d = document.querySelector('.dose[data-id="d-folders"] details.look-fold'); return d ? { sum: d.querySelector("summary").textContent, li: d.querySelectorAll("li").length, more: (d.querySelector("p") || {}).textContent, folds: document.querySelectorAll('.dose[data-id="d-folders"] details.look-fold').length } : null; })()`);
want("many: one folded line, 200 shown, 100 counted", many && many.folds === 1 && many.sum === "300 files worth a look" && many.li === 200 && many.more === "And 100 more like these.", many);
want("many: nothing shouted", (await ev("__stops()")) === 0, "");
want("own weak: nothing shouted", (await ev("__stops()")) === 0, await ev("__all()"));

// 3. Capped: files left over -> NOT given (the all-clear needs every file read), said in the note.
await load(CAPPED);
const k = await ev("__row()");
want("capped: not given, has a way on", k && k.state === "due" && k.flow === true && /5,000 older files were not read \(last changed on 1 Sept 2026 or before\) - there are more files here than one sweep reads/.test(k.note) && !/left for/.test(k.note), k);

// 4. YARA could not run: not given, and the note says so.
await load(NOYARA);
const y = await ev("__row()");
want("no yara: not given, said", y && y.state === "due" && /malware rules could not run \(rules not compiled\)/.test(y.note), y);

// 5. No answer at all (the call fails): a to-do row with its own way to run it - never a green tick.
// 29 Sep: a fingerprint hit among the Echap stalkerware samples is named as that spy app, and
// never credited to MalwareBazaar's list.
await load({ ...CLEAN, found: [{ ...SETUP, name: "SysUpdate.apk", path: "C:\\Users\\x\\Downloads\\SysUpdate.apk", stalkerware: "TheTruthSpy" }] });
const sp = await ev("__all()");
want("spy sample: named, Echap, not MalwareBazaar", /Stop - I found a harmful file/.test(sp) && /Its exact file is TheTruthSpy, a known spy app \(stalkerware\): its fingerprint is on the Echap list/.test(sp) && !/MalwareBazaar/.test(sp), sp.slice(0, 1200));
// The samples ship inside the app, so a sweep with NO list downloaded still finds one: still a Stop.
await load({ ...CLEAN, list: { checked: false, error: "no list of known malware downloaded yet" }, found: [{ ...SETUP, name: "SysUpdate.apk", path: "C:\\Users\\x\\Downloads\\SysUpdate.apk", stalkerware: "TheTruthSpy" }] });
const spn = await ev("__all()");
const spnRow = await ev("__row()");
want("spy sample, no list: still a Stop, named", /Stop - I found a harmful file/.test(spn) && /TheTruthSpy, a known spy app/.test(spn) && spnRow?.ok === false, [spn.slice(0, 600), spnRow]);
// 29 Sep: a weak find the online checker (CIRCL) names as malware arrives from Rust as a strong row
// with Vigil/KnownMaliciousOnline and `online`: a Stop naming who reported it.
const ONLINE_WORDS = (await import("node:fs")).readFileSync(new URL("../../src-tauri/src/deeplook.rs", import.meta.url), "utf8")
  .match(/\("KnownMaliciousOnline", false, "([^"]+)"\)/)[1];
await load({ ...CLEAN, found: [{ ...LNK, weak: false, online: "malshare.com", rules: [...LNK.rules, { set: "Vigil", rule: "KnownMaliciousOnline", weak: false }], why: [ONLINE_WORDS] }] });
const on = await ev("__all()");
want("online: a Stop, words from Rust, names the collection", /Stop - I found a harmful file/.test(on) && on.includes(ONLINE_WORDS.slice(0, 60)) && /Reported by: malshare\.com\./.test(on) && !/MalwareBazaar/.test(on), on.slice(0, 1400));
// A clean sweep says what was asked online; a look-up that failed says so, never "clean" for those.
await load({ ...CLEAN, online: { ran: true, asked: 3, remembered: 0, bad: 0, known: 0, unknown: 1, failed: 2, notAsked: 4, error: "no connection" } });
const onr = await ev("__row()");
want("online failed: named on the row", onr && /asked a free public checker \(CIRCL\) about 3 fingerprints/.test(onr.note) && /2 could not be asked \(no connection\)/.test(onr.note) && /4 more wait for the next check/.test(onr.note), onr?.note);
await load(null);
const z = await ev("__row()");
want("failed: to-do with a flow", z && z.state === "due" && z.flow === true && /Not swept/.test(z.note), z);
want("failed: no errors", JSON.stringify(await ev("__errs")) === "[]", await ev("__errs"));

ws.close();
if (fails.length) { console.log("FAIL folders.mjs\n  " + fails.join("\n  ")); process.exit(1); }
console.log("PASS folders.mjs (found: said+paths+red+guide+no repeat+again; clean; own words; capped; no yara; failed)");
