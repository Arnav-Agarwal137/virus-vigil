// Vigil's own look inside a checked file (sniff.rs -> r.look), who signed it (r.signer) and where it was
// downloaded from (r.origin), as the page words them. usage: node fileinside.mjs <cdp port>
// Setup as otherav.mjs (copy app/src, scan-calls-mock.js as mock.js, serve on :8767, append the window.__t line
// to the COPIED main.js). window.__file overrides the mocked check_file answer; window.__phish = names on the list.
// Part 1 needs no browser: every code sniff.rs can report must have words in knowledge.js LOOK (read from the files).
import { readFileSync } from "node:fs";
const here = new URL(".", import.meta.url);
const sniff = readFileSync(new URL("../../src-tauri/src/sniff.rs", here), "utf8");
const { LOOK } = await import(new URL("../../src/knowledge.js", here));
const codes = new Set([
  ...[...sniff.matchAll(/flag\(\s*&?(?:mut\s+)?\w+,\s*(?:"\w+"|if [^,]+)\s*,\s*"([a-z-]+)"/g)].map((m) => m[1]),
  ...[...sniff.matchAll(/code:\s*"([a-z-]+)"/g)].map((m) => m[1]),
]);
const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got)); };
want("found sniff codes (the reader itself works)", codes.size >= 30, [...codes]);
const noWords = [...codes].filter((c) => !LOOK[c]);
want("every sniff.rs code has words", noWords.length === 0, noWords);
const stale = Object.keys(LOOK).filter((c) => !codes.has(c));
want("no LOOK entry for a code sniff.rs never reports", stale.length === 0, stale);

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
const load = async (ua) => {
  await send("Emulation.setUserAgentOverride", { userAgent: ua });
  await send("Page.reload", { ignoreCache: true }); await sleep(3000);
  await ev(`window.__idle = async () => { for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 300)); };
  window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop(); const b = m.querySelector(".bubble");
    const v = b.querySelector(".verdict"); return { verdict: v ? [...v.classList].find((c) => c !== "verdict") : null, text: b.textContent.replace(/\\s+/g, " ").trim() }; };
  true`);
};
const check = (file, name, phish = []) => ev(`(async () => { window.__phish = ${JSON.stringify(phish)}; window.__file = ${JSON.stringify(file)};
  await __t.checkFile(${JSON.stringify("C:\\x\\" + name)}); await __idle(); return __last(); })()`);
const F = (level, code, detail = "") => ({ level, code, detail });
const out = {};

await load("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36");
const cases = [
  ["disguised", "invoice.pdf", { ext: "pdf", look: { read: true, kind: "program", flags: [F("danger", "disguised-program", ".pdf")] }, signer: { status: "NotSigned" }, origin: { marked: false } },
    (r) => r.verdict === "danger" && /program pretending to be a \.pdf file/.test(r.text) && /Nobody signed it/.test(r.text)],
  ["signed ok", "notepad.exe", { ext: "exe", look: { read: true, kind: "program", flags: [F("info", "can-run", ".exe")] }, signer: { status: "Valid", signer: "Microsoft Windows" }, origin: { marked: false } },
    (r) => r.verdict === "none" && /Signed by Microsoft Windows/.test(r.text) && /not that it is harmless/.test(r.text) && !/Nobody signed/.test(r.text) && !/opening it lets it do things/.test(r.text)],
  ["tampered", "tool.exe", { ext: "exe", look: { read: true, kind: "program", flags: [F("info", "can-run", ".exe")] }, signer: { status: "HashMismatch", signer: "Some Maker" }, origin: { marked: false } },
    (r) => r.verdict === "danger" && /changed after its maker signed it/.test(r.text)],
  ["self-signed", "tool2.exe", { ext: "exe", look: { read: true, kind: "program", flags: [F("info", "can-run", ".exe")] }, signer: { status: "NotTrusted", signer: "Google LLC" }, origin: { marked: false } },
    (r) => r.verdict === "danger" && /signature Windows doesn't trust/.test(r.text) && /Google LLC/.test(r.text)],
  ["unsigned program", "game.exe", { ext: "exe", look: { read: true, kind: "program", flags: [F("info", "can-run", ".exe")] }, signer: { status: "NotSigned" }, origin: { marked: false } },
    (r) => r.verdict === "careful" && /This is a program/.test(r.text) && /Nobody signed it/.test(r.text)],
  ["dropper script", "setup.ps1", { ext: "ps1", look: { read: true, kind: "text", flags: [F("info", "can-run", ".ps1"), F("careful", "downloads", "iwr x"), F("info", "starts-programs", "Start-Process"), F("careful", "hidden-window", "-w h"), F("danger", "download-and-run")] }, signer: { status: "NotSigned" }, origin: { marked: false } },
    (r) => r.verdict === "danger" && /downloads something and runs it/.test(r.text) && /What this script does if it is run/.test(r.text) && /downloads things from the internet/.test(r.text) && /runs in a hidden window/.test(r.text) && /starts other programs/.test(r.text)],
  ["mild script", "run.bat", { ext: "bat", look: { read: true, kind: "text", flags: [F("info", "can-run", ".bat"), F("info", "starts-programs", "cmd /c")] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "careful" && /starts other programs/.test(r.text) && !/this alone isn't proof/.test(r.text) && /This is a program/.test(r.text)],
  ["phish origin", "a.zip", { ext: "zip", look: { read: true, kind: "zip", flags: [] }, signer: null, origin: { marked: true, zone: 3, host: "https://evil-site.xyz/a.zip", referrer: "https://news.example.com/x" } },
    (r) => r.verdict === "danger" && /Downloaded from evil-site\.xyz/.test(r.text) && /news\.example\.com/.test(r.text) && /public list of phishing sites/.test(r.text), ["evil-site.xyz"]],
  ["plain origin", "b.zip", { ext: "zip", look: { read: true, kind: "zip", flags: [] }, signer: null, origin: { marked: true, zone: 3, host: "https://github.com/x/b.zip" } },
    (r) => r.verdict === "none" && /Downloaded from github\.com/.test(r.text) && !/phishing/.test(r.text)],
  ["mark without address", "c.txt", { ext: "txt", look: { read: true, kind: "text", flags: [] }, signer: null, origin: { marked: true, zone: 3 } },
    (r) => r.verdict === "none" && /marked this file as downloaded from the internet/.test(r.text)],
  ["unknown code shown", "d.dat", { ext: "dat", look: { read: true, kind: "other", flags: [F("careful", "brand-new-check", "xyz")] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "careful" && /Something unusual inside \(brand-new-check\)/.test(r.text) && /xyz/.test(r.text)],
  ["unreadable program", "e.exe", { ext: "exe", look: { read: false, error: "in use" }, signer: null, origin: null },
    (r) => r.verdict === "careful" && /couldn't open this file to look inside it \(in use\)/.test(r.text) && /This is a program/.test(r.text)],
  ["pdf auto code", "f.pdf", { ext: "pdf", look: { read: true, kind: "pdf", flags: [F("danger", "pdf-code", "runs on opening")] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "danger" && /This PDF contains code/.test(r.text) && /runs its code as soon as the file is opened/.test(r.text)],
  ["pdf plain code", "g.pdf", { ext: "pdf", look: { read: true, kind: "pdf", flags: [F("careful", "pdf-code", "")] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "careful" && !/as soon as the file is opened/.test(r.text)],
  ["clean text", "h.txt", { ext: "txt", look: { read: true, kind: "text", flags: [] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "none" && !/Be careful/.test(r.text) && /Nothing known found/.test(r.text)],
  ["macro doc", "i.docm", { ext: "docm", look: { read: true, kind: "zip", flags: [F("careful", "macros"), F("danger", "remote-template", "http://1.2.3.4/t.dotm")] }, signer: null, origin: { marked: false } },
    (r) => r.verdict === "danger" && /holds macros/.test(r.text) && /http:\/\/1\.2\.3\.4\/t\.dotm/.test(r.text)],
];
// "What I checked" (25 Sep): lists only checks that ran, with real counts and times from check_file.
const RC = [{ code: "type", n: 4096 }, { code: "name" }, { code: "pdf" }];
cases.push(
  ["receipt", "r.pdf", { ext: "pdf", size: 2097152, sha256: "ab", look: { read: true, kind: "pdf", flags: [], checked: RC }, ms: { hash: 12, look: 40, defender: 1300, total: 1400 }, signer: null, origin: { marked: false } },
    (r) => /What I checked \(6 checks - 1\.4 seconds\)/.test(r.text) && /fingerprint \(SHA-256\) from all 2\.0 MB/.test(r.text) && /inside the PDF/.test(r.text) && /Defender scanned it with its full engine 1\.3 s/.test(r.text) && /first 4 KB/.test(r.text)],
  ["receipt, Defender did not run", "r2.pdf", { ext: "pdf", size: 10, sha256: "ab", look: { read: true, kind: "pdf", flags: [], checked: RC }, defender: { ran: false, reason: "busy" }, signer: null, origin: null },
    (r) => /What I checked \(4 checks\)/.test(r.text) && !/scanned it with its full engine/.test(r.text) && !/downloaded from the internet/.test(r.text)],
  ["receipt, script lines", "s.ps1", { ext: "ps1", size: 900, sha256: "ab", look: { read: true, kind: "text", flags: [F("info", "can-run", ".ps1")], checked: [{ code: "type", n: 900 }, { code: "name" }, { code: "script", n: 10, lines: 1234 }] }, signer: { status: "NotSigned" }, origin: { marked: false } },
    (r) => /Read all 1,234 lines for 10 warning signs/.test(r.text) && /Checked who signed it/.test(r.text)],
  ["receipt, phishing lookup counted", "p.zip", { ext: "zip", size: 50, sha256: "ab", look: { read: true, kind: "zip", flags: [], checked: [{ code: "type", n: 50 }, { code: "name" }, { code: "zip-archive", n: 3 }] }, signer: null, origin: { marked: true, zone: 3, host: "https://downloads.example.com/p.zip" } },
    (r) => /read all 3 names inside/.test(r.text) && /Looked up downloads\.example\.com in a list of [\d,]+ phishing sites/.test(r.text)],
);
// Layer 2, YARA-X public malware patterns (25 Sep). A match is danger even when Defender is quiet;
// a scan that did not run is said, never counted as "nothing found".
const Y = (y) => ({ ext: "bin", size: 10, sha256: "ab", look: { read: true, kind: "other", flags: [], checked: [{ code: "type", n: 10 }] }, signer: null, origin: null, ms: { yara: 15 }, yara: y });
cases.push(
  ["pattern match", "m.bin", Y({ ran: true, rules: 1381, files: 418, ms: 15, matches: [{ rule: "Win32_Stealer_Test", set: "ReversingLabs", file: "rl/x.yara", what: { malware_type: "Stealer", malware: "Testy" } }] }),
    (r) => r.verdict === "danger" && /It matches 1 pattern known from malware \(ReversingLabs's public rules\)/.test(r.text) && /Win32_Stealer_Test - Stealer Testy/.test(r.text) && /Compared it against 1,381 public malware patterns/.test(r.text)],
  // 26 Sep 2026: a loose pattern alone (his own shortcut matched Script_in_LNK) is "careful", never "delete it".
  ["loose pattern only", "j.lnk", Y({ ran: true, rules: 1381, files: 418, ms: 15, matches: [{ rule: "Script_in_LNK", set: "bartblaze", file: "bartblaze/rules/generic/LNK_Ruleset.yar", what: {}, weak: true }] }),
    (r) => r.verdict === "careful" && /It matches 1 loose pattern \(bartblaze's public rules: Script_in_LNK\)/.test(r.text) && !/delete it/i.test(r.text) && !/known from malware/.test(r.text)],
  ["loose + strong = danger", "k.bin", Y({ ran: true, rules: 1381, files: 418, ms: 15, matches: [{ rule: "Script_in_LNK", set: "bartblaze", file: "bartblaze/rules/generic/LNK_Ruleset.yar", what: {}, weak: true }, { rule: "Win32_Stealer_Test", set: "ReversingLabs", file: "rl/x.yara", what: {}, weak: false }] }),
    (r) => r.verdict === "danger" && /It matches 2 patterns known from malware/.test(r.text)],
  ["pattern clean", "c.bin", Y({ ran: true, rules: 1381, files: 418, ms: 15, matches: [] }),
    (r) => r.verdict === "none" && !/known from malware/.test(r.text) && /Compared it against 1,381 public malware patterns \(ReversingLabs, bartblaze and YARAhub\) 15 ms/.test(r.text)],
  ["pattern check failed", "t.bin", Y({ ran: false, reason: "timeout", rules: 1381 }),
    (r) => /malware-pattern check couldn't read it \(timeout\)/.test(r.text) && !/Compared it against/.test(r.text) && !/known from malware/.test(r.text)],
);
// MalwareBazaar fingerprint list (25 Sep). found = danger; looked up and absent = a receipt line only;
// not looked up = said in words, never counted as a check.
const K = (known) => ({ ...Y({ ran: true, rules: 1381, files: 418, ms: 1, matches: [] }), ms: { known: 3 }, known });
cases.push(
  ["known sample", "k.bin", K({ checked: true, found: true, count: 1143140, recent: 2433, ageHours: 2 }),
    (r) => r.verdict === "danger" && /This exact file is a known malware sample/.test(r.text) && /Looked its fingerprint up among 11,45,573 known malware samples \(MalwareBazaar, list from today\) 3 ms/.test(r.text)],
  ["not a known sample", "n.bin", K({ checked: true, found: false, count: 1143140, recent: 0, ageHours: 60 }),
    (r) => r.verdict === "none" && !/known malware sample\./.test(r.text) && /among 11,43,140 known malware samples \(MalwareBazaar, list 3 days old\)/.test(r.text)],
  ["stalkerware sample", "s.apk", K({ checked: true, found: true, stalkerware: "mSpy", count: 1143140, recent: 2433, ageHours: 2 }),
    (r) => r.verdict === "danger" && /This exact file is mSpy, a known spy app \(stalkerware\)\. Its fingerprint is on the Echap list/.test(r.text) && !/known malware sample\./.test(r.text) && !/public list of files that security researchers/.test(r.text)],
  // 29 Sep: the online checker (CIRCL), asked with the fingerprint only.
  ["online: known malware", "o.bin", { ...K({ checked: true, found: false, count: 1143140, recent: 0, ageHours: 60 }), online: { said: "bad", source: "malshare.com", error: null } },
    (r) => r.verdict === "danger" && /A free public checker knows this exact file as malware \(CIRCL hashlookup; reported by malshare\.com\)/.test(r.text) && /Asked a free public checker \(CIRCL hashlookup\) about its fingerprint only - it knows this file as malware/.test(r.text)],
  ["online: never seen", "u.bin", { ...K({ checked: true, found: false, count: 1143140, recent: 0, ageHours: 60 }), online: { said: "unknown", source: null, error: null } },
    (r) => r.verdict === "none" && /it has never seen this file/.test(r.text) && !/knows this exact file as malware/.test(r.text)],
  ["online: could not ask", "f.bin", { ...K({ checked: true, found: false, count: 1143140, recent: 0, ageHours: 60 }), online: { said: null, source: null, error: "no connection" } },
    (r) => r.verdict === "none" && /couldn't ask the online checker about its fingerprint \(no connection\)/.test(r.text) && !/Asked a free public checker/.test(r.text)],
  ["no list yet", "x.bin", K({ checked: false, found: false, error: "no list of known malware on this laptop yet" }),
    (r) => /couldn't look its fingerprint up in the list of known malware \(no list of known malware on this laptop yet\)/.test(r.text) && !/Looked its fingerprint up/.test(r.text) && /What I checked \(4 checks/.test(r.text)],
);
for (const [name, fname, file, ok, phish] of cases) {
  const r = await check(file, fname, phish);
  out[name] = r;
  want("laptop: " + name, typeof r === "object" && ok(r), r);
}

// Phone: an .exe cannot run there, and there is no signature or Mark of the Web.
await load("Mozilla/5.0 (Linux; Android 12; V2111) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Mobile Safari/537.36");
const ph = await check({ ext: "exe", look: { read: true, kind: "program", flags: [F("info", "can-run", ".exe")] }, signer: null, origin: null, defender: { ran: false, reason: "phone" } }, "x.exe");
out.phone = ph;
want("phone: exe can't run here", typeof ph === "object" && /can't run on this phone/.test(ph.text) && !/opening it lets it do things on your laptop/.test(ph.text), ph);
const py = await check({ ext: "exe", look: { read: true, kind: "program", flags: [] }, signer: null, origin: null, defender: { ran: false, reason: "phone" }, yara: { ran: false, reason: "phone" } }, "y.exe");
want("phone: no word about the pattern check", typeof py === "object" && !/pattern/.test(py.text), py);
// Phone YARA-X (25 Sep evening): a match is flagged as on the laptop; the crash guard's switch-off is said.
const PY = (yara) => ({ ext: "pdf", look: { read: true, kind: "other", flags: [] }, signer: null, origin: null, defender: { ran: false, reason: "phone" }, yara, ms: { yara: 40 } });
const pm = await check(PY({ ran: true, rules: 1381, files: 418, ms: 40, matches: [{ rule: "Win32_Stealer_Test", set: "ReversingLabs", file: "rl/x.yara", what: { description: "Stealer Testy" } }] }), "m.pdf");
out.phoneMatch = pm;
want("phone: pattern match flagged + receipt", typeof pm === "object" && pm.verdict === "danger" && /It matches 1 pattern known from malware/.test(pm.text) && /Compared it against 1,381 public malware patterns/.test(pm.text), pm);
const po = await check(PY({ ran: false, reason: "off-here" }), "o.pdf");
out.phoneOff = po;
want("phone: guard switch-off said in words", typeof po === "object" && /switched off on this phone/.test(po.text) && !/Compared it against/.test(po.text) && !/couldn't read it/.test(po.text), po);
// Phone hash list (25 Sep): on mobile data only the recent list is there - the receipt must say so.
const PK = (known) => ({ ext: "bin", look: { read: true, kind: "other", flags: [] }, signer: null, origin: null, defender: { ran: false, reason: "phone" }, yara: { ran: false, reason: "phone" }, ms: { known: 2 }, known });
const pr = await check(PK({ checked: true, found: false, count: 0, recent: 2400, ageHours: 1, full: false }), "r.bin");
out.phoneRecent = pr;
want("phone: recent-only list said as such", typeof pr === "object" && pr.verdict === "none" && /among 2,400 known malware samples/.test(pr.text) && /only the last 48 hours' samples/.test(pr.text) && /once you're on Wi-Fi/.test(pr.text), pr);
const pf = await check(PK({ checked: true, found: true, count: 1143140, recent: 2400, ageHours: 1, full: true }), "f.bin");
out.phoneFound = pf;
want("phone: known sample flagged, no laptop advice", typeof pf === "object" && pf.verdict === "danger" && /This exact file is a known malware sample/.test(pf.text) && !/Scan everything/.test(pf.text) && !/only the last 48 hours/.test(pf.text), pf);

// 31 Oct 2026: the phishing list's makers stopped updating it - a link check says so after a week,
// from THEIR date (sourceDays), and says nothing when it is fresh or the date is unknown.
const linkSay = (days) => ev(`(async () => { window.__phish = []; window.__phishDays = ${JSON.stringify(days)}; await __t.analyze("is this safe https://sbi-kyc-update.xyz/login"); await __idle(); const r = __last(); window.__phishDays = undefined; return r; })()`);
out.phStale = await linkSay(29);
want("phishing list 29 days unchanged: said so", typeof out.phStale === "object" && /hasn't been updated by its makers for 29 days/.test(out.phStale.text), out.phStale);
out.phFresh = await linkSay(1);
want("phishing list 1 day old: no staleness line", typeof out.phFresh === "object" && !/hasn't been updated by its makers/.test(out.phFresh.text), out.phFresh);
out.phUnknown = await linkSay(null);
want("phishing list date unknown: no staleness line", typeof out.phUnknown === "object" && !/hasn't been updated by its makers/.test(out.phUnknown.text), out.phUnknown);

// 2 Nov 2026: two lists. Each list's own makers' date decides its own words, and a hit names the
// list that found it.
const two = (lists, phish = [], by = {}) => ev(`(async () => { window.__phish = ${JSON.stringify(phish)}; window.__phishLists = ${JSON.stringify(lists)}; window.__phishBy = ${JSON.stringify(by)}; await __t.analyze("is this safe https://sbi-kyc-update.xyz/login"); await __idle(); const r = __last(); window.__phishLists = undefined; window.__phishBy = undefined; return r; })()`);
const L = (pdb, cert) => [{ source: "Phishing.Database", count: 392000, ageHours: 3, sourceDays: pdb, error: null }, { source: "CERT Polska", count: 126000, ageHours: 1, sourceDays: cert, error: null }];
out.twoStale = await two(L(31, 0));
want("two lists: the stale one named, the fresh one said", typeof out.twoStale === "object" && /Phishing.Database hasn't been updated by its makers for 31 days/.test(out.twoStale.text) && /CERT Polska is up to date/.test(out.twoStale.text) && /Poland/.test(out.twoStale.text), out.twoStale);
out.twoFresh = await two(L(1, 0));
want("two lists both fresh: no staleness line", typeof out.twoFresh === "object" && !/hasn't been updated by its makers/.test(out.twoFresh.text), out.twoFresh);
out.twoHit = await two(L(31, 0), ["sbi-kyc-update.xyz"], { "sbi-kyc-update.xyz": ["CERT Polska"] });
want("a CERT Polska hit says CERT Polska", typeof out.twoHit === "object" && out.twoHit.verdict === "danger" && /public list of phishing sites \(CERT Polska\)/.test(out.twoHit.text), out.twoHit);

out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(JSON.stringify(out, null, 1).slice(0, 6000));
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : `PASS all checks (${cases.length} laptop cases + phone + ${codes.size} codes covered)`);
ws.close();
process.exit(fails.length ? 1 : 0);
