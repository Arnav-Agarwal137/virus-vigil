// "Do it all for me" (his idea, 7 Oct 2026): red rows carry the right Windows fix id, the summary's main
// button lists what changes and what stays by hand, one apply_all call carries every fix (passwords and
// cards untouched), "All but Remote Desktop" leaves RDP out, No changes nothing, and the full scan
// starts only after a Yes. usage: bash run.sh allfix.mjs (mock: window.__av = "red", apply_all).
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
await send("Emulation.setUserAgentOverride", { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36" });
await send("Page.reload", { ignoreCache: true }); await sleep(3000);
await ev(`window.__idle = async () => { await new Promise((r) => setTimeout(r, 200)); for (let k = 0; k < 100 && (document.querySelector(".thinking") || __t.state.busy); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 300)); };
window.__said = (n) => [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).slice(-n).map((m) => m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim().slice(0, 1500));
window.__row = () => { const rows = document.querySelectorAll(".choices"); return rows[rows.length - 1]; };
window.__btns = () => { const row = __row(); return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent + (b.classList.contains("main") ? "*" : "")) : []; };
window.__click = async (label) => { const b = [...(__row()?.querySelectorAll(".choice") || [])].find((x) => x.textContent === label); if (!b) return "no button " + label; b.click(); await __idle(); return "ok"; };
true`);

const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got)); };
const out = {};
const fresh = (av) => ev(`(async () => { window.__av = ${JSON.stringify(av)}; window.__allNo = false; window.__allArgs = []; localStorage.removeItem("vv.sweep");
  __t.state.scan = null; await __t.checkup(); await __idle(); return true; })()`);

// 1. Fix ids on the rows, from the checkup the page itself runs.
await fresh("red");
const ids = await ev(`(() => { const g = __t.allDoses(); return Object.fromEntries([...g.laptop, ...g.deeper].map((d) => [d.id, d.sysFix])); })()`);
out.ids = ids;
const expect = { shield: "realtime", fw: "fw", uac: "uac", "deep-guest": "guest", "deep-smb1": "smb1", "deep-rdp": "rdp" };
for (const [row, fix] of Object.entries(expect)) want(`red ${row} -> ${fix}`, ids[row] === fix, ids[row]);
for (const row of ["tamper", "sigs", "smartscreen", "deep-nopass"]) want(`${row} not fixable here`, ids[row] == null, ids[row]);

// 2. Summary: the main button, the hand-made rest still reachable, the old browser-only button gone.
const sum = await ev(`({ said: __said(1)[0], btns: __btns() })`);
out.summary = sum;
want("summary main = Do it all for me", sum.btns[0] === "Do it all for me*", sum.btns);
want("summary keeps the by-hand path", sum.btns.includes("Show me how to fix the rest"), sum.btns);
want("no old Fix what I can", !sum.btns.some((b) => /Fix what I can/.test(b)), sum.btns);
want("summary says one Yes box", /6 of them for you, behind one Windows Yes box/.test(sum.said), sum.said);

// 3. The offer itself.
await ev(`__click("Do it all for me")`);
const offer = await ev(`({ said: __said(1)[0], btns: __btns() })`);
out.offer = offer;
for (const n of ["Virus shield switched on", "Firewall on for every network", "Asks before big changes", "Guest account off", "Old file-sharing switched off", "Remote control from outside off"])
  want("offer lists " + n, offer.said.includes(n), offer.said);
want("offer names the full scan", /start a full scan of every file/.test(offer.said), offer.said);
want("offer warns restart (UAC)", /Asking before big changes takes effect after your next restart/.test(offer.said), offer.said);
want("offer warns Remote Desktop", /If you use Remote Desktop/.test(offer.said), offer.said);
want("offer names what stays by hand", /stay on your card marked to do: Every account has a password/.test(offer.said), offer.said);
want("offer buttons", JSON.stringify(offer.btns) === JSON.stringify(["Yes, do it all*", "All but Remote Desktop", "One by one", "Not now"]), offer.btns);
want("nothing changed before Yes", (await ev(`__allArgs.length`)) === 0, "called early");

// 4. All but Remote Desktop -> Yes: one call, RDP left out, passwords/cards untouched, then the full scan.
await ev(`__click("All but Remote Desktop")`);
const noRdp = await ev(`({ said: __said(1)[0], btns: __btns() })`);
want("no-RDP offer drops RDP", !noRdp.said.includes("Remote control from outside off") && !noRdp.btns.includes("All but Remote Desktop"), noRdp);
await ev(`__click("Yes, do it all")`); await sleep(1500); await ev(`__idle()`);
const args = await ev(`__allArgs`);
out.args = args;
want("exactly one apply_all", args.length === 1, args);
const a0 = args[0] || {};
want("system ids without rdp", JSON.stringify([...(a0.system || [])].sort()) === JSON.stringify(["fw", "guest", "realtime", "smb1", "uac"]), a0.system);
want("passwords + cards untouched", a0.blockPasswords === false && a0.blockCards === false, a0);
const after = await ev(`({ said: __said(10), sweep: JSON.parse(localStorage.getItem("vv.sweep") || "null") })`);
out.after = after;
want("report counts read-back", after.said.some((s) => /5 of 5 settings changed - I read each one back/.test(s)), after.said);
want("report says restart", after.said.some((s) => /Restart the laptop/.test(s)), after.said);
want("full scan started after Yes", !!after.sweep?.started && after.said.some((s) => /Windows Defender is now opening every file/.test(s)), after.sweep);

// 5. No on Windows' box: nothing changed, no scan.
await fresh("red");
await ev(`window.__allNo = true`);
await ev(`__click("Do it all for me")`);
await ev(`__click("Yes, do it all")`);
const no = await ev(`({ said: __said(1)[0], btns: __btns(), sweep: localStorage.getItem("vv.sweep") })`);
out.no = no;
want("No: nothing changed", /nothing was changed/.test(no.said) && no.btns.includes("Try again"), no);
want("No: no full scan", no.sweep == null, no.sweep);

// 6. One row from the card: just that fix, no full scan, no one-by-one.
await fresh("red");
const one = await ev(`(async () => { document.querySelector('[data-guide="fw"]').click(); await __idle(); return { said: __said(1)[0], btns: __btns(), go: document.querySelector('[data-id="fw"] .dose-go')?.textContent }; })()`);
out.one = one;
want("card row says I can fix this", /I can fix this/.test(one.go || ""), one.go);
want("single offer", JSON.stringify(one.btns) === JSON.stringify(["Yes, do it*", "Not now"]) && !/full scan/.test(one.said), one);
await ev(`window.__allNo = false; window.__allArgs = []`);
await ev(`__click("Yes, do it")`); await sleep(500);
const oneArgs = await ev(`__allArgs`);
want("single call = fw only", oneArgs.length === 1 && JSON.stringify(oneArgs[0].system) === '["fw"]' && oneArgs[0].browsers.length === 0, oneArgs);
want("single: no scan started", (await ev(`localStorage.getItem("vv.sweep")`)) == null, "sweep started");

// 7. Another antivirus on duty and out of date: its shield is NOT Defender's to switch on.
await fresh("stale");
const st = await ev(`(() => { const g = __t.allDoses(); return { shield: g.laptop.find((d) => d.id === "shield")?.sysFix ?? null, btns: __btns() }; })()`);
out.stale = st;
want("stale other AV: no realtime fix", st.shield === null, st);
want("stale other AV: no Do it all", !st.btns.some((b) => /Do it/.test(b)), st.btns);

// 8. All green: no button.
await fresh("defender");
const green = await ev(`__btns()`);
want("all green: no Do it all", !green.some((b) => /Do it/.test(b)), green);

out.errs = await ev("__errs");
want("no page errors", Array.isArray(out.errs) && out.errs.length === 0, out.errs);
console.log(JSON.stringify(out, null, 1).slice(0, 6000));
console.log(fails.length ? "FAIL " + fails.length + "\n" + fails.join("\n") : "PASS all checks");
ws.close();
process.exit(fails.length ? 1 : 0);
