// "Which is closest?" (his tap 25 Sep 20:53): when Vigil is unsure which problem a typed message is,
// it asks one tap question instead of guessing. usage: node closest.mjs <cdp port>   (exit 1 on any fault)
// Setup: tests/page/run.sh closest.mjs (serves a mocked copy of app/src on :8767).
// The two messages are real routes today (checked against tests/triage/detect.mjs): a pattern that the
// word counts doubt, and a message no pattern matched.
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
await ev(`window.__idle = async () => { for (let k = 0; k < 100 && document.querySelector(".thinking"); k++) await new Promise((r) => setTimeout(r, 150)); await new Promise((r) => setTimeout(r, 300)); };
window.__last = () => { const m = [...document.querySelectorAll(".msg.vigil")].filter((x) => !x.classList.contains("thinking")).pop(); return m ? m.querySelector(".bubble").textContent.replace(/\\s+/g, " ").trim() : ""; };
window.__btns = () => { const rows = document.querySelectorAll(".choices"); const row = rows[rows.length - 1]; return row ? [...row.querySelectorAll(".choice")].map((b) => b.textContent) : []; };
window.__type = async (t) => { document.querySelector("#ask-input").value = t; document.querySelector("#ask").requestSubmit(); await new Promise((r) => setTimeout(r, 200)); await __idle(); return { said: __last(), btns: __btns() }; };
window.__tap = async (label) => { const rows = document.querySelectorAll(".choices"); const b = [...rows[rows.length - 1].querySelectorAll(".choice")].find((x) => x.textContent === label); if (!b) return { said: "NO BUTTON " + label, btns: __btns() }; b.click(); await new Promise((r) => setTimeout(r, 200)); await __idle(); return { said: __last(), btns: __btns() }; };
true`);

const fails = [];
const want = (name, cond, got) => { if (!cond) fails.push(name + " :: " + JSON.stringify(got)); };
const Q = /Which is closest to what happened/;

// 1. Doubt: the "app" pattern fires (installed ... app), the words say the phone is acting up. App stays first.
// (The first example, "mouse apne aap chal raha", now goes straight to remote - fixed 25 Sep.)
const d = await ev(`__type("installed some cleaner app now phone showing ads everywhere even outside the app, remove kaise kare")`);
want("doubt: asks", Q.test(d.said), d);
want("doubt: pattern's family first", d.btns[0] === "I installed something doubtful", d.btns);
want("doubt: device offered", d.btns.includes("My phone or laptop acts strange"), d.btns);
want("doubt: something else + none", d.btns.includes("Something else ›") && d.btns.includes("None of these - I'll type it"), d.btns);
want("doubt: at most 4 families + 2", d.btns.length <= 6, d.btns);
// Tapping a family opens THAT family, still reading the message: "phone" + "ads everywhere" are
// picked up, so it goes straight to the device answer (its trail names the family).
const r = await ev(`__tap("My phone or laptop acts strange")`);
want("doubt: tap opens device", /triage "device"/.test(r.said) && /Pop-ups or ads everywhere \(from your message\)/.test(r.said) && !Q.test(r.said), r);

// 2. Nothing matched: the likeliest problems as buttons.
const c = await ev(`__type("my son clicked something on his tablet and now bank sms coming")`);
want("closest: asks", Q.test(c.said), c);
want("closest: 4 families + 2", c.btns.length === 6, c.btns);
const s = await ev(`__tap("Something else ›")`);
want("closest: something else opens the full menu", /What happened\? Pick the closest one/.test(s.said), s);

// 3. A how-to question and a plain problem the patterns are sure of are NOT asked.
const h = await ev(`__type("how do I turn on two step verification on whatsapp")`);
want("how-to: not asked", !Q.test(h.said), h);
const m = await ev(`__type("20000 rupees debited from my SBI account yesterday, I didn't share any otp")`);
want("sure problem: not asked", !Q.test(m.said), m);

const errs = await ev(`__errs`);
want("no page errors", Array.isArray(errs) && errs.length === 0, errs);
console.log(fails.length ? "FAIL\n  " + fails.join("\n  ") : "PASS closest.mjs (doubt, nothing-matched, how-to, sure problem)");
ws.close();
process.exit(fails.length ? 1 : 0);
