// node tests/spy/match.mjs   (from app/)
// Expectations are read OUT of the bundled list (not typed here), plus fixed negatives.
import { spyOf, SPY_LIST } from "../../src/spy.js";
import { STALKERWARE } from "../../src/stalkerware.js";
let fail = 0;
const check = (what, got, want) => { const ok = JSON.stringify(got) === JSON.stringify(want); if (!ok) fail++; console.log(ok ? "ok  " : "FAIL", what, ok ? "" : `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); };

// Every package and every certificate in the list is found (first owner wins for shared ones).
let pk = 0, ce = 0;
const firstPkg = new Map(), firstCert = new Map();
for (const a of STALKERWARE.apps) { a.packages.forEach((p) => firstPkg.has(p) || firstPkg.set(p, a.name)); a.certs.forEach((c) => firstCert.has(c) || firstCert.set(c, a.name)); }
for (const [p, n] of firstPkg) { if (spyOf({ pkg: p, certs: null })?.name === n) pk++; }
for (const [c, n] of firstCert) { if (spyOf({ pkg: "x.y", certs: [c.toLowerCase()] })?.name === n) ce++; }
check("all packages match", pk, firstPkg.size);
check("all certificates match (lower-case input too)", ce, firstCert.size);
check("list size sane", SPY_LIST.apps > 100 && SPY_LIST.packages > 500 && SPY_LIST.certs > 400, true);

// mSpy by package; TheTruthSpy by certificate under an unknown package name.
check("mSpy by package", spyOf({ pkg: "com.mspy.lite", certs: [] }), { name: "mSpy", by: "package" });
check("TheTruthSpy by certificate", spyOf({ pkg: "com.innocent.name", certs: ["AAAA", "31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"] }), { name: "TheTruthSpy", by: "certificate" });

// Ordinary apps: never flagged. Certificates below are real ones (Vigil's own release key SHA-1 is not
// known here; these are the AOSP public test/platform keys - hobby apps signed with them must NOT match).
for (const [pkg, certs] of [["com.whatsapp", null], ["com.google.android.apps.maps", []], ["com.arnav.virusvigil", ["61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81"]],
  ["com.android.dialer", ["27196E386B875E76ADF700E7EA84E4C6EEE33DFA"]], ["in.org.npci.upiapp", null], ["com.phonepe.app", null]]) {
  check(`not a spy: ${pkg}`, spyOf({ pkg, certs }), null);
}
check("null app", spyOf(null), null);
check("prefix is not a match (com.mspy.lite.fake)", spyOf({ pkg: "com.mspy.lite.fake", certs: null }), null);
console.log(fail ? `${fail} FAILED` : "all passed");
process.exit(fail ? 1 : 0);
