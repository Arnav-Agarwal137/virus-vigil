// Walks EVERY question path in src/triage.js, on phone and on laptop, and checks each ends in a
// proper answer. Run: node tests/triage/walk.mjs   (exit 1 on any fault)
import { FAMILIES, NODES, optionsFor, nextOf, familyOf, leafFor } from "../../src/triage.js";

const GO_KEYS = new Set(["hacked", "accounts", "password", "checkup", "apps", "payment", "camera", "file", "second", "stealer"]);
const faults = [];
let paths = 0;
const fault = (path, why) => faults.push(`${path.join(" > ")}: ${why}`);

function checkLeaf(fam, ctx, phone, path) {
  let r;
  try { r = leafFor(fam, ctx, phone); } catch (e) { fault(path, `leaf threw ${e.message}`); return; }
  paths++;
  if (!r.title || !r.say) fault(path, "no title or say");
  if (!r.typeIt && (!Array.isArray(r.steps) || r.steps.length < 2)) fault(path, `only ${r.steps?.length} steps`);
  const text = JSON.stringify(r);
  if (/undefined|NaN|\[object/.test(text)) fault(path, "text contains undefined/NaN/[object");
  for (const g of r.go || []) if (!GO_KEYS.has(g)) fault(path, `unknown go key ${g}`);
  for (const l of r.links || []) if (!/^https:\/\//.test(l.url) || !l.label) fault(path, `bad link ${JSON.stringify(l)}`);
  const seen = new Set();
  for (const s of r.steps || []) { if (seen.has(s)) fault(path, `repeated step: ${s.slice(0, 40)}`); seen.add(s); }
}

function walk(nodeId, ctx, phone, path, depth) {
  const node = NODES[nodeId];
  if (!node) { fault(path, `missing node ${nodeId}`); return; }
  if (depth > 4) { fault(path, "more than 4 questions"); return; }
  const opts = optionsFor(node, phone);
  if (opts.length < 2) fault(path, `${nodeId} has ${opts.length} options`);
  for (const o of opts) {
    if (o.hint && o.hint.test("")) fault(path, `${nodeId} "${o.label}" hint matches empty text`);
    const c = { ...ctx, ...(o.set || {}) };
    const p = [...path, `${nodeId}:${o.label}`];
    const next = nextOf(node, o);
    if (next) walk(next, c, phone, p, depth + 1);
    else checkLeaf(familyOf(nodeId), c, phone, p);
    // "Skip - just tell me what to do" at this question: the leaf with what is known so far
    if (!node.noSkip) checkLeaf(familyOf(nodeId), ctx, phone, [...path, `${nodeId}:SKIP`]);
  }
}

for (const phone of [true, false]) {
  for (const [fam, f] of Object.entries(FAMILIES)) {
    if (!NODES[f.start]) fault([fam], `start node ${f.start} missing`);
    else walk(f.start, {}, phone, [phone ? "phone" : "laptop", fam], 1);
  }
}
// every node reachable
const reach = new Set();
const mark = (id) => { if (reach.has(id) || !NODES[id]) return; reach.add(id); for (const o of NODES[id].options) { const n = nextOf(NODES[id], o); if (n) mark(n); } };
for (const f of Object.values(FAMILIES)) mark(f.start);
for (const id of Object.keys(NODES)) if (!reach.has(id)) faults.push(`node ${id} unreachable`);

console.log(`paths walked: ${paths}, nodes: ${Object.keys(NODES).length}, families: ${Object.keys(FAMILIES).length}`);
if (faults.length) { console.log(`FAULTS (${faults.length}):`); for (const f of faults.slice(0, 40)) console.log("  " + f); process.exit(1); }
console.log("OK - every path ends in a proper answer");
