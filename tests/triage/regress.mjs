// Did the triage change what happens to the answer-library question sets? Prints every question
// whose route is a problem family, so a how-to or a pasted message sent to triage is visible.
// node tests/triage/regress.mjs tests/answers/built-from.json tests/answers/held-out.json
import fs from "node:fs";
import { detectProblem, closestFamilies, doubtFamilies, isDistress, HOW_TO } from "../../src/triage.js";
import { ANSWERS } from "../../src/answers.js";
import { SCAMS } from "../../src/knowledge.js";
for (const f of process.argv.slice(2)) {
  const rows = JSON.parse(fs.readFileSync(f, "utf8"));
  const cats = {};
  for (const [cat, q] of rows) {
    const lib = ANSWERS.find((e) => e.test.test(q));
    const p = HOW_TO.test(q) && lib ? null : detectProblem(q);
    // The "Which is closest?" question (25 Sep): a doubted pattern, or nothing matched but the words lean to a problem.
    const doubt = p && doubtFamilies(q, p);
    const closest = !p && !(HOW_TO.test(q) && lib) && !lib && closestFamilies(q);
    const got = doubt ? `ask(${doubt})` : p || (closest ? `ask(${closest})` : !lib && isDistress(q) && !SCAMS.some((s) => s.test.test(q)) ? "vague" : null);
    cats[cat] = cats[cat] || { n: 0, triage: 0 };
    cats[cat].n++;
    if (got) { cats[cat].triage++; if (cat !== "incident") console.log(`  ${cat} -> ${got}: ${q}`); }
    else if (cat === "incident") console.log(`  incident NOT triaged: ${q}`);
  }
  console.log(f.split(/[\\/]/).pop(), JSON.stringify(cats));
}
