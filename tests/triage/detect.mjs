// Scores detectProblem() on a labelled set: node tests/triage/detect.mjs <set.json> [tune|held|all] [quiet]
// Rows alternate: odd index = "tune" (may be read and fixed against), even = "held" (never read;
// only the score is printed). A set written blind by another agent, 24 Sep 2026.
// "quiet" prints only the scores, never a row: for a fresh blind set that must stay unseen.
// VV_NOASK=1 turns off the "Which is closest?" question (25 Sep 20:53) to reproduce the old routing.
import fs from "node:fs";
import { detectProblem, closestFamilies, doubtFamilies, isDistress, HOW_TO } from "../../src/triage.js";
import { ANSWERS } from "../../src/answers.js";
import { SCAMS } from "../../src/knowledge.js";
// Same order as analyze() in main.js: problem families, then the how-to library, then the
// "Which is closest?" question, then the worried-words menu.
const looksLikeQuestion = (t) => /\?\s*$|^(?:what|how|why|when|where|who|which|should|can|could|is|are|do|does|did|will|would|am|tell me|explain)\b/i.test(t);
const hasUrl = (t) => /https?:|www\.|\b[a-z0-9-]+\.(?:com|in|net|org|xyz|top|info|co|me|ly|link|site|online)\b/i.test(t);
const ASK = !process.env.VV_NOASK;
export function route(t) {
  if (!hasUrl(t) && HOW_TO.test(t) && ANSWERS.find((e) => e.test.test(t))) return null;
  const p = detectProblem(t);
  if (p && ASK) {
    const d = doubtFamilies(t, p);
    if (d) return { ask: d };
  }
  if (p) return p;
  const words = t.split(/\s+/).length;
  if (!hasUrl(t) && words <= 20 && (looksLikeQuestion(t) || words <= 8) && ANSWERS.find((e) => e.test.test(t))) return null;
  if (ASK && !hasUrl(t)) {
    const c = closestFamilies(t);
    if (c) return { ask: c };
  }
  return !hasUrl(t) && isDistress(t) && !SCAMS.some((s) => s.test.test(t)) ? "vague" : null;
}

const [file, part = "all", quiet] = process.argv.slice(2);
if (file) {
  const rows = JSON.parse(fs.readFileSync(file, "utf8")).map((r, i) => ({ i, fam: r[0], msg: r[1] }));
  const pick = rows.filter((r) => part === "all" || (part === "tune" ? r.i % 2 === 1 : r.i % 2 === 0));
  let right = 0, missed = 0, wrong = 0, falseAlarm = 0;
  // The question: offered = the right family was among the buttons (one tap away);
  // notOffered = a problem, asked, but the right family was not a button ("Something else" still reaches it);
  // needless = a non-problem that got the question (one wasted tap, "None of these" on the page).
  let asked = 0, offered = 0, notOffered = 0, needless = 0;
  const show = [];
  for (const r of pick) {
    const got = route(r.msg);
    const want = r.fam === "notproblem" ? null : r.fam;
    if (got && typeof got === "object") {
      asked++;
      if (!want) { needless++; show.push(`ASKED   (not a problem) offered ${got.ask.join(",")}: ${r.msg}`); }
      else if (want === "vague" || got.ask.includes(want)) offered++;
      else { notOffered++; show.push(`ASKED   want ${want} offered ${got.ask.join(",")}: ${r.msg}`); }
      continue;
    }
    if (got === want) right++;
    else if (want && !got) { missed++; show.push(`MISSED  want ${want}: ${r.msg}`); }
    else if (!want && got) { falseAlarm++; show.push(`FALSE   got ${got}: ${r.msg}`); }
    else { wrong++; show.push(`WRONG   want ${want} got ${got}: ${r.msg}`); }
  }
  console.log(`${part}: ${right}/${pick.length} right · ${missed} missed · ${wrong} other family · ${falseAlarm} non-problems taken as problems`);
  if (ASK) console.log(`  question asked ${asked}: right family among the buttons ${offered} · not among them ${notOffered} · asked a non-problem ${needless} -> right with at most one tap ${right + offered}/${pick.length}`);
  if (part !== "held" && quiet !== "quiet") for (const s of show) console.log("  " + s);
}
