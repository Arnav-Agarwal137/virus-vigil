// The word-count guess and the call pattern's Hinglish/platform wording (25 Sep 2026).
// node tests/triage/guess.mjs   (exit 1 on any fault). Examples are tune rows or his own wording.
import { detectProblem, doubtFamilies, patternFamily, GUESS_SURE, ASK_COUNT } from "../../src/triage.js";
import { wordRank } from "../../src/wordscore.js";

let bad = 0;
const check = (name, ok, got) => { if (!ok) { bad++; console.log("FAIL", name, "got", JSON.stringify(got)); } };

// 1. A weak word-count guess (no pattern, top below GUESS_SURE) is a question, the guess first.
const weak = "my phone screen flickers and torch turns on by itself at night";
const wr = wordRank(weak);
check("weak: no pattern fires", patternFamily(weak, true) === null, patternFamily(weak, true));
check("weak: top is below GUESS_SURE", wr[0].p < GUESS_SURE, wr[0].p);
const guess = detectProblem(weak);
const d = doubtFamilies(weak, guess);
check("weak: asked", Array.isArray(d) && d.length === ASK_COUNT, d);
check("weak: guess is the first button", d && d[0] === guess, d);
check("weak: no notproblem/vague button", d && !d.includes("notproblem") && !d.includes("vague"), d);

// 2. A sure word-count guess still answers straight away.
const sure = "he morphed my picture and is asking for money or he'll post it";
const sr = wordRank(sure);
check("sure: no pattern fires", patternFamily(sure, true) === null, patternFamily(sure, true));
check("sure: top at or above GUESS_SURE", sr[0].p >= GUESS_SURE, sr[0].p);
check("sure: not asked", doubtFamilies(sure, detectProblem(sure)) === null, doubtFamilies(sure, detectProblem(sure)));

// 3. A pattern's answer is never turned into a question by a weak word score.
const pat = "someone called me and i shared the otp";
check("pattern: fires", patternFamily(pat, true) !== null, patternFamily(pat, true));
const pr = wordRank(pat);
const pf = detectProblem(pat);
check("pattern: not asked unless the words are sure of ANOTHER family",
  doubtFamilies(pat, pf) === null || (pr[0].fam !== pf && pr[0].p >= 0.9), doubtFamilies(pat, pf));

// 3b. Pattern fired AND the word counts weakly agree (below GUESS_SURE): still answered, never asked.
const agree = "laptop chori ho gaya car se";
check("agree: pattern is lost", patternFamily(agree, true) === "lost", patternFamily(agree, true));
check("agree: words agree below GUESS_SURE", wordRank(agree)[0].fam === "lost" && wordRank(agree)[0].p < GUESS_SURE, wordRank(agree)[0]);
check("agree: not asked", doubtFamilies(agree, detectProblem(agree)) === null, doubtFamilies(agree, detectProblem(agree)));

// 4. Call: Hinglish "message aaya" and "a strange WhatsApp message" (was routed to remote by word counts).
for (const m of [
  "mera whatsapp pe ajeeb message aaya aur maine reply kar diya ab darr lag raha hai",
  "I got a strange WhatsApp message and I replied, now I am scared",
  "kal raat ek unknown number se sms aaya ki bijli kat jayegi",
]) check("call: " + m, detectProblem(m) === "call", detectProblem(m));

console.log(bad ? `FAIL guess.mjs (${bad})` : "PASS guess.mjs (weak guess asks, sure guess answers, pattern untouched, 3 call wordings)");
process.exit(bad ? 1 : 0);
