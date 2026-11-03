// Words and word pairs of a message, for the word-count backup (wordscore.js). Shared with its builder.
const STOP = new Set(["the", "a", "an", "and", "to", "of", "is", "it", "in", "on", "for", "at", "that", "this", "was", "be", "so", "or", "hai", "ka", "ki", "ke", "se", "ko", "to", "bhi"]);
export function tokens(text) {
  const w = String(text || "").toLowerCase().split(/[^a-z0-9ऀ-ॿ']+/).filter((x) => x && !STOP.has(x));
  const out = [...w];
  for (let i = 0; i + 1 < w.length; i++) out.push(w[i] + "_" + w[i + 1]);
  return out;
}
